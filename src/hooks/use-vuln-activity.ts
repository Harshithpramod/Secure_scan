import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { JobLogLine, VulnEvent } from "@/lib/activity-format";

/**
 * A missing table (lifecycle migration not applied yet) reads as "no
 * activity" rather than an error banner: the rest of the finding still works.
 */
function isMissingTable(err: { code?: string; message?: string } | null): boolean {
  if (!err) return false;
  return (
    ["42P01", "PGRST205", "PGRST204"].includes(String(err.code)) ||
    /does not exist|could not find the table/i.test(String(err.message ?? ""))
  );
}

/** Realtime INSERTs for one finding; the query re-fetches on each. */
function useInsertSubscription(table: string, vulnerabilityId: string | null, queryKey: unknown[]) {
  const qc = useQueryClient();
  useEffect(() => {
    if (!vulnerabilityId) return;
    const channel = supabase
      .channel(`${table}-${vulnerabilityId}`)
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table,
          filter: `vulnerability_id=eq.${vulnerabilityId}`,
        },
        () => qc.invalidateQueries({ queryKey }),
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
    // queryKey is rebuilt every render; its contents are what matter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [table, vulnerabilityId, qc]);
}

export function useVulnerabilityEvents(vulnerabilityId: string | null, { poll = false } = {}) {
  const queryKey = ["vuln-events", vulnerabilityId];
  useInsertSubscription("vulnerability_events", vulnerabilityId, queryKey);
  return useQuery({
    queryKey,
    enabled: Boolean(vulnerabilityId),
    queryFn: async (): Promise<VulnEvent[]> => {
      const { data, error } = await supabase
        .from("vulnerability_events")
        .select("id, kind, message, data, created_at, scan_id")
        .eq("vulnerability_id", vulnerabilityId!)
        .order("created_at", { ascending: true });
      if (error) {
        if (isMissingTable(error)) return [];
        throw error;
      }
      return (data ?? []) as VulnEvent[];
    },
    refetchInterval: poll ? 4000 : false,
  });
}

/**
 * Console lines for every verify/fix job run against this finding. Polls
 * while a job is in flight, as a fallback for projects without Realtime
 * enabled on the table.
 */
export function useJobLogs(vulnerabilityId: string | null, { active = false } = {}) {
  const queryKey = ["job-logs", vulnerabilityId];
  useInsertSubscription("job_logs", vulnerabilityId, queryKey);
  return useQuery({
    queryKey,
    enabled: Boolean(vulnerabilityId),
    queryFn: async (): Promise<JobLogLine[]> => {
      const { data, error } = await supabase
        .from("job_logs")
        .select("id, job_id, job_kind, seq, stage, level, message, data, created_at")
        .eq("vulnerability_id", vulnerabilityId!)
        .order("created_at", { ascending: true })
        .limit(1500);
      if (error) {
        if (isMissingTable(error)) return [];
        throw error;
      }
      return (data ?? []) as JobLogLine[];
    },
    refetchInterval: active ? 1500 : false,
  });
}
