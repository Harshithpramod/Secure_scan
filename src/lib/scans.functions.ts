import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { z } from "zod";
import { triggerScan } from "@/lib/scan-trigger.server";

// The scan pipeline itself (file selection, secret regexes, the AI call) now
// lives in sandbox/worker/scan.js. It used to run inline here, which meant ~20
// sequential GitHub fetches plus a slow LLM call inside a single HTTP request —
// past Cloudflare Workers' limits in production, and unresumable if the
// connection dropped. This function now only claims a scan row and enqueues
// the job; results arrive via the signed sandbox callback.
//
// The actual triggering logic lives in scan-trigger.server.ts, shared with the
// weekly sweep (weekly-scan-sweep.server.ts) so a button click and an
// automated weekly scan can never behave differently by accident.

export const startScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ repositoryId: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
    const supabaseAdmin = getSupabaseAdmin();

    const result = await triggerScan(supabaseAdmin, {
      repositoryId: data.repositoryId,
      userId: context.userId,
      trigger: "manual",
    });

    if (!result.ok) throw new Error(result.message);
    return { scanId: result.scanId, status: "queued" as const };
  });

export const getScanDetail = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ scanId: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
    const supabaseAdmin = getSupabaseAdmin();
    const { data: scan } = await supabaseAdmin
      .from("scans")
      .select("*, repositories(full_name)")
      .eq("id", data.scanId)
      .eq("user_id", context.userId)
      .maybeSingle();
    if (!scan) return { scan: null, logs: [] };

    const { data: logs } = await supabaseAdmin
      .from("scan_logs")
      .select("*")
      .eq("scan_id", data.scanId)
      .eq("user_id", context.userId)
      .order("created_at", { ascending: true });
    return { scan, logs: logs ?? [] };
  });
