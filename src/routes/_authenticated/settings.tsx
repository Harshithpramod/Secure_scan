import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Loader2, Github, CheckCircle2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { connectGithubPat, disconnectGithub, getGithubStatus } from "@/lib/github.functions";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({
    meta: [
      { title: "Settings — PentestAI" },
      { name: "description", content: "Manage your profile, notifications, and integrations." },
    ],
  }),
  component: SettingsPage,
});

function SettingsPage() {
  const qc = useQueryClient();

  const { data } = useQuery({
    queryKey: ["settings"],
    queryFn: async () => {
      const { data: userData } = await supabase.auth.getUser();
      const uid = userData.user?.id;
      if (!uid) throw new Error("Not signed in");
      const [profile, prefs] = await Promise.all([
        supabase.from("profiles").select("*").eq("id", uid).maybeSingle(),
        supabase.from("notification_preferences").select("*").eq("user_id", uid).maybeSingle(),
      ]);
      return {
        email: userData.user?.email ?? "",
        profile: profile.data,
        prefs: prefs.data,
        userId: uid,
      };
    },
  });

  const [fullName, setFullName] = useState("");
  const [jobTitle, setJobTitle] = useState("");
  // True once the user edits a field and until the save lands. Guards against
  // a background refetch (React Query refetches on window focus, reconnect and
  // remount) replacing half-typed input with the stale server value — the
  // fields would appear to blank themselves mid-edit.
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (data?.profile && !dirty) {
      setFullName(data.profile.full_name ?? "");
      setJobTitle(data.profile.job_title ?? "");
    }
    // `dirty` is intentionally not a dependency: this should re-seed when
    // server data arrives, not the moment editing stops.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.profile]);

  const saveProfile = useMutation({
    mutationFn: async () => {
      if (!data?.userId) throw new Error("Not signed in — reload the page and try again.");
      // upsert, not update: a missing profiles row (possible if the signup
      // trigger never ran for this account) makes update a silent no-op.
      // .select() then tells us how many rows were actually written — without
      // it, PostgREST returns 204 with no body and a zero-row write is
      // indistinguishable from success, so the UI would claim "Profile saved"
      // while nothing changed.
      const { data: rows, error } = await supabase
        .from("profiles")
        .upsert({ id: data.userId, full_name: fullName, job_title: jobTitle }, { onConflict: "id" })
        .select("id");
      if (error) throw error;
      if (!rows || rows.length === 0) {
        throw new Error("Nothing was saved — the profile row could not be written.");
      }
    },
    onSuccess: () => {
      toast.success("Profile saved");
      setDirty(false);
      qc.invalidateQueries({ queryKey: ["settings"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const updatePref = useMutation({
    mutationFn: async ({ key, value }: { key: string; value: boolean }) => {
      if (!data?.userId) return;
      const { error } = await supabase.from("notification_preferences").upsert(
        {
          user_id: data.userId,
          ...(data.prefs ?? {}),
          [key]: value,
          updated_at: new Date().toISOString(),
        } as never,
        { onConflict: "user_id" },
      );
      if (error) throw error;
    },
    onMutate: async ({ key, value }) => {
      await qc.cancelQueries({ queryKey: ["settings"] });
      const prev = qc.getQueryData(["settings"]);
      qc.setQueryData(["settings"], (old: any) =>
        old ? { ...old, prefs: { ...(old.prefs ?? {}), [key]: value } } : old,
      );
      return { prev };
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
    onError: (e: Error, _v, ctx: any) => {
      if (ctx?.prev) qc.setQueryData(["settings"], ctx.prev);
      toast.error(e.message);
    },
  });

  const prefs = data?.prefs;

  return (
    <div className="space-y-6 max-w-3xl">
      <section className="rounded-lg border border-border bg-card p-6">
        <h2 className="font-semibold mb-4">Profile</h2>
        <div className="space-y-4">
          <div>
            <Label>Email</Label>
            <Input aria-label="Email" value={data?.email ?? ""} disabled className="mt-1" />
          </div>
          <div>
            <Label htmlFor="fullName">Full name</Label>
            <Input
              id="fullName"
              value={fullName}
              onChange={(e) => {
                setFullName(e.target.value);
                setDirty(true);
              }}
              className="mt-1"
            />
          </div>
          <div>
            <Label htmlFor="jobTitle">Job title</Label>
            <Input
              id="jobTitle"
              value={jobTitle}
              onChange={(e) => {
                setJobTitle(e.target.value);
                setDirty(true);
              }}
              className="mt-1"
            />
          </div>
          <Button
            onClick={() => saveProfile.mutate()}
            disabled={saveProfile.isPending}
            className=""
          >
            {saveProfile.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save changes
          </Button>
        </div>
      </section>

      <section className="rounded-lg border border-border bg-card p-6">
        <h2 className="font-semibold mb-4">Notifications</h2>
        <div className="space-y-3">
          {[
            { key: "email_enabled", label: "Email notifications" },
            { key: "security_alerts", label: "Critical security alerts" },
            { key: "scan_completed", label: "Scan completed" },
            { key: "vulnerability_detected", label: "New vulnerability detected" },
            { key: "weekly_summary", label: "Weekly summary" },
          ].map((n) => (
            <label
              key={n.key}
              htmlFor={`pref-${n.key}`}
              // htmlFor forwards the row click to the switch and names it.
              className="flex min-h-11 cursor-pointer items-center justify-between gap-4 rounded-md px-1 transition-colors hover:bg-accent/40"
            >
              <span className="text-sm">{n.label}</span>
              <Switch
                id={`pref-${n.key}`}
                checked={!!prefs?.[n.key as keyof typeof prefs]}
                onCheckedChange={(v) => updatePref.mutate({ key: n.key, value: v })}
              />
            </label>
          ))}
        </div>
      </section>

      <GithubSection />
    </div>
  );
}

function GithubSection() {
  const qc = useQueryClient();
  const statusFn = useServerFn(getGithubStatus);
  const connectFn = useServerFn(connectGithubPat);
  const disconnectFn = useServerFn(disconnectGithub);
  const [token, setToken] = useState("");

  const { data: status, isLoading } = useQuery({
    queryKey: ["github-status"],
    queryFn: () => statusFn(),
  });

  const connect = useMutation({
    mutationFn: (t: string) => connectFn({ data: { token: t } }),
    onSuccess: (r) => {
      toast.success(`Connected as ${r.username}`);
      setToken("");
      qc.invalidateQueries({ queryKey: ["github-status"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const disconnect = useMutation({
    mutationFn: () => disconnectFn(),
    onSuccess: () => {
      toast.success("GitHub disconnected");
      qc.invalidateQueries({ queryKey: ["github-status"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <section className="rounded-lg border border-border bg-card p-6">
      <h2 className="font-semibold mb-2 flex items-center gap-2">
        <Github className="h-4 w-4" /> GitHub connection
      </h2>
      <p className="text-sm text-muted-foreground mb-4">
        Paste a GitHub Personal Access Token with <code>repo</code> and <code>read:user</code>{" "}
        scopes. Create one at{" "}
        <a
          href="https://github.com/settings/tokens/new?scopes=repo,read:user&description=PentestAI"
          target="_blank"
          rel="noreferrer"
          className="inline-flex min-h-6 items-center cursor-pointer text-accent-fg underline"
        >
          github.com/settings/tokens
        </a>
        . Stored server-side, never exposed to the browser.
      </p>

      {isLoading ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : status ? (
        <div className="flex items-center justify-between rounded-md border border-border p-3">
          <div className="flex items-center gap-2 text-sm">
            <CheckCircle2 className="h-4 w-4 text-severity-low" />
            Connected as <span className="font-medium">{(status as any).github_username}</span>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => disconnect.mutate()}
            disabled={disconnect.isPending}
          >
            Disconnect
          </Button>
        </div>
      ) : (
        <div className="flex gap-2">
          <Input
            type="password"
            placeholder="ghp_... or github_pat_..."
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <Button
            onClick={() => connect.mutate(token)}
            disabled={!token || connect.isPending}
            className=""
          >
            {connect.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Connect
          </Button>
        </div>
      )}
    </section>
  );
}
