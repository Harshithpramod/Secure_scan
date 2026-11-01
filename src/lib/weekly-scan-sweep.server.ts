// Handles the sandbox worker's periodic "run this week's due scans" request
// (server-only). Shaped like sandbox-callback.server.ts's handler: a bearer
// token instead of the callback's HMAC signature, because this is a pull
// (the worker asking the app to act) rather than a push of a result.
//
// Auth reuses SANDBOX_API_TOKEN — the same token the app already presents to
// the sandbox for job submission — rather than introducing a third shared
// secret. Both sides already hold it.

import { triggerScan } from "@/lib/scan-trigger.server";

function timingSafeTokenEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function handleWeeklySweepRequest(request: Request): Promise<Response> {
  const expected = process.env.SANDBOX_API_TOKEN;
  if (!expected) {
    console.error("[weekly-sweep] SANDBOX_API_TOKEN not set");
    return new Response("misconfigured", { status: 500 });
  }

  const auth = request.headers.get("authorization") ?? "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token || !timingSafeTokenEqual(token, expected)) {
    return new Response("unauthorized", { status: 401 });
  }

  const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
  const supabaseAdmin = getSupabaseAdmin();

  // The worker pings this endpoint on a fixed schedule with no memory of when
  // it last actually triggered anything (the sandbox's Redis isn't persisted
  // — see docker-compose.yml — so the worker can't reliably remember that
  // across restarts). Due-ness is decided here instead, from
  // repositories.last_scan_at, which is durable and already updated by every
  // scan regardless of trigger type. Most pings should find nothing due.
  const intervalHours = Number(process.env.WEEKLY_SWEEP_INTERVAL_HOURS ?? 168);
  const cutoff = new Date(Date.now() - intervalHours * 60 * 60 * 1000).toISOString();

  const { data: repos, error } = await supabaseAdmin
    .from("repositories")
    .select("id, user_id, full_name")
    .eq("scan_mode", "weekly")
    .or(`last_scan_at.is.null,last_scan_at.lt.${cutoff}`);
  if (error) {
    console.error("[weekly-sweep] failed to list due repositories", error);
    return new Response("db error", { status: 500 });
  }

  if (!repos || repos.length === 0) {
    return Response.json({ weeklyRunId: null, triggered: 0, skipped: 0 });
  }

  const weeklyRunId = crypto.randomUUID();
  let triggered = 0;
  let skipped = 0;

  // Sequential, not parallel: the sandbox only runs one worker instance, so
  // actual execution is already serialized by its Redis queue — submitting
  // all jobs at once would just queue them instantly with no benefit, while
  // adding a burst of simultaneous GitHub API calls for no reason.
  for (const repo of repos) {
    try {
      const result = await triggerScan(supabaseAdmin, {
        repositoryId: repo.id,
        userId: repo.user_id,
        trigger: "scheduled",
        weeklyRunId,
      });
      if (result.ok) {
        triggered++;
      } else {
        skipped++;
        console.log(`[weekly-sweep] skipped ${repo.full_name}: ${result.message}`);
      }
    } catch (err) {
      // One user's broken GitHub connection must not abort the sweep for
      // everyone else's repos.
      skipped++;
      console.error(`[weekly-sweep] error triggering ${repo.full_name}`, err);
    }
  }

  console.log(`[weekly-sweep] run ${weeklyRunId}: triggered ${triggered}, skipped ${skipped}`);
  return Response.json({ weeklyRunId, triggered, skipped });
}
