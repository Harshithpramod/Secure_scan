// Checks whether a weekly sweep is fully finished for a user, and if so sends
// them one digest email covering every scan and verification from that run
// (server-only).
//
// Called from two places after their own DB writes: persistScanResults (a
// scan just finished) and applyVerifyVerdict (a verification just finished).
// Both a scan-complete and a verify-complete callback can notice "this run is
// done" within moments of each other, so the actual send is guarded by an
// insert into weekly_digest_log — whichever call wins the unique-constraint
// race sends the email; the other sees a conflict and does nothing.
//
// No timeout fallback: the sandbox guarantees a terminal callback for every
// job it accepts (a worker exception or probe crash both still post a
// "failed" verdict), so a run cannot wait forever for a stray job.

import type { AdminClient } from "@/lib/supabase-admin.server";
import { sendEmail } from "@/lib/email.server";

type Sev = "critical" | "high" | "medium" | "low";

export async function maybeSendWeeklyDigest(
  supabaseAdmin: AdminClient,
  userId: string,
  weeklyRunId: string | null | undefined,
): Promise<void> {
  if (!weeklyRunId) return;

  const { data: scans, error: scansErr } = await supabaseAdmin
    .from("scans")
    .select("id, status, repository_id, security_score, repositories(full_name)")
    .eq("user_id", userId)
    .eq("weekly_run_id", weeklyRunId);
  if (scansErr) throw scansErr;
  if (!scans || scans.length === 0) return;

  const allScansTerminal = scans.every(
    (s: any) => s.status === "completed" || s.status === "failed",
  );
  if (!allScansTerminal) return;

  const scanIds = scans.map((s: any) => s.id);
  // Findings carry across scans now, so "this week's findings" means the ones
  // each scan saw, not only the ones it saw first.
  const { findingsForScans } = await import("@/lib/vuln-lifecycle.server");
  const { rows: vulns, presentIn } = await findingsForScans<DigestVuln>(
    supabaseAdmin,
    scanIds,
    "id, scan_id, title, severity, verification_status, cwe_id, file_path, line_start, description",
  );

  const anyPendingVerification = (vulns ?? []).some(
    (v: any) => v.verification_status === "pending",
  );
  if (anyPendingVerification) return;

  // Checked BEFORE claiming: an opted-out user shouldn't get a
  // weekly_digest_log row implying an email went out when none did. Reading
  // prefs has no side effect, so re-running this check on every trigger for
  // an opted-out user costs nothing worth guarding against.
  const { data: prefs } = await supabaseAdmin
    .from("notification_preferences")
    .select("email_enabled, weekly_summary")
    .eq("user_id", userId)
    .maybeSingle();
  if (!prefs?.email_enabled || !prefs?.weekly_summary) return;

  const { data: userResult } = await supabaseAdmin.auth.admin.getUserById(userId);
  const email = userResult?.user?.email;
  if (!email) return;

  // Claim the send. A conflict here means another trigger already won this
  // race (a scan-complete and a verify-complete callback can both notice
  // "this run just finished" within moments of each other) — not an error,
  // just "someone else is sending it."
  const { error: claimErr } = await supabaseAdmin
    .from("weekly_digest_log")
    .insert({ weekly_run_id: weeklyRunId, user_id: userId });
  if (claimErr) {
    if (claimErr.code === "23505") return; // unique_violation
    throw claimErr;
  }

  const { html, text, subject } = buildDigest(scans, vulns ?? [], presentIn);
  await sendEmail({ to: email, subject, html, text });
}

type DigestVuln = {
  id: string;
  scan_id: string | null;
  title: string;
  severity: string;
  verification_status: string;
  cwe_id: string | null;
  file_path: string | null;
  line_start: number | null;
  description: string | null;
};

function buildDigest(scans: any[], vulns: DigestVuln[], presentIn: (v: DigestVuln) => Set<string>) {
  const appUrl = (process.env.APP_URL ?? "").replace(/\/$/, "");
  const link = (path: string) => (appUrl ? `${appUrl}${path}` : path);

  const totals: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) if (v.severity in totals) totals[v.severity as Sev] += 1;

  const confirmed = vulns.filter((v) => v.verification_status === "confirmed");
  const reposScanned = scans.length;
  const totalFindings = vulns.length;
  const headline =
    totals.critical + totals.high > 0
      ? `${totals.critical + totals.high} high/critical finding${totals.critical + totals.high === 1 ? "" : "s"} this week`
      : "No high or critical findings this week";

  const repoRows = scans
    .map((s: any) => {
      const repoFindings = vulns.filter((v) => presentIn(v).has(s.id));
      const name = s.repositories?.full_name ?? "Repository";
      if (s.status === "failed") return `<li>${escapeHtml(name)} — scan failed</li>`;
      const counts: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const v of repoFindings) if (v.severity in counts) counts[v.severity as Sev] += 1;
      return `<li>${escapeHtml(name)} — score ${s.security_score ?? "—"}/100, ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low</li>`;
    })
    .join("\n");

  const confirmedRows = confirmed
    .map(
      (v: any) =>
        `<li><strong>${escapeHtml(v.title)}</strong> (${escapeHtml(v.severity)}${v.cwe_id ? `, ${escapeHtml(v.cwe_id)}` : ""})${v.file_path ? ` — <code>${escapeHtml(v.file_path)}${v.line_start ? `:${v.line_start}` : ""}</code>` : ""}</li>`,
    )
    .join("\n");

  const html = `
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
      <h2>Weekly scan summary</h2>
      <p>${escapeHtml(headline)} across ${reposScanned} repositor${reposScanned === 1 ? "y" : "ies"} (${totalFindings} finding${totalFindings === 1 ? "" : "s"} total).</p>
      <h3>By repository</h3>
      <ul>${repoRows || "<li>No repositories were due this run.</li>"}</ul>
      ${
        confirmed.length > 0
          ? `<h3>Confirmed exploitable (sandbox-verified)</h3><ul>${confirmedRows}</ul>`
          : ""
      }
      ${
        // Only linked when APP_URL is set. Without it these would be relative
        // hrefs, which have no base to resolve against in a mail client — a
        // dead link is worse than no link. The plain-text part omits them on
        // the same condition.
        appUrl
          ? `<p><a href="${link("/vulnerabilities")}">View all findings</a> · <a href="${link("/repositories")}">Manage repositories</a></p>`
          : ""
      }
      <p style="color:#888;font-size:12px">You're receiving this because "Weekly summary" is enabled in PentestAI Settings.</p>
    </div>
  `.trim();

  const text = [
    "Weekly scan summary",
    headline,
    `${reposScanned} repositories scanned, ${totalFindings} finding(s) total.`,
    "",
    "By repository:",
    ...scans.map((s: any) => {
      const name = s.repositories?.full_name ?? "Repository";
      return s.status === "failed"
        ? `- ${name}: scan failed`
        : `- ${name}: score ${s.security_score ?? "—"}/100`;
    }),
    ...(confirmed.length > 0
      ? ["", "Confirmed exploitable:", ...confirmed.map((v: any) => `- ${v.title} (${v.severity})`)]
      : []),
    "",
    appUrl ? `View all findings: ${link("/vulnerabilities")}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  return { subject: `PentestAI weekly summary — ${headline}`, html, text };
}

function escapeHtml(value: string): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}
