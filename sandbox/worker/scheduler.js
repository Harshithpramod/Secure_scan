// Weekly-scan scheduler. The worker is the only persistent, always-on process
// in this stack (docker-compose gives it `restart: unless-stopped`; the app
// itself is request-driven with no equivalent), so it's the natural place to
// notice "time to check for due scans" — regardless of whether the app is
// running locally or ever moves to a stateless deploy target.
//
// This module is a dumb, stateless pinger by design: it holds no memory of
// when it last ran (the sandbox's Redis deliberately isn't persisted — see
// docker-compose.yml — so anything tracked here would be forgotten on every
// worker restart). Instead it just asks the app "is anything due?" on a fixed
// interval, and the app answers that using repositories.last_scan_at, which is
// already durable in Postgres. A ping that finds nothing due is a cheap no-op.

const CHECK_MS = Number(process.env.WEEKLY_SWEEP_CHECK_MINUTES || 60) * 60 * 1000;
const SWEEP_PATH = "/api/public/run-weekly-scans";

/**
 * Derived from PENTESTAI_CALLBACK_URL rather than APP_URL, because that is
 * already the address this container uses to reach the app — in local dev it
 * is http://host.docker.internal:8080, while APP_URL is the browser-facing
 * http://localhost:8080, which from inside a container means the container
 * itself. Both are app endpoints under /api/public/, so swapping the path is
 * exact. APP_URL is only the fallback (and is correct on a real deploy, where
 * the two are the same public URL).
 */
function sweepUrl() {
  const callback = process.env.PENTESTAI_CALLBACK_URL;
  if (callback) {
    try {
      const url = new URL(callback);
      url.pathname = SWEEP_PATH;
      url.search = "";
      return url.toString();
    } catch {
      // Malformed callback URL — fall back to APP_URL below.
    }
  }
  const appUrl = process.env.APP_URL;
  return appUrl ? `${appUrl.replace(/\/$/, "")}${SWEEP_PATH}` : null;
}

async function ping() {
  const target = sweepUrl();
  const token = process.env.SANDBOX_API_TOKEN;
  if (!target || !token) {
    console.log(
      "weekly-sweep: need SANDBOX_API_TOKEN and one of PENTESTAI_CALLBACK_URL/APP_URL, skipping",
    );
    return;
  }

  try {
    const res = await fetch(target, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await res.text();
    if (!res.ok) {
      console.error(`weekly-sweep: app returned ${res.status}: ${body.slice(0, 500)}`);
      return;
    }
    // The app itself decides whether anything was actually due; a body like
    // {"triggered":0,...} on most pings is expected, not an error.
    console.log(`weekly-sweep: ${body}`);
  } catch (err) {
    console.error("weekly-sweep: request failed", err);
  }
}

/** Pings once at startup, then on a fixed interval, for the rest of the process's life. */
export function startWeeklySweepScheduler() {
  ping().catch((err) => console.error("weekly-sweep: startup ping failed", err));
  setInterval(() => {
    ping().catch((err) => console.error("weekly-sweep: ping failed", err));
  }, CHECK_MS);
}
