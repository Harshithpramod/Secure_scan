import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  Shield,
  Github,
  Loader2,
  ArrowLeft,
  Eye,
  UserRound,
  Lock,
  CheckCircle2,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in — PentestAI" },
      {
        name: "description",
        content: "Sign in to PentestAI with GitHub to scan your repositories.",
      },
    ],
  }),
  component: AuthPage,
});

/**
 * What the OAuth call actually asks for, spelled out at the point of decision.
 * The scopes below must stay in sync with the `scopes` string in handleGithub —
 * a disclosure that drifts from the real request is worse than none at all.
 */
const SCOPES = [
  {
    icon: Eye,
    name: "repo",
    label: "Read your repository code",
    detail: "So it can be analysed and re-checked in the sandbox.",
  },
  {
    icon: UserRound,
    name: "read:user · user:email",
    label: "Your GitHub username and email",
    detail: "Used to create your account. Nothing else.",
  },
];

const GUARANTEES = [
  "Your code is never modified",
  "Analysis runs with no network access",
  "Findings are encrypted at rest",
];

function AuthPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [existingEmail, setExistingEmail] = useState<string | null>(null);

  useEffect(() => {
    supabase.auth.getUser().then(({ data, error }) => {
      if (!error && data.user) setExistingEmail(data.user.email ?? "your account");
    });
  }, []);

  const handleSwitchAccount = async () => {
    setLoading(true);
    await supabase.auth.signOut();
    setExistingEmail(null);
    setLoading(false);
  };

  const handleGithub = async () => {
    setLoading(true);
    const redirectTo = `${window.location.origin}/dashboard`;
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo,
        scopes: "repo read:user user:email",
        skipBrowserRedirect: true,
      },
    });
    if (error || !data?.url) {
      toast.error(
        error?.message
          ? `Couldn't start GitHub sign-in. ${error.message}`
          : "Couldn't start GitHub sign-in. Try again.",
      );
      setLoading(false);
      return;
    }
    const inIframe = window.top !== window.self;
    if (inIframe) {
      const opened = window.open(data.url, "_blank", "noopener,noreferrer");
      if (!opened) {
        toast.error(
          "Your browser blocked the GitHub window. Allow popups for this site, or open the preview in a new tab.",
        );
        setLoading(false);
        return;
      }
      toast.info("Finish signing in on the GitHub tab, then come back here.");
      setLoading(false);
    } else {
      window.location.href = data.url;
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-landing-bg px-4 py-10">
      {/* Same light source as the homepage hero, so arriving here reads as the
          same product rather than a separate form page. Static CSS — nothing to
          gate behind prefers-reduced-motion.

          Dimmed to 70%: the hero can run this at full strength because its copy
          sits well above the cores, but here the column is vertically centred,
          which puts the small print near the brightest part. At full strength
          the disclaimer measured 2.16:1. */}
      <div aria-hidden className="landing-glow pointer-events-none absolute inset-0 opacity-70" />

      <main className="relative mx-auto flex min-h-[calc(100vh-5rem)] w-full max-w-md flex-col justify-center">
        {/* -mx-2 px-2 keeps the visual size of the wordmark while giving the hit
            area the full 44px minimum. */}
        <Link
          to="/"
          className="focus-ring -mx-2 mb-8 inline-flex min-h-11 w-fit items-center gap-2 rounded-md px-2 text-landing-fg-secondary transition-colors hover:text-landing-fg"
        >
          <ArrowLeft aria-hidden className="h-4 w-4" />
          <Shield aria-hidden className="h-5 w-5 text-landing-accent" strokeWidth={2.5} />
          <span className="font-display text-lg font-bold text-landing-fg">PentestAI</span>
        </Link>

        <div className="rounded-2xl border border-landing-border bg-landing-surface p-8">
          {existingEmail ? (
            /* A live session makes the sign-in button noise: the only two
               things worth offering are "carry on" and "not me". */
            <>
              <h1 className="font-display text-2xl font-semibold tracking-[-0.02em] text-landing-fg">
                You&apos;re already signed in
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-landing-fg-secondary">
                Signed in as <span className="font-medium text-landing-fg">{existingEmail}</span>.
              </p>

              <button
                type="button"
                onClick={() => navigate({ to: "/dashboard", replace: true })}
                className="focus-ring mt-6 inline-flex h-11 w-full cursor-pointer items-center justify-center gap-2 rounded-md bg-landing-primary font-medium text-white transition-colors hover:bg-landing-primary-hover"
              >
                Continue to dashboard
              </button>
              <button
                type="button"
                disabled={loading}
                onClick={handleSwitchAccount}
                className="focus-ring mt-3 inline-flex h-11 w-full cursor-pointer items-center justify-center gap-2 rounded-md border border-landing-border text-sm font-medium text-landing-fg-secondary transition-colors hover:border-landing-border-strong hover:text-landing-fg disabled:opacity-60"
              >
                {loading ? (
                  <>
                    <Loader2 aria-hidden className="h-4 w-4 animate-spin" />
                    Signing out…
                  </>
                ) : (
                  "Use a different account"
                )}
              </button>
            </>
          ) : (
            <>
              <h1 className="font-display text-2xl leading-[1.15] font-semibold tracking-[-0.02em] text-landing-fg">
                Scan your first repository
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-landing-fg-secondary">
                Sign in with GitHub to connect a repository and get a sandbox-verified report.
              </p>

              <button
                type="button"
                onClick={handleGithub}
                disabled={loading}
                aria-busy={loading}
                className="focus-ring mt-7 inline-flex h-11 w-full cursor-pointer items-center justify-center gap-2 rounded-md bg-landing-primary font-medium text-white transition-colors hover:bg-landing-primary-hover disabled:opacity-70"
              >
                {loading ? (
                  <>
                    <Loader2 aria-hidden className="h-4 w-4 animate-spin" />
                    Redirecting to GitHub…
                  </>
                ) : (
                  <>
                    <Github aria-hidden className="h-4 w-4" />
                    Continue with GitHub
                  </>
                )}
              </button>

              {/* The substantive addition. `repo` is a broad, write-capable
                  scope covering private code — asking for it without saying so
                  is the kind of thing this product exists to flag in other
                  people's software. */}
              <div className="mt-7 border-t border-landing-border pt-6">
                <h2 className="font-mono text-[11px] tracking-[0.14em] text-landing-fg-muted uppercase">
                  What PentestAI gets
                </h2>
                <ul className="mt-4 space-y-4">
                  {SCOPES.map((s) => (
                    <li key={s.name} className="flex gap-3">
                      <s.icon
                        aria-hidden
                        className="mt-0.5 h-4 w-4 shrink-0 text-landing-accent"
                        strokeWidth={2}
                      />
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-landing-fg">{s.label}</p>
                        <p className="mt-0.5 text-xs leading-relaxed text-landing-fg-secondary">
                          {s.detail}
                        </p>
                        <code className="mt-1 inline-block font-mono text-[11px] text-landing-fg-muted">
                          {s.name}
                        </code>
                      </div>
                    </li>
                  ))}
                </ul>

                {/* Inside the card rather than floating under it: these sit on
                    the solid surface, which both keeps them next to the
                    permission they answer and gives them a backdrop that isn't
                    the glow. */}
                <ul className="mt-6 space-y-2 border-t border-landing-border pt-5">
                  {GUARANTEES.map((g) => (
                    <li
                      key={g}
                      className="flex items-center gap-2 text-xs text-landing-fg-secondary"
                    >
                      <CheckCircle2 aria-hidden className="h-3.5 w-3.5 shrink-0 text-low" />
                      {g}
                    </li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>

        {/* fg-secondary, not fg-muted: this line sits outside the card, over the
            glow, where muted measured 2.16:1. */}
        <p className="mt-6 flex items-start gap-2 text-xs leading-relaxed text-landing-fg-secondary">
          <Lock aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          Only scan repositories you own or are explicitly authorised to test.
        </p>
      </main>
    </div>
  );
}
