import { useCallback, useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { OnboardingTour, type TourStep } from "@/components/app/onboarding-tour";
import { getOnboardingStatus, completeOnboarding } from "@/lib/onboarding.functions";

// Resume point only. Whether the tour is *done* lives on the profile row, so
// clearing storage or switching browsers can't resurrect it for the account.
const STEP_KEY = "pentestai:onboarding-step";

const STEPS: TourStep[] = [
  {
    target: "dashboard",
    text: "Welcome! This is your dashboard — your starting point for everything in the app.",
    placement: "right",
  },
  {
    target: "repositories",
    text: "Connect a GitHub repository here, then launch a pen test against it in one click.",
    placement: "right",
  },
  {
    target: "search",
    text: "Use this to quickly find a repository, scan or finding without clicking through screens.",
    placement: "bottom",
  },
  {
    target: "vulnerabilities",
    text: "Findings land here, triaged by severity — with sandbox-verified proof where we have it.",
    placement: "right",
  },
  {
    target: "account",
    text: "Manage your profile, notifications and GitHub connection from your account settings.",
    placement: "bottom",
  },
  {
    target: "assistant",
    text: "And I'm always here if you need help. Just ask me anything about the app!",
    placement: "left",
  },
];

function readStoredStep(): number {
  if (typeof window === "undefined") return 0;
  const raw = Number(window.sessionStorage.getItem(STEP_KEY));
  return Number.isInteger(raw) && raw >= 0 && raw < STEPS.length ? raw : 0;
}

export function Onboarding() {
  const [show, setShow] = useState(false);
  const [startIndex, setStartIndex] = useState(0);
  const statusFn = useServerFn(getOnboardingStatus);
  const completeFn = useServerFn(completeOnboarding);

  useEffect(() => {
    let cancelled = false;
    statusFn()
      .then((res: any) => {
        if (cancelled || res?.completed) return;
        setStartIndex(readStoredStep());
        setShow(true);
      })
      .catch((err) => {
        // Never let a status failure wedge the app behind an overlay.
        console.error("[onboarding] status check failed", err);
      });
    return () => {
      cancelled = true;
    };
  }, [statusFn]);

  const handleStepChange = useCallback((index: number) => {
    try {
      window.sessionStorage.setItem(STEP_KEY, String(index));
    } catch {
      /* storage unavailable — resume is a nicety, not a requirement */
    }
  }, []);

  const handleFinish = useCallback(
    (_reason: "completed" | "skipped") => {
      // Close immediately; persistence is best-effort in the background so a
      // slow network never leaves the user staring at the overlay.
      setShow(false);
      try {
        window.sessionStorage.removeItem(STEP_KEY);
      } catch {
        /* ignore */
      }
      // Surfaced, not just logged: a silent failure here means the tour
      // replays on every refresh, which is exactly the kind of bug that hides
      // in a console nobody has open.
      completeFn().catch((err) => {
        console.error("[onboarding] could not persist", err);
        toast.error("Couldn't save your onboarding progress — the tour may reappear.");
      });
    },
    [completeFn],
  );

  if (!show) return null;

  return (
    <OnboardingTour
      steps={STEPS}
      startIndex={startIndex}
      onStepChange={handleStepChange}
      onFinish={handleFinish}
    />
  );
}
