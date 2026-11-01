-- First-time user onboarding. The guided tour must run exactly once per
-- account, so completion is recorded against the profile rather than in
-- localStorage — otherwise the tour reappears on every new browser, and never
-- reappears after a user clears storage on the one they set up on.
--
-- Defaults to false so every existing account is treated as "not yet toured";
-- backfill below marks anyone who already has activity as done, so the tour
-- only ever targets genuinely new users.
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS onboarding_completed_at TIMESTAMPTZ;

-- Existing users have already found their way around; don't interrupt them.
UPDATE public.profiles p
SET onboarding_completed = true,
    onboarding_completed_at = now()
WHERE p.onboarding_completed = false
  AND (
    EXISTS (SELECT 1 FROM public.repositories r WHERE r.user_id = p.id)
    OR EXISTS (SELECT 1 FROM public.scans s WHERE s.user_id = p.id)
  );
