import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

// Postgres "column does not exist" — raised until the onboarding migration is
// applied. Treated as "already onboarded" so an unmigrated database silently
// skips the tour instead of showing it on every single page load.
const UNDEFINED_COLUMN = "42703";

function isMissingColumn(error: { code?: string; message?: string } | null): boolean {
  if (!error) return false;
  return error.code === UNDEFINED_COLUMN || /onboarding_completed/.test(error.message ?? "");
}

export const getOnboardingStatus = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
    const supabaseAdmin = getSupabaseAdmin();

    const { data, error } = await supabaseAdmin
      .from("profiles")
      .select("onboarding_completed")
      .eq("id", context.userId)
      .maybeSingle();

    if (error) {
      if (isMissingColumn(error)) {
        console.warn(
          "[onboarding] profiles.onboarding_completed is missing — apply the " +
            "20260825120000_onboarding_state migration to enable the tour.",
        );
        return { completed: true, ready: false };
      }
      throw error;
    }

    // No profile row yet (the handle_new_user trigger runs on signup, but a
    // row can be absent for accounts created before it existed): treat as new.
    return { completed: Boolean(data?.onboarding_completed), ready: true };
  });

export const completeOnboarding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
    const supabaseAdmin = getSupabaseAdmin();

    // Upsert, not update: the handle_new_user trigger does not reliably leave a
    // profiles row behind (accounts exist with none), and `update` against a
    // missing row matches zero rows and reports success — so the flag silently
    // never persisted and the tour replayed on every refresh. Only the columns
    // in this payload are touched, so an existing profile keeps its other data.
    const { data, error } = await supabaseAdmin
      .from("profiles")
      .upsert(
        {
          id: context.userId,
          onboarding_completed: true,
          onboarding_completed_at: new Date().toISOString(),
        },
        { onConflict: "id" },
      )
      .select("id")
      .maybeSingle();

    if (error) {
      if (isMissingColumn(error)) return { completed: true, persisted: false };
      throw error;
    }
    // Never report success for a write that affected nothing.
    if (!data) throw new Error("Onboarding state did not persist (no profile row written).");
    return { completed: true, persisted: true };
  });
