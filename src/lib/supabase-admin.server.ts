import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

/**
 * The service-role client, typed against the generated schema.
 *
 * It used to be `SupabaseClient<any, "public", any>`, which forced every caller
 * to write `getSupabaseAdmin() as any` and gave up column checking across the
 * whole server surface — a typo'd column name reached Postgres before anything
 * noticed. Typed properly, the same mistakes fail at compile time.
 *
 * Keep `src/integrations/supabase/types.ts` in step with the migrations; a
 * column that exists in the database but not in that file is a type error at
 * the call site, not a silent `any`.
 */
export type AdminClient = SupabaseClient<Database, "public">;

let cached: AdminClient | null = null;

export function getSupabaseAdmin(): AdminClient {
  if (cached) return cached;
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.PENTEST_SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) {
    throw new Error(
      "Missing SUPABASE_URL or PENTEST_SUPABASE_SERVICE_ROLE_KEY. Set the service role key in Project Secrets.",
    );
  }
  cached = createClient<Database, "public">(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cached;
}
