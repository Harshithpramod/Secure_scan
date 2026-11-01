// Single source of truth for reading a user's GitHub access token (server-only).
//
// This helper was previously copy-pasted into github.functions.ts and
// scans.functions.ts. It lives in a .server.ts module so it can be imported by
// the *.functions.ts files without any risk of the token-handling code being
// reachable from the client bundle.

import { decryptToken, encryptToken, isEncryptedToken } from "@/lib/token-crypto.server";

/**
 * Returns the decrypted GitHub token for a user.
 *
 * Rows written before at-rest encryption existed hold plaintext. Those are
 * upgraded in place on first read so the plaintext copy stops existing, rather
 * than requiring every user to reconnect GitHub.
 */
export async function getUserAccessToken(userId: string): Promise<string> {
  const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
  const supabaseAdmin = getSupabaseAdmin();

  const { data, error } = await supabaseAdmin
    .from("github_connections")
    .select("access_token_encrypted")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw error;

  const stored = data?.access_token_encrypted as string | undefined;
  if (!stored) throw new Error("GitHub is not connected");

  if (isEncryptedToken(stored)) return decryptToken(stored);

  // Legacy plaintext row. Upgrade it, then hand back the token we already have.
  try {
    const upgraded = await encryptToken(stored);
    await supabaseAdmin
      .from("github_connections")
      .update({ access_token_encrypted: upgraded })
      .eq("user_id", userId);
  } catch (err) {
    // An upgrade failure must not break the caller's actual request — the token
    // is still valid, it just stays plaintext until the next read succeeds.
    console.error("[github-token] failed to upgrade legacy plaintext token", err);
  }
  return stored;
}

/**
 * Writes a GitHub token into `github_connections`, encrypted at rest.
 * Shared by the OAuth and PAT connect paths so neither can forget to encrypt.
 */
export async function storeUserAccessToken(args: {
  userId: string;
  token: string;
  githubUserId: number;
  githubUsername: string;
  scopes: string[];
}): Promise<void> {
  const { getSupabaseAdmin } = await import("@/lib/supabase-admin.server");
  const supabaseAdmin = getSupabaseAdmin();

  const { error } = await supabaseAdmin.from("github_connections").upsert(
    {
      user_id: args.userId,
      github_user_id: args.githubUserId,
      github_username: args.githubUsername,
      access_token_encrypted: await encryptToken(args.token),
      scopes: args.scopes,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id" },
  );
  if (error) throw error;
}
