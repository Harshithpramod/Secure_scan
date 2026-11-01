// Envelope encryption for GitHub access tokens at rest (server-only).
//
// The `github_connections.access_token_encrypted` column has always been named
// as though it held ciphertext, but until now it held plaintext — anyone with
// the service-role key (or a database dump) got live GitHub tokens. This module
// makes the column honest.
//
// AES-256-GCM via WebCrypto, which exists on both Cloudflare Workers and Node,
// so it works in every runtime this app deploys to. `pgsodium`/Supabase Vault
// would be the alternative, but it requires database-side setup and would tie
// decryption to the Postgres session rather than the app.

const ENVELOPE_VERSION = "v1";
const IV_BYTES = 12; // AES-GCM standard nonce length.

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Decode(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function keyBytes(): Uint8Array {
  const raw = process.env.TOKEN_ENCRYPTION_KEY?.trim();
  if (!raw) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY is not set. GitHub tokens cannot be stored or read " +
        "without it. Generate one with: openssl rand -hex 32",
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes). " +
        "Generate one with: openssl rand -hex 32",
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

let cachedKey: Promise<CryptoKey> | undefined;

function getKey(): Promise<CryptoKey> {
  // Cache the imported key, but only after keyBytes() has validated the env —
  // a bad key must throw on every call, not just the first.
  const bytes = keyBytes();
  if (!cachedKey) {
    cachedKey = crypto.subtle.importKey("raw", bytes as BufferSource, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }
  return cachedKey;
}

/**
 * True when `stored` is one of our envelopes rather than a legacy plaintext
 * token. Used to decide whether a row needs upgrading in place.
 */
export function isEncryptedToken(stored: string): boolean {
  return stored.startsWith(`${ENVELOPE_VERSION}.`);
}

export async function encryptToken(plaintext: string): Promise<string> {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return `${ENVELOPE_VERSION}.${base64Encode(iv)}.${base64Encode(new Uint8Array(ciphertext))}`;
}

/**
 * Decrypts an envelope. A value that isn't an envelope is returned unchanged —
 * rows written before this module existed are plaintext, and refusing to read
 * them would lock every existing user out of their own GitHub connection.
 * Callers should re-encrypt those rows (see getUserAccessToken).
 */
export async function decryptToken(stored: string): Promise<string> {
  if (!isEncryptedToken(stored)) return stored;

  const parts = stored.split(".");
  if (parts.length !== 3) {
    throw new Error("Stored GitHub token is malformed (expected v1.<iv>.<ciphertext>)");
  }

  const key = await getKey();
  const iv = base64Decode(parts[1]);
  const ciphertext = base64Decode(parts[2]);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext as BufferSource,
    );
  } catch {
    // GCM authentication failure: wrong key, or the row was tampered with.
    // Never fall through to returning the ciphertext as if it were a token.
    throw new Error(
      "Failed to decrypt the stored GitHub token. TOKEN_ENCRYPTION_KEY may have " +
        "changed — reconnect GitHub to store a fresh token under the current key.",
    );
  }
  return new TextDecoder().decode(plaintext);
}
