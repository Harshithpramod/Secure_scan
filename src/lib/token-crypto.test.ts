import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// A fixed, obviously-fake key. Every test sets it explicitly so a developer's
// real TOKEN_ENCRYPTION_KEY can never influence a result.
const KEY_A = "a".repeat(64);
const KEY_B = "b".repeat(64);

/**
 * The module caches the imported CryptoKey, so each test needs a fresh copy to
 * exercise a different key or a missing-env path.
 */
async function loadFresh(key?: string) {
  vi.resetModules();
  if (key === undefined) delete process.env.TOKEN_ENCRYPTION_KEY;
  else process.env.TOKEN_ENCRYPTION_KEY = key;
  return import("./token-crypto.server");
}

const ORIGINAL = process.env.TOKEN_ENCRYPTION_KEY;
beforeEach(() => {
  process.env.TOKEN_ENCRYPTION_KEY = KEY_A;
});
afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.TOKEN_ENCRYPTION_KEY;
  else process.env.TOKEN_ENCRYPTION_KEY = ORIGINAL;
});

describe("token encryption", () => {
  it("round-trips a token", async () => {
    const { encryptToken, decryptToken } = await loadFresh(KEY_A);
    const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    expect(await decryptToken(await encryptToken(token))).toBe(token);
  });

  it("never leaves the plaintext recoverable from the envelope", async () => {
    const { encryptToken } = await loadFresh(KEY_A);
    const token = "ghp_supersecretvalue";
    const envelope = await encryptToken(token);
    expect(envelope).not.toContain(token);
    // Base64 of the plaintext must not appear either.
    expect(envelope).not.toContain(Buffer.from(token).toString("base64"));
  });

  it("uses a fresh IV per call, so identical inputs differ", async () => {
    const { encryptToken } = await loadFresh(KEY_A);
    const a = await encryptToken("same-token");
    const b = await encryptToken("same-token");
    expect(a).not.toBe(b);
  });

  it("produces the documented v1.<iv>.<ciphertext> envelope", async () => {
    const { encryptToken, isEncryptedToken } = await loadFresh(KEY_A);
    const envelope = await encryptToken("t");
    const parts = envelope.split(".");
    expect(parts).toHaveLength(3);
    expect(parts[0]).toBe("v1");
    expect(isEncryptedToken(envelope)).toBe(true);
  });

  // The migration path: rows written before encryption existed hold plaintext.
  // Refusing to read them would lock every existing user out of GitHub.
  it("passes legacy plaintext through untouched and does not claim it is encrypted", async () => {
    const { decryptToken, isEncryptedToken } = await loadFresh(KEY_A);
    const legacy = "ghp_legacyplaintexttoken";
    expect(isEncryptedToken(legacy)).toBe(false);
    expect(await decryptToken(legacy)).toBe(legacy);
  });

  it("rejects an envelope encrypted under a different key rather than returning junk", async () => {
    const { encryptToken } = await loadFresh(KEY_A);
    const envelope = await encryptToken("secret");
    const { decryptToken: decryptWithB } = await loadFresh(KEY_B);
    await expect(decryptWithB(envelope)).rejects.toThrow(/decrypt/i);
  });

  it("rejects a tampered ciphertext (GCM authentication)", async () => {
    const { encryptToken, decryptToken } = await loadFresh(KEY_A);
    const envelope = await encryptToken("secret");
    const [v, iv, ct] = envelope.split(".");
    // Flip a character in the ciphertext.
    const flipped = ct[0] === "A" ? "B" + ct.slice(1) : "A" + ct.slice(1);
    await expect(decryptToken(`${v}.${iv}.${flipped}`)).rejects.toThrow();
  });

  it("rejects a malformed envelope", async () => {
    const { decryptToken } = await loadFresh(KEY_A);
    await expect(decryptToken("v1.onlytwoparts")).rejects.toThrow(/malformed/i);
  });

  it("fails loudly when the key is missing, rather than storing plaintext", async () => {
    const { encryptToken } = await loadFresh(undefined);
    await expect(encryptToken("secret")).rejects.toThrow(/TOKEN_ENCRYPTION_KEY is not set/);
  });

  it("rejects a key that is not 64 hex characters", async () => {
    const { encryptToken } = await loadFresh("tooshort");
    await expect(encryptToken("secret")).rejects.toThrow(/64 hex characters/);
  });
});
