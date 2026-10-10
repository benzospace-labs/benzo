import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  verifyGoogleIdToken,
  _resetJwksCacheForTest,
  JWKS_MISS_COOLDOWN_MS,
  googleConfigured,
} from "./google-oidc.js";

function createTestKey(kid: string) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { publicKey, privateKey, jwk };
}

function makeIdToken(
  privateKey: any,
  kid?: string,
  claims: Record<string, unknown> = {}
) {
  const headerObj: Record<string, string> = { alg: "RS256" };
  if (kid !== undefined) {
    headerObj.kid = kid;
  }
  const header = Buffer.from(JSON.stringify(headerObj)).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      sub: "user-123",
      iss: "https://accounts.google.com",
      aud: "test-client-id",
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...claims,
    })
  ).toString("base64url");
  const sig = sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url");
  return `${header}.${payload}.${sig}`;
}

describe("verifyGoogleIdToken - kid miss refetch and cooldown", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    _resetJwksCacheForTest();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("verifies a token signed with an already-cached key without refetching", async () => {
    const key1 = createTestKey("key-1");
    let fetchCalls = 0;

    globalThis.fetch = vi.fn(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ keys: [key1.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    const token = makeIdToken(key1.privateKey, "key-1");
    const claims = await verifyGoogleIdToken(token, "test-client-id");
    expect(claims.sub).toBe("user-123");
    expect(fetchCalls).toBe(1);

    // Second verification should use the cached key set without refetching
    const claims2 = await verifyGoogleIdToken(token, "test-client-id");
    expect(claims2.sub).toBe("user-123");
    expect(fetchCalls).toBe(1);
  });

  it("refetches Google JWKS when kid misses cache (key rotation) and verifies successfully", async () => {
    const key1 = createTestKey("key-1");
    const key2 = createTestKey("key-2");
    let fetchCalls = 0;

    globalThis.fetch = vi.fn(async () => {
      fetchCalls++;
      if (fetchCalls === 1) {
        // Initial keys before rotation
        return new Response(JSON.stringify({ keys: [key1.jwk] }), { status: 200 });
      }
      // Keys after rotation include key2
      return new Response(JSON.stringify({ keys: [key1.jwk, key2.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    // First, cache key1
    const token1 = makeIdToken(key1.privateKey, "key-1");
    await verifyGoogleIdToken(token1, "test-client-id");
    expect(fetchCalls).toBe(1);

    // Token signed with newly rotated key-2 should miss cache and trigger a forced refetch
    const token2 = makeIdToken(key2.privateKey, "key-2");
    const claims = await verifyGoogleIdToken(token2, "test-client-id");
    expect(claims.sub).toBe("user-123");
    expect(fetchCalls).toBe(2);

    // Subsequent token signed with key-2 does not refetch
    const claims2 = await verifyGoogleIdToken(token2, "test-client-id");
    expect(claims2.sub).toBe("user-123");
    expect(fetchCalls).toBe(2);
  });

  it("enforces cooldown on repeated unknown kids so Google is not hammered", async () => {
    const key1 = createTestKey("key-1");
    const keyUnknown1 = createTestKey("unknown-1");
    const keyUnknown2 = createTestKey("unknown-2");
    let fetchCalls = 0;

    globalThis.fetch = vi.fn(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ keys: [key1.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    // First call caches key1
    const token1 = makeIdToken(key1.privateKey, "key-1");
    await verifyGoogleIdToken(token1, "test-client-id");
    expect(fetchCalls).toBe(1);

    // Unknown kid 1 causes a cache miss, triggering 1 forced refetch
    const tokenBad1 = makeIdToken(keyUnknown1.privateKey, "unknown-1");
    await expect(verifyGoogleIdToken(tokenBad1, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(2);

    // Inside cooldown window, repeated unknown kids do NOT trigger additional refetches
    const tokenBad2 = makeIdToken(keyUnknown2.privateKey, "unknown-2");
    await expect(verifyGoogleIdToken(tokenBad2, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(2);

    const tokenBad3 = makeIdToken(keyUnknown2.privateKey, "unknown-2");
    await expect(verifyGoogleIdToken(tokenBad3, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(2);
  });

  it("allows refetch after cooldown expires", async () => {
    const key1 = createTestKey("key-1");
    const keyUnknown = createTestKey("unknown-key");
    let fetchCalls = 0;

    globalThis.fetch = vi.fn(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ keys: [key1.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    // Seed cache
    const token1 = makeIdToken(key1.privateKey, "key-1");
    await verifyGoogleIdToken(token1, "test-client-id");
    expect(fetchCalls).toBe(1);

    // First miss triggers refetch
    const badToken = makeIdToken(keyUnknown.privateKey, "unknown-key");
    await expect(verifyGoogleIdToken(badToken, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(2);

    // Advance time past cooldown window
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(Date.now() + JWKS_MISS_COOLDOWN_MS + 1000);

    // After cooldown expires, a miss can refetch again
    await expect(verifyGoogleIdToken(badToken, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(3);

    nowSpy.mockRestore();
  });

  it("throws if token has no kid header without refetching", async () => {
    const key1 = createTestKey("key-1");
    let fetchCalls = 0;

    globalThis.fetch = vi.fn(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ keys: [key1.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    const tokenNoKid = makeIdToken(key1.privateKey, undefined);
    await expect(verifyGoogleIdToken(tokenNoKid, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    // Initial fetch was called to check keys, but no forced refetch happened
    expect(fetchCalls).toBe(1);
  });

  it("deduplicates concurrent fetches on kid miss", async () => {
    const key1 = createTestKey("key-1");
    const key2 = createTestKey("key-2");
    let fetchCalls = 0;

    globalThis.fetch = vi.fn(async () => {
      fetchCalls++;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return new Response(JSON.stringify({ keys: [key1.jwk, key2.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    // Run two concurrent verifications for rotated key-2
    const token = makeIdToken(key2.privateKey, "key-2");
    const [c1, c2] = await Promise.all([
      verifyGoogleIdToken(token, "test-client-id"),
      verifyGoogleIdToken(token, "test-client-id"),
    ]);

    expect(c1.sub).toBe("user-123");
    expect(c2.sub).toBe("user-123");
    expect(fetchCalls).toBe(1);
  });

  it("googleConfigured returns true when GOOGLE_CLIENT_ID is set", () => {
    const prev = process.env.GOOGLE_CLIENT_ID;
    try {
      process.env.GOOGLE_CLIENT_ID = "test-id";
      expect(googleConfigured()).toBe(true);
      delete process.env.GOOGLE_CLIENT_ID;
      expect(googleConfigured()).toBe(false);
    } finally {
      if (prev !== undefined) {
        process.env.GOOGLE_CLIENT_ID = prev;
      } else {
        delete process.env.GOOGLE_CLIENT_ID;
      }
    }
  });
});
