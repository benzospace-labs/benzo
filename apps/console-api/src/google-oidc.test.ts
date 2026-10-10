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

describe("console-api verifyGoogleIdToken - kid miss refetch and cooldown", () => {
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
        return new Response(JSON.stringify({ keys: [key1.jwk] }), { status: 200 });
      }
      return new Response(JSON.stringify({ keys: [key1.jwk, key2.jwk] }), { status: 200 });
    }) as unknown as typeof fetch;

    const token1 = makeIdToken(key1.privateKey, "key-1");
    await verifyGoogleIdToken(token1, "test-client-id");
    expect(fetchCalls).toBe(1);

    const token2 = makeIdToken(key2.privateKey, "key-2");
    const claims = await verifyGoogleIdToken(token2, "test-client-id");
    expect(claims.sub).toBe("user-123");
    expect(fetchCalls).toBe(2);

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

    const token1 = makeIdToken(key1.privateKey, "key-1");
    await verifyGoogleIdToken(token1, "test-client-id");
    expect(fetchCalls).toBe(1);

    const tokenBad1 = makeIdToken(keyUnknown1.privateKey, "unknown-1");
    await expect(verifyGoogleIdToken(tokenBad1, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(2);

    const tokenBad2 = makeIdToken(keyUnknown2.privateKey, "unknown-2");
    await expect(verifyGoogleIdToken(tokenBad2, "test-client-id")).rejects.toThrow(
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

    const token1 = makeIdToken(key1.privateKey, "key-1");
    await verifyGoogleIdToken(token1, "test-client-id");
    expect(fetchCalls).toBe(1);

    const badToken = makeIdToken(keyUnknown.privateKey, "unknown-key");
    await expect(verifyGoogleIdToken(badToken, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(2);

    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(Date.now() + JWKS_MISS_COOLDOWN_MS + 1000);

    await expect(verifyGoogleIdToken(badToken, "test-client-id")).rejects.toThrow(
      "no matching Google JWK for kid"
    );
    expect(fetchCalls).toBe(3);

    nowSpy.mockRestore();
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
