import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type GoogleClaims,
  verifyGoogleIdToken,
  _resetJwksCacheForTest,
  JWKS_MISS_COOLDOWN_MS,
  googleConfigured,
} from "./google-oidc.js";

function b64url(input: string | Buffer): string {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("apps/console-api/src/google-oidc.ts nonce verification", () => {
  const CLIENT_ID = "test-google-client-id";
  let privateKeyPem: string;
  let publicJwk: Record<string, unknown>;

  beforeAll(() => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    jwk.kid = "test-kid-1";
    jwk.alg = "RS256";
    jwk.use = "sig";
    publicJwk = jwk;
  });

  beforeEach(() => {
    // Stub global fetch to return the local JWKS
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ keys: [publicJwk] }),
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function createSignedToken(claims: Partial<GoogleClaims>): string {
    const header = { alg: "RS256", kid: "test-kid-1" };
    const payload: GoogleClaims = {
      sub: "google-sub-12345",
      iss: "https://accounts.google.com",
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...claims,
    };

    const encodedHeader = b64url(JSON.stringify(header));
    const encodedPayload = b64url(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKeyPem);
    const encodedSignature = b64url(signature);

    return `${signingInput}.${encodedSignature}`;
  }

  it("accepts a valid token when the token nonce matches expectedNonce", async () => {
    const expectedNonce = "challenge-nonce-xyz-789";
    const token = createSignedToken({ nonce: expectedNonce });

    const claims = await verifyGoogleIdToken(token, CLIENT_ID, expectedNonce);
    expect(claims.sub).toBe("google-sub-12345");
    expect(claims.nonce).toBe(expectedNonce);
  });

  it("rejects a valid token when expectedNonce is provided but the token has no nonce claim", async () => {
    const expectedNonce = "challenge-nonce-xyz-789";
    const tokenWithoutNonce = createSignedToken({ nonce: undefined });

    await expect(
      verifyGoogleIdToken(tokenWithoutNonce, CLIENT_ID, expectedNonce),
    ).rejects.toThrow("id token is missing required nonce");
  });

  it("rejects a valid token when the token nonce does not match expectedNonce", async () => {
    const expectedNonce = "challenge-nonce-xyz-789";
    const replayedOrWrongNonce = "stale-replay-nonce-000";
    const token = createSignedToken({ nonce: replayedOrWrongNonce });

    await expect(
      verifyGoogleIdToken(token, CLIENT_ID, expectedNonce),
    ).rejects.toThrow("id token nonce mismatch");
  });

  it("allows verification without nonce check when expectedNonce is not requested", async () => {
    const token = createSignedToken({ nonce: undefined });
    const claims = await verifyGoogleIdToken(token, CLIENT_ID);
    expect(claims.sub).toBe("google-sub-12345");
  });
});

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
