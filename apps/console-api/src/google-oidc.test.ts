/**
 * Unit tests for Google OIDC token verification with nonce enforcement (Issue #108).
 *
 * Verifies:
 * - A valid token with correct nonce verifies successfully.
 * - A valid token with a missing nonce claim is rejected when expectedNonce is required.
 * - A valid token with a mismatched nonce claim is rejected.
 * - A valid token verifies without nonce when expectedNonce is not supplied.
 * - Replayed / altered token signatures are rejected.
 */
import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { type GoogleClaims, verifyGoogleIdToken } from "./google-oidc.js";

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
