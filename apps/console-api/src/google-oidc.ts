/**
 * Real Google ID-token (JWT) verification for zkLogin Phase 1 — RS256 verified
 * against Google's published JWKs using Node's built-in crypto (no extra dep).
 *
 * This is the off-chain JWT step of zkLogin: the BFF confirms the token is a
 * genuine, unexpired Google token for THIS app (aud = client id) and returns the
 * verified `sub`/`iss`/`aud`. The browser then derives the Benzo account from
 * those claims (accountFromOidc) — the chain never sees the Google identity.
 * Phase 2 moves this RSA check in-circuit so the chain verifies the JWT step.
 */
import { createPublicKey, verify as cryptoVerify, type JsonWebKey as NodeJWK } from "node:crypto";

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISS = ["https://accounts.google.com", "accounts.google.com"];

let jwksCache: { at: number; keys: NodeJWK[] } | null = null;
async function googleJwks(): Promise<NodeJWK[]> {
  if (jwksCache && Date.now() - jwksCache.at < 3_600_000) return jwksCache.keys;
  const r = await fetch(GOOGLE_JWKS_URL);
  if (!r.ok) throw new Error(`google JWKS fetch failed: ${r.status}`);
  const body = (await r.json()) as { keys: NodeJWK[] };
  jwksCache = { at: Date.now(), keys: body.keys };
  return body.keys;
}

const b64urlJson = (seg: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));

export interface GoogleClaims {
  sub: string;
  iss: string;
  aud: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  nonce?: string;
  exp: number;
}

/**
 * Verify a Google ID token (RS256) against Google's JWKs. Real signature + claim
 * verification (alg, kid, iss, aud, exp). Throws on any failure.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  clientId: string,
  expectedNonce?: string,
): Promise<GoogleClaims> {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed id token");
  const header = b64urlJson(parts[0]) as { alg?: string; kid?: string };
  const payload = b64urlJson(parts[1]) as unknown as GoogleClaims;
  if (header.alg !== "RS256") throw new Error(`unexpected alg ${header.alg}`);

  const keys = await googleJwks();
  const jwk = keys.find((k) => (k as { kid?: string }).kid === header.kid);
  if (!jwk) throw new Error("no matching Google JWK for kid");
  const pub = createPublicKey({ key: jwk, format: "jwk" });
  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2].replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (!cryptoVerify("RSA-SHA256", signingInput, pub, sig)) {
    throw new Error("Google id token signature invalid");
  }

  if (!GOOGLE_ISS.includes(payload.iss)) throw new Error(`bad iss ${payload.iss}`);
  if (clientId && payload.aud !== clientId) throw new Error("aud does not match GOOGLE_CLIENT_ID");
  if (!payload.exp || payload.exp * 1000 < Date.now()) throw new Error("id token expired");
  if (!payload.sub) throw new Error("id token has no sub");
  if (expectedNonce !== undefined) {
    if (!payload.nonce) throw new Error("id token is missing required nonce");
    if (payload.nonce !== expectedNonce) throw new Error("id token nonce mismatch");
  }
  return payload;
}

/** Is real Google login configured on this BFF? */
export function googleConfigured(): boolean {
  return !!process.env.GOOGLE_CLIENT_ID;
}
