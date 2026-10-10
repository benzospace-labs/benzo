/**
 * @benzo/relayer HTTP service — the one server the wallet needs.
 *
 * Two endpoints, both self-hosted, both liveness-only (never custody):
 *   POST /sponsor/onboard  → co-sign a 0-XLM account + USDC trustline for a
 *                            browser-generated key (the wallet adds its own
 *                            signature and submits — non-custodial).
 *   POST /relay            → submit a proven `transfer` (gasless): the relayer
 *                            pays the XLM fee; the self-authorizing proof means
 *                            it cannot alter the transfer.
 *
 * Run: `pnpm --filter @benzo/relayer serve` (after `set -a; . ./.env; set +a`).
 *
 * Operational hardening (the proof already prevents value theft; these bound
 * *resource* abuse of the operator's own XLM/reserve budget):
 *   - Optional bearer auth (enforced iff RELAYER_AUTH_TOKEN is set).
 *   - Durable token-bucket rate limits (per IP, per new-account on onboard, and
 *     global relay) + a daily sponsored-onboard cap.
 *   - CORS origin allowlist (BENZO_ALLOWED_ORIGINS).
 *   - Relayer recipient check: the relayer only subsidizes a transfer that pays
 *     ITS OWN address (else an unauthenticated caller could make it burn XLM
 *     relaying transfers that compensate a third party — the "unbounded
 *     subsidy" gap). The wallet pays no USDC fee today, so there is no fee floor.
 *   - Durable HTTP idempotency keyed by the transfer's nullifiers: a resubmit
 *     returns the original txHash instead of a guaranteed-failing double-spend.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StellarCli, configFromEnv, prepareSponsoredOnboard, requireEnv } from "@benzo/core";
import { createRelayerAbuseStore } from "./abuse-store.js";

const PORT = Number(process.env.RELAYER_PORT ?? 8788);
const RELAYER_SOURCE = process.env.RELAYER_SOURCE ?? "benzo-relayer";
const HORIZON_URL = process.env.HORIZON_URL ?? "https://horizon-testnet.stellar.org";

// ---- abuse-control config (all overridable; safe testnet defaults) ----
/** When set, both money endpoints require `Authorization: Bearer <token>`. */
const AUTH_TOKEN = process.env.RELAYER_AUTH_TOKEN ?? "";
/** The relayer's fee-receiving G-address; transfers must pay this address. */
const RELAYER_ADDRESS = process.env.RELAYER_PUBLIC ?? "";
// Empty/whitespace ⇒ unset ⇒ open ("*"); an explicit list restricts to it.
// (An empty-but-defined env var must NOT silently close CORS on every request.)
const ALLOWED_ORIGINS = (() => {
  const raw = (process.env.BENZO_ALLOWED_ORIGINS ?? "").trim();
  if (raw === "") return ["*"];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
})();
/** Trust the client-supplied X-Forwarded-For header (only behind a trusted proxy). */
const TRUST_PROXY = /^(1|true|yes)$/i.test(process.env.RELAYER_TRUST_PROXY ?? "");
const RELAY_BURST = Number(process.env.RELAYER_RELAY_BURST ?? 20);
const RELAY_PER_MIN = Number(process.env.RELAYER_RELAY_PER_MIN ?? 60);
/** Global /relay ceiling — bounds abuse even if per-IP is evaded (e.g. spoofed XFF). */
const RELAY_GLOBAL_BURST = Number(process.env.RELAYER_RELAY_GLOBAL_BURST ?? 60);
const RELAY_GLOBAL_PER_MIN = Number(process.env.RELAYER_RELAY_GLOBAL_PER_MIN ?? 240);
const ONBOARD_BURST = Number(process.env.RELAYER_ONBOARD_BURST ?? 3);
const ONBOARD_PER_MIN = Number(process.env.RELAYER_ONBOARD_PER_MIN ?? 5);
const MAX_ONBOARDS_PER_DAY = Number(process.env.RELAYER_MAX_ONBOARDS_PER_DAY ?? 500);
const IDEMPOTENCY_TTL_MS = 60 * 60 * 1000; // 1h

const cli = new StellarCli(configFromEnv());
const abuse = createRelayerAbuseStore();

// ---- daily sponsored-onboard cap (UTC day) ----
async function onboardWithinDailyCap(): Promise<boolean> {
  const day = new Date().toISOString().slice(0, 10);
  return abuse.takeDaily(`onboard:${day}`, MAX_ONBOARDS_PER_DAY);
}

function clientIp(req: IncomingMessage): string {
  // Only trust X-Forwarded-For behind an explicit trusted proxy; otherwise it is
  // attacker-controlled and would let a caller mint a fresh rate-limit bucket
  // per request.
  if (TRUST_PROXY) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
  }
  return req.socket.remoteAddress ?? "unknown";
}

function originAllowed(origin: string | undefined): string | null {
  if (ALLOWED_ORIGINS.includes("*")) return "*";
  if (origin && ALLOWED_ORIGINS.includes(origin)) return origin;
  return null;
}

function cors(res: ServerResponse, origin: string | undefined): void {
  const allowOrigin = originAllowed(origin);
  if (allowOrigin) res.setHeader("Access-Control-Allow-Origin", allowOrigin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type, authorization");
}

function send(res: ServerResponse, origin: string | undefined, code: number, body: unknown): void {
  cors(res, origin);
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function safeServerError(): { error: string } {
  return { error: "Relayer temporarily unavailable. Please try again." };
}

function authed(req: IncomingMessage): boolean {
  if (!AUTH_TOKEN) return true; // open dev mode (warned at boot)
  const h = req.headers.authorization;
  return typeof h === "string" && h === `Bearer ${AUTH_TOKEN}`;
}

/** Read the value following a CLI-style `--flag` in the fnArgs array. */
function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

const server = createServer(async (req, res) => {
  const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
  if (req.method === "OPTIONS") {
    cors(res, origin);
    res.writeHead(204);
    res.end();
    return;
  }
  try {
    if (req.url === "/health") return send(res, origin, 200, { ok: true });

    // Both money endpoints require auth when a token is configured.
    if (req.url === "/sponsor/onboard" || req.url === "/relay") {
      if (!authed(req)) return send(res, origin, 401, { error: "unauthorized" });
    }

    if (req.url === "/sponsor/onboard" && req.method === "POST") {
      const ip = clientIp(req);
      const { newAccountPublic } = await readJson(req);
      if (typeof newAccountPublic !== "string") {
        return send(res, origin, 400, { error: "newAccountPublic (string) required" });
      }
      if (
        !(await abuse.allow(`onboard:ip:${ip}`, ONBOARD_BURST, ONBOARD_PER_MIN)) ||
        !(await abuse.allow(`onboard:acct:${newAccountPublic}`, ONBOARD_BURST, ONBOARD_PER_MIN))
      ) {
        return send(res, origin, 429, { error: "rate limit exceeded" });
      }
      if (!(await onboardWithinDailyCap())) {
        return send(res, origin, 429, { error: "daily sponsored-onboard cap reached" });
      }
      const out = await prepareSponsoredOnboard({
        horizonUrl: HORIZON_URL,
        networkPassphrase: requireEnv("NETWORK_PASSPHRASE"),
        sponsorSecret: requireEnv("DEPLOYER_SECRET"),
        asset: { code: requireEnv("USDC_CODE"), issuer: requireEnv("USDC_ISSUER") },
        newAccountPublic,
      });
      return send(res, origin, 200, out);
    }

    if (req.url === "/relay" && req.method === "POST") {
      const ip = clientIp(req);
      // Per-IP AND a global ceiling (the latter still bounds abuse if the per-IP
      // key is evaded, e.g. a spoofed XFF in default-open mode).
      if (
        !(await abuse.allow(`relay:ip:${ip}`, RELAY_BURST, RELAY_PER_MIN)) ||
        !(await abuse.allow("relay:global", RELAY_GLOBAL_BURST, RELAY_GLOBAL_PER_MIN))
      ) {
        return send(res, origin, 429, { error: "rate limit exceeded" });
      }
      const { contractId, fnArgs } = await readJson(req);
      if (typeof contractId !== "string" || !Array.isArray(fnArgs)) {
        return send(res, origin, 400, { error: "contractId + fnArgs required" });
      }
      const args = fnArgs as string[];
      // Liveness-only: the relayer submits ONLY a proven `transfer`. The proof
      // fixes nullifiers/commitments/fee/relayer, so it cannot be altered.
      if (args[0] !== "transfer") {
        return send(res, origin, 403, { error: "relayer only submits `transfer`" });
      }
      // Recipient check: the relayer only subsidizes a transfer that pays ITS
      // OWN address (the fee/relayer are bound in-proof). This is the control
      // that closes the unbounded-subsidy gap — it refuses to burn XLM relaying
      // a transfer that compensates a third party. (The wallet pays no USDC fee
      // today, so there is intentionally no fee floor to enforce.)
      const relayerArg = flag(args, "--relayer");
      if (RELAYER_ADDRESS && relayerArg !== RELAYER_ADDRESS) {
        return send(res, origin, 403, { error: "transfer fee must be paid to this relayer" });
      }
      // Idempotency: a resubmit of the same nullifiers returns the original
      // result instead of a guaranteed-failing double-spend submission.
      const n0 = flag(args, "--nullifier0");
      const n1 = flag(args, "--nullifier1");
      const idemKey = n0 && n1 ? `${n0}:${n1}` : null;
      if (idemKey) {
        const cached = await abuse.idemGet(idemKey, IDEMPOTENCY_TTL_MS);
        if (cached) return send(res, origin, cached.code, cached.body);
      }
      const r = await cli.invoke({
        contractId,
        source: RELAYER_SOURCE,
        send: true,
        fnArgs: args,
      });
      const body = { result: r.result, txHash: r.txHash, raw: r.raw };
      if (idemKey) await abuse.idemSet(idemKey, { code: 200, body, at: Date.now() });
      return send(res, origin, 200, body);
    }

    send(res, origin, 404, { error: "not found" });
  } catch {
    send(res, origin, 500, safeServerError());
  }
});

server.listen(PORT, () => {
  console.error(`[benzo-relayer] listening on :${PORT} (relayer source: ${RELAYER_SOURCE})`);
  if (!abuse.durable) {
    console.error(
      "[benzo-relayer] WARNING: using RELAYER_STORE_MEMORY=1/dev memory abuse store. Set DATABASE_URL for durable rate limits and idempotency.",
    );
  }
  if (!AUTH_TOKEN) {
    console.error(
      "[benzo-relayer] WARNING: RELAYER_AUTH_TOKEN unset — endpoints are open (still rate-limited). Set it to require a bearer token.",
    );
  }
  if (ALLOWED_ORIGINS.length === 0) {
    console.error(
      "[benzo-relayer] WARNING: BENZO_ALLOWED_ORIGINS resolved to an empty allowlist — all browser CORS is blocked. Set it to '*' or a real origin.",
    );
  } else if (ALLOWED_ORIGINS.includes("*")) {
    console.error(
      "[benzo-relayer] WARNING: CORS open to '*' — set BENZO_ALLOWED_ORIGINS to restrict browser origins.",
    );
  }
  if (!RELAYER_ADDRESS) {
    console.error(
      "[benzo-relayer] WARNING: RELAYER_PUBLIC unset — fee-recipient check disabled.",
    );
  }
});

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    abuse.close?.();
  });
}

