/**
 * @benzo/console-api — the BFF the console UI calls. Matches the repo's
 * node:http style (cf. anchor/relayer). Implements the typed endpoint registry
 * from @benzo/types over the workspace state; on-chain ops route through chain.ts
 * (the @benzo/core seam). If the live chain client is unavailable, app API routes
 * fail closed instead of serving local state as live data.
 */
import "./loadEnv.js"; // FIRST: load .env so missing live env fails closed.
import { AsyncLocalStorage } from "node:async_hooks";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import type {
  ApproveRequest,
  ConnectIntegrationRequest,
  Counterparty,
  CreateCounterpartyRequest,
  CreateInvoiceRequest,
  CreatePaymentRequest,
  CreatePayrollRequest,
  CreateViewingGrantRequest,
  DashboardSummary,
  InviteMemberRequest,
  LedgerEntry,
  Member,
  PaymentOrder,
  PayrollBatch,
  PayrollLine,
  TreasuryView,
} from "@benzo/types";
import { ROLE_PERMISSIONS } from "@benzo/types";
import { anchorPrivateAuditRoot, attestKyb, auditorGrantViewKey, computeTreasury, fundTreasury, getKybStatus, isLive, liveStatus, payOne, payableBalance, proveAnonymousApproval, proveBalance, proveFunded, proveKybCredential, proveLineCap, proveLineInnocence, proveNetting, proveRunComputation, proveSolvency, proveTotal, proveTotalAttestation, registerOwnerMvk, submitShieldedTransfer, treasuryPublicBalance, treasuryReceiveInfo, treasurySendPublic, type OnChainRef } from "./chain.js";
import { verifyGoogleIdToken, googleConfigured } from "./google-oidc.js";
import { accountBinding, authFromRequest, createTestAuthToken, currentAuth, runWithAuth } from "./auth.js";
import { matchPolicy, progress, recordApproval } from "./approvals.js";
import { auditOrgIdForScope } from "./auditScope.js";
import { validateInviteInput } from "./inviteValidation.js";
import { validateNettingAmounts } from "./nettingValidation.js";
import { validateGrantInput } from "./grantValidation.js";
import { activateAcceptedMemberInvite, db, fmtUsd, id, now, parseRosterCsv, recoverySummary, RecoveryRequiredError, runWithConsoleTenant, runWithConsoleTenantKey, tenantDataMissing, currentConsoleTenantKey, type OrgInvite } from "./store.js";
import { lookupTenantRoute, registerTenantRoute, takeTenantRateLimit, tenantStorageStatus } from "./tenantData.js";
import { hostedRuntime, serverlessRuntime } from "./runtime.js";
import { encodeBenzoLink } from "@benzo/links";
import { auditPacketHash, buildAnchor, buildAuditPacket, createPrivateEvent, deriveEventKey, GENESIS_HASH, sha256Hex, verifyHashChain, type AuditPacket, type PrivateEventType } from "@benzo/private-events";

function normalizeHandle(handle: string): string {
  return handle.startsWith("@") ? handle : `@${handle}`;
}

function applyCounterpartyHandle(cp: Counterparty, handle: string): string {
  const normalized = normalizeHandle(handle);
  cp.paymentAddress = {
    shielded: normalized,
    spendPub: cp.paymentAddress?.spendPub ?? `testnet-spend-${cp.id}`,
    viewPub: cp.paymentAddress?.viewPub ?? `testnet-view-${cp.id}`,
    mvkScalar: cp.paymentAddress?.mvkScalar ?? `testnet-mvk-${cp.id}`,
  };
  return normalized;
}

function privateEventSecret(): string {
  const secret = process.env.BENZO_PRIVATE_EVENT_SECRET;
  if (secret) return secret;
  if (hostedRuntime()) throw new Error("BENZO_PRIVATE_EVENT_SECRET is required for hosted private-event encryption");
  return process.env.DEPLOYER_SECRET || "benzo-local-dev-private-event-key";
}

function privateAuditOrgId(): string {
  const auth = currentAuth();
  return auditOrgIdForScope({
    authKey: auth?.key,
    tenantKey: currentConsoleTenantKey(),
    hosted: hostedRuntime(),
    localOrgId: db.org.id,
  });
}

function unavailableTreasury(): TreasuryView {
  const zero = { amount: "0", assetCode: "USDC" as const };
  return {
    totalHidden: zero,
    accounts: db.accounts.map((account) => ({ account, balance: null })),
    proveBalanceAvailable: false,
    live: false,
  };
}

async function safeComputeTreasury(): Promise<TreasuryView> {
  try {
    return await computeTreasury();
  } catch {
    return unavailableTreasury();
  }
}

function privateEventKey(): Buffer {
  return deriveEventKey(privateEventSecret(), `benzo/private-events/v1/${privateAuditOrgId()}`);
}

function appendPrivateEvent<TPayload extends Record<string, unknown>>(
  type: PrivateEventType,
  subjectId: string,
  schema: string,
  payload: TPayload,
  publicMeta: Record<string, string | number | boolean | null> = {},
): void {
  const prevHash = db.privateEvents[db.privateEvents.length - 1]?.hash ?? GENESIS_HASH;
  db.privateEvents.push(createPrivateEvent({ orgId: privateAuditOrgId(), type, subjectId, schema, payload, publicMeta }, { key: privateEventKey(), prevHash }));
}

function privateEventAuditSummary() {
  const events = db.privateEvents;
  return {
    anchor: buildAnchor(privateAuditOrgId(), events),
    integrity: verifyHashChain(events),
    note: "Encrypted private-event envelopes only. Plaintext requires a scoped viewing key.",
  };
}

function privateAuditOrgHash(): string {
  return sha256Hex(`benzo:audit-org:v1:${privateAuditOrgId()}`);
}

function stellarExpertTx(txHash?: string): string | undefined {
  return txHash ? `https://stellar.expert/explorer/testnet/tx/${txHash}` : undefined;
}

function recordProofReceipt(action: string, ref: OnChainRef | undefined, publicInputs?: unknown): void {
  if (!ref) return;
  db.proofReceipts ??= [];
  db.proofReceipts.push({
    id: id("prf"),
    action,
    vkId: ref.vkId,
    verified: ref.verified,
    verifier: ref.verifier,
    network: ref.network,
    txHash: ref.txHash,
    root: ref.root,
    publicInputs: publicInputs ?? ref.publics,
    createdAt: now(),
  });
}

function recordProofReceiptParts(action: string, input: {
  vkId: string;
  verified: boolean;
  verifier?: string;
  network?: string;
  txHash?: string;
  root?: string;
  publicInputs?: unknown;
}): void {
  db.proofReceipts ??= [];
  db.proofReceipts.push({
    id: id("prf"),
    action,
    vkId: input.vkId,
    verified: input.verified,
    verifier: input.verifier,
    network: input.network ?? process.env.NETWORK_PASSPHRASE ?? "testnet",
    txHash: input.txHash,
    root: input.root,
    publicInputs: input.publicInputs,
    createdAt: now(),
  });
}

const localRateLimits = new Map<string, { windowStart: number; count: number }>();

function takeLocalRateLimit(path: string, method: string): { ok: true } | { ok: false; retryAfter: number } {
  const write = method !== "GET";
  const key = write ? "write" : "read";
  const limit = write ? 50 : 240;
  const nowMs = Date.now();
  const bucket = localRateLimits.get(key) ?? { windowStart: nowMs, count: 0 };
  if (nowMs - bucket.windowStart >= 60_000) {
    bucket.windowStart = nowMs;
    bucket.count = 0;
  }
  bucket.count += path.includes("/settlements/") ? 3 : 1;
  localRateLimits.set(key, bucket);
  if (bucket.count > limit) return { ok: false, retryAfter: Math.max(1, Math.ceil((60_000 - (nowMs - bucket.windowStart)) / 1000)) };
  return { ok: true };
}

async function rateLimit(path: string, method: string): Promise<{ ok: true } | { ok: false; retryAfter: number }> {
  const write = method !== "GET";
  const bucketName = write ? "write" : "read";
  const limit = write ? 50 : 240;
  const weight = path.includes("/settlements/") ? 3 : 1;
  const tenantKey = currentConsoleTenantKey();
  if (tenantKey) return takeTenantRateLimit("console", tenantKey, bucketName, weight, limit, 60);
  return takeLocalRateLimit(path, method);
}

function counterpartyHandle(counterpartyId?: string): string | undefined {
  if (!counterpartyId) return undefined;
  return db.counterparties.find((c) => c.id === counterpartyId)?.paymentAddress?.shielded;
}

function payrollLineHandle(line: PayrollLine): string | undefined {
  return line.settlementHandle ?? counterpartyHandle(line.counterpartyId);
}

/**
 * Assemble a payroll run by COMPUTING each line from the contractor's stored rate
 * card — never trusting a caller-supplied amount (that is the line between a rail
 * and a payroll product). A contractor with no rate fails its line visibly
 * (PayrollLine.error) instead of silently summing zero.
 */
function assemblePayroll(reqLines: Array<{ counterpartyId: string }>): {
  lines: PayrollLine[];
  total: string;
  handles: { handle?: string; amount: string }[];
} {
  const lines: PayrollLine[] = [];
  const handles: { handle?: string; amount: string }[] = [];
  let total = 0n;
  for (const l of reqLines) {
    const cp = db.counterparties.find((c) => c.id === l.counterpartyId);
    if (!cp) {
      lines.push({ counterpartyId: l.counterpartyId, amount: "0", status: "failed", error: "unknown contractor" });
      handles.push({ amount: "0" });
      continue;
    }
    const rate = cp.payRate?.amount;
    if (!rate || BigInt(rate) <= 0n) {
      lines.push({ counterpartyId: cp.id, amount: "0", status: "failed", error: `no rate card set for ${cp.name}` });
      handles.push({ amount: "0" });
      continue;
    }
    // v1: fixed-monthly retainer — gross is the stored rate, computed here, not by the caller.
    total += BigInt(rate);
    const handle = cp.paymentAddress?.shielded;
    lines.push({ counterpartyId: cp.id, amount: rate, rate, settlementHandle: handle, status: "pending" });
    handles.push({ handle, amount: rate });
  }
  return { lines, total: total.toString(), handles };
}

/**
 * Settle an approved run — idempotently, funded, and resumably (the trust gate):
 *  - never re-pays a line already settled on-chain (re-approve/retry is safe);
 *  - pre-checks the live treasury balance and fails over-budget lines visibly
 *    instead of running dry mid-batch;
 *  - per-line try/catch surfaces WHICH line failed and WHY to the operator.
 */
// ---- Tamper-evident audit hash-chain over the double-entry ledger ----
// Each entry commits to the prior via SHA-256(prevHash + canonical(entry)). Any
// later edit/insert/delete breaks the chain from that point, so an auditor can
// verify the whole log is intact. This is the off-chain system-of-record's
// integrity guarantee (the on-chain settlement txIds are the other half).
function canonicalLedger(e: LedgerEntry): string {
  const { hash: _h, ...rest } = e;
  return JSON.stringify(rest);
}
function chainHash(prev: string | undefined, e: LedgerEntry): string {
  return createHash("sha256").update((prev ?? "GENESIS") + canonicalLedger(e)).digest("hex");
}
/** Append an entry, sealing it into the chain. */
function postLedger(entry: LedgerEntry): void {
  entry.hash = chainHash(db.ledger[db.ledger.length - 1]?.hash, entry);
  db.ledger.push(entry);
}
/** One-time backfill so pre-existing ledger entries join the chain as genesis. */
function sealSeedLedger(): void {
  let prev: string | undefined;
  for (const e of db.ledger) {
    if (!e.hash) e.hash = chainHash(prev, e);
    prev = e.hash;
  }
}
/** Re-walk the chain; report the first tampered index (or ok). */
export function verifyLedgerChain(): { ok: boolean; length: number; brokenAt?: number } {
  let prev: string | undefined;
  for (let i = 0; i < db.ledger.length; i++) {
    if (db.ledger[i].hash !== chainHash(prev, db.ledger[i])) return { ok: false, length: db.ledger.length, brokenAt: i };
    prev = db.ledger[i].hash;
  }
  return { ok: true, length: db.ledger.length };
}

/** Post the immutable double-entry record for one settled payroll line (Dr payroll expense / Cr treasury). */
function writeRunLedger(batch: PayrollBatch, line: PayrollLine, txId?: string): void {
  postLedger({
    id: id("le"), orgId: db.org.id, txId, postedAt: now(), sourceType: "payroll", sourceId: batch.id,
    lines: [
      { accountId: "acc_pay", direction: "debit", amount: line.amount, assetCode: "USDC" },
      { accountId: "acc_tre", direction: "credit", amount: line.amount, assetCode: "USDC" },
    ],
  });
  appendPrivateEvent(
    "payment.settled",
    txId ?? `${batch.id}:${line.counterpartyId}`,
    "payment.settled.v1",
    { batch, line, txId, settledAt: now() },
    { status: line.status, source: "payroll", live: Boolean(txId) },
  );
}

async function settlePayroll(batch: PayrollBatch): Promise<void> {
  const { live, stroops: balance } = await payableBalance();

  // "Payroll funded ✓" — before moving a cent, prove ON-CHAIN (vk_id ORGBAL) that
  // the M-of-N treasury covers this run's unsettled TOTAL, revealing neither the
  // treasury nor the total. An over-budget run is provably blocked (funded:false
  // => we refuse to settle), not discovered halfway through draining the treasury.
  const runTotal = batch.lines
    .filter((l) => !l.onChain && BigInt(l.amount || "0") > 0n)
    .reduce((s, l) => s + BigInt(l.amount), 0n);
  if (live && runTotal > 0n) {
    const f = await proveFunded(runTotal.toString());
    batch.fundedProof = { funded: f.funded, onChain: f.onChain, provenAt: now() };
    if (f.onChain && !f.funded) {
      // Cryptographic "no" — top up the treasury and re-approve to retry.
      for (const l of batch.lines) {
        if (!l.onChain && BigInt(l.amount || "0") > 0n) {
          l.status = "failed";
          l.error = "run not funded - treasury below run total (proven on-chain). Top up and re-approve.";
        }
      }
      batch.status = "processing";
      return;
    }
  }

  let remaining = balance;
  for (let i = 0; i < batch.lines.length; i++) {
    const l = batch.lines[i];
    if (l.onChain) continue; // idempotent: a settled line is never paid twice
    const amt = BigInt(l.amount || "0");
    if (amt <= 0n) {
      l.status = "failed";
      l.error = l.error ?? "no rate card / zero amount";
      continue;
    }
    if (live && amt > remaining) {
      l.status = "failed";
      l.error = "insufficient treasury balance - top up and re-approve to retry";
      continue;
    }
    const r = await payOne(payrollLineHandle(l), l.amount);
    if (r.onChain) {
      l.status = "paid";
      l.txHash = r.txHash;
      l.onChain = true;
      l.error = undefined;
      remaining -= amt;
      writeRunLedger(batch, l, r.txHash); // immutable record per settled line
    } else {
      l.status = "failed";
      l.error = r.error ?? "settlement failed";
    }
  }
  const settled = (l: PayrollLine) => l.status === "paid" || (l.status === "failed" && BigInt(l.amount || "0") === 0n);
  batch.status = batch.lines.every(settled) ? "completed" : "processing";
}

const PORT = Number(process.env.CONSOLE_API_PORT ?? 8790);
const rawBodies = new WeakMap<IncomingMessage, string>();
const idempotencyScope = new AsyncLocalStorage<{ key: string; bodyHash: string }>();
const inviteRouteScope = new AsyncLocalStorage<{ token: string }>();

// ---------------------------------------------------------------- http utils
function cors(res: ServerResponse): void {
  res.setHeader("Access-Control-Allow-Origin", process.env.CONSOLE_ALLOWED_ORIGIN ?? "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type, authorization, idempotency-key, x-benzo-org-invite-token, x-benzo-test-secret");
}
function json(res: ServerResponse, code: number, body: unknown): void {
  cors(res);
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
  const idem = idempotencyScope.getStore();
  if (idem && code < 500) {
    db.idempotency ??= {};
    db.idempotency[idem.key] = { bodyHash: idem.bodyHash, status: code, body, createdAt: now() };
  }
}
async function rawBody(req: IncomingMessage): Promise<string> {
  const cached = rawBodies.get(req);
  if (cached !== undefined) return cached;
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  rawBodies.set(req, raw);
  return raw;
}
async function readJson<T>(req: IncomingMessage): Promise<T> {
  const raw = await rawBody(req);
  return (raw ? JSON.parse(raw) : {}) as T;
}

function currentInviteRouteToken(): string | null {
  return inviteRouteScope.getStore()?.token ?? null;
}

function idempotencyHeader(req: IncomingMessage): string | null {
  const h = req.headers["idempotency-key"];
  const v = Array.isArray(h) ? h[0] : h;
  return v?.trim() || null;
}

function requiresIdempotency(method: string, path: string): boolean {
  if (!hostedRuntime()) return false;
  if (!path.startsWith("/api/")) return false;
  const m = method.toUpperCase();
  if (m === "GET" || m === "HEAD" || m === "OPTIONS") return false;
  return path !== "/api/auth/google" && path !== "/api/auth/test" && path !== "/api/auth/local";
}

async function inviteRouteToken(req: IncomingMessage, path: string): Promise<string | null> {
  if (path === "/api/invites/accept") {
    const body = await readJson<{ token?: string }>(req);
    return body.token?.trim() || null;
  }
  if (path === "/api/invoices") {
    const h = req.headers["x-benzo-org-invite-token"];
    const fromHeader = (Array.isArray(h) ? h[0] : h)?.trim();
    if (fromHeader) return fromHeader;
    if ((req.method ?? "GET").toUpperCase() !== "GET") {
      const body = await readJson<{ inviteToken?: string }>(req);
      return body.inviteToken?.trim() || null;
    }
  }
  return null;
}

async function runIdempotent(req: IncomingMessage, res: ServerResponse, path: string, fn: () => Promise<void>): Promise<void> {
  const method = req.method ?? "GET";
  const header = method === "GET" ? null : idempotencyHeader(req);
  if (!header) return fn();
  const raw = await rawBody(req);
  const bodyHash = createHash("sha256").update(raw).digest("hex");
  const key = `${method}:${path}:${header}`;
  db.idempotency ??= {};
  const existing = db.idempotency[key];
  if (existing) {
    if (existing.bodyHash !== bodyHash) return json(res, 409, { error: "Idempotency key was already used with a different request body." });
    return json(res, existing.status, existing.body);
  }
  await idempotencyScope.run({ key, bodyHash }, fn);
}

// --------------------------------------------------------------- tiny router
type Handler = (
  req: IncomingMessage,
  res: ServerResponse,
  params: Record<string, string>,
) => void | Promise<void>;
interface Route {
  method: string;
  segments: string[];
  handler: Handler;
}
const routes: Route[] = [];
function route(method: string, path: string, handler: Handler): void {
  routes.push({ method, segments: path.split("/").filter(Boolean), handler });
}
function match(method: string, path: string): { handler: Handler; params: Record<string, string> } | null {
  const segs = path.split("/").filter(Boolean);
  for (const r of routes) {
    if (r.method !== method || r.segments.length !== segs.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < segs.length; i++) {
      const rs = r.segments[i];
      if (rs.startsWith(":")) params[rs.slice(1)] = segs[i];
      else if (rs !== segs[i]) {
        ok = false;
        break;
      }
    }
    if (ok) return { handler: r.handler, params };
  }
  return null;
}

// -------------------------------------------------------------------- routes
route("GET", "/health", (_req, res) => json(res, 200, { ok: true }));

route("GET", "/api/session", (_req, res) => {
  const member = db.members.find((m) => m.id === db.sessionMemberId);
  if (!member) return json(res, 404, { error: "no session" });
  json(res, 200, { member, org: db.org, permissions: ROLE_PERMISSIONS[member.role] });
});

route("GET", "/api/recovery/status", (_req, res) =>
  json(res, 200, { status: "ok", recovery: recoverySummary() }),
);

// ----------------------------------------------------------------- zkLogin / SSO
// Tells the frontend whether REAL Google sign-in is configured (a GOOGLE_CLIENT_ID is set).
route("GET", "/api/auth/config", (_req, res) =>
  json(res, 200, { googleClientId: process.env.GOOGLE_CLIENT_ID ?? null, google: googleConfigured() }),
);
// Verify a Google ID token (zkLogin Phase 1: real OAuth + real RS256 verification
// against Google's JWKs). Returns the verified claims; the browser derives the
// Benzo account from `sub` via accountFromOidc — the chain never sees the identity.
route("POST", "/api/auth/google", async (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) return json(res, 200, { verified: false, configured: false, note: "GOOGLE_CLIENT_ID not set" });
  try {
    const body = await readJson<{ credential: string; nonce?: string }>(req);
    const claims = await verifyGoogleIdToken(String(body.credential), clientId, body.nonce);
    json(res, 200, { verified: true, sub: claims.sub, iss: claims.iss, aud: claims.aud, email: claims.email, name: claims.name });
  } catch (e) {
    json(res, 401, { verified: false, error: (e as Error).message });
  }
});

function providedTestSecret(req: IncomingMessage, body: { secret?: string }): string {
  const h = req.headers["x-benzo-test-secret"];
  return (Array.isArray(h) ? h[0] : h) || body.secret || "";
}

function secretMatches(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function hostnameIsLocalhost(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const parsed = value.includes("://")
      ? new URL(value).hostname
      : value.startsWith("[::1]")
        ? "::1"
        : value.split(":")[0];
    return parsed === "localhost" || parsed === "127.0.0.1" || parsed === "::1" || parsed === "[::1]";
  } catch {
    return false;
  }
}

function isLocalVerificationRequest(req: IncomingMessage): boolean {
  if (process.env.BENZO_LOCAL_UI_TEST_AUTH !== "1") return false;
  const host = req.headers.host;
  const forwardedHost = Array.isArray(req.headers["x-forwarded-host"])
    ? req.headers["x-forwarded-host"][0]
    : req.headers["x-forwarded-host"];
  const origin = Array.isArray(req.headers.origin) ? req.headers.origin[0] : req.headers.origin;
  const referer = Array.isArray(req.headers.referer) ? req.headers.referer[0] : req.headers.referer;
  if (!hostnameIsLocalhost(forwardedHost || host)) return false;
  if (origin && !hostnameIsLocalhost(origin)) return false;
  if (!origin && referer && !hostnameIsLocalhost(referer)) return false;
  return true;
}

route("POST", "/api/auth/test", async (req, res) => {
  const expected = hostedRuntime() ? process.env.BENZO_TEST_AUTH_SECRET : undefined;
  if (!expected) return json(res, 404, { error: "not found" });
  const body = await readJson<{ secret?: string; subject?: string; email?: string; name?: string; ttlSeconds?: number }>(req);
  if (!secretMatches(providedTestSecret(req, body), expected)) {
    return json(res, 401, { error: "test auth unavailable" });
  }
  const token = createTestAuthToken({
    subject: body.subject,
    email: body.email,
    name: body.name,
    ttlSeconds: body.ttlSeconds,
  });
  json(res, 200, { token, tokenType: "Bearer", expiresIn: Math.max(60, Math.min(body.ttlSeconds ?? 900, 3600)) });
});

route("POST", "/api/auth/local", async (req, res) => {
  if (!isLocalVerificationRequest(req)) return json(res, 404, { error: "not found" });
  const body = await readJson<{ subject?: string; name?: string; ttlSeconds?: number }>(req);
  const subject = String(body.subject || `codex-console-ui-${Date.now()}`).replace(/[^a-zA-Z0-9_.:-]/g, "").slice(0, 80);
  const token = createTestAuthToken({
    subject,
    email: `${subject}@benzo.local`,
    name: body.name || "Local Verification Console",
    ttlSeconds: body.ttlSeconds,
  });
  json(res, 200, { token, tokenType: "Bearer", expiresIn: Math.max(60, Math.min(body.ttlSeconds ?? 900, 3600)) });
});

// ---------------------------------------------------------------- onboarding (P0-B1)
// The wizard's draft + the real on-chain actions. KYB is a REAL on-chain
// attestation (org_account, issuer-signed) — the console reads the decision from
// chain; the member MVK registration is likewise a
// genuine on-chain tx when live. ZK and KYB paths are on-chain.
route("GET", "/api/onboarding", (_req, res) => json(res, 200, db.onboarding));
route("PATCH", "/api/onboarding", async (req, res) => {
  const body = await readJson<typeof db.onboarding>(req);
  db.onboarding = { ...db.onboarding, ...body };
  appendPrivateEvent("onboarding.updated", db.org.id, "onboarding.v1", { onboarding: db.onboarding, updatedAt: now() }, { source: "onboarding" });
  json(res, 200, db.onboarding);
});
/**
 * KYB — a REAL on-chain attestation. The provider's checks gate the decision,
 * which is then POSTED ON-CHAIN by the issuer key (issuer-gated in org_account)
 * and read back from chain. The provider integration is the seam: the issuer key
 * is ours today; a real provider would hold it (or we re-point to theirs).
 */
route("POST", "/api/onboarding/kyb", async (req, res) => {
  const body = await readJson<typeof db.onboarding & { approve?: boolean }>(req);
  db.onboarding = { ...db.onboarding, ...body };
  try {
    const attested = await attestKyb(body.approve !== false);
    db.onboarding.kyb = {
      status: attested.status as "approved" | "pending" | "rejected" | "unverified",
      provider: "On-chain attestation (org_account)",
      inquiryRef: attested.inquiryRef,
      checks: ["business_registration", "beneficial_owners", "ofac_screen", "tax_id"],
      onChain: attested.onChain,
      txHash: attested.txHash,
    };
    appendPrivateEvent("onboarding.kyb_attested", db.org.id, "onboarding.kyb.v1", { kyb: db.onboarding.kyb, attestedAt: now() }, { status: db.onboarding.kyb.status, source: "onboarding", live: Boolean(attested.onChain) });
    json(res, 200, db.onboarding.kyb);
  } catch {
    console.error("[benzo-console-api] KYB attestation failed");
    json(res, 502, { error: "Could not post the KYB attestation on-chain. Please try again." });
  }
});
/** The org's KYB status, read live FROM CHAIN (org_account.kyb_status). */
route("GET", "/api/onboarding/kyb-status", async (_req, res) => {
  const s = await getKybStatus();
  json(res, 200, s);
});
/** Register the org owner's MVK on-chain — the real ZK action of onboarding. */
route("POST", "/api/onboarding/register-mvk", async (_req, res) => {
  const r = await registerOwnerMvk();
  db.onboarding.mvk = r;
  appendPrivateEvent("onboarding.mvk_registered", db.org.id, "onboarding.mvk.v1", { mvk: r, registeredAt: now() }, { source: "onboarding", live: Boolean(r.onChain) });
  json(res, 200, r);
});
/** Finish — apply the draft to the org so the console boots into the live workspace. */
route("POST", "/api/onboarding/finish", async (_req, res) => {
  if (db.onboarding.name) db.org.name = db.onboarding.name;
  if (db.onboarding.legalName) db.org.legalName = db.onboarding.legalName;
  if (db.onboarding.country) db.org.country = db.onboarding.country;
  if (db.onboarding.complianceZoneId) db.org.complianceZoneId = db.onboarding.complianceZoneId;
  // Reflect the REAL on-chain KYB decision (read from chain when live), so the
  // workspace boots with the attested status rather than an assumed one.
  const chainKyb = await getKybStatus();
  db.org.kybStatus = chainKyb.status;
  const member = db.members.find((m) => m.id === db.sessionMemberId)!;
  appendPrivateEvent("onboarding.finished", db.org.id, "onboarding.finish.v1", { org: db.org, member, finishedAt: now() }, { status: db.org.kybStatus, source: "onboarding" });
  json(res, 200, { member, org: db.org, permissions: ROLE_PERMISSIONS[member.role] });
});

route("GET", "/api/dashboard", async (_req, res) => {
  const treasury = await safeComputeTreasury();
  const summary: DashboardSummary = {
    totalPosition: treasury.totalHidden,
    pendingApprovals: db.payments.filter((p) => p.status === "needs_approval").length,
    openInvoices: db.invoices.filter((i) => i.status === "open").length,
    scheduledPayrolls: db.payrolls.filter((p) => p.status === "needs_approval" || p.status === "approved").length,
    recentActivity: [
      ...db.payments.map((p) => ({
        id: p.id, kind: "payment" as const, title: p.memo ?? "Payment", status: p.status,
        amountLabel: p.privacy.amountHidden ? "Private" : fmtUsd(p.amount.amount), at: p.updatedAt,
      })),
      ...db.invoices.map((i) => ({
        id: i.id, kind: "invoice" as const, title: i.number, status: i.status,
        amountLabel: fmtUsd(i.total.amount), at: i.createdAt,
      })),
    ].slice(0, 10),
    live: isLive() && treasury.live,
  };
  json(res, 200, summary);
});

route("GET", "/api/treasury", async (_req, res) => json(res, 200, await safeComputeTreasury()));
route("POST", "/api/treasury/prove-balance", async (req, res) => {
  const body = await readJson<{ min: string }>(req);
  const proof = await proveBalance(String(body.min));
  recordProofReceipt("treasury.prove-balance", proof.ref);
  json(res, 200, proof);
});
route("POST", "/api/treasury/prove-total", async (_req, res) => {
  const proof = await proveTotal();
  recordProofReceipt("treasury.prove-total", proof.ref);
  json(res, 200, proof);
});
// KYB-as-ZK credential (Z7): prove "verified business, jurisdiction Y, tier Z"
// on-chain (vk_id KYB) without revealing the documents; sybil-resistant.
route("POST", "/api/compliance/kyb-credential", async (_req, res) => {
  const proof = await proveKybCredential();
  recordProofReceipt("compliance.kyb-credential", proof.ref);
  json(res, 200, proof);
});
// Cross-entity private netting (Z8): net mutual invoices with a counterparty and
// settle only the difference on-chain (vk_id NETTING); grosses hidden.
route("POST", "/api/invoices/net", async (req, res) => {
  const body = await readJson<{ weOwe?: unknown; theyOwe?: unknown }>(req);
  const validation = validateNettingAmounts(body);
  if ("error" in validation) return json(res, 400, { error: validation.error });
  const proof = await proveNetting(validation.we, validation.they);
  recordProofReceipt("invoices.net", proof.ref);
  json(res, 200, proof);
});
// Records export (Z2): network-verified period-total attestation for a tax
// authority/auditor. Embeds the real ORGSUM proof + publics for independent
// re-verification on-chain. Salaries stay hidden; only the total is disclosed.
route("POST", "/api/records/period-total", async (req, res) => {
  const body = await readJson<{ period?: string }>(req);
  const att = await proveTotalAttestation(body.period || db.org?.name + " period");
  recordProofReceiptParts("records.period-total", {
    vkId: att.vkId,
    verified: att.onChain,
    verifier: att.verifier,
    network: att.network,
    root: att.root,
    publicInputs: att.sorobanPublics,
  });
  json(res, 200, { live: true, org: db.org?.name ?? "Organization", ...att });
});
// True solvency — prove treasury >= Σ liabilities (pending payroll + open
// invoices), both hidden, on-chain (ORGBAL). Liabilities summed from the books.
route("POST", "/api/treasury/prove-solvency", async (_req, res) => {
  const pendingPayroll = db.payrolls
    .filter((p) => p.status === "needs_approval" || p.status === "approved" || p.status === "processing")
    .reduce((s, p) => s + BigInt(p.total.amount || "0"), 0n);
  const openInvoices = db.invoices
    .filter((i) => i.status !== "paid" && i.status !== "cancelled")
    .reduce((s, i) => s + BigInt(i.total.amount || "0"), 0n);
  const liabilities = (pendingPayroll + openInvoices).toString();
  const proof = await proveSolvency(liabilities);
  recordProofReceipt("treasury.prove-solvency", proof.ref);
  json(res, 200, proof);
});
route("POST", "/api/treasury/fund", async (req, res) => {
  const body = await readJson<{ amount: string }>(req);
  // amount in USDC (human) -> stroops (7dp). This is also "Make private" (shield).
  const stroops = BigInt(Math.round(Number(body.amount) * 1e7)).toString();
  const r = await fundTreasury(stroops);
  appendPrivateEvent("treasury.funded", r.txHash ?? id("treasury"), "treasury.fund.v1", { requestedAmount: body.amount, stroops, result: r, fundedAt: now() }, { source: "treasury", live: Boolean(r.onChain) });
  json(res, 200, r);
});
// Two-balance model: the treasury's PUBLIC (liquid, unshielded) USDC balance —
// what external wallets/exchanges see. The org's M-of-N shielded pool is /treasury.
route("GET", "/api/treasury/public-balance", async (_req, res) => json(res, 200, await treasuryPublicBalance()));
// Receive: address + asset/issuer for a Receive QR (inbound lands in Public).
route("GET", "/api/treasury/receive", async (_req, res) => {
  const info = await treasuryReceiveInfo();
  json(res, 200, info);
});
// "Send to a wallet": a real on-chain USDC transfer from the Public balance to an
// external G-address (credits the recipient's USDC trustline). Friendly errors.
route("POST", "/api/treasury/send-public", async (req, res) => {
  const body = await readJson<{ to: string; amount: string }>(req);
  // amount in USDC (human) -> stroops (7dp), matching /treasury/fund.
  const stroops = BigInt(Math.round(Number(body.amount) * 1e7)).toString();
  const r = await treasurySendPublic(String(body.to ?? ""), stroops);
  appendPrivateEvent("treasury.public_sent", r.txHash ?? id("treasury"), "treasury.public-send.v1", { to: body.to, requestedAmount: body.amount, stroops, result: r, sentAt: now() }, { source: "treasury", live: Boolean(r.onChain) });
  json(res, 200, r);
});
function appLiveStatus() {
  const s = liveStatus();
  const missing = [...new Set([...s.missing, ...tenantDataMissing()])];
  const live = s.live && missing.length === 0;
  return { ...s, live, mode: live ? "live" as const : "unavailable" as const, missing, tenantStorage: tenantStorageStatus() };
}

route("GET", "/api/live", (_req, res) => json(res, 200, appLiveStatus()));

// Stateless console actions for the privacy-first UI. Mutable business objects
// live encrypted in the browser; the BFF only receives the minimum witness data
// required to prove locally and submit to testnet.
route("POST", "/api/settlements/payment", async (req, res) => {
  const body = await readJson<{ amount?: { amount?: string }; toHandle?: string }>(req);
  const r = await payOne(body.toHandle, String(body.amount?.amount ?? "0"));
  appendPrivateEvent("settlement.payment", r.txHash ?? id("settle"), "settlement.payment.v1", { request: body, result: r, settledAt: now() }, { source: "settlement", live: Boolean(r.onChain) });
  json(res, 200, r);
});
route("POST", "/api/settlements/payroll", async (req, res) => {
  const body = await readJson<{ lines?: Array<{ counterpartyId: string; amount: string; handle?: string }> }>(req);
  const lines = [];
  for (const l of body.lines ?? []) {
    if (BigInt(l.amount || "0") <= 0n) {
      lines.push({ counterpartyId: l.counterpartyId, status: "failed" as const, error: "no rate card / zero amount" });
      continue;
    }
    try {
      const r = await payOne(l.handle, l.amount);
      lines.push({
        counterpartyId: l.counterpartyId,
        status: r.onChain ? "paid" as const : "failed" as const,
        txHash: r.txHash,
        onChain: r.onChain,
        error: r.error,
      });
    } catch (e) {
      lines.push({
        counterpartyId: l.counterpartyId,
        status: "failed" as const,
        error: e instanceof Error ? e.message : "payroll payout failed",
      });
    }
  }
  appendPrivateEvent("settlement.payroll", id("settle"), "settlement.payroll.v1", { request: body, lines, settledAt: now() }, { source: "settlement", itemCount: lines.length });
  json(res, 200, { lines });
});
route("POST", "/api/payroll-proofs/funded", async (req, res) => {
  const body = await readJson<{ runTotal?: string }>(req);
  const r = await proveFunded(String(body.runTotal ?? "0"));
  recordProofReceipt("payroll.funded", r.ref);
  json(res, 200, { runTotal: String(body.runTotal ?? "0"), funded: r.funded, onChain: r.onChain, provenAt: now(), ref: r.ref });
});
route("POST", "/api/payroll-proofs/approval", async (req, res) => {
  const body = await readJson<{ batchId?: string }>(req);
  const { ref, ...r } = await proveAnonymousApproval(body.batchId ?? id("pr"));
  recordProofReceipt("payroll.approval", ref);
  json(res, 200, { ...r, provenAt: now(), ref });
});
route("POST", "/api/payroll-proofs/computation", async (req, res) => {
  const body = await readJson<{ lines?: Array<{ amount: string; handle?: string }> }>(req);
  const r = await proveRunComputation((body.lines ?? []).map((l) => ({ amount: l.amount, handle: l.handle })));
  recordProofReceipt("payroll.computation", r.ref);
  json(res, 200, { ok: r.ok, onChain: r.onChain, runTotal: r.runTotal, provenAt: now(), ref: r.ref });
});
route("POST", "/api/payroll-proofs/policy", async (req, res) => {
  const body = await readJson<{ cap?: string; lines?: Array<{ counterpartyId: string; amount: string; handle?: string }> }>(req);
  const capHuman = String(body.cap ?? "0");
  const capStroops = BigInt(Math.round(Number(capHuman) * 1e7)).toString();
  const lines = [];
  for (let i = 0; i < (body.lines ?? []).length; i++) {
    const l = (body.lines ?? [])[i];
    if (!l.handle || BigInt(l.amount || "0") <= 0n) {
      lines.push({
        counterpartyId: l.counterpartyId,
        capProof: { withinCap: false, onChain: false },
        screenProof: { innocent: false, onChain: false },
      });
      continue;
    }
    const cap = await proveLineCap(l.handle, l.amount, capStroops, BigInt(i + 1));
    const screen = await proveLineInnocence(l.handle, l.amount, BigInt(1000 + i));
    recordProofReceiptParts("payroll.policy.cap", { vkId: "SPENDCAP", verified: cap.withinCap && cap.onChain });
    recordProofReceiptParts("payroll.policy.screen", { vkId: "POIPAYOUT", verified: screen.innocent && screen.onChain });
    lines.push({
      counterpartyId: l.counterpartyId,
      capProof: { withinCap: cap.withinCap, onChain: cap.onChain },
      screenProof: { innocent: screen.innocent, onChain: screen.onChain },
    });
  }
  json(res, 200, { cap: capHuman, lines });
});

route("GET", "/api/members", (_req, res) => json(res, 200, db.members));
route("POST", "/api/members", async (req, res) => {
  const body = await readJson<InviteMemberRequest>(req);
  const member = { id: id("mem"), orgId: db.org.id, email: body.email, role: body.role, status: "invited" as const, createdAt: now() };
  db.members.push(member);
  appendPrivateEvent("member.invited", member.id, "member.v1", { member, invitedAt: member.createdAt }, { status: member.status, source: "members" });
  json(res, 201, member);
});

route("GET", "/api/accounts", (_req, res) => json(res, 200, db.accounts));

route("GET", "/api/counterparties", (_req, res) => json(res, 200, db.counterparties));
route("POST", "/api/counterparties", async (req, res) => {
  const body = await readJson<CreateCounterpartyRequest>(req);
  const cp = {
    id: id("cp"), orgId: db.org.id, name: body.name, type: body.type, email: body.email,
    status: "pending_screening" as const, externalAccounts: [], createdAt: now(),
  };
  db.counterparties.push(cp);
  appendPrivateEvent("counterparty.created", cp.id, "counterparty.v1", { counterparty: cp, createdAt: cp.createdAt }, { status: cp.status, kind: cp.type, source: "counterparties" });
  json(res, 201, cp);
});

route("GET", "/api/payments", (_req, res) => json(res, 200, db.payments));
route("POST", "/api/payments", async (req, res) => {
  const body = await readJson<CreatePaymentRequest>(req);
  // Evaluate the maker-checker policy over the PLAINTEXT proposal (privacy-aware seam).
  const policy = matchPolicy(BigInt(body.amount.amount));
  const po: PaymentOrder = {
    id: id("po"), orgId: db.org.id, type: body.type, status: policy ? "needs_approval" : "approved",
    amount: body.amount, fromAccountId: body.fromAccountId, toCounterpartyId: body.toCounterpartyId,
    memo: body.memo, ref: body.ref, approvalPolicyId: policy?.id, approvals: [],
    privacy: { amountHidden: true, counterpartyHidden: true, visibleTo: [db.sessionMemberId] },
    settlement: {}, createdByMemberId: db.sessionMemberId, createdAt: now(), updatedAt: now(),
  };
  // `toHandle` (the recipient @handle) drives the live joinsplit; stash it for
  // the approve/release step when the payment needs approval first. Resolve it
  // from the selected payee's saved handle when the caller didn't pass one, so
  // the UI never makes the user re-type a handle the dropdown already implies.
  const payee = db.counterparties.find((c) => c.id === po.toCounterpartyId);
  const toHandle = (body as CreatePaymentRequest & { toHandle?: string }).toHandle ?? payee?.paymentAddress?.shielded;
  if (toHandle && payee) applyCounterpartyHandle(payee, toHandle);
  if (!policy) await submitShieldedTransfer(po, toHandle); // auto-settle when no approval needed
  db.payments.push(po);
  appendPrivateEvent(
    "payment.submitted",
    po.id,
    "payment.order.v1",
    { payment: po, toHandle, requestedAt: po.createdAt },
    { status: po.status, kind: po.type, source: "console" },
  );
  if (po.settlement?.onChain || po.settlement?.txHash) {
    appendPrivateEvent(
      "payment.settled",
      po.settlement.txHash ?? po.id,
      "payment.settled.v1",
      { payment: po, settlement: po.settlement, settledAt: now() },
      { status: po.status, source: "direct", live: Boolean(po.settlement.onChain) },
    );
  }
  json(res, 201, po);
});
route("GET", "/api/payments/:id", (_req, res, p) => {
  const po = db.payments.find((x) => x.id === p.id);
  return po ? json(res, 200, po) : json(res, 404, { error: "not found" });
});
route("POST", "/api/payments/:id/approve", async (req, res, p) => {
  const po = db.payments.find((x) => x.id === p.id);
  if (!po) return json(res, 404, { error: "not found" });
  const body = await readJson<ApproveRequest & { actorMemberId?: string }>(req);
  const policy = db.policies.find((x) => x.id === po.approvalPolicyId);
  po.approvals = po.approvals ?? [];
  if (body.decision === "denied") {
    recordApproval({ policy, approvals: po.approvals, proposerId: po.createdByMemberId, actorMemberId: body.actorMemberId, decision: "denied", comment: body.comment, paymentOrderId: po.id });
    po.status = "cancelled";
    po.updatedAt = now();
    appendPrivateEvent("approval.recorded", po.id, "approval.v1", { payment: po, decision: "denied", actorMemberId: body.actorMemberId, comment: body.comment, recordedAt: po.updatedAt }, { status: po.status, source: "payment" });
    return json(res, 200, { ...po, progress: progress(policy, po.approvals) });
  }
  // Record ONE approval against the next unsatisfied step (segregation of duties enforced).
  const r = recordApproval({ policy, approvals: po.approvals, proposerId: po.createdByMemberId, actorMemberId: body.actorMemberId, decision: "approved", comment: body.comment, paymentOrderId: po.id });
  if (r.error) return json(res, 400, { error: r.error });
  // Release ONLY when every step + the release gate are satisfied.
  const releaseHandle = counterpartyHandle(po.toCounterpartyId);
  if (r.progress.satisfied) await submitShieldedTransfer(po, releaseHandle);
  po.updatedAt = now();
  appendPrivateEvent("approval.recorded", po.id, "approval.v1", { payment: po, decision: "approved", actorMemberId: body.actorMemberId, comment: body.comment, progress: r.progress, recordedAt: po.updatedAt }, { status: po.status, source: "payment" });
  if (po.settlement?.onChain || po.settlement?.txHash) {
    appendPrivateEvent(
      "payment.settled",
      po.settlement.txHash ?? po.id,
      "payment.settled.v1",
      { payment: po, settlement: po.settlement, settledAt: po.updatedAt },
      { status: po.status, source: "approval", live: Boolean(po.settlement.onChain) },
    );
  }
  json(res, 200, { ...po, progress: r.progress });
});

// ---------------------------------------------------------------- invites (P0-B2)
// Onboard employees/customers/contractors via a BUSINESS-scoped link. The
// `app:"business"` tag means the consumer wallet refuses it (MismatchScreen) and
// a consumer claim secret can't reconstruct a business account (HKDF domain sep).
// Only TEAM invites create a console seat; contractor/customer onboard in the wallet.
const DEFAULT_WALLET_ORIGIN = "https://wallet.benzo.space";
const DEFAULT_CONSOLE_ORIGIN = "https://console.benzo.space";

function routeEncodedLink(origin: string, link: string): string {
  return `${origin.replace(/\/+$/, "")}/claim#${encodeURIComponent(link)}`;
}

function makeInvite(kind: OrgInvite["kind"], opts: { name?: string; email?: string; role?: string; counterpartyId?: string }): OrgInvite {
  const token = id("tok");
  const expiresAt = Math.floor(Date.now() / 1000) + 14 * 86_400;
  // app = where it's REDEEMED: a team member joins the CONSOLE (business); a
  // contractor/customer onboards in the consumer WALLET (with an org backref).
  // So only member invites bounce if opened in the wallet (MismatchScreen).
  const app = kind === "member" ? "business" : "consumer";
  const payload = encodeBenzoLink(
    {
      type: "org",
      orgId: db.org.id,
      kind,
      role: opts.role,
      orgName: db.org.name,
      counterpartyId: opts.counterpartyId,
      inviteeName: opts.name ?? opts.email,
      token,
      app,
      expiresAt: String(expiresAt),
    },
    "scheme",
  );
  const link =
    app === "consumer"
      ? routeEncodedLink(process.env.BENZO_WALLET_ORIGIN || DEFAULT_WALLET_ORIGIN, payload)
      : routeEncodedLink(process.env.BENZO_CONSOLE_ORIGIN || DEFAULT_CONSOLE_ORIGIN, payload);
  return { id: id("invite"), kind, name: opts.name, email: opts.email, role: opts.role, counterpartyId: opts.counterpartyId, link, token, expiresAt, status: "sent", createdAt: now() };
}

async function registerInviteRoute(inv: OrgInvite): Promise<void> {
  const tenantKey = currentConsoleTenantKey();
  if (!tenantKey) return;
  await registerTenantRoute("console", "invite", inv.token, tenantKey, inv.expiresAt);
}

function upsertInviteCounterparty(kind: "contractor" | "customer", name: string, handle?: string): Counterparty {
  let cp = db.counterparties.find((c) => c.name.toLowerCase() === name.toLowerCase() && c.type === kind);
  if (!cp) {
    cp = { id: id("cp"), orgId: db.org.id, name, type: kind, status: "pending_screening", externalAccounts: [], createdAt: now() };
    db.counterparties.push(cp);
  }
  if (handle) applyCounterpartyHandle(cp, handle);
  return cp;
}

route("GET", "/api/invites", (_req, res) => json(res, 200, db.invites));
route("POST", "/api/invites", async (req, res) => {
  const body = await readJson<{ kind?: OrgInvite["kind"]; name?: string; email?: string; role?: string; handle?: string }>(req);
  const checked = validateInviteInput(body);
  if (!checked.ok) return json(res, 400, { error: checked.error });
  const { kind, name, email, handle, role } = checked.value;
  let counterpartyId: string | undefined;
  if (kind === "contractor" || kind === "customer") counterpartyId = upsertInviteCounterparty(kind, name!, handle).id;
  if (kind === "member") {
    db.members.push({ id: id("mem"), orgId: db.org.id, email: email!, role: role as Member["role"], status: "invited", createdAt: now() });
  }
  const inv = makeInvite(kind, { name, email, role, counterpartyId });
  db.invites.push(inv);
  await registerInviteRoute(inv);
  appendPrivateEvent("invite.created", inv.id, "invite.v1", { invite: inv, createdAt: inv.createdAt }, { status: inv.status, kind: inv.kind, source: "invites" });
  json(res, 201, inv);
});
/** Bulk contractor invites from a CSV (name,handle,rate) — one business-scoped link each. */
route("POST", "/api/invites/bulk", async (req, res) => {
  const body = await readJson<{ csv: string }>(req);
  if (!body.csv) return json(res, 400, { error: "csv required" });
  const { rows, errors } = parseRosterCsv(body.csv);
  const created: OrgInvite[] = [];
  for (const r of rows) {
    const cp = upsertInviteCounterparty("contractor", r.name, r.handle);
    if (r.rate && BigInt(r.rate) > 0n) {
      cp.payRate = { amount: r.rate, assetCode: "USDC" };
      cp.payCadence = "monthly";
    }
    const inv = makeInvite("contractor", { name: r.name, counterpartyId: cp.id });
    db.invites.push(inv);
    await registerInviteRoute(inv);
    created.push(inv);
  }
  appendPrivateEvent("invite.created", id("bulk"), "invite.bulk.v1", { invites: created, errors, createdAt: now() }, { status: "sent", kind: "contractor", source: "invites", itemCount: created.length });
  json(res, 200, { created: created.length, errors, invites: created });
});
route("POST", "/api/invites/:id/revoke", (_req, res, p) => {
  const inv = db.invites.find((x) => x.id === p.id);
  if (!inv) return json(res, 404, { error: "not found" });
  inv.status = "revoked";
  appendPrivateEvent("invite.revoked", inv.id, "invite.v1", { invite: inv, revokedAt: now() }, { status: inv.status, kind: inv.kind, source: "invites" });
  json(res, 200, inv);
});
/** Accept an invite by token (the contractor/employee onboarding handshake). */
route("POST", "/api/invites/accept", async (req, res) => {
  const body = await readJson<{ token: string; handle?: string; counterpartyId?: string; kind?: OrgInvite["kind"]; orgId?: string; name?: string }>(req);
  const inv = db.invites.find((x) => x.token === body.token);
  if (!inv) {
    if (!body.counterpartyId || (body.kind !== "contractor" && body.kind !== "customer")) {
      return json(res, 404, { error: "invite not found or expired" });
    }
    const cp = db.counterparties.find((c) => c.id === body.counterpartyId);
    if (cp && body.handle) {
      applyCounterpartyHandle(cp, body.handle);
      cp.status = "allowlisted";
    }
    appendPrivateEvent("invite.accepted", body.counterpartyId, "invite.accept.v1", { request: body, acceptedAt: now() }, { status: "accepted", kind: body.kind, source: "invites" });
    return json(res, 200, { ok: true, orgName: db.org.name, kind: body.kind, counterpartyId: body.counterpartyId, orgId: body.orgId ?? db.org.id });
  }
  if (inv.status === "revoked") return json(res, 400, { error: "invite was revoked" });
  inv.status = "accepted";
  activateAcceptedMemberInvite(inv, body.name);
  // a contractor accepting from the wallet hands over their @handle for settlement
  if (inv.counterpartyId && body.handle) {
    const cp = db.counterparties.find((c) => c.id === inv.counterpartyId);
    if (cp) {
      applyCounterpartyHandle(cp, body.handle);
      cp.status = "allowlisted";
    }
  }
  appendPrivateEvent("invite.accepted", inv.id, "invite.accept.v1", { invite: inv, request: body, acceptedAt: now() }, { status: inv.status, kind: inv.kind, source: "invites" });
  json(res, 200, { ok: true, orgName: db.org.name, kind: inv.kind, counterpartyId: inv.counterpartyId, orgId: db.org.id });
});

function inviteCounterparty(): { ok: true; counterpartyId: string } | { ok: false; error: string } | null {
  const token = currentInviteRouteToken();
  if (!token) return null;
  const inv = db.invites.find((x) => x.token === token);
  if (!inv || inv.status === "revoked") return { ok: false, error: "invite not found or expired" };
  if (!inv.counterpartyId || (inv.kind !== "contractor" && inv.kind !== "customer")) {
    return { ok: false, error: "invite cannot submit invoices" };
  }
  return { ok: true, counterpartyId: inv.counterpartyId };
}

route("GET", "/api/invoices", (_req, res) => {
  const scoped = inviteCounterparty();
  if (scoped && !scoped.ok) return json(res, 403, { error: scoped.error });
  const rows = scoped?.ok ? db.invoices.filter((i) => i.counterpartyId === scoped.counterpartyId) : db.invoices;
  json(res, 200, rows);
});
route("POST", "/api/invoices", async (req, res) => {
  const body = await readJson<CreateInvoiceRequest & { inviteToken?: string }>(req);
  const scoped = inviteCounterparty();
  if (scoped && !scoped.ok) return json(res, 403, { error: scoped.error });
  if (scoped?.ok && body.counterpartyId && body.counterpartyId !== scoped.counterpartyId) {
    return json(res, 403, { error: "invite cannot bill this counterparty" });
  }
  if (scoped?.ok) body.counterpartyId = scoped.counterpartyId;
  if (body.externalId) {
    const existing = db.invoices.find((x) => x.externalId === body.externalId);
    if (existing) return json(res, 200, existing);
  }
  if (!body.counterpartyId) return json(res, 400, { error: "counterpartyId required" });
  if (!Array.isArray(body.lineItems) || body.lineItems.length === 0) return json(res, 400, { error: "invoice must include at least one line item" });
  let cp = db.counterparties.find((c) => c.id === body.counterpartyId);
  if (!cp && body.counterpartyName) {
    cp = { id: body.counterpartyId, orgId: db.org.id, name: body.counterpartyName, type: "contractor", status: "pending_screening", externalAccounts: [], createdAt: now() };
    db.counterparties.push(cp);
  }
  if (!cp) return json(res, 404, { error: "counterparty not found" });
  if (body.handle) {
    applyCounterpartyHandle(cp, body.handle);
    cp.status = "allowlisted";
  }
  const total = body.lineItems.reduce((s, li) => s + BigInt(li.unitAmount) * BigInt(li.quantity), 0n);
  if (total <= 0n) return json(res, 400, { error: "invoice total must be positive" });
  const inv = {
    id: id("inv"), orgId: db.org.id, number: body.number ?? `INV-${db.invoices.length + 1001}`,
    counterpartyId: body.counterpartyId, lineItems: body.lineItems,
    total: { amount: total.toString(), assetCode: body.assetCode }, status: "open" as const,
    dueDate: body.dueDate, hostedUrl: `https://pay.benzo.test/i/${id("secret")}`, paymentOrderIds: [], externalId: body.externalId, createdAt: now(),
  };
  db.invoices.push(inv);
  appendPrivateEvent(
    "invoice.created",
    inv.id,
    "invoice.v1",
    { invoice: inv, createdAt: inv.createdAt },
    { status: inv.status, itemCount: inv.lineItems.length, source: "console" },
  );
  json(res, 201, inv);
});

/** Invoice-to-pay (AP, the 2nd front-door): pay a contractor-submitted invoice through the
 *  SAME maker-checker + settlement engine as a payroll run. Over-threshold → Approvals first. */
route("POST", "/api/invoices/:id/pay", async (_req, res, pp) => {
  const inv = db.invoices.find((x) => x.id === pp.id);
  if (!inv) return json(res, 404, { error: "not found" });
  if (inv.status === "paid") return json(res, 400, { error: "invoice already paid" });
  const policy = matchPolicy(BigInt(inv.total.amount));
  const po: PaymentOrder = {
    id: id("po"), orgId: db.org.id, type: "invoice_payment", status: policy ? "needs_approval" : "approved",
    amount: inv.total, fromAccountId: "acc_op", toCounterpartyId: inv.counterpartyId,
    memo: `Pay ${inv.number}`, ref: inv.id, approvalPolicyId: policy?.id, approvals: [],
    privacy: { amountHidden: true, counterpartyHidden: true, visibleTo: [db.sessionMemberId] },
    settlement: {}, createdByMemberId: db.sessionMemberId, createdAt: now(), updatedAt: now(),
  };
  const payee = db.counterparties.find((c) => c.id === inv.counterpartyId);
  const h = payee?.paymentAddress?.shielded;
  if (!policy) await submitShieldedTransfer(po, h); // under threshold → settle now
  db.payments.push(po);
  inv.paymentOrderIds = [...(inv.paymentOrderIds ?? []), po.id];
  if (po.settlement?.onChain) inv.status = "paid";
  appendPrivateEvent(
    "payment.submitted",
    po.id,
    "payment.order.v1",
    { invoice: inv, payment: po, toHandle: h, requestedAt: po.createdAt },
    { status: po.status, kind: po.type, source: "invoice" },
  );
  if (inv.status === "paid") {
    appendPrivateEvent(
      "invoice.paid",
      inv.id,
      "invoice.v1",
      { invoice: inv, payment: po, paidAt: now() },
      { status: inv.status, source: "invoice" },
    );
  }
  if (po.settlement?.onChain || po.settlement?.txHash) {
    appendPrivateEvent(
      "payment.settled",
      po.settlement.txHash ?? po.id,
      "payment.settled.v1",
      { invoice: inv, payment: po, settlement: po.settlement, settledAt: now() },
      { status: po.status, source: "invoice", live: Boolean(po.settlement.onChain) },
    );
  }
  json(res, 201, { invoice: inv, payment: po });
});

route("GET", "/api/payrolls", (_req, res) => json(res, 200, db.payrolls));
route("POST", "/api/payrolls", async (req, res) => {
  const body = await readJson<CreatePayrollRequest>(req);
  // COMPUTE the run from each contractor's stored rate card (server-side).
  const { lines, total, handles } = assemblePayroll(body.lines);
  // Maker-checker: a run over the policy threshold needs approval before it can settle.
  const policy = matchPolicy(BigInt(total));
  const batch = {
    id: id("pr"), orgId: db.org.id, period: body.period, source: body.source,
    status: (policy ? "needs_approval" : "approved") as "needs_approval" | "approved",
    lines, total: { amount: total, assetCode: "USDC" }, approvals: [], scheduledAt: body.scheduledAt, createdAt: now(),
  };
  db.payrolls.push(batch);
  appendPrivateEvent(
    "payroll.computed",
    batch.id,
    "payroll.batch.v1",
    { batch, handles, computedAt: batch.createdAt },
    { status: batch.status, source: batch.source, itemCount: batch.lines.length },
  );
  json(res, 201, batch);
});

/** Import a contractor roster CSV (name,handle,rate): upserts the rate cards + returns row errors. */
route("POST", "/api/payrolls/import", async (req, res) => {
  const body = await readJson<{ csv: string }>(req);
  if (!body.csv) return json(res, 400, { error: "csv required" });
  const { rows, errors } = parseRosterCsv(body.csv);
  const imported: Counterparty[] = [];
  for (const r of rows) {
    let cp = db.counterparties.find((c) => c.name.toLowerCase() === r.name.toLowerCase());
    if (cp) {
      cp.payRate = { amount: r.rate, assetCode: "USDC" };
      cp.payCadence = "monthly";
    } else {
      cp = {
        id: id("cp"), orgId: db.org.id, name: r.name, type: "contractor", status: "pending_screening",
        externalAccounts: [], payRate: { amount: r.rate, assetCode: "USDC" }, payCadence: "monthly", createdAt: now(),
      };
      db.counterparties.push(cp);
    }
    if (r.handle) applyCounterpartyHandle(cp, r.handle);
    imported.push(cp);
  }
  appendPrivateEvent("roster.imported", id("roster"), "contractor-roster.v1", { rows, errors, imported, importedAt: now() }, { status: errors.length ? "partial" : "imported", source: "contractors", itemCount: imported.length });
  json(res, 200, { imported: imported.length, errors, contractors: db.counterparties.filter((c) => c.type === "contractor") });
});

/** Roster rate-card / status / handle management (the Contractors screen). */
route("PATCH", "/api/counterparties/:id", async (req, res, p) => {
  const cp = db.counterparties.find((c) => c.id === p.id);
  if (!cp) return json(res, 404, { error: "not found" });
  const body = await readJson<{ payRate?: string; status?: Counterparty["status"]; handle?: string; name?: string }>(req);
  if (body.payRate !== undefined) {
    cp.payRate = { amount: body.payRate, assetCode: "USDC" };
    cp.payCadence = "monthly";
  }
  if (body.status) cp.status = body.status;
  if (body.name) cp.name = body.name;
  if (body.handle) applyCounterpartyHandle(cp, body.handle);
  appendPrivateEvent("counterparty.updated", cp.id, "counterparty.v1", { counterparty: cp, update: body, updatedAt: now() }, { status: cp.status, kind: cp.type, source: "counterparties" });
  json(res, 200, cp);
});
route("POST", "/api/payrolls/:id/approve", async (req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const body = await readJson<{ decision?: "approved" | "denied"; actorMemberId?: string; comment?: string }>(req);
  const policy = matchPolicy(BigInt(batch.total.amount));
  batch.approvals = batch.approvals ?? [];
  if (body.decision === "denied") {
    recordApproval({ policy, approvals: batch.approvals, proposerId: db.sessionMemberId, actorMemberId: body.actorMemberId, decision: "denied", payrollBatchId: batch.id });
    batch.status = "cancelled";
    appendPrivateEvent("approval.recorded", batch.id, "approval.v1", { batch, decision: "denied", actorMemberId: body.actorMemberId, comment: body.comment, recordedAt: now() }, { status: batch.status, source: "payroll" });
    return json(res, 200, { ...batch, progress: progress(policy, batch.approvals) });
  }
  // Record ONE approval against the next unsatisfied step (segregation of duties enforced).
  const r = recordApproval({ policy, approvals: batch.approvals, proposerId: db.sessionMemberId, actorMemberId: body.actorMemberId, decision: "approved", comment: body.comment, payrollBatchId: batch.id });
  if (r.error) return json(res, 400, { error: r.error });
  if (!r.progress.satisfied) {
    batch.status = "needs_approval"; // more approvals required before release
    appendPrivateEvent("approval.recorded", batch.id, "approval.v1", { batch, decision: "approved", actorMemberId: body.actorMemberId, comment: body.comment, progress: r.progress, recordedAt: now() }, { status: batch.status, source: "payroll" });
    return json(res, 200, { ...batch, progress: r.progress });
  }
  await settlePayroll(batch); // fully approved → idempotent, funded, resumable settlement
  appendPrivateEvent("approval.recorded", batch.id, "approval.v1", { batch, decision: "approved", actorMemberId: body.actorMemberId, comment: body.comment, progress: r.progress, recordedAt: now() }, { status: batch.status, source: "payroll" });
  json(res, 200, { ...batch, progress: r.progress });
});

/**
 * "Payroll funded ✓" — prove ON-CHAIN (vk_id ORGBAL) that the treasury covers
 * this run's TOTAL before approving, revealing neither figure. Lets the UI show
 * a real (not asserted) funded badge on the run before anyone clicks Approve.
 */
route("POST", "/api/payrolls/:id/prove-funded", async (_req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const runTotal = batch.lines
    .filter((l) => !l.onChain && BigInt(l.amount || "0") > 0n)
    .reduce((s, l) => s + BigInt(l.amount), 0n);
  const f = await proveFunded(runTotal.toString());
  batch.fundedProof = { funded: f.funded, onChain: f.onChain, provenAt: now() };
  recordProofReceipt("payroll.run-funded", f.ref);
  json(res, 200, { runTotal: runTotal.toString(), ...batch.fundedProof, ref: f.ref });
});

/**
 * Compliance pre-flight (Z3 + Z4) — for EACH line of a run, prove ON-CHAIN, with
 * amounts and recipients hidden:
 *   • within cap   (vk_id SPENDCAP) — amount ≤ approved per-payout cap
 *   • not sanctioned (vk_id POIPAYOUT) — recipient ∉ the deny set
 * Either failing comes back as a cryptographic "no" (provably blocked).
 */
route("POST", "/api/payrolls/:id/prove-policy", async (req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const body = await readJson<{ cap: string }>(req);
  const capStroops = BigInt(Math.round(Number(body.cap) * 1e7)).toString();
  for (let i = 0; i < batch.lines.length; i++) {
    const l = batch.lines[i];
    const handle = payrollLineHandle(l);
    if (!handle || BigInt(l.amount || "0") <= 0n) {
      l.capProof = { withinCap: false, onChain: false };
      l.screenProof = { innocent: false, onChain: false };
      continue;
    }
    const cap = await proveLineCap(handle, l.amount, capStroops, BigInt(i + 1));
    l.capProof = { withinCap: cap.withinCap, onChain: cap.onChain };
    const screen = await proveLineInnocence(handle, l.amount, BigInt(1000 + i));
    l.screenProof = { innocent: screen.innocent, onChain: screen.onChain };
    recordProofReceiptParts("payroll.run-policy.cap", { vkId: "SPENDCAP", verified: cap.withinCap && cap.onChain });
    recordProofReceiptParts("payroll.run-policy.screen", { vkId: "POIPAYOUT", verified: screen.innocent && screen.onChain });
  }
  json(res, 200, {
    cap: body.cap,
    lines: batch.lines.map((l) => ({ counterpartyId: l.counterpartyId, capProof: l.capProof, screenProof: l.screenProof })),
  });
});

/**
 * Anonymous approver / surveillance-free dual-control (Z5) — prove >= threshold
 * DISTINCT approvers signed this run on-chain (vk_id ORGAUTH), WITHOUT revealing
 * which. Surfaces a "approved M-of-N, members anonymous" badge on the run.
 */
route("POST", "/api/payrolls/:id/prove-approval", async (_req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const { ref, ...r } = await proveAnonymousApproval(batch.id);
  batch.approvalProof = { ...r, provenAt: now() };
  recordProofReceipt("payroll.run-approval", ref);
  json(res, 200, { ...batch.approvalProof, ref });
});

/**
 * Verifiable payroll computation (Z6) — prove the run total + per-line
 * commitments were derived from the rate card (rate×period−deductions) on-chain
 * (vk_id PAYCOMP), rate card private. Computed-not-asserted.
 */
route("POST", "/api/payrolls/:id/prove-computation", async (_req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const lines = batch.lines.map((l) => ({ handle: payrollLineHandle(l), amount: l.amount }));
  const r = await proveRunComputation(lines);
  batch.computationProof = { ok: r.ok, onChain: r.onChain, runTotal: r.runTotal, provenAt: now() };
  recordProofReceipt("payroll.run-computation", r.ref);
  json(res, 200, { ...batch.computationProof, ref: r.ref });
});

/** Payroll register as a downloadable CSV (the CFO/accountant record + GL feed). */
route("GET", "/api/payrolls/:id/export", (_req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const rows = [["Period", "Contractor", "Gross USDC", "Status", "TxHash"]];
  for (const l of batch.lines) {
    const cp = db.counterparties.find((c) => c.id === l.counterpartyId);
    rows.push([batch.period, cp?.name ?? l.counterpartyId, (Number(l.amount) / 1e7).toFixed(2), l.status + (l.error ? ` (${l.error})` : ""), l.txHash ?? ""]);
  }
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  cors(res);
  res.writeHead(200, { "content-type": "text/csv", "content-disposition": `attachment; filename="payroll-${batch.period}.csv"` });
  res.end(csv);
});

/** Per-contractor payslips for a run (employer-generated; amounts stay hidden on-chain). */
route("GET", "/api/payrolls/:id/payslips", (_req, res, p) => {
  const batch = db.payrolls.find((x) => x.id === p.id);
  if (!batch) return json(res, 404, { error: "not found" });
  const slips = batch.lines.map((l) => {
    const cp = db.counterparties.find((c) => c.id === l.counterpartyId);
    return { period: batch.period, contractor: cp?.name ?? l.counterpartyId, gross: l.amount, status: l.status, txHash: l.txHash, error: l.error };
  });
  json(res, 200, slips);
});

/** Employer-visible pay history for one contractor across all runs ("when were they paid?"). */
route("GET", "/api/contractors/:id/history", (_req, res, p) => {
  const history: Array<{ period: string; amount: string; status: string; txHash?: string; batchId: string }> = [];
  for (const b of db.payrolls) {
    for (const l of b.lines) {
      if (l.counterpartyId === p.id) history.push({ period: b.period, amount: l.amount, status: l.status, txHash: l.txHash, batchId: b.id });
    }
  }
  json(res, 200, history);
});

route("GET", "/api/policies", (_req, res) => json(res, 200, db.policies));
route("POST", "/api/policies", async (req, res) => {
  const body = await readJson<{ name: string; policy: Record<string, unknown> }>(req);
  const policy = { id: id("pol"), orgId: db.org.id, createdAt: now(), name: body.name, ...(body.policy as object) } as (typeof db.policies)[number];
  db.policies.push(policy);
  appendPrivateEvent("policy.created", policy.id, "approval-policy.v1", { policy, createdAt: policy.createdAt }, { source: "policies" });
  json(res, 201, policy);
});
route("PATCH", "/api/policies/:id", async (req, res, p) => {
  const body = await readJson<Record<string, unknown>>(req);
  const pol = db.policies.find((x) => x.id === p.id);
  if (!pol) return json(res, 404, { error: "policy not found" });
  if (typeof body.name === "string") pol.name = body.name;
  if (Array.isArray(body.conditions)) pol.conditions = body.conditions as typeof pol.conditions;
  if (Array.isArray(body.steps)) pol.steps = body.steps as typeof pol.steps;
  if ("releaseGate" in body) pol.releaseGate = body.releaseGate as typeof pol.releaseGate;
  appendPrivateEvent("policy.updated", pol.id, "approval-policy.v1", { policy: pol, update: body, updatedAt: now() }, { source: "policies" });
  json(res, 200, pol);
});

route("GET", "/api/grants", (_req, res) => json(res, 200, db.grants));
route("POST", "/api/grants", async (req, res) => {
  const body = await readJson<CreateViewingGrantRequest>(req);
  const validation = validateGrantInput(body);
  if (!validation.ok) return json(res, 400, { error: validation.error });
  const grantRequest = validation.value;
  // Real scoped viewing key (one-way TVK derived from the org MVK + scope) —
  // decrypt-only, never a signer. Not a random hash.
  const vk = auditorGrantViewKey(grantRequest.scope.label || grantRequest.tier);
  const grant = {
    id: id("vg"), orgId: db.org.id, auditorName: grantRequest.auditorName, auditorPubKey: grantRequest.auditorPubKey,
    tier: grantRequest.tier, scope: grantRequest.scope,
    onChainKeyHash: vk.viewKey ? vk.viewKey.slice(0, 24) : undefined,
    viewKey: vk.viewKey || undefined, live: vk.live, expiry: grantRequest.expiry,
    status: "active" as const, createdAt: now(),
  };
  db.grants.push(grant);
  appendPrivateEvent(
    "grant.created",
    grant.id,
    "viewing-grant.v1",
    { grant, createdAt: grant.createdAt },
    { status: grant.status, tier: grant.tier, source: "audit" },
  );
  json(res, 201, grant);
});
route("POST", "/api/grants/:id/revoke", (_req, res, p) => {
  const grant = db.grants.find((x) => x.id === p.id);
  if (!grant) return json(res, 404, { error: "not found" });
  grant.status = "revoked";
  appendPrivateEvent(
    "grant.revoked",
    grant.id,
    "viewing-grant.v1",
    { grant, revokedAt: now() },
    { status: grant.status, tier: grant.tier, source: "audit" },
  );
  json(res, 200, grant);
});

route("GET", "/api/compliance/zones", (_req, res) => json(res, 200, db.zones));
route("GET", "/api/ledger", (_req, res) => json(res, 200, db.ledger));
// Tamper-evidence: re-walk the audit hash-chain and report integrity.
route("GET", "/api/ledger/verify", (_req, res) => json(res, 200, verifyLedgerChain()));
route("GET", "/api/proof-receipts", (_req, res) =>
  json(res, 200, [...(db.proofReceipts ?? [])].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))),
);
route("GET", "/api/audit/private-events", (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const eventTypes = url.searchParams.get("eventTypes")?.split(",").filter(Boolean) as PrivateEventType[] | undefined;
  const scope = {
    label: url.searchParams.get("label") || "console-private-events",
    from: url.searchParams.get("from") || undefined,
    to: url.searchParams.get("to") || undefined,
    eventTypes,
  };
  const events = db.privateEvents;
  json(res, 200, {
    packet: buildAuditPacket({ orgId: privateAuditOrgId(), events, scope }),
    integrity: verifyHashChain(events),
    disclosure: "ciphertext-only; decrypt selected records with a scoped viewing key outside this API",
  });
});
route("POST", "/api/audit/private-events/anchor", async (req, res) => {
  const body = await readJson<{ packet?: AuditPacket; packetHash?: string; orgHash?: string }>(req);
  const events = db.privateEvents;
  const packet = body.packet ?? buildAuditPacket({ orgId: privateAuditOrgId(), events, scope: { label: "console-private-events" } });
  const packetHash = body.packet ? auditPacketHash(packet) : auditPacketHash(packet);
  const orgHash = body.orgHash ?? privateAuditOrgHash();
  if (body.packetHash && body.packetHash !== packetHash) return json(res, 400, { error: "packetHash does not match packet" });
  if (packet.anchor.eventCount === 0) {
    return json(res, 200, {
      packet,
      integrity: body.packet ? { ok: true, headHash: packet.anchor.headHash } : verifyHashChain(events),
      packetHash,
      orgHash,
      anchor: { onChain: false, error: "no private events to anchor" },
      disclosure: "only roots/hashes/event counts are submitted on-chain; records remain ciphertext",
    });
  }
  const anchored = await anchorPrivateAuditRoot({
    orgHash,
    merkleRoot: packet.anchor.merkleRoot,
    headHash: packet.anchor.headHash,
    packetHash,
    eventCount: packet.anchor.eventCount,
  });
  if (anchored.txHash) packet.anchor.txHash = anchored.txHash;
  json(res, 200, {
    packet,
    integrity: body.packet ? { ok: true, headHash: packet.anchor.headHash } : verifyHashChain(events),
    packetHash,
    orgHash,
    anchor: {
      ...anchored,
      explorer: stellarExpertTx(anchored.txHash),
    },
    disclosure: "only roots/hashes/event counts are submitted on-chain; records remain ciphertext",
  });
});
// The audit trail IS the tamper-evident double-entry ledger (hash-chained). Return
// the real entries + chain-integrity, plus the private-event anchor for encrypted facts.
route("GET", "/api/audit", (_req, res) => json(res, 200, { entries: db.ledger, integrity: verifyLedgerChain(), privateEvents: privateEventAuditSummary() }));

route("GET", "/api/integrations", (_req, res) => json(res, 200, db.integrations));
route("POST", "/api/integrations", async (req, res) => {
  const body = await readJson<ConnectIntegrationRequest>(req);
  // Accounting/HRIS connectors (QuickBooks/Xero/Slack) are not wired in this
  // build — be honest rather than fabricate a "connected" status. The real
  // export path is the on-chain-backed CSV/GL export + the tamper-evident ledger.
  const note = "Connector not configured in this build — use the CSV/GL export.";
  const existing = db.integrations.find((i) => i.provider === body.provider);
  if (existing) {
    existing.status = "disconnected";
    appendPrivateEvent("integration.changed", existing.id, "integration.v1", { integration: existing, request: body, changedAt: now() }, { status: existing.status, source: "integrations" });
    return json(res, 200, { ...existing, note });
  }
  const integration = { id: id("int"), orgId: db.org.id, provider: body.provider, status: "disconnected" as const, connectedAt: undefined };
  db.integrations.push(integration);
  appendPrivateEvent("integration.changed", integration.id, "integration.v1", { integration, request: body, changedAt: now() }, { status: integration.status, source: "integrations" });
  json(res, 201, { ...integration, note });
});

// --------------------------------------------------------------------- server
export async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const rpcPath = url.pathname === "/api/rpc" ? url.searchParams.get("path") : null;
  const effectiveUrl = rpcPath?.startsWith("/") && !rpcPath.startsWith("//")
    ? new URL(`/api${rpcPath}`, `http://localhost:${PORT}`)
    : url;
  if (req.method === "OPTIONS") {
    cors(res);
    res.writeHead(204);
    res.end();
    return;
  }
  try {
    const m = match(req.method ?? "GET", effectiveUrl.pathname);
    if (!m) return json(res, 404, { error: "not found" });
    const routeToken = hostedRuntime() ? await inviteRouteToken(req, effectiveUrl.pathname) : null;
    const routeTenantKey = routeToken ? await lookupTenantRoute("console", "invite", routeToken) : null;
    if (
      hostedRuntime() &&
      (effectiveUrl.pathname === "/api/invites/accept" || (effectiveUrl.pathname === "/api/invoices" && routeToken)) &&
      !routeTenantKey
    ) {
      return json(res, 404, { error: "invite not found or expired" });
    }
    const publicHosted =
      effectiveUrl.pathname === "/api/live" ||
      effectiveUrl.pathname === "/api/auth/config" ||
      effectiveUrl.pathname === "/api/auth/google" ||
      effectiveUrl.pathname === "/api/auth/test" ||
      effectiveUrl.pathname === "/api/auth/local" ||
      Boolean(routeTenantKey);
    let auth: Awaited<ReturnType<typeof authFromRequest>> = null;
    if (hostedRuntime()) {
      try {
        auth = await authFromRequest(req);
      } catch (e) {
        return json(res, 401, { error: (e as Error).message, live: false, mode: "unavailable", missing: [] });
      }
      if (!auth && effectiveUrl.pathname.startsWith("/api/") && !publicHosted) {
        return json(res, 401, { error: "Sign in with Google to unlock this console.", live: false, mode: "unavailable", missing: [] });
      }
    }
    if (requiresIdempotency(req.method ?? "GET", effectiveUrl.pathname) && !idempotencyHeader(req)) {
      return json(res, 428, { error: "Idempotency-Key header is required for hosted console writes." });
    }
    await runWithAuth(auth, async () => {
      const persistTenant = !["GET", "HEAD", "OPTIONS"].includes((req.method ?? "GET").toUpperCase());
      const runTenant = routeTenantKey
        ? (fn: () => Promise<void>) => runWithConsoleTenantKey(routeTenantKey, fn, { persist: persistTenant })
        : (fn: () => Promise<void>) => runWithConsoleTenant(auth?.key ?? null, auth?.claims ?? null, auth ? accountBinding(auth) : null, fn, { persist: persistTenant });
      await runTenant(async () => {
        if (effectiveUrl.pathname.startsWith("/api/") && !publicHosted && (!isLive() || tenantDataMissing().length > 0)) {
          return json(res, 503, {
            error: "Live testnet client unavailable. Refusing to serve app data.",
            ...appLiveStatus(),
          });
        }
        if (effectiveUrl.pathname.startsWith("/api/") && !publicHosted) {
          const rl = await rateLimit(effectiveUrl.pathname, req.method ?? "GET");
          if (!rl.ok) return json(res, 429, { error: "Too many requests. Please wait a moment and try again.", retryAfter: rl.retryAfter });
        }
        const invoke = () => runIdempotent(req, res, effectiveUrl.pathname, () => Promise.resolve(m.handler(req, res, m.params)));
        if (routeToken) await inviteRouteScope.run({ token: routeToken }, invoke);
        else await invoke();
      });
    });
  } catch (e) {
    console.error("[benzo-console-api] route failed", {
      method: req.method,
      path: req.url,
      error: e instanceof Error ? e.message : String(e),
      stack: e instanceof Error ? e.stack : undefined,
    });
    if (e instanceof RecoveryRequiredError) {
      return json(res, 409, {
        error: e.message,
        code: e.code,
        recovery: {
          status: "required",
          reason: e.code,
        },
      });
    }
    json(res, 500, { error: "Server unavailable. Please try again.", live: false, mode: "unavailable" });
  }
}

export default handle;

sealSeedLedger(); // bring pre-existing ledger entries into the audit chain as genesis
const server = createServer(handle);
if (!serverlessRuntime()) server.listen(PORT, () => {
  const s = liveStatus();
  console.error(`[benzo-console-api] listening on :${PORT}`);
  if (s.live) {
    console.error("[benzo-console-api] MODE=LIVE — serving REAL on-chain data via @benzo/core (testnet).");
  } else {
    console.error(
      `[benzo-console-api] MODE=UNAVAILABLE — refusing app data. ` +
        `Missing: ${s.missing.join(", ") || "(client init failed — see logs)"}. ` +
        `To go live: set -a; . ./.env; set +a; then restart.`,
    );
  }
});
