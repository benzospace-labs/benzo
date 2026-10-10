import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { neon, type NeonQueryFunction } from "@neondatabase/serverless";
import { hostedRuntime } from "./runtime.js";

let sqlClient: NeonQueryFunction<false, false> | null | undefined;
let schemaReady: Promise<void> | null = null;
const memoryDocuments = new Map<string, string>();
const memoryRoutes = new Map<string, { tenantKey: string; expiresAt?: number }>();
const memoryRateLimits = new Map<string, { windowStart: number; count: number }>();

function useMemoryStore(): boolean {
  if (hostedRuntime() && process.env.BENZO_TENANT_STORE_MEMORY === "1") {
    throw new Error("BENZO_TENANT_STORE_MEMORY is not allowed for hosted tenant storage");
  }
  if (hostedRuntime() && process.env.BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE === "1") {
    throw new Error("BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE is not allowed for hosted tenant storage");
  }
  return process.env.BENZO_TENANT_STORE_MEMORY === "1";
}

function encryptionSecret(): string | null {
  const secret = process.env.BENZO_DATA_ENCRYPTION_SECRET;
  if (!secret && hostedRuntime()) throw new Error("BENZO_DATA_ENCRYPTION_SECRET is required for hosted tenant storage");
  return secret || null;
}

function sql(): NeonQueryFunction<false, false> | null {
  if (sqlClient !== undefined) return sqlClient;
  const url = process.env.DATABASE_URL;
  if (!url) {
    if (hostedRuntime()) throw new Error("DATABASE_URL is required for hosted tenant storage");
    sqlClient = null;
    return null;
  }
  sqlClient = neon(url);
  return sqlClient;
}

// Retention horizon for request rate limits (default: 7 days).
// Rows with window_start older than the horizon are pruned opportunistically
// on schema bootstrap and via pruneExpiredRequestLimits().
export const REQUEST_LIMIT_RETENTION_SECONDS = 7 * 24 * 60 * 60; // 7 days

export function getRequestLimitRetentionSeconds(): number {
  const envVal = process.env.BENZO_REQUEST_LIMIT_RETENTION_SECONDS;
  if (envVal) {
    const parsed = Number(envVal);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return REQUEST_LIMIT_RETENTION_SECONDS;
}

async function pruneExpiredRequestLimitsOnDb(
  db: NeonQueryFunction<false, false>,
  cutoffSec: number = Math.floor(Date.now() / 1000) - Math.max(getRequestLimitRetentionSeconds(), 60),
): Promise<number> {
  const rows = await db`
    delete from benzo_request_limits
    where window_start < ${cutoffSec}
    returning 1
  `;
  return rows.length;
}

async function ensureSchema(): Promise<void> {
  const db = sql();
  if (!db) return;
  schemaReady ??= (async () => {
    await db`
      create table if not exists benzo_tenant_documents (
        app text not null,
        tenant_key text not null,
        version integer not null default 1,
        ciphertext text not null,
        updated_at timestamptz not null default now(),
        primary key (app, tenant_key)
      )
    `;
    await db`
      create table if not exists benzo_tenant_routes (
        app text not null,
        route_type text not null,
        route_hash text not null,
        tenant_key text not null,
        expires_at bigint,
        created_at timestamptz not null default now(),
        primary key (app, route_type, route_hash)
      )
    `;
    await db`
      create table if not exists benzo_request_limits (
        app text not null,
        tenant_key text not null,
        bucket text not null,
        window_start bigint not null,
        count integer not null,
        updated_at timestamptz not null default now(),
        primary key (app, tenant_key, bucket)
      )
    `;
    await db`
      create index if not exists benzo_request_limits_window_start_idx
      on benzo_request_limits (window_start)
    `;
    await pruneExpiredRequestLimitsOnDb(db).catch(() => 0);
  })();
  await schemaReady;
}

function key(): Buffer {
  const secret = encryptionSecret();
  if (!secret) throw new Error("tenant storage encryption unavailable");
  return createHash("sha256").update(secret).digest();
}

function tenantAad(app: string, tenantKey: string): Buffer {
  return Buffer.from(`benzo:tenant-doc:v1:${app}:${tenantKey}`, "utf8");
}

function encrypt(app: string, tenantKey: string, value: unknown): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(tenantAad(app, tenantKey));
  const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, body]).toString("base64url");
}

function decryptBound<T>(app: string, tenantKey: string, ciphertext: string): T {
  const raw = Buffer.from(ciphertext, "base64url");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const body = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key(), iv);
  decipher.setAAD(tenantAad(app, tenantKey));
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8")) as T;
}

function decryptLegacy<T>(ciphertext: string): T {
  const raw = Buffer.from(ciphertext, "base64url");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const body = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key(), iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8")) as T;
}

function decrypt<T>(app: string, tenantKey: string, ciphertext: string): T {
  try {
    return decryptBound<T>(app, tenantKey, ciphertext);
  } catch (error) {
    if (process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT === "1") throw error;
    return decryptLegacy<T>(ciphertext);
  }
}

export function tenantStorageMissing(): string[] {
  const missing: string[] = [];
  if (hostedRuntime()) {
    if (process.env.BENZO_TENANT_STORE_MEMORY === "1") missing.push("BENZO_TENANT_STORE_MEMORY");
    if (process.env.BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE === "1") missing.push("BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE");
    if (!process.env.DATABASE_URL) missing.push("DATABASE_URL");
    if (!process.env.BENZO_DATA_ENCRYPTION_SECRET) missing.push("BENZO_DATA_ENCRYPTION_SECRET");
  }
  return missing;
}

export function tenantStorageStatus(): { hosted: boolean; durable: boolean; provider: "memory" | "neon" | "postgres" | "none" } {
  if (process.env.BENZO_TENANT_STORE_MEMORY === "1") {
    return { hosted: hostedRuntime(), durable: false, provider: "memory" };
  }
  const url = process.env.DATABASE_URL;
  if (!url) return { hosted: hostedRuntime(), durable: false, provider: "none" };
  try {
    const host = new URL(url).hostname;
    return { hosted: hostedRuntime(), durable: true, provider: host.endsWith(".neon.tech") ? "neon" : "postgres" };
  } catch {
    return { hosted: hostedRuntime(), durable: true, provider: "postgres" };
  }
}

export async function loadTenantDocument<T>(app: string, tenantKey: string): Promise<T | null> {
  if (useMemoryStore()) {
    const ciphertext = memoryDocuments.get(`${app}:${tenantKey}`);
    return ciphertext ? decrypt<T>(app, tenantKey, ciphertext) : null;
  }
  await ensureSchema();
  const db = sql();
  if (!db) return null;
  const rows = await db`select ciphertext from benzo_tenant_documents where app = ${app} and tenant_key = ${tenantKey} limit 1`;
  const row = rows[0] as { ciphertext?: string } | undefined;
  return row?.ciphertext ? decrypt<T>(app, tenantKey, row.ciphertext) : null;
}

export async function saveTenantDocument(app: string, tenantKey: string, value: unknown): Promise<void> {
  if (useMemoryStore()) {
    memoryDocuments.set(`${app}:${tenantKey}`, encrypt(app, tenantKey, value));
    return;
  }
  await ensureSchema();
  const db = sql();
  if (!db) return;
  const ciphertext = encrypt(app, tenantKey, value);
  await db`
    insert into benzo_tenant_documents (app, tenant_key, ciphertext, updated_at)
    values (${app}, ${tenantKey}, ${ciphertext}, now())
    on conflict (app, tenant_key)
    do update set ciphertext = excluded.ciphertext, updated_at = now()
  `;
}

function routeHash(routeType: string, token: string): string {
  return createHash("sha256").update(`benzo:tenant-route:v1:${routeType}:${token}`).digest("hex");
}

function routeMemoryKey(app: string, routeType: string, token: string): string {
  return `${app}:${routeType}:${routeHash(routeType, token)}`;
}

export async function registerTenantRoute(app: string, routeType: string, token: string, tenantKey: string, expiresAt?: number): Promise<void> {
  if (!token || !tenantKey) return;
  if (useMemoryStore()) {
    memoryRoutes.set(routeMemoryKey(app, routeType, token), { tenantKey, expiresAt });
    return;
  }
  await ensureSchema();
  const db = sql();
  if (!db) return;
  const hash = routeHash(routeType, token);
  await db`
    insert into benzo_tenant_routes (app, route_type, route_hash, tenant_key, expires_at, created_at)
    values (${app}, ${routeType}, ${hash}, ${tenantKey}, ${expiresAt ?? null}, now())
    on conflict (app, route_type, route_hash)
    do update set tenant_key = excluded.tenant_key, expires_at = excluded.expires_at
  `;
}

export async function lookupTenantRoute(app: string, routeType: string, token: string): Promise<string | null> {
  if (!token) return null;
  const nowSec = Math.floor(Date.now() / 1000);
  if (useMemoryStore()) {
    const route = memoryRoutes.get(routeMemoryKey(app, routeType, token));
    if (!route) return null;
    if (route.expiresAt && route.expiresAt < nowSec) return null;
    return route.tenantKey;
  }
  await ensureSchema();
  const db = sql();
  if (!db) return null;
  const hash = routeHash(routeType, token);
  const rows = await db`
    select tenant_key, expires_at from benzo_tenant_routes
    where app = ${app} and route_type = ${routeType} and route_hash = ${hash}
    limit 1
  `;
  const row = rows[0] as { tenant_key?: string; expires_at?: string | number | null } | undefined;
  if (!row?.tenant_key) return null;
  const expiresAt = row.expires_at === null || row.expires_at === undefined ? null : Number(row.expires_at);
  if (expiresAt && expiresAt < nowSec) return null;
  return row.tenant_key;
}

export async function pruneExpiredRequestLimits(
  horizonOrOptions?: number | { horizonSeconds?: number; nowSec?: number },
  explicitNowSec?: number,
): Promise<number> {
  const horizonSeconds =
    typeof horizonOrOptions === "number"
      ? horizonOrOptions
      : (horizonOrOptions?.horizonSeconds ?? getRequestLimitRetentionSeconds());
  const nowSec =
    typeof horizonOrOptions === "object" && horizonOrOptions?.nowSec !== undefined
      ? horizonOrOptions.nowSec
      : (explicitNowSec ?? Math.floor(Date.now() / 1000));

  // The sweep must never delete rows for an active window.
  // Standard windows are up to 60 seconds, so safe horizon ensures cutoff is strictly before active windows.
  const safeHorizon = Math.max(horizonSeconds, 60);
  const cutoff = nowSec - safeHorizon;

  if (useMemoryStore()) {
    let pruned = 0;
    for (const [key, bucket] of memoryRateLimits.entries()) {
      if (bucket.windowStart < cutoff) {
        memoryRateLimits.delete(key);
        pruned++;
      }
    }
    return pruned;
  }
  await ensureSchema();
  const db = sql();
  if (!db) {
    let pruned = 0;
    for (const [key, bucket] of memoryRateLimits.entries()) {
      if (bucket.windowStart < cutoff) {
        memoryRateLimits.delete(key);
        pruned++;
      }
    }
    return pruned;
  }
  return pruneExpiredRequestLimitsOnDb(db, cutoff);
}

function currentWindow(nowSec: number, windowSeconds: number): number {
  return Math.floor(nowSec / windowSeconds) * windowSeconds;
}

function takeMemoryRateLimit(
  key: string,
  weight: number,
  limit: number,
  windowSeconds: number,
  nowSec: number = Math.floor(Date.now() / 1000),
): { ok: true } | { ok: false; retryAfter: number } {
  const now = nowSec;
  const windowStart = currentWindow(now, windowSeconds);
  const bucket = memoryRateLimits.get(key) ?? { windowStart, count: 0 };
  if (bucket.windowStart !== windowStart) {
    bucket.windowStart = windowStart;
    bucket.count = 0;
  }
  bucket.count += weight;
  memoryRateLimits.set(key, bucket);
  if (bucket.count > limit) return { ok: false, retryAfter: Math.max(1, windowSeconds - (now - windowStart)) };
  return { ok: true };
}

export async function takeTenantRateLimit(
  app: string,
  tenantKey: string,
  bucketName: string,
  weight: number,
  limit: number,
  windowSeconds: number,
  nowSec?: number,
): Promise<{ ok: true } | { ok: false; retryAfter: number }> {
  const key = `${app}:${tenantKey}:${bucketName}`;
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  if (useMemoryStore()) return takeMemoryRateLimit(key, weight, limit, windowSeconds, now);
  await ensureSchema();
  const db = sql();
  if (!db) return takeMemoryRateLimit(key, weight, limit, windowSeconds, now);
  const windowStart = currentWindow(now, windowSeconds);
  const rows = await db`
    insert into benzo_request_limits (app, tenant_key, bucket, window_start, count, updated_at)
    values (${app}, ${tenantKey}, ${bucketName}, ${windowStart}, ${weight}, now())
    on conflict (app, tenant_key, bucket)
    do update set
      window_start = case
        when benzo_request_limits.window_start = ${windowStart} then benzo_request_limits.window_start
        else ${windowStart}
      end,
      count = case
        when benzo_request_limits.window_start = ${windowStart} then benzo_request_limits.count + ${weight}
        else ${weight}
      end,
      updated_at = now()
    returning count
  `;
  const count = Number((rows[0] as { count?: number | string } | undefined)?.count ?? weight);
  if (count > limit) return { ok: false, retryAfter: Math.max(1, windowSeconds - (now - windowStart)) };
  return { ok: true };
}
