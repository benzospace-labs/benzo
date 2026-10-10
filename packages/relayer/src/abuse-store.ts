import { neon, type NeonQueryFunction } from "@neondatabase/serverless";

export interface CachedResponse {
  code: number;
  body: unknown;
  at: number;
}

export interface SweepOptions {
  now?: number;
  idempotencyTtlMs?: number;
  bucketHorizonMs?: number;
  dailyHorizonMs?: number;
  limit?: number;
}

export interface AbuseStoreOptions {
  sweepIntervalMs?: number;
  autoSweep?: boolean;
  sweepLimit?: number;
  idempotencyTtlMs?: number;
  bucketHorizonMs?: number;
  dailyHorizonMs?: number;
}

export interface RelayerAbuseStore {
  durable: boolean;
  allow(key: string, burst: number, perMin: number): Promise<boolean>;
  takeDaily(key: string, max: number): Promise<boolean>;
  idemGet(key: string, ttlMs: number): Promise<CachedResponse | undefined>;
  idemSet(key: string, value: CachedResponse): Promise<void>;
  sweep(options?: SweepOptions): Promise<number>;
  close?(): void;
}

export const DEFAULT_IDEMPOTENCY_TTL_MS = 60 * 60 * 1000; // 1h
export const DEFAULT_BUCKET_HORIZON_MS = 24 * 60 * 60 * 1000; // 24h
export const DEFAULT_DAILY_HORIZON_MS = 24 * 60 * 60 * 1000; // 24h
export const DEFAULT_SWEEP_LIMIT = 1000;
export const DEFAULT_SWEEP_INTERVAL_MS = 10 * 60 * 1000; // 10m

interface MemoryBucket {
  tokens: number;
  last: number;
}

interface MemoryDaily {
  count: number;
  last: number;
}

export class MemoryRelayerAbuseStore implements RelayerAbuseStore {
  readonly durable = false;
  private readonly buckets = new Map<string, MemoryBucket>();
  private readonly daily = new Map<string, MemoryDaily>();
  private readonly idempotency = new Map<string, CachedResponse>();
  private sweepTimer: NodeJS.Timeout | null = null;

  constructor(readonly options?: AbuseStoreOptions) {}

  async allow(key: string, burst: number, perMin: number): Promise<boolean> {
    const now = Date.now();
    const refillPerMs = perMin / 60_000;
    const b = this.buckets.get(key) ?? { tokens: burst, last: now };
    b.tokens = Math.min(burst, b.tokens + (now - b.last) * refillPerMs);
    b.last = now;
    if (b.tokens < 1) {
      this.buckets.set(key, b);
      return false;
    }
    b.tokens -= 1;
    this.buckets.set(key, b);
    return true;
  }

  async takeDaily(key: string, max: number): Promise<boolean> {
    const now = Date.now();
    const entry = this.daily.get(key) ?? { count: 0, last: now };
    if (entry.count >= max) return false;
    this.daily.set(key, { count: entry.count + 1, last: now });
    return true;
  }

  async idemGet(key: string, ttlMs: number): Promise<CachedResponse | undefined> {
    const c = this.idempotency.get(key);
    if (!c) return undefined;
    if (Date.now() - c.at > ttlMs) {
      this.idempotency.delete(key);
      return undefined;
    }
    return c;
  }

  async idemSet(key: string, value: CachedResponse): Promise<void> {
    this.idempotency.set(key, value);
  }

  async sweep(options?: SweepOptions): Promise<number> {
    const now = options?.now ?? Date.now();
    const idemTtl = options?.idempotencyTtlMs ?? this.options?.idempotencyTtlMs ?? DEFAULT_IDEMPOTENCY_TTL_MS;
    const bucketHorizon = options?.bucketHorizonMs ?? this.options?.bucketHorizonMs ?? DEFAULT_BUCKET_HORIZON_MS;
    const dailyHorizon = options?.dailyHorizonMs ?? this.options?.dailyHorizonMs ?? DEFAULT_DAILY_HORIZON_MS;
    const limit = options?.limit ?? this.options?.sweepLimit ?? DEFAULT_SWEEP_LIMIT;
    const today = new Date(now).toISOString().slice(0, 10);

    let deleted = 0;

    for (const [key, c] of this.idempotency.entries()) {
      if (deleted >= limit) break;
      if (now - c.at > idemTtl) {
        this.idempotency.delete(key);
        deleted++;
      }
    }

    for (const [key, b] of this.buckets.entries()) {
      if (deleted >= limit) break;
      if (now - b.last > bucketHorizon) {
        this.buckets.delete(key);
        deleted++;
      }
    }

    for (const [key, d] of this.daily.entries()) {
      if (deleted >= limit) break;
      if (key.includes(today)) continue;
      if (now - d.last > dailyHorizon) {
        this.daily.delete(key);
        deleted++;
      }
    }

    return deleted;
  }

  startSweepTimer(intervalMs: number): void {
    if (this.sweepTimer || intervalMs <= 0) return;
    this.sweepTimer = setInterval(() => {
      this.sweep().catch((err) => {
        console.error("[benzo-relayer] background memory abuse sweep failed:", err);
      });
    }, intervalMs);
    this.sweepTimer.unref();
  }

  close(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
  }
}

/**
 * Neon/Postgres durable store for relayer rate-limiting, daily counters, and idempotency.
 *
 * Retention management:
 * 1. Application-level background sweep: `sweep()` runs periodically on a timer (default 10m)
 *    or can be triggered on demand. It issues a bounded deletion pass (`LIMIT 1000`) selecting
 *    candidates via the composite index `(kind, last_ms)` to avoid lock contention.
 * 2. Database-level alternative via pg_cron: Operators who prefer the database to own retention
 *    can disable application sweeps (RELAYER_SWEEP_INTERVAL_MS=0) and schedule a pg_cron job:
 *
 *    SELECT cron.schedule(
 *      'sweep-benzo-relayer-abuse',
 *      '0-59/10 * * * *',
 *      $$
 *        WITH candidates AS (
 *          (
 *            SELECT kind, key FROM benzo_relayer_abuse
 *            WHERE kind = 'idempotency' AND last_ms < (EXTRACT(EPOCH FROM now()) * 1000 - 3600000)
 *            LIMIT 1000
 *          )
 *          UNION ALL
 *          (
 *            SELECT kind, key FROM benzo_relayer_abuse
 *            WHERE kind = 'bucket' AND last_ms < (EXTRACT(EPOCH FROM now()) * 1000 - 86400000)
 *            LIMIT 1000
 *          )
 *          UNION ALL
 *          (
 *            SELECT kind, key FROM benzo_relayer_abuse
 *            WHERE kind = 'daily'
 *              AND COALESCE(last_ms, CAST(EXTRACT(EPOCH FROM updated_at) * 1000 AS BIGINT)) < (EXTRACT(EPOCH FROM now()) * 1000 - 86400000)
 *              AND key NOT LIKE ('%:' || TO_CHAR(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD'))
 *            LIMIT 1000
 *          )
 *          LIMIT 1000
 *        )
 *        DELETE FROM benzo_relayer_abuse
 *        WHERE (kind, key) IN (SELECT kind, key FROM candidates);
 *      $$
 *    );
 */
export class NeonRelayerAbuseStore implements RelayerAbuseStore {
  readonly durable = true;
  private readonly db: NeonQueryFunction<false, false>;
  private schemaReady: Promise<void> | null = null;
  private sweepTimer: NodeJS.Timeout | null = null;

  constructor(
    urlOrDb: string | NeonQueryFunction<false, false>,
    readonly options?: AbuseStoreOptions,
  ) {
    this.db = typeof urlOrDb === "string" ? neon(urlOrDb) : urlOrDb;
  }

  private async ensureSchema(): Promise<void> {
    this.schemaReady ??= (async () => {
      await this.db`
        create table if not exists benzo_relayer_abuse (
          kind text not null,
          key text not null,
          tokens double precision,
          last_ms bigint,
          count integer,
          code integer,
          body jsonb,
          updated_at timestamptz not null default now(),
          primary key (kind, key)
        )
      `;
      await this.db`
        create index if not exists benzo_relayer_abuse_kind_last_ms_idx
        on benzo_relayer_abuse (kind, last_ms)
      `;
      await this.db`
        create index if not exists benzo_relayer_abuse_updated_at_idx
        on benzo_relayer_abuse (updated_at)
      `;
    })();
    await this.schemaReady;
  }

  async allow(key: string, burst: number, perMin: number): Promise<boolean> {
    await this.ensureSchema();
    const now = Date.now();
    const refillPerMs = perMin / 60_000;
    const rows = await this.db`
      insert into benzo_relayer_abuse (kind, key, tokens, last_ms, updated_at)
      values ('bucket', ${key}, ${Math.max(0, burst - 1)}, ${now}, now())
      on conflict (kind, key) do update set
        tokens = least(${burst}, benzo_relayer_abuse.tokens + ((${now} - benzo_relayer_abuse.last_ms) * ${refillPerMs})) - 1,
        last_ms = ${now},
        updated_at = now()
      where least(${burst}, benzo_relayer_abuse.tokens + ((${now} - benzo_relayer_abuse.last_ms) * ${refillPerMs})) >= 1
      returning tokens
    `;
    return rows.length > 0;
  }

  async takeDaily(key: string, max: number): Promise<boolean> {
    await this.ensureSchema();
    const now = Date.now();
    const rows = await this.db`
      insert into benzo_relayer_abuse (kind, key, count, last_ms, updated_at)
      values ('daily', ${key}, 1, ${now}, now())
      on conflict (kind, key) do update set
        count = benzo_relayer_abuse.count + 1,
        last_ms = ${now},
        updated_at = now()
      where benzo_relayer_abuse.count < ${max}
      returning count
    `;
    return rows.length > 0;
  }

  async idemGet(key: string, ttlMs: number): Promise<CachedResponse | undefined> {
    await this.ensureSchema();
    const cutoff = Date.now() - ttlMs;
    const rows = await this.db`
      select code, body, last_ms
      from benzo_relayer_abuse
      where kind = 'idempotency' and key = ${key} and last_ms >= ${cutoff}
      limit 1
    `;
    const row = rows[0] as { code?: number; body?: unknown; last_ms?: string | number } | undefined;
    if (!row || typeof row.code !== "number") return undefined;
    return { code: row.code, body: row.body, at: Number(row.last_ms ?? Date.now()) };
  }

  async idemSet(key: string, value: CachedResponse): Promise<void> {
    await this.ensureSchema();
    await this.db`
      insert into benzo_relayer_abuse (kind, key, code, body, last_ms, updated_at)
      values ('idempotency', ${key}, ${value.code}, ${JSON.stringify(value.body)}::jsonb, ${value.at}, now())
      on conflict (kind, key) do update set
        code = excluded.code,
        body = excluded.body,
        last_ms = excluded.last_ms,
        updated_at = now()
    `;
  }

  async sweep(options?: SweepOptions): Promise<number> {
    await this.ensureSchema();
    const now = options?.now ?? Date.now();
    const idemTtl = options?.idempotencyTtlMs ?? this.options?.idempotencyTtlMs ?? DEFAULT_IDEMPOTENCY_TTL_MS;
    const bucketHorizon = options?.bucketHorizonMs ?? this.options?.bucketHorizonMs ?? DEFAULT_BUCKET_HORIZON_MS;
    const dailyHorizon = options?.dailyHorizonMs ?? this.options?.dailyHorizonMs ?? DEFAULT_DAILY_HORIZON_MS;
    const limit = options?.limit ?? this.options?.sweepLimit ?? DEFAULT_SWEEP_LIMIT;

    const idemCutoff = now - idemTtl;
    const bucketCutoff = now - bucketHorizon;
    const dailyCutoff = now - dailyHorizon;
    const dailyCutoffDate = new Date(dailyCutoff).toISOString();
    const today = new Date(now).toISOString().slice(0, 10);
    const todayPattern = `%:${today}`;

    const rows = await this.db`
      with candidates as (
        (
          select kind, key
          from benzo_relayer_abuse
          where kind = 'idempotency' and last_ms < ${idemCutoff}
          limit ${limit}
        )
        union all
        (
          select kind, key
          from benzo_relayer_abuse
          where kind = 'bucket' and last_ms < ${bucketCutoff}
          limit ${limit}
        )
        union all
        (
          select kind, key
          from benzo_relayer_abuse
          where kind = 'daily'
            and (last_ms < ${dailyCutoff} or (last_ms is null and updated_at < ${dailyCutoffDate}::timestamptz))
            and key not like ${todayPattern}
          limit ${limit}
        )
        limit ${limit}
      ),
      deleted as (
        delete from benzo_relayer_abuse
        where (kind, key) in (select kind, key from candidates)
        returning 1
      )
      select count(*)::int as count from deleted
    `;
    const row = rows[0] as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }

  startSweepTimer(intervalMs: number): void {
    if (this.sweepTimer || intervalMs <= 0) return;
    this.sweepTimer = setInterval(() => {
      this.sweep().catch((err) => {
        console.error("[benzo-relayer] background durable abuse sweep failed:", err);
      });
    }, intervalMs);
    this.sweepTimer.unref();
  }

  close(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
  }
}

export function createRelayerAbuseStore(
  env: NodeJS.ProcessEnv = process.env,
  options?: AbuseStoreOptions,
): RelayerAbuseStore {
  const isMemory = env.RELAYER_STORE_MEMORY === "1";
  const isProd = env.NODE_ENV === "production" || env.VERCEL === "1";
  const dbUrl = env.DATABASE_URL;

  let store: RelayerAbuseStore;
  if (isMemory) {
    store = new MemoryRelayerAbuseStore(options);
  } else if (dbUrl) {
    store = new NeonRelayerAbuseStore(dbUrl, options);
  } else if (isProd) {
    throw new Error("DATABASE_URL is required for durable relayer rate limits and idempotency");
  } else {
    store = new MemoryRelayerAbuseStore(options);
  }

  const sweepIntervalMs = options?.sweepIntervalMs ?? (() => {
    if (env.RELAYER_SWEEP_INTERVAL_MS !== undefined) {
      return Number(env.RELAYER_SWEEP_INTERVAL_MS);
    }
    if (env.RELAYER_AUTO_SWEEP === "0" || env.RELAYER_AUTO_SWEEP === "false") {
      return 0;
    }
    if (env.NODE_ENV === "test") {
      return 0;
    }
    return DEFAULT_SWEEP_INTERVAL_MS;
  })();

  if (sweepIntervalMs > 0 && typeof (store as MemoryRelayerAbuseStore | NeonRelayerAbuseStore).startSweepTimer === "function") {
    (store as MemoryRelayerAbuseStore | NeonRelayerAbuseStore).startSweepTimer(sweepIntervalMs);
  }

  return store;
}

