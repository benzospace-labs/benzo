import { describe, expect, it } from "vitest";
import {
  createRelayerAbuseStore,
  MemoryRelayerAbuseStore,
  NeonRelayerAbuseStore,
} from "../src/abuse-store.js";

describe("relayer abuse store", () => {
  it("fails closed in production without a durable database", () => {
    expect(() => createRelayerAbuseStore({ NODE_ENV: "production" })).toThrow(/DATABASE_URL/);
  });

  it("supports explicit dev memory mode for local tests", async () => {
    const store = createRelayerAbuseStore({ RELAYER_STORE_MEMORY: "1", NODE_ENV: "test" });
    expect(store.durable).toBe(false);
    expect(await store.allow("k", 1, 0)).toBe(true);
    expect(await store.allow("k", 1, 0)).toBe(false);
    expect(await store.takeDaily("day", 1)).toBe(true);
    expect(await store.takeDaily("day", 1)).toBe(false);

    await store.idemSet("n0:n1", { code: 200, body: { txHash: "abc" }, at: Date.now() });
    await expect(store.idemGet("n0:n1", 60_000)).resolves.toMatchObject({ code: 200, body: { txHash: "abc" } });
  });

  describe("MemoryRelayerAbuseStore sweep", () => {
    it("expires idempotency rows past TTL without requiring a lookup", async () => {
      const store = new MemoryRelayerAbuseStore();
      const now = Date.now();
      const oldTime = now - 2 * 3600_000; // 2 hours ago (TTL is 1 hour)

      await store.idemSet("old_tx", { code: 200, body: { txHash: "old" }, at: oldTime });
      await store.idemSet("fresh_tx", { code: 200, body: { txHash: "fresh" }, at: now });

      const deleted = await store.sweep({ now, idempotencyTtlMs: 3600_000 });
      expect(deleted).toBe(1);

      // old_tx was removed by the sweep
      // fresh_tx is still present
      await expect(store.idemGet("fresh_tx", 3600_000)).resolves.toMatchObject({ code: 200 });
    });

    it("preserves live buckets and expires inactive buckets past horizon", async () => {
      const store = new MemoryRelayerAbuseStore();
      const now = Date.now();

      // create a bucket
      await store.allow("live_bucket", 10, 60);

      // artificially inject a stale bucket
      (store as any).buckets.set("stale_bucket", {
        tokens: 0,
        last: now - 48 * 3600_000, // 48h ago
      });

      const deleted = await store.sweep({ now, bucketHorizonMs: 24 * 3600_000 });
      expect(deleted).toBe(1);

      expect((store as any).buckets.has("live_bucket")).toBe(true);
      expect((store as any).buckets.has("stale_bucket")).toBe(false);
    });

    it("preserves current day counters and expires previous days past horizon", async () => {
      const store = new MemoryRelayerAbuseStore();
      const now = Date.now();
      const today = new Date(now).toISOString().slice(0, 10);

      await store.takeDaily(`onboard:${today}`, 100);

      // old day counter
      (store as any).daily.set("onboard:2020-01-01", {
        count: 50,
        last: now - 48 * 3600_000,
      });

      const deleted = await store.sweep({ now, dailyHorizonMs: 24 * 3600_000 });
      expect(deleted).toBe(1);

      expect((store as any).daily.has(`onboard:${today}`)).toBe(true);
      expect((store as any).daily.has("onboard:2020-01-01")).toBe(false);
    });

    it("respects bounded limit", async () => {
      const store = new MemoryRelayerAbuseStore();
      const now = Date.now();
      const oldTime = now - 2 * 3600_000;

      for (let i = 0; i < 10; i++) {
        await store.idemSet(`tx_${i}`, { code: 200, body: { txHash: `${i}` }, at: oldTime });
      }

      const deleted = await store.sweep({ now, idempotencyTtlMs: 3600_000, limit: 3 });
      expect(deleted).toBe(3);
    });
  });

  describe("NeonRelayerAbuseStore schema and sweep", () => {
    it("ensures schema and creates indexed predicates on kind and last_ms", async () => {
      const executed: string[] = [];
      const mockQueryFn: any = (strings: TemplateStringsArray) => {
        const text = strings.join(" ");
        executed.push(text);
        return Promise.resolve([]);
      };

      const store = new NeonRelayerAbuseStore(mockQueryFn);
      await store.allow("k", 1, 0);

      expect(executed.some((s) => s.includes("create table if not exists benzo_relayer_abuse"))).toBe(true);
      expect(
        executed.some(
          (s) =>
            s.includes("create index if not exists benzo_relayer_abuse_kind_last_ms_idx") &&
            s.includes("on benzo_relayer_abuse (kind, last_ms)"),
        ),
      ).toBe(true);
    });

    it("records last_ms on takeDaily updates", async () => {
      const executed: string[] = [];
      const mockQueryFn: any = (strings: TemplateStringsArray) => {
        const text = strings.join(" ");
        executed.push(text);
        if (text.includes("returning count")) return Promise.resolve([{ count: 1 }]);
        return Promise.resolve([]);
      };

      const store = new NeonRelayerAbuseStore(mockQueryFn);
      const res = await store.takeDaily("onboard:2026-10-10", 100);
      expect(res).toBe(true);

      const dailyQuery = executed.find((s) => s.includes("values ('daily'"));
      expect(dailyQuery).toBeDefined();
      expect(dailyQuery).toContain("last_ms");
    });

    it("executes bounded deletion pass with indexed predicate CTE", async () => {
      let sweepSql = "";
      const mockQueryFn: any = (strings: TemplateStringsArray, ...values: unknown[]) => {
        const text = strings.reduce((acc, str, i) => acc + str + (i < values.length ? `$${i + 1}` : ""), "");
        if (text.includes("with candidates as")) {
          sweepSql = text;
          return Promise.resolve([{ count: 4 }]);
        }
        return Promise.resolve([]);
      };

      const store = new NeonRelayerAbuseStore(mockQueryFn);
      const deleted = await store.sweep({
        now: 1700000000000,
        idempotencyTtlMs: 3600_000,
        bucketHorizonMs: 86400_000,
        dailyHorizonMs: 86400_000,
        limit: 500,
      });

      expect(deleted).toBe(4);
      expect(sweepSql).toContain("with candidates as");
      expect(sweepSql).toContain("kind = 'idempotency' and last_ms <");
      expect(sweepSql).toContain("kind = 'bucket' and last_ms <");
      expect(sweepSql).toContain("kind = 'daily'");
      expect(sweepSql).toContain("key not like");
      expect(sweepSql).toContain("delete from benzo_relayer_abuse");
      expect(sweepSql).toContain("returning 1");
    });

    it("handles close cleanly without lingering timers", () => {
      const store = new NeonRelayerAbuseStore((() => Promise.resolve([])) as any);
      store.startSweepTimer(1000);
      expect(() => store.close()).not.toThrow();
    });
  });
});

