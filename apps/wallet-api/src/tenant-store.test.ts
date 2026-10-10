import { afterEach, expect, test, vi } from "vitest";

const ENV_KEYS = [
  "VERCEL",
  "BENZO_HOSTED_RUNTIME",
  "BENZO_HOSTED_TENANT_TEST",
  "BENZO_TENANT_STORE_MEMORY",
  "BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE",
  "BENZO_DATA_ENCRYPTION_SECRET",
  "BENZO_DISABLE_TENANT_LEGACY_DECRYPT",
  "DATABASE_URL",
] as const;
const originalEnv = new Map<string, string | undefined>(ENV_KEYS.map((k) => [k, process.env[k]]));

afterEach(() => {
  for (const k of ENV_KEYS) {
    const v = originalEnv.get(k);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  vi.resetModules();
});

test("hosted wallet UX, invites, and accounting state are encrypted and partitioned by auth key", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { loadTenantDocument } = await import("./tenantData.js");
  const { appendWalletLedger, appendWalletProofReceipt, db, runWithWalletTenant, verifyWalletLedger, walletLedgerBalances } = await import("./store.js");

  await runWithWalletTenant("alice", { name: "Alice" }, { accountFingerprint: "wallet_alice", subjectKey: "alice" }, async () => {
    db.profile.handle = "@alice";
    db.contacts.push({ handle: "@bob", name: "Bob" });
    db.invites.push({
      localId: "inv_alice",
      amount: "30000000",
      note: "private invite",
      link: "https://wallet.benzo.space/claim#alice",
      secret: "encrypted-in-tenant-doc",
      createdAt: 1,
      expiresAt: 2,
      status: "pending",
    });
    appendWalletLedger({
      sourceType: "onramp",
      status: "settled",
      txId: "tx_onramp",
      requestedAmount: "3",
      lines: [
        { accountId: "ramp_reserve", direction: "debit", amount: "30000000", assetCode: "USDC" },
        { accountId: "private", direction: "credit", amount: "30000000", assetCode: "USDC" },
      ],
    });
    appendWalletLedger({
      sourceType: "offramp",
      status: "failed",
      requestedAmount: "100",
      lines: [],
      errorCode: "reserve",
      error: "The cash reserve is topping up. Try again in a moment, or a smaller amount.",
    });
    appendWalletProofReceipt({
      action: "wallet.add-money",
      vkId: "SHIELD",
      prover: "local",
      verified: true,
      txHash: "tx_shield",
      verifier: "verifier_contract",
      publicInputs: { source: "settlement-tx", txHash: "tx_shield" },
    });
    db.coreState["benzo:alice-view:journal"] = JSON.stringify([{ type: "shield", amount: "30000000" }]);
    db.coreState["benzo:global:asp"] = JSON.stringify({ cursorLedger: 12, leaves: ["1"] });
    expect(verifyWalletLedger()).toMatchObject({ ok: true, length: 2 });
    expect(walletLedgerBalances()).toMatchObject({ private: "30000000", ramp_reserve: "-30000000" });
  });

  await runWithWalletTenant("bob", { name: "Bob" }, { accountFingerprint: "wallet_bob", subjectKey: "bob" }, async () => {
    expect(db.profile.handle).toBe("@you");
    expect(db.contacts).toEqual([]);
    expect(db.invites).toEqual([]);
    expect(db.ledger).toEqual([]);
    expect(db.proofReceipts).toEqual([]);
    expect(db.coreState).toEqual({});
    db.profile.handle = "@bob";
    db.coreState["benzo:bob-view:journal"] = JSON.stringify([{ type: "shield", amount: "10000000" }]);
  });

  await runWithWalletTenant("alice", null, { accountFingerprint: "wallet_alice", subjectKey: "alice" }, async () => {
    expect(db.profile.handle).toBe("@alice");
    expect(db.contacts).toHaveLength(1);
    expect(db.invites.map((i) => i.localId)).toEqual(["inv_alice"]);
    expect(db.ledger.map((e) => e.sourceType)).toEqual(["onramp", "offramp"]);
    expect(db.proofReceipts.map((r) => [r.action, r.vkId, r.txHash])).toEqual([["wallet.add-money", "SHIELD", "tx_shield"]]);
    expect(db.coreState).toEqual({});
    await expect(loadTenantDocument("wallet-core", "wallet:alice:benzo:alice-view:journal")).resolves.toMatchObject({
      value: JSON.stringify([{ type: "shield", amount: "30000000" }]),
    });
    await expect(loadTenantDocument("wallet-core", "wallet:alice:benzo:global:asp")).resolves.toMatchObject({
      value: JSON.stringify({ cursorLedger: 12, leaves: ["1"] }),
    });
    await expect(loadTenantDocument("wallet-core", "wallet:alice:benzo:bob-view:journal")).resolves.toBeNull();
    expect(db.coreState["benzo:bob-view:journal"]).toBeUndefined();
    expect(verifyWalletLedger()).toMatchObject({ ok: true, length: 2 });
    expect(walletLedgerBalances()).toMatchObject({ private: "30000000", ramp_reserve: "-30000000" });
    db.ledger[0].requestedAmount = "999";
    expect(verifyWalletLedger()).toMatchObject({ ok: false, brokenAt: 0 });
  });
});

test("hosted wallet save merge preserves a claimed handle from a stale seed write", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { mergeWalletDbForSave, seed, verifyWalletLedgerEntries } = await import("./store.js");

  const current = seed();
  current.profile = { handle: "claimed", name: "Claimed User" };
  current.ledger.push({
    id: "old-ledger",
    postedAt: 1,
    sourceType: "onramp",
    status: "settled",
    txId: "tx_old",
    lines: [
      { accountId: "ramp_reserve", direction: "debit", amount: "10000000", assetCode: "USDC" },
      { accountId: "private", direction: "credit", amount: "10000000", assetCode: "USDC" },
    ],
  });

  const staleNext = seed();
  staleNext.profile = { handle: "@you", name: "Late request" };
  staleNext.ledger.push({
    id: "new-ledger",
    postedAt: 2,
    sourceType: "send_private",
    status: "settled",
    txId: "tx_new",
    lines: [
      { accountId: "private", direction: "debit", amount: "1000000", assetCode: "USDC" },
      { accountId: "external", direction: "credit", amount: "1000000", assetCode: "USDC" },
    ],
  });

  const merged = mergeWalletDbForSave(current, staleNext);

  expect(merged.profile).toEqual({ handle: "claimed", name: "Claimed User" });
  expect(merged.ledger.map((entry) => entry.id)).toEqual(["old-ledger", "new-ledger"]);
  expect(verifyWalletLedgerEntries(merged.ledger)).toMatchObject({ ok: true, length: 2 });
  expect(merged.coreState).toEqual({});
});

test("hosted wallet request reconciliation markers persist and merge", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, isRequestTxReconciled, markRequestTxReconciled, mergeWalletDbForSave, runWithWalletTenant, seed } = await import("./store.js");

  await runWithWalletTenant("request-user", { name: "Request User" }, { accountFingerprint: "wallet_request", subjectKey: "request-user" }, async () => {
    expect(isRequestTxReconciled("req_1", "ABC123")).toBe(false);
    markRequestTxReconciled("req_1", "ABC123");
    expect(isRequestTxReconciled("req_1", "abc123")).toBe(true);
    expect(db.requestReconciledTxs).toEqual({ req_1: ["abc123"] });
  });

  await runWithWalletTenant("request-user", null, { accountFingerprint: "wallet_request", subjectKey: "request-user" }, async () => {
    expect(isRequestTxReconciled("req_1", "abc123")).toBe(true);
    expect(isRequestTxReconciled("req_1", "def456")).toBe(false);
  });

  const current = seed();
  current.requestReconciledTxs = { req_1: ["abc123"], req_2: ["old"] };
  const staleNext = seed();
  staleNext.requestReconciledTxs = { req_1: ["ABC123", "def456"], req_3: ["new"] };

  const merged = mergeWalletDbForSave(current, staleNext);

  expect(merged.requestReconciledTxs).toEqual({
    req_1: ["abc123", "def456"],
    req_2: ["old"],
    req_3: ["new"],
  });
});

test("hosted wallet fails closed when a tenant account binding changes", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, recoverySummary, RecoveryRequiredError, runWithWalletTenant } = await import("./store.js");

  await runWithWalletTenant("recovery-user", { name: "Recovery" }, { accountFingerprint: "wallet_original", subjectKey: "recovery-user" }, async () => {
    db.profile.handle = "@recovery";
  });

  await expect(
    runWithWalletTenant("recovery-user", null, { accountFingerprint: "wallet_rotated", subjectKey: "recovery-user" }, async () => {
      db.profile.handle = "@wrong";
    }),
  ).rejects.toBeInstanceOf(RecoveryRequiredError);

  await runWithWalletTenant("recovery-user", null, { accountFingerprint: "wallet_original", subjectKey: "recovery-user" }, async () => {
    expect(db.profile.handle).toBe("@recovery");
    expect(db.recovery?.accountFingerprint).toBe("wallet_original");
    expect(recoverySummary()).toMatchObject({ bound: true });
    expect(recoverySummary()).not.toHaveProperty("accountFingerprint");
    expect(recoverySummary()).not.toHaveProperty("subjectKey");
  });
});

test("read-only hosted wallet requests do not overwrite a saved write", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, runWithWalletTenant } = await import("./store.js");

  await runWithWalletTenant("race-user", { name: "Race" }, { accountFingerprint: "wallet_race", subjectKey: "race-user" }, async () => {
    db.profile.handle = "@claimed";
  });

  await runWithWalletTenant("race-user", { name: "Race" }, { accountFingerprint: "wallet_race", subjectKey: "race-user" }, async () => {
    db.profile.handle = "@stale-read";
  }, { persist: false });

  await runWithWalletTenant("race-user", null, { accountFingerprint: "wallet_race", subjectKey: "race-user" }, async () => {
    expect(db.profile.handle).toBe("@claimed");
  });
});

test("failed wallet ledger entries do not become spendable balance fallback", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const {
    appendWalletLedger,
    hasSettledWalletLedgerEntries,
    runWithWalletTenant,
    verifyWalletLedger,
    walletLedgerBalances,
  } = await import("./store.js");

  await runWithWalletTenant("failed-only", { name: "Failed Only" }, { accountFingerprint: "wallet_failed", subjectKey: "failed-only" }, async () => {
    appendWalletLedger({
      sourceType: "offramp",
      status: "failed",
      requestedAmount: "3",
      lines: [],
      errorCode: "limit",
      error: "Cash-out must be between $5 and $2,500.",
    });

    expect(verifyWalletLedger()).toMatchObject({ ok: true, length: 1 });
    expect(hasSettledWalletLedgerEntries()).toBe(false);
    expect(walletLedgerBalances()).toMatchObject({ private: "0", public: "0", ramp_reserve: "0" });
  });
});

test("hosted wallet account deletion clears only the current tenant document", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, deleteCurrentWalletTenant, runWithWalletTenant } = await import("./store.js");

  await runWithWalletTenant("delete-alice", { name: "Alice" }, { accountFingerprint: "wallet_alice", subjectKey: "delete-alice" }, async () => {
    db.profile.handle = "@deletealice";
  });
  await runWithWalletTenant("delete-bob", { name: "Bob" }, { accountFingerprint: "wallet_bob", subjectKey: "delete-bob" }, async () => {
    db.profile.handle = "@deletebob";
  });

  await runWithWalletTenant("delete-alice", null, { accountFingerprint: "wallet_alice", subjectKey: "delete-alice" }, async () => {
    expect(db.profile.handle).toBe("@deletealice");
    expect(db.accountGeneration).toBe(0);
    await deleteCurrentWalletTenant();
    expect(db.accountGeneration).toBe(1);
  });

  await runWithWalletTenant("delete-alice", { name: "Alice" }, { accountFingerprint: "wallet_alice_rotated", subjectKey: "delete-alice" }, async () => {
    expect(db.accountGeneration).toBe(1);
    expect(db.profile.handle).toBe("@you");
    expect(db.contacts).toEqual([]);
    expect(db.ledger).toEqual([]);
  });
  await runWithWalletTenant("delete-bob", null, { accountFingerprint: "wallet_bob", subjectKey: "delete-bob" }, async () => {
    expect(db.profile.handle).toBe("@deletebob");
  });
});

test("hosted wallet request limits are tenant-scoped outside the product document", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { takeTenantRateLimit } = await import("./tenantData.js");
  const { db, runWithWalletTenant } = await import("./store.js");

  await expect(takeTenantRateLimit("wallet", "wallet:alice", "write", 1, 1, 60)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("wallet", "wallet:alice", "write", 1, 1, 60)).resolves.toMatchObject({ ok: false });
  await expect(takeTenantRateLimit("wallet", "wallet:bob", "write", 1, 1, 60)).resolves.toEqual({ ok: true });

  await runWithWalletTenant("alice", { name: "Alice" }, { accountFingerprint: "wallet_alice", subjectKey: "alice" }, async () => {
    expect("rateLimits" in db).toBe(false);
  });
});

test("hosted wallet retention sweep deletes expired request limits and preserves active window", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { pruneExpiredRequestLimits, takeTenantRateLimit, REQUEST_LIMIT_RETENTION_SECONDS } = await import("./tenantData.js");

  expect(REQUEST_LIMIT_RETENTION_SECONDS).toBe(7 * 24 * 60 * 60);

  const baseNow = 2_000_000;
  const horizon = 7 * 24 * 60 * 60; // 7 days = 604,800s
  const expiredTime = baseNow - (10 * 24 * 60 * 60); // 10 days ago (expired)
  const recentTime = baseNow - (2 * 24 * 60 * 60); // 2 days ago (within horizon)
  const activeTime = baseNow; // current active window

  // Max out rate limits for three different tenants at distinct times
  await expect(takeTenantRateLimit("wallet", "wallet:expired", "write", 1, 1, 60, expiredTime)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("wallet", "wallet:expired", "write", 1, 1, 60, expiredTime)).resolves.toMatchObject({ ok: false });

  await expect(takeTenantRateLimit("wallet", "wallet:recent", "write", 1, 1, 60, recentTime)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("wallet", "wallet:recent", "write", 1, 1, 60, recentTime)).resolves.toMatchObject({ ok: false });

  await expect(takeTenantRateLimit("wallet", "wallet:active", "write", 1, 1, 60, activeTime)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("wallet", "wallet:active", "write", 1, 1, 60, activeTime)).resolves.toMatchObject({ ok: false });

  // Run retention sweep at baseNow
  const pruned = await pruneExpiredRequestLimits({ horizonSeconds: horizon, nowSec: baseNow });
  expect(pruned).toBe(1);

  // Expired tenant's record should be pruned, allowing a new request in that old window
  await expect(takeTenantRateLimit("wallet", "wallet:expired", "write", 1, 1, 60, expiredTime)).resolves.toEqual({ ok: true });

  // Recent and active tenants must still be rate-limited
  await expect(takeTenantRateLimit("wallet", "wallet:recent", "write", 1, 1, 60, recentTime)).resolves.toMatchObject({ ok: false });
  await expect(takeTenantRateLimit("wallet", "wallet:active", "write", 1, 1, 60, activeTime)).resolves.toMatchObject({ ok: false });

  // Running sweep with zero horizon clamps to safe horizon (60s), which protects the active window
  // (at baseNow), while pruning any past windows older than 60s (both wallet:expired and wallet:recent).
  const safePruned = await pruneExpiredRequestLimits({ horizonSeconds: 0, nowSec: baseNow });
  expect(safePruned).toBe(2);
  // Crucially, the active window row is NOT deleted and remains rate-limited:
  await expect(takeTenantRateLimit("wallet", "wallet:active", "write", 1, 1, 60, activeTime)).resolves.toMatchObject({ ok: false });
});

test("hosted wallet refuses the in-memory tenant store on Vercel", async () => {
  process.env.VERCEL = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  const { loadTenantDocument, tenantStorageMissing } = await import("./tenantData.js");

  expect(tenantStorageMissing()).toContain("BENZO_TENANT_STORE_MEMORY");
  await expect(loadTenantDocument("wallet", "wallet:alice")).rejects.toThrow("BENZO_TENANT_STORE_MEMORY is not allowed");
});

test("hosted wallet refuses local memory override outside Vercel too", async () => {
  process.env.BENZO_HOSTED_RUNTIME = "1";
  process.env.BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.DATABASE_URL = "postgres://user:pass@example.neon.tech/db";
  const { loadTenantDocument, tenantStorageMissing } = await import("./tenantData.js");

  expect(tenantStorageMissing()).toContain("BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE");
  await expect(loadTenantDocument("wallet", "wallet:alice")).rejects.toThrow("BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE is not allowed");
});
