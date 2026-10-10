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

test("hosted console starts empty and partitions org documents by auth key", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, runWithConsoleTenant } = await import("./store.js");

  await runWithConsoleTenant("alice", { email: "alice@example.com", name: "Alice" }, { accountFingerprint: "console_alice", subjectKey: "alice" }, async () => {
    expect(db.counterparties).toEqual([]);
    expect(db.invoices).toEqual([]);
    db.org.name = "Alice LLC";
    db.counterparties.push({
      id: "cp_alice",
      orgId: db.org.id,
      name: "Alice Contractor",
      type: "contractor",
      status: "pending_screening",
      externalAccounts: [],
      createdAt: new Date().toISOString(),
    });
  });

  await runWithConsoleTenant("bob", { email: "bob@example.com", name: "Bob" }, { accountFingerprint: "console_bob", subjectKey: "bob" }, async () => {
    expect(db.org.name).toBe("New workspace");
    expect(db.counterparties).toEqual([]);
    expect(db.payments).toEqual([]);
  });

  await runWithConsoleTenant("alice", null, { accountFingerprint: "console_alice", subjectKey: "alice" }, async () => {
    expect(db.org.name).toBe("Alice LLC");
    expect(db.counterparties.map((c) => c.id)).toEqual(["cp_alice"]);
  });
});

test("hosted console persists operational state in the encrypted tenant document", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, runWithConsoleTenant } = await import("./store.js");

  await runWithConsoleTenant("ops", { email: "ops@example.com", name: "Ops" }, { accountFingerprint: "console_ops", subjectKey: "ops" }, async () => {
    db.onboarding = { name: "Ops Treasury", country: "US" };
    db.invites.push({
      id: "invite_ops",
      kind: "contractor",
      name: "Private Contractor",
      counterpartyId: "cp_ops",
      link: "https://wallet.benzo.space/claim#secret",
      token: "tok_ops",
      status: "sent",
      createdAt: new Date().toISOString(),
    });
    db.payrolls.push({
      id: "pr_ops",
      orgId: db.org.id,
      period: "2026-06",
      source: "manual",
      status: "needs_approval",
      lines: [{ counterpartyId: "cp_ops", amount: "10000000", settlementHandle: "@ops", status: "pending" }],
      total: { amount: "10000000", assetCode: "USDC" },
      createdAt: new Date().toISOString(),
    });
    db.privateEvents.push({
      id: "pe_ops",
      orgId: `org-ops`,
      type: "payment.submitted",
      subjectId: "po_ops",
      schema: "payment.order.v1",
      occurredAt: new Date().toISOString(),
      publicMeta: { status: "needs_approval" },
      ciphertext: "cipher",
      iv: "iv",
      tag: "tag",
      aadHash: "aad",
      payloadHash: "payload",
      prevHash: "GENESIS",
      hash: "hash",
    });
    db.proofReceipts.push({
      id: "prf_ops",
      action: "treasury.prove-total",
      vkId: "ORGSUM",
      verified: true,
      verifier: "verifier_contract",
      network: "testnet",
      publicInputs: [{ k: "Total", v: "hidden" }],
      createdAt: new Date().toISOString(),
    });
    db.idempotency["POST:/api/payments:key_ops"] = {
      bodyHash: "hash_ops",
      status: 201,
      body: { id: "po_ops" },
      createdAt: new Date().toISOString(),
    };
  });

  await runWithConsoleTenant("ops", null, { accountFingerprint: "console_ops", subjectKey: "ops" }, async () => {
    expect(db.onboarding).toMatchObject({ name: "Ops Treasury", country: "US" });
    expect(db.invites.map((i) => i.id)).toEqual(["invite_ops"]);
    expect(db.payrolls[0].lines[0].settlementHandle).toBe("@ops");
    expect(db.privateEvents.map((e) => e.id)).toEqual(["pe_ops"]);
    expect(db.proofReceipts.map((r) => r.vkId)).toEqual(["ORGSUM"]);
    expect(db.idempotency["POST:/api/payments:key_ops"]).toMatchObject({ bodyHash: "hash_ops", status: 201 });
  });
});

test("hosted console read-only tenant runs cannot clobber persisted writes", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, runWithConsoleTenant } = await import("./store.js");

  await runWithConsoleTenant("race", { email: "race@example.com", name: "Race" }, { accountFingerprint: "console_race", subjectKey: "race" }, async () => {
    db.org.name = "Race Org";
    db.counterparties.push({
      id: "cp_original",
      orgId: db.org.id,
      name: "Original Contractor",
      type: "contractor",
      status: "pending_screening",
      externalAccounts: [],
      createdAt: new Date().toISOString(),
    });
  });

  await runWithConsoleTenant("race", null, { accountFingerprint: "console_race", subjectKey: "race" }, async () => {
    db.org.name = "Stale Read Snapshot";
    db.counterparties.length = 0;
  }, { persist: false });

  await runWithConsoleTenant("race", null, { accountFingerprint: "console_race", subjectKey: "race" }, async () => {
    expect(db.org.name).toBe("Race Org");
    expect(db.counterparties.map((c) => c.id)).toEqual(["cp_original"]);
  });
});

test("accepted member invites activate the invited console seat", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { activateAcceptedMemberInvite, db, runWithConsoleTenant } = await import("./store.js");

  await runWithConsoleTenant("member-accept", { email: "owner@example.com", name: "Owner" }, { accountFingerprint: "console_member_accept", subjectKey: "member-accept" }, async () => {
    const invitedAt = new Date().toISOString();
    db.members.push({ id: "mem_second", orgId: db.org.id, email: "second-owner@example.com", name: "Second Owner", role: "owner", status: "invited", createdAt: invitedAt });
    const invite = {
      id: "invite_second",
      kind: "member" as const,
      name: "Second Owner",
      email: "second-owner@example.com",
      role: "owner",
      link: "https://console.benzo.space/claim#secret",
      token: "tok_second",
      status: "accepted" as const,
      createdAt: invitedAt,
    };

    const member = activateAcceptedMemberInvite(invite, "Second Owner");
    expect(member).toMatchObject({ email: "second-owner@example.com", role: "owner", status: "active" });
    const again = activateAcceptedMemberInvite(invite, "Second Owner");
    expect(again?.id).toBe("mem_second");
    expect(db.members.filter((m) => m.email === "second-owner@example.com")).toHaveLength(1);
  });
});

test("accepted member invite creates an active seat when the pending seat is missing", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { activateAcceptedMemberInvite, db, runWithConsoleTenant } = await import("./store.js");

  await runWithConsoleTenant("member-accept-create", { email: "owner@example.com", name: "Owner" }, { accountFingerprint: "console_member_accept_create", subjectKey: "member-accept-create" }, async () => {
    const member = activateAcceptedMemberInvite({
      id: "invite_missing",
      kind: "member",
      name: "Approver",
      email: "approver@example.com",
      role: "approver",
      link: "https://console.benzo.space/claim#secret",
      token: "tok_missing",
      status: "accepted",
      createdAt: new Date().toISOString(),
    }, "Approver");
    expect(member).toMatchObject({ email: "approver@example.com", role: "approver", status: "active" });
    expect(db.members.filter((m) => m.email === "approver@example.com")).toHaveLength(1);
  });
});

test("hosted console request limits are tenant-scoped outside the product document", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { takeTenantRateLimit } = await import("./tenantData.js");
  const { db, runWithConsoleTenant } = await import("./store.js");

  await expect(takeTenantRateLimit("console", "console:alice", "write", 1, 1, 60)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("console", "console:alice", "write", 1, 1, 60)).resolves.toMatchObject({ ok: false });
  await expect(takeTenantRateLimit("console", "console:bob", "write", 1, 1, 60)).resolves.toEqual({ ok: true });

  await runWithConsoleTenant("alice", { email: "alice@example.com", name: "Alice" }, { accountFingerprint: "console_alice", subjectKey: "alice" }, async () => {
    expect("rateLimits" in db).toBe(false);
  });
});

test("hosted console retention sweep deletes expired request limits and preserves active window", async () => {
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
  await expect(takeTenantRateLimit("console", "console:expired", "write", 1, 1, 60, expiredTime)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("console", "console:expired", "write", 1, 1, 60, expiredTime)).resolves.toMatchObject({ ok: false });

  await expect(takeTenantRateLimit("console", "console:recent", "write", 1, 1, 60, recentTime)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("console", "console:recent", "write", 1, 1, 60, recentTime)).resolves.toMatchObject({ ok: false });

  await expect(takeTenantRateLimit("console", "console:active", "write", 1, 1, 60, activeTime)).resolves.toEqual({ ok: true });
  await expect(takeTenantRateLimit("console", "console:active", "write", 1, 1, 60, activeTime)).resolves.toMatchObject({ ok: false });

  // Run retention sweep at baseNow
  const pruned = await pruneExpiredRequestLimits({ horizonSeconds: horizon, nowSec: baseNow });
  expect(pruned).toBe(1);

  // Expired tenant's record should be pruned, allowing a new request in that old window
  await expect(takeTenantRateLimit("console", "console:expired", "write", 1, 1, 60, expiredTime)).resolves.toEqual({ ok: true });

  // Recent and active tenants must still be rate-limited
  await expect(takeTenantRateLimit("console", "console:recent", "write", 1, 1, 60, recentTime)).resolves.toMatchObject({ ok: false });
  await expect(takeTenantRateLimit("console", "console:active", "write", 1, 1, 60, activeTime)).resolves.toMatchObject({ ok: false });

  // Running sweep with zero horizon clamps to safe horizon (60s), which protects the active window
  // (at baseNow), while pruning any past windows older than 60s (both console:expired and console:recent).
  const safePruned = await pruneExpiredRequestLimits({ horizonSeconds: 0, nowSec: baseNow });
  expect(safePruned).toBe(2);
  // Crucially, the active window row is NOT deleted and remains rate-limited:
  await expect(takeTenantRateLimit("console", "console:active", "write", 1, 1, 60, activeTime)).resolves.toMatchObject({ ok: false });
});

test("hosted console fails closed when a tenant account binding changes", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { db, recoverySummary, RecoveryRequiredError, runWithConsoleTenant } = await import("./store.js");

  await runWithConsoleTenant("recovery-org", { email: "owner@example.com", name: "Owner" }, { accountFingerprint: "console_original", subjectKey: "recovery-org" }, async () => {
    db.org.name = "Recovery Org";
  });

  await expect(
    runWithConsoleTenant("recovery-org", null, { accountFingerprint: "console_rotated", subjectKey: "recovery-org" }, async () => {
      db.org.name = "Wrong Org";
    }),
  ).rejects.toBeInstanceOf(RecoveryRequiredError);

  await runWithConsoleTenant("recovery-org", null, { accountFingerprint: "console_original", subjectKey: "recovery-org" }, async () => {
    expect(db.org.name).toBe("Recovery Org");
    expect(db.recovery?.accountFingerprint).toBe("console_original");
    expect(recoverySummary()).toMatchObject({ bound: true });
    expect(recoverySummary()).not.toHaveProperty("accountFingerprint");
    expect(recoverySummary()).not.toHaveProperty("subjectKey");
  });
});

test("hosted console invite routes resolve back to the inviter org tenant", async () => {
  process.env.BENZO_HOSTED_TENANT_TEST = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.BENZO_DISABLE_TENANT_LEGACY_DECRYPT = "1";
  const { currentConsoleTenantKey, db, runWithConsoleTenant, runWithConsoleTenantKey } = await import("./store.js");
  const { lookupTenantRoute, registerTenantRoute } = await import("./tenantData.js");

  await runWithConsoleTenant("acme-owner", { email: "owner@acme.example", name: "Owner" }, { accountFingerprint: "console_acme", subjectKey: "acme-owner" }, async () => {
    db.org.name = "Acme";
    db.counterparties.push({ id: "cp_route", orgId: db.org.id, name: "Route Contractor", type: "contractor", status: "invited", externalAccounts: [], createdAt: new Date().toISOString() });
    db.invites.push({
      id: "invite_route",
      kind: "contractor",
      name: "Route Contractor",
      counterpartyId: "cp_route",
      link: "https://wallet.benzo.space/claim#secret",
      token: "tok_route",
      expiresAt: Math.floor(Date.now() / 1000) + 60,
      status: "sent",
      createdAt: new Date().toISOString(),
    });
    await registerTenantRoute("console", "invite", "tok_route", currentConsoleTenantKey()!, Math.floor(Date.now() / 1000) + 60);
  });

  const tenantKey = await lookupTenantRoute("console", "invite", "tok_route");
  expect(tenantKey).toBe("console:acme-owner");

  await runWithConsoleTenantKey(tenantKey, async () => {
    const inv = db.invites.find((i) => i.token === "tok_route")!;
    inv.status = "accepted";
    db.counterparties.find((c) => c.id === inv.counterpartyId)!.status = "allowlisted";
  });

  await runWithConsoleTenant("acme-owner", null, { accountFingerprint: "console_acme", subjectKey: "acme-owner" }, async () => {
    expect(db.invites.find((i) => i.token === "tok_route")?.status).toBe("accepted");
    expect(db.counterparties.find((c) => c.id === "cp_route")?.status).toBe("allowlisted");
  });

  await runWithConsoleTenant("other-owner", { email: "other@example.com", name: "Other" }, { accountFingerprint: "console_other", subjectKey: "other-owner" }, async () => {
    expect(db.invites).toEqual([]);
    expect(db.counterparties).toEqual([]);
  });
});

test("hosted console refuses the in-memory tenant store on Vercel", async () => {
  process.env.VERCEL = "1";
  process.env.BENZO_TENANT_STORE_MEMORY = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  const { loadTenantDocument, tenantStorageMissing } = await import("./tenantData.js");

  expect(tenantStorageMissing()).toContain("BENZO_TENANT_STORE_MEMORY");
  await expect(loadTenantDocument("console", "console:alice")).rejects.toThrow("BENZO_TENANT_STORE_MEMORY is not allowed");
});

test("hosted console refuses local memory override outside Vercel too", async () => {
  process.env.BENZO_HOSTED_RUNTIME = "1";
  process.env.BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE = "1";
  process.env.BENZO_DATA_ENCRYPTION_SECRET = "tenant-store-test-secret";
  process.env.DATABASE_URL = "postgres://user:pass@example.neon.tech/db";
  const { loadTenantDocument, tenantStorageMissing } = await import("./tenantData.js");

  expect(tenantStorageMissing()).toContain("BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE");
  await expect(loadTenantDocument("console", "console:alice")).rejects.toThrow("BENZO_ALLOW_LOCAL_MEMORY_TENANT_STORE is not allowed");
});
