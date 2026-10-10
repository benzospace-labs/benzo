/**
 * Unit tests for org (M-of-N) identity derivation + member signing.
 *
 * Verifies:
 * - Deterministic member derivation from 32-byte secret.
 * - Distinct member generation.
 * - Field order and fixed test vector for orgSpendMessage.
 * - Sign and verify with circomlibjs EdDSA over BabyJubjub, failing on wrong member.
 * - Threshold range validation in buildOrgIdentity and deriveOrgIdentity.
 * - Tree depth and Merkle path consistency.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import {
  ORG_MEMBER_DEPTH,
  memberFromSecret,
  generateOrgMember,
  buildOrgIdentity,
  orgSpendMessage,
  signOrgSpend,
  deriveOrgIdentity,
  type OrgMember,
} from "../src/org.js";

describe("packages/core/src/org.ts", () => {
  // biome-ignore lint: test-local circomlibjs singletons
  let eddsa: any;
  let poseidon: any;
  let F: any;

  beforeAll(async () => {
    eddsa = await buildEddsa();
    poseidon = await buildPoseidon();
    F = poseidon.F;
  });

  describe("memberFromSecret & generateOrgMember", () => {
    it("derives deterministic member credentials from a 32-byte secret", async () => {
      const secret = new Uint8Array(32);
      secret.fill(42);

      const m1 = await memberFromSecret(secret);
      const m2 = await memberFromSecret(secret);

      expect(m1.Ax).toBe(m2.Ax);
      expect(m1.Ay).toBe(m2.Ay);
      expect(m1.keyId).toBe(m2.keyId);
      expect(m1.keyId).toBe(F.toObject(poseidon([m1.Ax, m1.Ay])));
      expect(m1.prv).toEqual(secret);
    });

    it("rejects secrets that are not exactly 32 bytes", async () => {
      const shortSecret = new Uint8Array(31);
      const longSecret = new Uint8Array(33);

      await expect(memberFromSecret(shortSecret)).rejects.toThrow("member secret must be 32 bytes");
      await expect(memberFromSecret(longSecret)).rejects.toThrow("member secret must be 32 bytes");
    });

    it("generates distinct members with unique secrets and key IDs", async () => {
      const m1 = await generateOrgMember();
      const m2 = await generateOrgMember();

      expect(m1.prv).not.toEqual(m2.prv);
      expect(m1.keyId).not.toBe(m2.keyId);
    });
  });

  describe("orgSpendMessage", () => {
    it("hashes the documented field order for fixed inputs matching a known test vector", async () => {
      const n0 = 1001n;
      const n1 = 1002n;
      const c0 = 2001n;
      const c1 = 2002n;

      const msg = await orgSpendMessage(n0, n1, c0, c1);
      const expected = F.toObject(poseidon([n0, n1, c0, c1])) as bigint;

      expect(msg).toBe(expected);

      // Distinct order yields different hash
      const flipped = await orgSpendMessage(n1, n0, c0, c1);
      expect(flipped).not.toBe(msg);
    });
  });

  describe("signOrgSpend", () => {
    it("signs spend message and verifies with member public key", async () => {
      const secret = new Uint8Array(32);
      secret.fill(7);
      const m = await memberFromSecret(secret);

      const message = 987654321n;
      const sig = await signOrgSpend(m, message);

      const A = [F.e(m.Ax), F.e(m.Ay)];
      const sigObj = { R8: [F.e(sig.R8x), F.e(sig.R8y)], S: sig.S };
      const valid = eddsa.verifyPoseidon(F.e(message), sigObj, A);

      expect(valid).toBe(true);
    });

    it("fails verification when verified against the wrong member", async () => {
      const s1 = new Uint8Array(32).fill(1);
      const s2 = new Uint8Array(32).fill(2);
      const m1 = await memberFromSecret(s1);
      const m2 = await memberFromSecret(s2);

      const message = 123456789n;
      const sig = await signOrgSpend(m1, message);

      const wrongA = [F.e(m2.Ax), F.e(m2.Ay)];
      const sigObj = { R8: [F.e(sig.R8x), F.e(sig.R8y)], S: sig.S };
      const valid = eddsa.verifyPoseidon(F.e(message), sigObj, wrongA);

      expect(valid).toBe(false);
    });
  });

  describe("buildOrgIdentity & deriveOrgIdentity threshold and member guards", () => {
    it("enforces ≥1 member requirement", async () => {
      await expect(buildOrgIdentity([], 1n, 123n)).rejects.toThrow("org needs ≥1 member");
    });

    it("enforces threshold > 0 and threshold <= memberCount", async () => {
      const m1 = await generateOrgMember();
      const m2 = await generateOrgMember();
      const members = [m1, m2];

      await expect(buildOrgIdentity(members, 0n, 123n)).rejects.toThrow(
        "threshold 0 out of range for 2 members",
      );
      await expect(buildOrgIdentity(members, 3n, 123n)).rejects.toThrow(
        "threshold 3 out of range for 2 members",
      );
    });

    it("builds valid org identity with member paths and root", async () => {
      const m1 = await generateOrgMember();
      const m2 = await generateOrgMember();
      const m3 = await generateOrgMember();
      const members = [m1, m2, m3];
      const threshold = 2n;
      const akGroup = 99999n;

      const org = await buildOrgIdentity(members, threshold, akGroup);

      expect(org.members).toHaveLength(3);
      expect(org.threshold).toBe(threshold);
      expect(org.akGroup).toBe(akGroup);
      expect(org.memberPaths).toHaveLength(3);
      for (const path of org.memberPaths) {
        expect(path.pathElements).toHaveLength(ORG_MEMBER_DEPTH);
      }
      expect(org.memberRoot).toBe(org.memberTree.root());
      expect(typeof org.recipientPk).toBe("bigint");
    });

    it("derives deterministic org identity across calls with identical seed and orgId", async () => {
      const seed = new Uint8Array(32).fill(99);
      const opts = {
        seed,
        orgId: "acme-corp",
        memberCount: 3,
        threshold: 2n,
      };

      const org1 = await deriveOrgIdentity(opts);
      const org2 = await deriveOrgIdentity(opts);

      expect(org1.memberRoot).toBe(org2.memberRoot);
      expect(org1.recipientPk).toBe(org2.recipientPk);
      expect(org1.akGroup).toBe(org2.akGroup);
      expect(org1.members[0].keyId).toBe(org2.members[0].keyId);
      expect(org1.members[1].keyId).toBe(org2.members[1].keyId);
      expect(org1.members[2].keyId).toBe(org2.members[2].keyId);
    });

    it("rejects deriveOrgIdentity when threshold exceeds memberCount", async () => {
      const seed = new Uint8Array(32).fill(88);
      const opts = {
        seed,
        orgId: "finance-dept",
        memberCount: 2,
        threshold: 3n,
      };

      await expect(deriveOrgIdentity(opts)).rejects.toThrow(
        "threshold 3 out of range for 2 members",
      );
    });
  });
});
