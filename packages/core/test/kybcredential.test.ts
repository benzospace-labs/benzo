/**
 * Unit tests for KYB credential circuit binding (packages/core/src/kybcredential.ts).
 *
 * Verifies:
 * - Fixed credential fixture with deterministic witness generation.
 * - Issuer-tree depth constant matches 16-level witness array length.
 * - Non-member issuer produces a witness the stub prover rejects.
 * - Tier and jurisdiction values are carried in public inputs.
 * - Expired-but-otherwise-valid credential is rejected before proving.
 */
import { describe, expect, it, vi } from "vitest";
import {
  KYB_ISSUER_LEVELS,
  type ProveKybCredentialParams,
  proveKybCredential,
} from "../src/kybcredential.js";
import type { CircuitArtifacts, ProveResult, ProverPort } from "../src/prover.js";

const ARTIFACTS: CircuitArtifacts = {
  wasmPath: "mock/kyb_credential.wasm",
  zkeyPath: "mock/kyb_credential.zkey",
};

// Fixed credential test fixture
const FIXTURE = {
  issuerSeed: 42,
  holderSk: 12345678901234567890n,
  jurisdiction: 840n, // US
  tier: 3n,
  docsHash: 98765432109876543210n,
  expiry: 1_800_000_000n,
  serial: 101n,
  scope: 777n,
  currentTime: 1_700_000_000n, // valid (currentTime < expiry)
};

function createStubProver(options?: {
  rejectNonMember?: boolean;
  expectedIssuerRoot?: bigint;
}): ProverPort & { capturedWitness: any } {
  const captured: { witness: any } = { witness: null };
  return {
    name: "stub-kyb-prover",
    capturedWitness: captured,
    prove: vi.fn(
      async (
        _artifacts: CircuitArtifacts,
        witness: Record<string, string | string[]>,
      ): Promise<ProveResult> => {
        captured.witness = witness;

        if (options?.rejectNonMember && options.expectedIssuerRoot !== undefined) {
          const witnessRoot = BigInt(witness.issuerRegistryRoot as string);
          if (witnessRoot !== options.expectedIssuerRoot) {
            throw new Error("non-member issuer rejected: registry root mismatch");
          }
        }

        // Circuit public inputs order:
        // [issuerRegistryRoot, jurisdiction, tier, currentTime, scope, orgNullifier, addressBinding]
        const publicSignals = [
          witness.issuerRegistryRoot as string,
          witness.jurisdiction as string,
          witness.tier as string,
          witness.currentTime as string,
          witness.scope as string,
          witness.orgNullifier as string,
          witness.addressBinding as string,
        ];

        return {
          proof: {
            pi_a: ["0", "0", "1"],
            pi_b: [
              ["0", "0"],
              ["0", "0"],
              ["1", "0"],
            ],
            pi_c: ["0", "0", "1"],
          },
          publicSignals,
          sorobanProof: {
            a: "00".repeat(64),
            b: "00".repeat(128),
            c: "00".repeat(64),
          },
          sorobanPublics: publicSignals,
        };
      },
    ),
  };
}

describe("packages/core/src/kybcredential.ts", () => {
  it(
    "proves a valid credential with matching witness structure and public inputs",
    async () => {
      const prover = createStubProver();
      const params: ProveKybCredentialParams = {
        prover,
        artifacts: ARTIFACTS,
        ...FIXTURE,
      };

      const result = await proveKybCredential(params);

      expect(prover.prove).toHaveBeenCalledTimes(1);
      expect(result.tier).toBe(FIXTURE.tier);
      expect(result.jurisdiction).toBe(FIXTURE.jurisdiction);
      expect(typeof result.orgNullifier).toBe("bigint");
      expect(typeof result.addressBinding).toBe("bigint");
      expect(typeof result.issuerRegistryRoot).toBe("bigint");

      // Public inputs carry tier and jurisdiction in designated slots
      expect(result.publicSignals[1]).toBe(FIXTURE.jurisdiction.toString());
      expect(result.publicSignals[2]).toBe(FIXTURE.tier.toString());
    },
    30_000,
  );

  it("asserts the 16-level tree depth constant matches the witness array length", async () => {
    expect(KYB_ISSUER_LEVELS).toBe(16);

    const prover = createStubProver();
    const params: ProveKybCredentialParams = {
      prover,
      artifacts: ARTIFACTS,
      ...FIXTURE,
    };

    await proveKybCredential(params);

    const witness = prover.capturedWitness.witness;
    expect(witness).toBeDefined();
    // Path elements array must have exactly KYB_ISSUER_LEVELS (16) entries
    expect(Array.isArray(witness.issuerPathElements)).toBe(true);
    expect(witness.issuerPathElements).toHaveLength(KYB_ISSUER_LEVELS);
    expect(witness.issuerPathIndices).toBeDefined();
  });

  it("fails closed when an expired credential is submitted before proving", async () => {
    const prover = createStubProver();
    const params: ProveKybCredentialParams = {
      prover,
      artifacts: ARTIFACTS,
      ...FIXTURE,
      currentTime: FIXTURE.expiry + 100n, // expired
    };

    await expect(proveKybCredential(params)).rejects.toThrow("credential expired");
    // Prover must NEVER be invoked for expired credentials
    expect(prover.prove).not.toHaveBeenCalled();
  });

  it("fails closed when credential expiry equals currentTime exactly", async () => {
    const prover = createStubProver();
    const params: ProveKybCredentialParams = {
      prover,
      artifacts: ARTIFACTS,
      ...FIXTURE,
      currentTime: FIXTURE.expiry, // boundary condition
    };

    await expect(proveKybCredential(params)).rejects.toThrow("credential expired");
    expect(prover.prove).not.toHaveBeenCalled();
  });

  it("fails closed when a non-member issuer witness is rejected by the prover", async () => {
    // Prover expects a specific authorized registry root
    const authorizedRoot = 112233445566778899n;
    const prover = createStubProver({
      rejectNonMember: true,
      expectedIssuerRoot: authorizedRoot,
    });

    // Submitting with an unauthorized issuerSeed generates a different registry root
    const params: ProveKybCredentialParams = {
      prover,
      artifacts: ARTIFACTS,
      ...FIXTURE,
      issuerSeed: 999, // non-member issuer
    };

    await expect(proveKybCredential(params)).rejects.toThrow(
      "non-member issuer rejected: registry root mismatch",
    );
    expect(prover.prove).toHaveBeenCalledTimes(1);
  });
});
