import { describe, expect, it, vi } from "vitest";
import { noteCommitment } from "../src/notes.js";
import {
  PAYROLL_LINES,
  type PayrollLineInput,
  payrollCommitDigest,
  payrollGross,
  provePayrollComputation,
} from "../src/payrollcomp.js";
import type { ProveResult, ProverPort } from "../src/prover.js";

const ASSET_ID = 123456789n;
const ARTIFACTS = { wasmPath: "mock.wasm", zkeyPath: "mock.zkey" };
const LINE: PayrollLineInput = {
  rate: 100n,
  period: 2n,
  deductions: 10n,
  recipientPk: 987654321n,
  blinding: 42n,
};

function mockProver(): ProverPort {
  return {
    name: "mock",
    prove: vi.fn(async (): Promise<ProveResult> => ({
      proof: {
        pi_a: ["0", "0", "1"],
        pi_b: [["0", "0"], ["0", "0"], ["1", "0"]],
        pi_c: ["0", "0", "1"],
      },
      publicSignals: ["0", "0", "0", "0"],
      sorobanProof: { a: "00".repeat(64), b: "00".repeat(128), c: "00".repeat(64) },
      sorobanPublics: ["0", "0", "0", "0"],
    })),
  };
}

describe("provePayrollComputation", () => {
  it("proves a valid two-line run with zero-line padding and matching digest", async () => {
    const prover = mockProver();
    const lines = [LINE, { ...LINE, rate: 50n, period: 3n, deductions: 20n }];

    const result = await provePayrollComputation({
      prover, artifacts: ARTIFACTS, lines, assetId: ASSET_ID,
    });

    expect(prover.prove).toHaveBeenCalledTimes(1);
    expect(result.runTotal).toBe(320n);
    const commitments = lines.map((line) => noteCommitment({
      amount: payrollGross(line),
      recipientPk: line.recipientPk,
      blinding: line.blinding,
      assetId: ASSET_ID,
    }));
    while (commitments.length < PAYROLL_LINES) {
      commitments.push(noteCommitment({
        amount: 0n, recipientPk: 0n, blinding: 0n, assetId: ASSET_ID,
      }));
    }
    expect(result.commitDigest).toBe(payrollCommitDigest(commitments));
    expect(prover.prove).toHaveBeenCalledWith(ARTIFACTS, expect.objectContaining({
      runTotal: "320",
      commitDigest: result.commitDigest.toString(),
      rate: ["100", "50", "0", "0"],
      period: ["2", "3", "0", "0"],
      deductions: ["10", "20", "0", "0"],
      recipientPk: ["987654321", "987654321", "0", "0"],
      blinding: ["42", "42", "0", "0"],
    }));
  });

  it("rejects a negative gross before proving", async () => {
    const prover = mockProver();
    await expect(provePayrollComputation({
      prover,
      artifacts: ARTIFACTS,
      lines: [LINE, { ...LINE, deductions: 201n }],
      assetId: ASSET_ID,
    })).rejects.toThrow("payroll line 1 gross is outside the unsigned 64-bit range: -1");
    expect(prover.prove).not.toHaveBeenCalled();
  });

  it("rejects a total overflow with individually valid grosses before proving", async () => {
    const prover = mockProver();
    const line = { ...LINE, rate: 1n << 31n, period: 1n << 31n, deductions: 0n };
    await expect(provePayrollComputation({
      prover,
      artifacts: ARTIFACTS,
      lines: Array.from({ length: PAYROLL_LINES }, () => ({ ...line })),
      assetId: ASSET_ID,
    })).rejects.toThrow("payroll run total is outside the unsigned 64-bit range: 18446744073709551616");
    expect(prover.prove).not.toHaveBeenCalled();
  });

  it("rejects a gross above the unsigned 64-bit range before proving", async () => {
    const prover = mockProver();
    await expect(provePayrollComputation({
      prover,
      artifacts: ARTIFACTS,
      lines: [{ ...LINE, rate: 1n << 64n, period: 1n, deductions: 0n }],
      assetId: ASSET_ID,
    })).rejects.toThrow("payroll line 0 gross is outside the unsigned 64-bit range: 18446744073709551616");
    expect(prover.prove).not.toHaveBeenCalled();
  });

  it("preserves the existing error for more than PAYROLL_LINES lines", async () => {
    const prover = mockProver();
    await expect(provePayrollComputation({
      prover,
      artifacts: ARTIFACTS,
      lines: Array.from({ length: PAYROLL_LINES + 1 }, () => ({ ...LINE })),
      assetId: ASSET_ID,
    })).rejects.toThrow(`payroll computation supports at most ${PAYROLL_LINES} lines`);
    expect(prover.prove).not.toHaveBeenCalled();
  });
});
