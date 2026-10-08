/**
 * Verifiable payroll computation (Z6).
 *
 * Proves the run total AND every per-line note commitment were CORRECTLY DERIVED
 * from the rate card — gross_i = rate_i * period_i - deductions_i, runTotal =
 * Σ gross_i — with the RATE CARD kept PRIVATE. The total is computed, not
 * asserted: the chain accepts it only if it equals the sum of the hidden grosses.
 *
 * `commitDigest` = Poseidon2 binary fold over the per-line note commitments binds
 * the proof to the actual notes; the SDK recomputes it the same way the circuit
 * does so the digest is reproducible from the settled commitments.
 *
 * Public inputs: [runTotal, assetId, context, commitDigest].
 */

import { hash } from "./crypto/poseidon2.js";
import { noteCommitment } from "./notes.js";
import { type CircuitArtifacts, type ProveResult, type ProverPort, toWitnessInput } from "./prover.js";

export const PAYROLL_LINES = 4; // circuit-fixed
export const PAYROLL_DIGEST_DOMAIN = 0x0bn;

export interface PayrollLineInput {
  rate: bigint; // per-period rate (minor units), PRIVATE
  period: bigint; // periods worked (e.g. months/hours), PRIVATE
  deductions: bigint; // deductions (minor units), PRIVATE
  recipientPk: bigint; // payout recipient pk
  blinding: bigint; // note blinding
}

/** gross_i = rate_i * period_i - deductions_i (mirrors the circuit). */
export function payrollGross(line: { rate: bigint; period: bigint; deductions: bigint }): bigint {
  return line.rate * line.period - line.deductions;
}

/** Commitment digest = H( H(c0,c1), H(c2,c3) ) over the 4 line commitments. */
export function payrollCommitDigest(commitments: bigint[]): bigint {
  const c = [...commitments];
  while (c.length < PAYROLL_LINES) c.push(0n);
  const h01 = hash([c[0], c[1]], PAYROLL_DIGEST_DOMAIN);
  const h23 = hash([c[2], c[3]], PAYROLL_DIGEST_DOMAIN);
  return hash([h01, h23], PAYROLL_DIGEST_DOMAIN);
}

export interface ProvePayrollComputationParams {
  prover: ProverPort;
  artifacts: CircuitArtifacts; // payroll_computation wasm + zkey
  lines: PayrollLineInput[]; // ≤ PAYROLL_LINES; padded with zero lines
  assetId: bigint;
  context?: bigint;
}

/**
 * Build the witness and prove the run was correctly computed from the rate card.
 * Returns the computed `runTotal` and `commitDigest` (both public) alongside the
 * proof. Throws (no proof) for more than `PAYROLL_LINES` lines, any line's gross
 * below zero or above the unsigned 64-bit range, or a run total above that range.
 * The circuit's `AmountCheck()` enforces the same 64-bit range for each gross at
 * prove time; the SDK checks up front for clean errors instead of snarkjs failures.
 * The SDK also limits the run total, which the circuit does not range-check.
 */
export async function provePayrollComputation(
  params: ProvePayrollComputationParams,
): Promise<ProveResult & { runTotal: bigint; commitDigest: bigint }> {
  if (params.lines.length > PAYROLL_LINES) {
    throw new Error(`payroll computation supports at most ${PAYROLL_LINES} lines`);
  }
  const maxAmount = (1n << 64n) - 1n;
  let runTotal = 0n;
  for (let i = 0; i < params.lines.length; i++) {
    const gross = payrollGross(params.lines[i]);
    if (gross < 0n || gross > maxAmount) {
      throw new Error(`payroll line ${i} gross is outside the unsigned 64-bit range: ${gross}`);
    }
    runTotal += gross;
    if (runTotal < 0n || runTotal > maxAmount) {
      throw new Error(`payroll run total is outside the unsigned 64-bit range: ${runTotal}`);
    }
  }
  const rate: bigint[] = [];
  const period: bigint[] = [];
  const deductions: bigint[] = [];
  const recipientPk: bigint[] = [];
  const blinding: bigint[] = [];
  const commitments: bigint[] = [];
  for (let i = 0; i < PAYROLL_LINES; i++) {
    const l = params.lines[i];
    if (l) {
      const gross = payrollGross(l);
      rate.push(l.rate);
      period.push(l.period);
      deductions.push(l.deductions);
      recipientPk.push(l.recipientPk);
      blinding.push(l.blinding);
      commitments.push(noteCommitment({ amount: gross, recipientPk: l.recipientPk, blinding: l.blinding, assetId: params.assetId }));
    } else {
      // zero line: gross 0, recipientPk 0, blinding 0
      rate.push(0n);
      period.push(0n);
      deductions.push(0n);
      recipientPk.push(0n);
      blinding.push(0n);
      commitments.push(noteCommitment({ amount: 0n, recipientPk: 0n, blinding: 0n, assetId: params.assetId }));
    }
  }
  const commitDigest = payrollCommitDigest(commitments);
  const witness = toWitnessInput({
    runTotal,
    assetId: params.assetId,
    context: params.context ?? 0n,
    commitDigest,
    rate,
    period,
    deductions,
    recipientPk,
    blinding,
  });
  const res = await params.prover.prove(params.artifacts, witness);
  return { ...res, runTotal, commitDigest };
}
