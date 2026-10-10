/**
 * KYB-as-ZK credential (Z7).
 *
 * Builds + proves the kyb_credential circuit: an org proves it holds a KYB
 * credential signed by an AUTHORIZED issuer, disclosing ONLY "verified business,
 * jurisdiction Y, tier Z" — WITHOUT revealing the underlying documents (only
 * their hash is signed, and it stays private). A scope-bound `orgNullifier` gives
 * one-credential-per-scope Sybil resistance.
 *
 * Node-only (circomlibjs EdDSA/Poseidon/BabyJubJub); exported from index.ts. The
 * managed service holds the issuer key and re-issues credentials from a verified
 * identity (Plaid KYB / document IDV) — the docs never reach the chain.
 *
 * Public inputs: [issuerRegistryRoot, jurisdiction, tier, currentTime, scope,
 *                 orgNullifier, addressBinding].
 */

import { buildEddsa, buildPoseidon } from "circomlibjs";
import { MerkleTreeMirror } from "./merkle.js";
import { type CircuitArtifacts, type ProveResult, type ProverPort, toWitnessInput } from "./prover.js";

export const KYB_ISSUER_LEVELS = 16; // circuit-fixed

/* eslint-disable @typescript-eslint/no-explicit-any */
let _eddsa: any;
let _poseidon: any;
async function tools(): Promise<{ eddsa: any; poseidon: any; babyjub: any; F: any }> {
  if (!_eddsa) _eddsa = await buildEddsa();
  if (!_poseidon) _poseidon = await buildPoseidon();
  // the eddsa object carries the BabyJubJub group (Base8 + mulPointEscalar).
  return { eddsa: _eddsa, poseidon: _poseidon, babyjub: _eddsa.babyJub, F: _poseidon.F };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export interface ProveKybCredentialParams {
  prover: ProverPort; // proving backend
  artifacts: CircuitArtifacts; // kyb_credential wasm + zkey
  issuerSeed: number; // the managed-service KYB issuer (deterministic)
  holderSk: bigint; // the org holder scalar (< 2^253)
  jurisdiction: bigint; // DISCLOSED jurisdiction code
  tier: bigint; // DISCLOSED KYB tier
  docsHash: bigint; // hash of the KYB documents (NEVER revealed)
  expiry: bigint; // credential expiry (unix seconds)
  serial: bigint; // credential serial
  scope: bigint; // sybil scope
  currentTime: bigint; // must be < expiry
}

/** Build the witness and prove the org holds a valid KYB credential. */
export async function proveKybCredential(
  params: ProveKybCredentialParams,
): Promise<ProveResult & { jurisdiction: bigint; tier: bigint; orgNullifier: bigint; addressBinding: bigint; issuerRegistryRoot: bigint }> {
  if (params.currentTime >= params.expiry) {
    throw new Error(`credential expired at ${params.expiry} (current: ${params.currentTime})`);
  }
  const { eddsa, poseidon, babyjub, F } = await tools();

  // Issuer BabyJubJub key + its registry key-id.
  const iprv = new Uint8Array(32).fill(params.issuerSeed & 0xff);
  const ipub = eddsa.prv2pub(iprv);
  const issuerAx = F.toObject(ipub[0]) as bigint;
  const issuerAy = F.toObject(ipub[1]) as bigint;
  const issuerKeyId = F.toObject(poseidon([issuerAx, issuerAy])) as bigint;

  // Holder org public key = BabyPbk(holderSk); addressBinding = Poseidon(Ax, Ay).
  const hp = babyjub.mulPointEscalar(babyjub.Base8, params.holderSk);
  const hAx = F.toObject(hp[0]) as bigint;
  const hAy = F.toObject(hp[1]) as bigint;
  const addressBinding = F.toObject(poseidon([hAx, hAy])) as bigint;
  const orgNullifier = F.toObject(poseidon([params.scope, params.holderSk])) as bigint;

  // Authorized-issuer registry (single-issuer tree for the managed-service issuer).
  const tree = new MerkleTreeMirror(KYB_ISSUER_LEVELS);
  const idx = tree.insert(issuerKeyId);
  const issuerRegistryRoot = tree.root();
  const path = tree.path(idx);

  // The issuer signs the credential message (an F element) the circuit verifies.
  const msgF = poseidon([params.docsHash, addressBinding, issuerKeyId, params.expiry, params.jurisdiction, params.tier, params.serial]);
  const sig = eddsa.signPoseidon(iprv, msgF);

  const witness = toWitnessInput({
    issuerRegistryRoot,
    jurisdiction: params.jurisdiction,
    tier: params.tier,
    currentTime: params.currentTime,
    scope: params.scope,
    orgNullifier,
    addressBinding,
    issuerAx,
    issuerAy,
    sigS: sig.S as bigint,
    sigR8x: F.toObject(sig.R8[0]) as bigint,
    sigR8y: F.toObject(sig.R8[1]) as bigint,
    holderSk: params.holderSk,
    docsHash: params.docsHash,
    expiry: params.expiry,
    serial: params.serial,
    issuerPathElements: path.pathElements,
    issuerPathIndices: BigInt(path.pathIndices),
  });
  const res = await params.prover.prove(params.artifacts, witness);
  return { ...res, jurisdiction: params.jurisdiction, tier: params.tier, orgNullifier, addressBinding, issuerRegistryRoot };
}
