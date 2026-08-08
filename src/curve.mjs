// SPDX-License-Identifier: Apache-2.0
/**
 * curve.mjs — "is this 32-byte value a valid ed25519 public key".
 *
 * ---------------------------------------------------------------------------
 * PROVENANCE
 * ---------------------------------------------------------------------------
 * This is a port of the ed25519 field arithmetic in `ops/src/census/crypto.mjs`,
 * kept as a copy for the same reason `base58.mjs` is a copy: `indexer/` must be
 * independently publishable, so a stranger can clone this directory alone and
 * run it with nothing installed. `curve.test.mjs` asserts that the two copies
 * agree whenever both are present in the same checkout, so the copy cannot drift
 * silently; when only this directory is published, that test skips.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT MEANS, AND — MORE IMPORTANTLY — WHAT IT DOES NOT
 * ---------------------------------------------------------------------------
 * A Solana address is 32 bytes. Only some 32-byte values are valid compressed
 * Edwards points; roughly half are not. An ed25519 PUBLIC KEY is by construction
 * a point on the curve, so:
 *
 *   OFF the curve  =>  no ed25519 secret key exists whose public key is this
 *                      address. There is no preimage to find, no key to lose or
 *                      steal or recover. This is arithmetic, not probability.
 *
 * `find_program_address` exploits exactly this: it rejects any candidate that IS
 * on the curve, so every PDA is off-curve. Off-curve therefore means "program
 * derived address" in practice.
 *
 * It does NOT mean "nobody controls it". A PDA can be signed for by its owning
 * program via `invoke_signed`. See `predicate.mjs`, which is where that
 * distinction is argued and where the consequences are written down.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A PURE FUNCTION OF THE ADDRESS, AND WHY THAT MATTERS
 * ---------------------------------------------------------------------------
 * The answer depends on the 32 bytes and on nothing else: not on account state,
 * not on the slot, not on which RPC you asked, not on when you asked. It is the
 * same answer in 1970 and in 2170. That is the property that lets an exclusion
 * predicate built on it be reproducible by a stranger — see predicate.mjs.
 */

import { b58decode } from './base58.mjs';

const P = (1n << 255n) - 19n;
// d = -121665 / 121666 (mod p)
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
// sqrt(-1) mod p
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

function mod(a) {
  const r = a % P;
  return r < 0n ? r + P : r;
}

/** Modular exponentiation (square-and-multiply). */
function powMod(base, exp) {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

function bytesToFieldLE(bytes) {
  let n = 0n;
  for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

/**
 * True when the 32 bytes decompress to a point on ed25519.
 *
 * Mirrors curve25519-dalek's `CompressedEdwardsY::decompress`: clear the sign bit
 * to get y, then x^2 = (y^2 - 1) / (d*y^2 + 1) must be a quadratic residue.
 */
export function isOnCurve(bytes) {
  if (!bytes || bytes.length !== 32) return false;

  const y = mod(bytesToFieldLE(bytes) & ((1n << 255n) - 1n)); // clear sign bit
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);          // numerator
  const v = mod(D * y2 + 1n);      // denominator

  if (v === 0n) return false;

  // Candidate root: x = u * v^3 * (u * v^7)^((p-5)/8)
  const v2 = (v * v) % P;
  const v3 = (v2 * v) % P;
  const v4 = (v2 * v2) % P;
  const v7 = (v3 * v4) % P;
  const uv3 = (u * v3) % P;
  const uv7 = (u * v7) % P;

  let x = (uv3 * powMod(uv7, (P - 5n) / 8n)) % P;

  const check = (vx2) => mod(vx2 - u) === 0n;
  const vx2 = (v * ((x * x) % P)) % P;

  if (check(vx2)) return true;                    // correct root
  if (mod(vx2 + u) === 0n) return true;           // off by sqrt(-1); still a valid point
  // Some implementations need the explicit sqrt(-1) multiply before rejecting.
  x = (x * SQRT_M1) % P;
  return check((v * ((x * x) % P)) % P);
}

/**
 * The three-valued form used by the predicate.
 *
 * Returns `true` / `false` for a well-formed 32-byte base58 address, and `null`
 * when the input is not one — because "this string is not an address" is a
 * different fact from "this address is off the curve", and collapsing the two
 * would let a malformed owner field be silently excluded. The caller must
 * decide what to do with `null`; `predicate.mjs` refuses the run.
 */
export function pubkeyOnCurve(address) {
  const d = b58decode(address);
  if (d === null || d.length !== 32) return null;
  return isOnCurve(d);
}
