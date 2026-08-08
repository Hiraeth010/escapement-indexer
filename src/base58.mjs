// SPDX-License-Identifier: Apache-2.0
/**
 * base58.mjs — base58 encode/decode, no dependencies.
 *
 * Lifted from `ops/src/census/crypto.mjs` (same house, same convention: return
 * null on bad input rather than throwing) and kept as a copy rather than an
 * import so that `indexer/` is independently publishable — a stranger clones
 * this directory alone and it runs.
 *
 * This file is NOT on the entitlement path. It converts identifiers to and from
 * bytes; it never touches a balance, a duration, or a payout. The `| 0` and `/`
 * below are integer operations on small values inside the base-conversion loop
 * and are excluded from the no-floating-point rule by scope, not by exception —
 * see `nofloat.test.mjs` for the modules the rule actually covers.
 */

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP = new Map([...B58_ALPHABET].map((c, i) => [c, i]));

/** Encode bytes to base58. */
export function b58encode(bytes) {
  if (!bytes || bytes.length === 0) return '';
  const input = Uint8Array.from(bytes);

  let zeros = 0;
  while (zeros < input.length && input[zeros] === 0) zeros++;

  const digits = [];
  for (let i = zeros; i < input.length; i++) {
    let carry = input[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i]];
  return out;
}

/** Decode base58 to Uint8Array. Returns null on an invalid character. */
export function b58decode(str) {
  if (typeof str !== 'string' || str.length === 0) return null;

  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;

  const bytes = [];
  for (let i = zeros; i < str.length; i++) {
    const val = B58_MAP.get(str[i]);
    if (val === undefined) return null;
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}

/** True if `s` decodes to exactly 32 bytes — i.e. looks like a pubkey. */
export function isPubkey(s) {
  const d = b58decode(s);
  return d !== null && d.length === 32;
}

/**
 * Decode a pubkey or throw. Used at every boundary where a malformed address
 * would otherwise be silently carried into a merkle leaf.
 */
export function pubkeyBytes(s, what = 'pubkey') {
  const d = b58decode(s);
  if (d === null || d.length !== 32) {
    throw new Error(`${what}: ${JSON.stringify(s)} is not a 32-byte base58 pubkey`);
  }
  return d;
}

/**
 * Byte-wise comparison of two base58 pubkeys, as an ordering.
 *
 * This is the ONE sort key used for every claimant ordering in the project.
 * Base58 string ordering is NOT the same as byte ordering (the alphabet skips
 * characters and is not in ASCII order), so sorting the strings would produce a
 * different tree — and a different root — from sorting the bytes. D10 says
 * "sorted ascending by claimant pubkey bytes"; this function is that sentence.
 */
export function comparePubkeys(a, b) {
  const x = pubkeyBytes(a, 'sort key');
  const y = pubkeyBytes(b, 'sort key');
  for (let i = 0; i < 32; i++) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  }
  return 0;
}
