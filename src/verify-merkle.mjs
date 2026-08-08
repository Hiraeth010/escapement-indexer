// SPDX-License-Identifier: Apache-2.0
/**
 * verify-merkle.mjs — a second, deliberately unrelated implementation of the
 * tree in `merkle.mjs`.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS AND IS NOT
 * ---------------------------------------------------------------------------
 * `verify` shares the fetching, decoding and accrual code with the producer, so
 * a bug in THAT code passes verification (the README says so in plain words).
 * The merkle layer is the one place where a second implementation is cheap
 * enough to be worth writing, so it is written: different data structures (a
 * flat rolling array rather than levels), different sorting call, different
 * encoding of the u64, no shared helper except `sha256` and base58 decoding.
 *
 * This catches a coding mistake in one of the two. It does NOT catch a
 * misreading of the specification, because the same person wrote both from the
 * same paragraph. Two implementations by one author are worth something and are
 * not worth what independent implementations are worth. That distinction is in
 * the README rather than only here.
 */

import { createHash } from 'node:crypto';
import { b58decode } from './base58.mjs';

const sha = (buf) => new Uint8Array(createHash('sha256').update(Buffer.from(buf)).digest());

function key32(s) {
  const d = b58decode(s);
  if (!d || d.length !== 32) throw new Error(`verify-merkle: bad pubkey ${s}`);
  return d;
}

/**
 * The v2 leaf domain, derived here a second time.
 *
 * `merkle.mjs` builds this with the project's `sha256` helper and its base58
 * encoder; this builds it with `createHash` and a hand-rolled digit loop. If the
 * two ever disagree, `verify` refuses to report on the publisher at all — which
 * is the point of having a second implementation of the layer that turns policy
 * into a commitment, not only of the layer that turns leaves into a root.
 */
export function independentDomain(configPubkey, policyBindingHex) {
  if (!/^[0-9a-f]{64}$/.test(policyBindingHex ?? '')) {
    throw new Error('verify-merkle: policy binding must be 64 lowercase hex characters');
  }
  const tag = Buffer.from('escapement.merkle/v2:domain', 'utf8');
  const cfg = Buffer.from(key32(configPubkey));
  const bind = Buffer.from(policyBindingHex, 'hex');
  const digest = createHash('sha256').update(Buffer.concat([tag, cfg, bind])).digest();

  // base58, written out rather than imported, for the same reason as the rest.
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const byte of digest) n = (n << 8n) | BigInt(byte);
  let s = '';
  while (n > 0n) {
    s = ALPHABET[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const byte of digest) {
    if (byte !== 0) break;
    s = '1' + s;
  }
  return s;
}

function leafBytes(domain, claimant, cumulative) {
  const out = new Uint8Array(1 + 32 + 32 + 8);
  out[0] = 0x00;
  out.set(key32(domain), 1);
  out.set(key32(claimant), 33);
  let v = BigInt(cumulative);
  if (v < 0n || v > (1n << 64n) - 1n) throw new Error('verify-merkle: cumulative out of u64 range');
  for (let i = 0; i < 8; i++) { out[65 + i] = Number(v % 256n); v /= 256n; }
  return out;
}

function pair(a, b) {
  let swap = false;
  for (let i = 0; i < 32; i++) {
    if (a[i] === b[i]) continue;
    swap = a[i] > b[i];
    break;
  }
  const [x, y] = swap ? [b, a] : [a, b];
  const out = new Uint8Array(65);
  out[0] = 0x01;
  out.set(x, 1);
  out.set(y, 33);
  return sha(out);
}

const EMPTY = Buffer.from(sha(Buffer.from('escapement.merkle/v1:empty', 'utf8'))).toString('hex');

/**
 * @param {string} domain base58 32 bytes — see `independentDomain`
 * @param {{claimant: string, cumulative: bigint|string}[]} entries
 * @returns {string} root, lowercase hex
 */
export function independentRoot(domain, entries) {
  if (entries.length === 0) return EMPTY;

  const withBytes = entries.map((e) => ({ k: key32(e.claimant), e }));
  withBytes.sort((p, q) => {
    for (let i = 0; i < 32; i++) if (p.k[i] !== q.k[i]) return p.k[i] - q.k[i];
    return 0;
  });
  for (let i = 1; i < withBytes.length; i++) {
    let same = true;
    for (let j = 0; j < 32; j++) if (withBytes[i - 1].k[j] !== withBytes[i].k[j]) { same = false; break; }
    if (same) throw new Error('verify-merkle: duplicate claimant');
  }

  let level = withBytes.map(({ e }) => sha(leafBytes(domain, e.claimant, e.cumulative)));
  while (level.length > 1) {
    const next = [];
    let i = 0;
    while (i < level.length) {
      if (i === level.length - 1) next.push(level[i]);   // odd tail: promoted, unchanged
      else next.push(pair(level[i], level[i + 1]));
      i += 2;
    }
    level = next;
  }
  return Buffer.from(level[0]).toString('hex');
}
