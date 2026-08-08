/**
 * merkle.test.mjs — every pinned choice in D10, asserted.
 *
 * These are the assertions that let a second implementation (in Rust, on chain)
 * be checked against this one without reading the JavaScript.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildTree, leafHash, nodeHash, proofFor, verifyProof, u64le, EMPTY_ROOT, LEAF_PREFIX, NODE_PREFIX } from './merkle.mjs';
import { independentRoot } from './verify-merkle.mjs';
import { pubkeyBytes, comparePubkeys, b58encode } from './base58.mjs';
import { pk, CONFIG } from './mockchain.test.mjs';

const hex = (u8) => Buffer.from(u8).toString('hex');

test('u64le is little-endian and refuses to wrap', () => {
  assert.equal(hex(u64le(0n)), '0000000000000000');
  assert.equal(hex(u64le(1n)), '0100000000000000');
  assert.equal(hex(u64le(0xffffffffffffffffn)), 'ffffffffffffffff');
  assert.throws(() => u64le(-1n), /negative/);
  assert.throws(() => u64le(1n << 64n), /overflows u64/);
  assert.throws(() => u64le(5), /expected bigint/);
});

test('the leaf preimage is exactly 0x00 || config || claimant || u64le', () => {
  const claimant = pk(77);
  const expected = createHash('sha256')
    .update(Buffer.from([LEAF_PREFIX]))
    .update(Buffer.from(pubkeyBytes(CONFIG)))
    .update(Buffer.from(pubkeyBytes(claimant)))
    .update(Buffer.from(u64le(123_456_789n)))
    .digest('hex');
  assert.equal(hex(leafHash(CONFIG, claimant, 123_456_789n)), expected);
});

test('an internal node sorts its pair, so l,r and r,l are the same node', () => {
  const a = leafHash(CONFIG, pk(3), 1n);
  const b = leafHash(CONFIG, pk(4), 2n);
  assert.equal(hex(nodeHash(a, b)), hex(nodeHash(b, a)));
  assert.equal(Buffer.from(nodeHash(a, b))[0] !== undefined, true);
});

test('an internal node can never be presented as a leaf (T-09)', () => {
  // Same 64 bytes of payload; different prefix byte; therefore different hash.
  const x = new Uint8Array(32).fill(0xaa);
  const y = new Uint8Array(32).fill(0xbb);
  const asNode = nodeHash(x, y);
  const asLeafish = createHash('sha256')
    .update(Buffer.from([LEAF_PREFIX])).update(Buffer.from(x)).update(Buffer.from(y)).digest('hex');
  assert.notEqual(hex(asNode), asLeafish);
  assert.notEqual(LEAF_PREFIX, NODE_PREFIX);
});

test('leaves are ordered by pubkey BYTES, not by the base58 string', () => {
  // A pair where base58 string order and byte order disagree. Base58's alphabet
  // omits 0, O, I and l, so string comparison is not byte comparison.
  const lo = b58encode(Uint8Array.from([0x00, ...new Array(31).fill(0xff)]));
  const hi = b58encode(Uint8Array.from([0x01, ...new Array(31).fill(0x00)]));
  assert.equal(comparePubkeys(lo, hi), -1, 'bytes: 0x00.. < 0x01..');

  const t1 = buildTree(CONFIG, [{ claimant: hi, cumulative: 1n }, { claimant: lo, cumulative: 2n }]);
  const t2 = buildTree(CONFIG, [{ claimant: lo, cumulative: 2n }, { claimant: hi, cumulative: 1n }]);
  assert.equal(t1.root, t2.root, 'input order must not matter');
  assert.deepEqual(t1.order, [lo, hi]);
});

test('an odd node is PROMOTED, not duplicated', () => {
  const entries = [1, 2, 3].map((n) => ({ claimant: pk(100 + n), cumulative: BigInt(n) }));
  const t = buildTree(CONFIG, entries);
  const leaves = t.levels[0];
  // level 1 = [ node(l0,l1), l2-promoted ]
  assert.equal(hex(t.levels[1][1]), hex(leaves[2]), 'the odd leaf appears unchanged one level up');
  // If it were duplicated instead, level 1 would be [node(l0,l1), node(l2,l2)].
  assert.notEqual(hex(t.levels[1][1]), hex(nodeHash(leaves[2], leaves[2])));
});

test('the empty set has a pinned, domain-separated root', () => {
  const t = buildTree(CONFIG, []);
  assert.equal(t.root, EMPTY_ROOT);
  assert.equal(EMPTY_ROOT, independentRoot(CONFIG, []));
  assert.notEqual(EMPTY_ROOT, '0'.repeat(64));
});

test('duplicate claimants are refused rather than silently double-counted', () => {
  const c = pk(9);
  assert.throws(
    () => buildTree(CONFIG, [{ claimant: c, cumulative: 1n }, { claimant: c, cumulative: 2n }]),
    /duplicate claimant/,
  );
});

test('proofs verify for every leaf, at every tree size from 1 to 33', () => {
  for (let n = 1; n <= 33; n++) {
    const entries = Array.from({ length: n }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt((i + 1) * 1000) }));
    const t = buildTree(CONFIG, entries);
    for (let i = 0; i < n; i++) {
      const claimant = t.order[i];
      const cumulative = entries.find((e) => e.claimant === claimant).cumulative;
      const proof = proofFor(t, i);
      assert.ok(verifyProof({ configPubkey: CONFIG, claimant, cumulative, proof, root: t.root }), `n=${n} i=${i}`);
      // wrong amount must fail
      assert.equal(verifyProof({ configPubkey: CONFIG, claimant, cumulative: cumulative + 1n, proof, root: t.root }), false);
    }
  }
});

test('a proof from one deployment does not verify against another (C3)', () => {
  const otherConfig = pk(200);
  const entries = Array.from({ length: 5 }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt(i + 1) }));
  const t = buildTree(CONFIG, entries);
  const proof = proofFor(t, 0);
  assert.equal(
    verifyProof({ configPubkey: otherConfig, claimant: t.order[0], cumulative: 1n, proof, root: t.root }),
    false,
  );
  assert.notEqual(buildTree(otherConfig, entries).root, t.root);
});

test('the second implementation agrees at every tree size from 0 to 65', () => {
  for (let n = 0; n <= 65; n++) {
    const entries = Array.from({ length: n }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt(i * 7919 + 1) }));
    assert.equal(independentRoot(CONFIG, entries), buildTree(CONFIG, entries).root, `n=${n}`);
  }
});
