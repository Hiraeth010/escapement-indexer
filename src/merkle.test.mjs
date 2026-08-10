// SPDX-License-Identifier: Apache-2.0
/**
 * merkle.test.mjs — every pinned choice in D10, asserted.
 *
 * These are the assertions that let a second implementation (in Rust, on chain)
 * be checked against this one without reading the JavaScript.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildTree, leafHash, nodeHash, proofFor, verifyProof, u64le, commitmentDomain, DOMAIN_TAG, EMPTY_ROOT, LEAF_PREFIX, NODE_PREFIX } from './merkle.mjs';
import { independentRoot, independentDomain } from './verify-merkle.mjs';
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
      assert.ok(verifyProof({ domain: CONFIG, claimant, cumulative, proof, root: t.root }), `n=${n} i=${i}`);
      // wrong amount must fail
      assert.equal(verifyProof({ domain: CONFIG, claimant, cumulative: cumulative + 1n, proof, root: t.root }), false);
    }
  }
});

test('a proof from one deployment does not verify against another (C3)', () => {
  const otherConfig = pk(200);
  const entries = Array.from({ length: 5 }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt(i + 1) }));
  const t = buildTree(CONFIG, entries);
  const proof = proofFor(t, 0);
  assert.equal(
    verifyProof({ domain: otherConfig, claimant: t.order[0], cumulative: 1n, proof, root: t.root }),
    false,
  );
  assert.notEqual(buildTree(otherConfig, entries).root, t.root);
});

// ---------------------------------------------------------------------------
// The v2 domain: the leaf's first 32 bytes bind the deployment AND the policy.
// ---------------------------------------------------------------------------

const BINDING_A = 'a'.repeat(64);
const BINDING_B = 'b'.repeat(64);

test('the commitment domain is exactly sha256(len || tag || config || policy_binding)', () => {
  const tag = Buffer.from(DOMAIN_TAG, 'utf8');
  const expected = createHash('sha256')
    .update(Buffer.from([tag.length & 0xff, (tag.length >> 8) & 0xff]))
    .update(tag)
    .update(Buffer.from(pubkeyBytes(CONFIG)))
    .update(Buffer.from(BINDING_A, 'hex'))
    .digest();
  assert.equal(hex(pubkeyBytes(commitmentDomain(CONFIG, BINDING_A))), hex(expected));
  assert.equal(DOMAIN_TAG, 'escapement.merkle/v2:domain');
});

// ---------------------------------------------------------------------------
// The tag is an argument now, so that somebody who is not us can use this.
// ---------------------------------------------------------------------------

test('a custom domain tag produces a different domain, and the default is unchanged by passing it', () => {
  assert.notEqual(commitmentDomain(CONFIG, BINDING_A, 'acme.rewards/v1'),
    commitmentDomain(CONFIG, BINDING_A));
  assert.equal(commitmentDomain(CONFIG, BINDING_A, DOMAIN_TAG),
    commitmentDomain(CONFIG, BINDING_A),
    'passing the default explicitly must be identical to omitting it, or every artifact we have '
    + 'published becomes unreproducible by anyone who reads the signature');
});

test('a proof under one tag does not verify under another', () => {
  const entries = Array.from({ length: 9 }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt(i + 1) }));
  const mine = buildTree(commitmentDomain(CONFIG, BINDING_A), entries);
  const theirs = commitmentDomain(CONFIG, BINDING_A, 'acme.rewards/v1');
  assert.equal(verifyProof({
    domain: theirs, claimant: mine.order[0],
    cumulative: entries.find((e) => e.claimant === mine.order[0]).cumulative,
    proof: proofFor(mine, 0), root: mine.root,
  }), false, 'a third party must not be able to replay our proofs into their tree, or vice versa');
});

test('the tag is length-prefixed, so a shifted tag cannot land in another domain', () => {
  // Without the u16 length, sha256(tag || config || binding) lets an attacker
  // choose a LONGER tag whose extra bytes are the first bytes of the config key
  // — the concatenation is ambiguous and two different (tag, config) pairs hash
  // the same. Constructed concretely: take a config key, move its leading byte
  // into the tag, and check the two do not collide.
  const cfgBytes = Buffer.from(pubkeyBytes(CONFIG));
  const shiftedTag = DOMAIN_TAG + String.fromCharCode(cfgBytes[0]);
  // Only meaningful if that byte is a legal tag character; pick one that is.
  const tagB = /^[\x21-\x7e]$/.test(String.fromCharCode(cfgBytes[0])) ? shiftedTag : `${DOMAIN_TAG}x`;
  assert.notEqual(commitmentDomain(CONFIG, BINDING_A, tagB), commitmentDomain(CONFIG, BINDING_A));

  // The direct statement of the property: tag length is inside the hash.
  assert.notEqual(commitmentDomain(CONFIG, BINDING_A, 'ab'), commitmentDomain(CONFIG, BINDING_A, 'a'));
});

test('a domain tag that cannot be retyped exactly is refused', () => {
  for (const bad of ['', ' ', 'has space', 'tab\there', 'nul\0byte', 'café', 'x'.repeat(129), null, 7]) {
    assert.throws(() => commitmentDomain(CONFIG, BINDING_A, bad),
      /domain tag/, `tag ${JSON.stringify(bad)} must be refused`);
  }
  assert.equal(typeof commitmentDomain(CONFIG, BINDING_A, 'x'.repeat(128)), 'string');

  // `undefined` is NOT a bad tag — it is how the default parameter is selected,
  // and it must stay that way: an explicitly-passed undefined from a caller that
  // did not set the option has to mean "ours", not "throw".
  assert.equal(commitmentDomain(CONFIG, BINDING_A, undefined), commitmentDomain(CONFIG, BINDING_A));
  // But null is a value somebody chose, not an absence, so it is refused above.
});

test('the second implementation agrees on custom tags too', () => {
  for (const t of [DOMAIN_TAG, 'acme.rewards/v1', 'a', 'x'.repeat(128), '~!@#$%^&*()_+']) {
    assert.equal(independentDomain(CONFIG, BINDING_A, t), commitmentDomain(CONFIG, BINDING_A, t), `tag ${t}`);
  }
  for (const bad of ['', 'has space', 'x'.repeat(129)]) {
    assert.throws(() => independentDomain(CONFIG, BINDING_A, bad), /domain tag/);
  }
});

test('the second implementation derives the same domain', () => {
  for (const b of [BINDING_A, BINDING_B, '0'.repeat(64), 'f'.repeat(64)]) {
    assert.equal(independentDomain(CONFIG, b), commitmentDomain(CONFIG, b), `binding ${b.slice(0, 8)}`);
  }
  // Leading zero bytes in the digest must survive base58 encoding on both sides,
  // which is the one place a hand-rolled encoder usually gets it wrong.
  for (let i = 0; i < 200; i++) {
    const b = createHash('sha256').update(String(i)).digest('hex');
    assert.equal(independentDomain(CONFIG, b), commitmentDomain(CONFIG, b), `i=${i}`);
  }
});

test('a different policy binding is a different root, even over identical leaves', () => {
  const entries = Array.from({ length: 7 }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt(i + 1) }));
  const rootA = buildTree(commitmentDomain(CONFIG, BINDING_A), entries).root;
  const rootB = buildTree(commitmentDomain(CONFIG, BINDING_B), entries).root;
  assert.notEqual(rootA, rootB, 'the policy must be inside the root, not merely beside it');

  // And a proof under one policy must not verify under another.
  const t = buildTree(commitmentDomain(CONFIG, BINDING_A), entries);
  const proof = proofFor(t, 0);
  assert.equal(verifyProof({
    domain: commitmentDomain(CONFIG, BINDING_B), claimant: t.order[0],
    cumulative: entries.find((e) => e.claimant === t.order[0]).cumulative, proof, root: t.root,
  }), false);
});

test('a malformed policy binding is refused rather than coerced', () => {
  assert.throws(() => commitmentDomain(CONFIG, 'abc'), /64 lowercase hex/);
  assert.throws(() => commitmentDomain(CONFIG, 'A'.repeat(64)), /64 lowercase hex/);
  assert.throws(() => commitmentDomain(CONFIG, undefined), /64 lowercase hex/);
  assert.throws(() => independentDomain(CONFIG, 'abc'), /64 lowercase hex/);
});

test('the second implementation agrees at every tree size from 0 to 65', () => {
  for (let n = 0; n <= 65; n++) {
    const entries = Array.from({ length: n }, (_, i) => ({ claimant: pk(i + 1), cumulative: BigInt(i * 7919 + 1) }));
    assert.equal(independentRoot(CONFIG, entries), buildTree(CONFIG, entries).root, `n=${n}`);
  }
});
