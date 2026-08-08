import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, hashValue, LineHasher, prettyCanonical } from './canonical.mjs';

test('object key order cannot affect the bytes', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(hashValue({ x: { z: 1, y: 2 } }), hashValue({ x: { y: 2, z: 1 } }));
});

test('a bigint survives as a decimal string, at any size', () => {
  const big = (1n << 127n) + 7n;
  assert.equal(canonicalJson({ v: big }), `{"v":"${big.toString(10)}"}`);
});

test('a float is refused, not rounded — D7/A1 at the serialisation boundary', () => {
  assert.throws(() => canonicalJson({ v: 0.1 }), /No floating point is permitted/);
  assert.throws(() => canonicalJson({ v: 1 / 3 }), /No floating point is permitted/);
  assert.throws(() => canonicalJson({ v: NaN }), /non-finite/);
  assert.throws(() => canonicalJson({ v: Infinity }), /non-finite/);
  assert.throws(() => canonicalJson({ v: Number.MAX_SAFE_INTEGER + 2 }), /use a bigint/);
});

test('undefined is refused so "absent" and "present but empty" cannot collide', () => {
  assert.throws(() => canonicalJson({ v: undefined }), /Omit the key or use null/);
  assert.equal(canonicalJson({ v: null }), '{"v":null}');
});

test('the line hasher is order-sensitive and newline-safe', () => {
  const a = new LineHasher().push('one').push('two');
  const b = new LineHasher().push('two').push('one');
  assert.notEqual(a.digest(), b.digest());
  assert.equal(a.text(), 'one\ntwo\n');
  assert.throws(() => new LineHasher().push('a\nb'), /contains a newline/);

  // digest() must be repeatable and must not close the hash
  const h = new LineHasher().push('x');
  const first = h.digest();
  assert.equal(h.digest(), first);
  h.push('y');
  assert.notEqual(h.digest(), first);
});

test('pretty output keeps the canonical key order', () => {
  assert.equal(prettyCanonical({ b: 1, a: 2 }), '{\n  "a": 2,\n  "b": 1\n}\n');
});
