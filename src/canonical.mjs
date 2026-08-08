/**
 * canonical.mjs — one serialisation, so that "hash the inputs" is a definition
 * rather than an intention.
 *
 * Two honest parties must produce byte-identical bytes before they can produce
 * byte-identical hashes. `JSON.stringify` does not give you that: key order is
 * insertion order, and any float in the structure is at the mercy of the
 * shortest-round-trip printer. So:
 *
 *   - object keys are sorted by code unit, always;
 *   - `bigint` serialises as a decimal string (JSON has no integer type that can
 *     hold a u128, and we refuse to lose one);
 *   - a non-integer `number` THROWS. It is not rounded, not stringified, not
 *     tolerated. This is D7/A1 enforced at the serialisation boundary rather
 *     than left to review;
 *   - a `number` outside the safe-integer range also throws, because past 2^53
 *     JavaScript integers are already lying to you;
 *   - `undefined` throws. An absent field and a field-present-but-undefined hash
 *     differently in every implementation that tolerates both.
 */

import { createHash } from 'node:crypto';

export function canonicalJson(value, path = '$') {
  const t = typeof value;

  if (value === null) return 'null';
  if (t === 'boolean') return value ? 'true' : 'false';

  if (t === 'bigint') return JSON.stringify(value.toString(10));

  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error(`canonicalJson(${path}): non-finite number ${value}`);
    if (!Number.isInteger(value)) {
      throw new Error(
        `canonicalJson(${path}): ${value} is not an integer. No floating point is permitted anywhere ` +
        `in this artifact (threat model D7/A1). Use a bigint, or a string if it is genuinely fractional display text.`,
      );
    }
    if (!Number.isSafeInteger(value)) {
      throw new Error(`canonicalJson(${path}): ${value} exceeds Number.MAX_SAFE_INTEGER — use a bigint`);
    }
    return String(value);
  }

  if (t === 'string') return JSON.stringify(value);

  if (Array.isArray(value)) {
    return `[${value.map((v, i) => canonicalJson(v, `${path}[${i}]`)).join(',')}]`;
  }

  if (t === 'object') {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) {
        throw new Error(`canonicalJson(${path}.${k}): undefined. Omit the key or use null; do not leave it ambiguous.`);
      }
      parts.push(`${JSON.stringify(k)}:${canonicalJson(v, `${path}.${k}`)}`);
    }
    return `{${parts.join(',')}}`;
  }

  throw new Error(`canonicalJson(${path}): unserialisable value of type ${t}`);
}

/** sha256 of arbitrary bytes, as a lowercase hex string. */
export function sha256Hex(...chunks) {
  const h = createHash('sha256');
  for (const c of chunks) h.update(typeof c === 'string' ? Buffer.from(c, 'utf8') : Buffer.from(c));
  return h.digest('hex');
}

/** sha256 of arbitrary bytes, as bytes. */
export function sha256(...chunks) {
  const h = createHash('sha256');
  for (const c of chunks) h.update(Buffer.from(c));
  return new Uint8Array(h.digest());
}

/** Hash a JS value through the canonical serialisation above. */
export function hashValue(value) {
  return sha256Hex(canonicalJson(value));
}

/**
 * A streaming sha256 over newline-terminated lines.
 *
 * Used for the input-set commitment (D5). A line-oriented format is chosen over
 * a JSON blob for one reason: when two parties disagree, `diff` localises the
 * disagreement to a slot in one command. A single hash over a nested object
 * tells you only that you disagree.
 */
export class LineHasher {
  constructor() {
    this._h = createHash('sha256');
    this._lines = [];
    this._keep = true;
  }

  /** Stop retaining lines in memory (the hash is unaffected). */
  discardLines() { this._keep = false; this._lines = []; }

  push(line) {
    if (line.includes('\n')) throw new Error('LineHasher.push: line contains a newline');
    this._h.update(Buffer.from(line + '\n', 'utf8'));
    if (this._keep) this._lines.push(line);
    return this;
  }

  get lines() { return this._lines; }
  text() { return this._lines.length ? this._lines.join('\n') + '\n' : ''; }
  digest() { return this._h.copy().digest('hex'); }
}

/** Serialise for humans: same key order as the canonical form, but indented. */
export function prettyCanonical(value) {
  return JSON.stringify(JSON.parse(canonicalJson(value)), null, 2) + '\n';
}
