/**
 * nofloat.test.mjs — A1/D7 as a build failure rather than a code-review habit.
 *
 * "No floating point anywhere in the entitlement path" is the kind of rule that
 * is true on the day it is written and false six months later. This is the lint.
 *
 * Scope is deliberately narrow and named: the four modules that compute a
 * number a claimant is paid from. Slot indices, array lengths, retry backoff and
 * base58 digit conversion are integer arithmetic on small values elsewhere in
 * the tree and are not covered — a lint that flags everything gets suppressed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const ENTITLEMENT_PATH = ['accrue.mjs', 'entitle.mjs', 'merkle.mjs', 'extract.mjs'];

/**
 * Strip comments, string/template literals and regex literals, so that prose
 * about floats is not a float and `/^\d+$/` is not a division.
 */
function code(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``')
    // A regex literal only appears where a value may start, which after the
    // substitutions above means directly after one of these tokens.
    .replace(/([=(,:[!&|?{};+]\s*)\/(?![*/])(?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+\/[gimsuy]*/g, '$1RE');
}

const BANNED = [
  [/\bparseFloat\b/, 'parseFloat'],
  [/\bMath\.(?!floor\b)[a-z]/i, 'Math.* (other than Math.floor on an index)'],
  [/\bNumber\s*\(\s*(?!v\b)/, 'Number() coercion'],
  [/\buiAmount\b(?!String)/, 'uiAmount — the float field of a token balance; use uiTokenAmount.amount'],
  [/\d+\.\d+(?![\d.])/, 'a decimal literal'],
  [/\btoFixed\b|\btoPrecision\b/, 'toFixed/toPrecision'],
  [/\bBigInt\.asIntN\b|\bBigInt\.asUintN\b/, 'BigInt truncation helpers'],
];

for (const file of ENTITLEMENT_PATH) {
  test(`${file} contains no floating-point arithmetic`, () => {
    const src = code(readFileSync(new URL(`./${file}`, import.meta.url), 'utf8'));
    for (const [re, what] of BANNED) {
      const m = src.match(re);
      assert.equal(m, null, `${file}: found ${what} — ${m?.[0]}`);
    }
  });

  test(`${file} never divides outside BigInt`, () => {
    const src = code(readFileSync(new URL(`./${file}`, import.meta.url), 'utf8'));
    // Any `/` that is not part of a regex, a path, or `/=`. There is exactly one
    // division in the entitlement path (entitle.mjs, vault × slots ÷ total) and
    // both operands are BigInt by construction, checked by the type guards there.
    const divisions = [...src.matchAll(/[^\s/*][ ]*\/[ ]*[^\s/*=]/g)].map((m) => m[0]);
    const allowed = file === 'entitle.mjs' ? 1 : 0;
    assert.ok(
      divisions.length <= allowed,
      `${file}: ${divisions.length} division(s) found (${divisions.join(', ')}), expected at most ${allowed}`,
    );
  });
}

test('the artifact serialiser rejects a float even if one reaches it', async () => {
  const { canonicalJson } = await import('./canonical.mjs');
  assert.throws(() => canonicalJson({ payout: 1.5 }), /No floating point is permitted/);
});
