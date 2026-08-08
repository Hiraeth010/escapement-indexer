// SPDX-License-Identifier: Apache-2.0
/**
 * entitle.test.mjs — the rounding direction, proved rather than asserted.
 *
 * A3 says rounding is floor and that it must favour the vault. That is a claim
 * about every possible input, so it is tested against a large randomised sample
 * rather than three hand-picked cases: for 5,000 random distributions, the sum
 * of payouts never exceeds the vault, and the stranded remainder never exceeds
 * the n-1 bound the published spec (/spec §4.4) states.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { distribute } from './entitle.mjs';
import { pk } from './mockchain.test.mjs';

/** Deterministic PRNG, so a failure is reproducible from the seed alone. */
function rng(seed) {
  let s = BigInt(seed);
  return (n) => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return (s >> 17n) % BigInt(n);
  };
}

test('the worked example from /spec §4.3 foots', () => {
  // 100 SOL of volume at 30bps creator share = 300_000_000 lamports.
  const vault = 300_000_000n;
  const ledger = [
    { owner: pk(1), tokenSlots: 1_000_000n * 86_400n },
    { owner: pk(2), tokenSlots: 4_000_000n * 21_600n },
    { owner: pk(3), tokenSlots: 1_500_000n * 43_200n },
  ];
  const d = distribute({ vaultLamports: vault, ledger });

  // 86,400,000,000 + 86,400,000,000 + 64,800,000,000
  assert.equal(d.totalTokenSlots, 237_600_000_000n);
  // A and B hold identical token-slots and are therefore owed identical amounts,
  // which is the line /spec §4.3 tells the reader to stare at.
  assert.equal(d.rows.find((r) => r.owner === pk(1)).payout, d.rows.find((r) => r.owner === pk(2)).payout);
  assert.equal(d.distributed + d.remainder, vault);
  assert.ok(d.remainder >= 0n && d.remainder <= 2n);
});

test('floor rounding never over-allocates, over 5,000 random distributions', () => {
  const rand = rng(20260808);
  for (let trial = 0; trial < 5000; trial++) {
    const n = Number(rand(24)) + 1;
    const vault = rand(10n ** 12n) + 1n;
    const ledger = Array.from({ length: n }, (_, i) => ({
      owner: pk(i + 1),
      tokenSlots: rand(10n ** 18n) + 1n,
    }));
    const d = distribute({ vaultLamports: vault, ledger });

    assert.ok(d.distributed <= vault, `trial ${trial}: over-allocated`);
    assert.equal(d.distributed + d.remainder, vault);
    assert.ok(d.remainder >= 0n, `trial ${trial}: negative remainder`);
    assert.ok(d.remainder <= BigInt(n - 1), `trial ${trial}: remainder ${d.remainder} > n-1 = ${n - 1}`);

    // Every individual payout is at or below its exact rational share.
    for (const r of d.rows) {
      assert.ok(r.payout * d.totalTokenSlots <= vault * r.tokenSlots, `trial ${trial}: ${r.owner} rounded up`);
    }
  }
});

test('an empty ledger retains the whole vault instead of dividing by zero', () => {
  const d = distribute({ vaultLamports: 12_345n, ledger: [] });
  assert.equal(d.rows.length, 0);
  assert.equal(d.distributed, 0n);
  assert.equal(d.remainder, 12_345n);
  assert.equal(d.totalTokenSlots, 0n);
});

test('cumulative leaves cannot claw back a previous grant (G3)', () => {
  const alice = pk(1);
  const bob = pk(2);

  // Period 1: both hold.
  const p1 = distribute({
    vaultLamports: 1000n,
    ledger: [{ owner: alice, tokenSlots: 1n }, { owner: bob, tokenSlots: 1n }],
  });
  const prior = new Map(p1.rows.map((r) => [r.owner, r.cumulative]));
  assert.equal(prior.get(alice), 500n);

  // Period 2: Alice has sold everything and accrues nothing.
  const p2 = distribute({ vaultLamports: 1000n, ledger: [{ owner: bob, tokenSlots: 1n }], prior });

  const aliceRow = p2.rows.find((r) => r.owner === alice);
  assert.ok(aliceRow, 'an owner who accrued nothing this period must still appear, carrying their cumulative');
  assert.equal(aliceRow.payout, 0n);
  assert.equal(aliceRow.cumulative, 500n, 'the new root must not reduce what the old root granted');
  assert.equal(p2.rows.find((r) => r.owner === bob).cumulative, 1500n);
  assert.equal(p2.totalOwedCumulative, 2000n);
});

test('bad inputs are refused, not coerced', () => {
  assert.throws(() => distribute({ vaultLamports: 100, ledger: [] }), /must be a bigint/);
  assert.throws(() => distribute({ vaultLamports: -1n, ledger: [] }), /negative/);
  assert.throws(() => distribute({ vaultLamports: 1n, ledger: [{ owner: pk(1), tokenSlots: 0n }] }), /non-positive/);
  assert.throws(() => distribute({ vaultLamports: 1n, ledger: [{ owner: pk(1), tokenSlots: 5 }] }), /not a bigint/);
});
