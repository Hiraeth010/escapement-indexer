// SPDX-License-Identifier: Apache-2.0
/**
 * pot.test.mjs — B7. The pot must be derivable and refusable, and the derivation
 * must be attacked in the direction that FAILS, not only the one that passes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveMaxLegalTotal, checkPot, decodeConfig } from './pot.mjs';

const CAPS = { maxAbsDelta: 250_000_000_000n, divisor: 4n };
const RENT = 1_176_240n;

test('the max legal total is min(I1 ceiling, high_water + G2 delta)', () => {
  // Empty config, vault funded with 40M free: funded 40M, delta cap 10M, so a
  // first root may allocate at most 10M even though the vault holds 40M.
  const d = deriveMaxLegalTotal({
    vaultLamports: 40_000_000n + RENT, rentMin: RENT,
    totalClaimed: 0n, highWater: 0n, ...CAPS,
  });
  assert.equal(d.funded, 40_000_000n);
  assert.equal(d.maxDelta, 10_000_000n);
  assert.equal(d.maxTotal, 10_000_000n);
});

test('the G2 fractional cap binds even when the vault could afford more', () => {
  const state = {
    vaultLamports: 40_000_000n + RENT, rentMin: RENT,
    totalClaimed: 0n, highWater: 0n, ...CAPS,
  };
  // A publisher proposing to allocate half the vault is refused by G2b, not I1.
  const r = checkPot(20_000_000n, state);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'RootDeltaExceedsFraction');
});

test('a proposal above what the vault has ever been funded is RootExceedsFunded', () => {
  // high_water already near funded, so the delta cap is not what bites.
  const state = {
    vaultLamports: 40_000_000n + RENT, rentMin: RENT,
    totalClaimed: 0n, highWater: 39_000_000n, ...CAPS,
  };
  const r = checkPot(41_000_000n, state);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'RootExceedsFunded');
});

test('THE B7 ATTACK: an under-declared pot passes a naive equality but the ceiling still bounds it', () => {
  // The whole point of B7: verification must attack the pot in the direction that
  // fails. A publisher who UNDER-declares the pot strands money; a publisher who
  // OVER-declares is bounced on chain. checkPot must reject the over-declare (the
  // one that would move more money than is legal) rather than only bless the
  // convenient value.
  const state = {
    vaultLamports: 8_000_000n + RENT, rentMin: RENT,
    totalClaimed: 0n, highWater: 0n, ...CAPS,
  };
  // funded 8M, delta cap 2M. Over-declaring 3M must be refused.
  assert.equal(checkPot(3_000_000n, state).ok, false);
  // The honest maximum (2M) is accepted.
  const ok = checkPot(2_000_000n, state);
  assert.equal(ok.ok, true);
  assert.equal(ok.maxTotal, 2_000_000n);
});

test('a decrease below the high-water mark is refused (AllocationWentBackwards)', () => {
  const state = {
    vaultLamports: 40_000_000n + RENT, rentMin: RENT,
    totalClaimed: 5_000_000n, highWater: 10_000_000n, ...CAPS,
  };
  assert.equal(checkPot(9_000_000n, state).reason, 'AllocationWentBackwards');
});

test('total_claimed is folded back into funded, so an already-paid epoch does not shrink the ceiling', () => {
  // funded = (vault - rent) + total_claimed. A vault that has paid out 5M and
  // holds 35M+rent has funded 40M, same as before any claims.
  const d = deriveMaxLegalTotal({
    vaultLamports: 35_000_000n + RENT, rentMin: RENT,
    totalClaimed: 5_000_000n, highWater: 10_000_000n, ...CAPS,
  });
  assert.equal(d.funded, 40_000_000n);
  // high_water 10M + delta 10M = 20M, below the I1 ceiling 40M, so 20M binds.
  assert.equal(d.maxTotal, 20_000_000n);
});

test('decodeConfig reads the mirrored caps and counters at the right offsets', () => {
  // Build a synthetic Config buffer: 8 disc + 96 pubkeys + the u64/i64 fields.
  const buf = Buffer.alloc(8 + 210);
  buf.writeBigUInt64LE(1234n, 8 + 96); // total_claimed
  buf.writeBigUInt64LE(5678n, 8 + 104); // high_water_allocated
  buf.writeBigUInt64LE(9n, 8 + 112); // epoch_count
  buf.writeBigUInt64LE(42n, 8 + 120); // last_cutoff_slot
  buf.writeBigUInt64LE(250_000_000_000n, 8 + 168); // max_root_delta_lamports
  buf.writeBigUInt64LE(4n, 8 + 176); // max_root_delta_divisor
  const cfg = decodeConfig(buf.toString('base64'));
  assert.equal(cfg.total_claimed, 1234n);
  assert.equal(cfg.high_water_allocated, 5678n);
  assert.equal(cfg.epoch_count, 9n);
  assert.equal(cfg.last_cutoff_slot, 42n);
  assert.equal(cfg.max_root_delta_lamports, 250_000_000_000n);
  assert.equal(cfg.max_root_delta_divisor, 4n);
});
