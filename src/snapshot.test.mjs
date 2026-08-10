import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateCost, ledgerToCsv, costTable, SLOTS_PER_DAY } from './snapshot.mjs';

test('the cost estimate is stated in the units someone decides with', () => {
  const day = estimateCost(0, SLOTS_PER_DAY);
  assert.equal(day.slots, 216_000);
  assert.ok(day.days === 1, `a day of slots should be one day, got ${day.days}`);
  assert.ok(day.gigabytes > 1000, 'a day of chain is terabytes, not gigabytes');
  assert.equal(day.feasibleOnFreeRpc, false);
});

test('feasibility agrees with the cost printed beside it', () => {
  // The first version returned `slots <= 20_000`, which called 226 GB "feasible
  // on a free RPC" while the same function computed that number two lines
  // above. A threshold chosen in one unit while the cost is reported in another
  // is a coincidence, not a threshold. So this asserts the RELATIONSHIP rather
  // than a hardcoded slot count.
  for (const slots of [100, 1_000, 7_200, 20_000, 100_000, 216_000]) {
    const e = estimateCost(0, slots);
    if (e.feasibleOnFreeRpc) {
      assert.ok(e.gigabytes <= 20, `called ${e.gigabytes.toFixed(1)} GB feasible`);
      assert.ok(e.fetchHours <= 1, `called a ${e.fetchHours.toFixed(1)} h fetch feasible`);
    }
  }
  assert.equal(estimateCost(0, 100).feasibleOnFreeRpc, true, 'a tiny range must be usable');
  assert.equal(estimateCost(0, SLOTS_PER_DAY).feasibleOnFreeRpc, false, 'a day of chain is 2.4 TB');
});

test('the cost table names the wall rather than leaving it to be discovered', () => {
  const t = costTable();
  assert.match(t, /free public RPC/);
  assert.match(t, /paid archival endpoint/);
  // The point of the table is that the affordable rows and the unaffordable
  // rows are both visible in the same place.
  assert.match(t, /yes/);
  assert.match(t, /no —/);
});

test('CSV is ordered by holding, descending', () => {
  const csv = ledgerToCsv([
    { owner: 'small', tokenSlots: 1n },
    { owner: 'huge', tokenSlots: 1000n },
    { owner: 'mid', tokenSlots: 10n },
  ]);
  const owners = csv.trim().split('\n').slice(1).map((l) => l.split(',')[0]);
  assert.deepEqual(owners, ['huge', 'mid', 'small'],
    'the largest holder must be the first line — on a raw snapshot that is usually the AMM pool, '
    + 'and it should be impossible to miss');
});

test('shares are computed in integer arithmetic and sum to ~1', () => {
  // token_slots are enormous; a float share would lose precision, and this is
  // the column a downstream airdrop multiplies by.
  const csv = ledgerToCsv([
    { owner: 'a', tokenSlots: 793_100_000_000_000n },
    { owner: 'b', tokenSlots: 206_900_000_000_000n },
  ]);
  const shares = csv.trim().split('\n').slice(1).map((l) => Number(l.split(',')[2]));
  assert.ok(Math.abs(shares[0] - 0.7931) < 1e-9, `expected 0.7931, got ${shares[0]}`);
  assert.ok(Math.abs(shares.reduce((x, y) => x + y, 0) - 1) < 1e-9);
});

test('an empty ledger produces a header and no rows rather than throwing', () => {
  assert.equal(ledgerToCsv([]), 'owner,token_slots,share_of_total\n');
});

test('a zero-total ledger does not divide by zero', () => {
  const csv = ledgerToCsv([{ owner: 'x', tokenSlots: 0n }]);
  assert.match(csv, /^owner,token_slots,share_of_total\nx,0,0\n$/);
});
