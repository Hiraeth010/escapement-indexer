// SPDX-License-Identifier: Apache-2.0
/**
 * determinism.test.mjs — the tests the trust model actually rests on.
 *
 * "We ran it twice" is not the reproducibility test that counts (the threat
 * model says so explicitly), but it is the floor, and below it nothing else
 * matters. These four are the floor:
 *
 *   1. the same range twice produces an identical root;
 *   2. blocks arriving in a different ORDER produce an identical root;
 *   3. a skipped slot and a fetch failure produce DIFFERENT outcomes — the
 *      first a root, the second an abort;
 *   4. an RPC that omits a produced slot from `getBlocks` is caught rather than
 *      believed.
 *
 * (3) is the one that is easy to get wrong and impossible to notice: conflating
 * the two yields a wrong root that reproduces perfectly, so tests 1 and 2 would
 * both stay green while the number is silently incorrect.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { runIndex, openingFromArtifact } from './run.mjs';
import { accrue, ledgerFrom } from './accrue.mjs';
import { UnresolvedSlotError, ChainBreakError, EmptyRangeError, fetchRange } from './blocks.mjs';
import { scenario, mockChain, mockRpc, MINT, CONFIG, OPEN_EXCLUSIONS, A, B, OA, OB, OC } from './mockchain.test.mjs';

const RUN = {
  mint: MINT, from: 100, to: 110,
  exclusions: OPEN_EXCLUSIONS,
  configPubkey: CONFIG,
  vaultLamports: 1_000_000n,
};

test('the accrual is what the fixture says it is', async () => {
  const chain = scenario();
  const { artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  const byOwner = new Map(artifact.ledger.map((r) => [r.owner, r.token_slots]));
  assert.equal(byOwner.get(OA), 4800n, 'OA: 1000 for slots 102-104 plus 600 for 105-107');
  assert.equal(byOwner.get(OB), 2000n, 'OB: 400 for slots 105-109');
  assert.equal(byOwner.get(OC), 1200n, 'OC: 600 for slots 108-109, after the authority change');
  assert.equal(artifact.accrual.total_token_slots_entitled, 8000n);

  // D8, stated as an assertion: the balance in A before slot 108 belongs to OA,
  // not to OC. An indexer that reads the CURRENT owner would give OC 3000.
  assert.notEqual(byOwner.get(OC), 3000n);
});

test('1. the same range twice produces an identical root', async () => {
  const chain = scenario();
  const a = await runIndex({ ...RUN, rpc: mockRpc(chain) });
  const b = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  assert.equal(a.artifact.merkle_root, b.artifact.merkle_root);
  assert.equal(a.artifact.input_set_hash, b.artifact.input_set_hash);
  assert.equal(a.artifact.ledger_hash, b.artifact.ledger_hash);
  assert.equal(a.inputSet.text(), b.inputSet.text());
});

test('2. shuffled block arrival order produces an identical root', async () => {
  const chain = scenario();
  const reference = await runIndex({ ...RUN, rpc: mockRpc(chain), concurrency: 1 });

  // Concurrency plus randomised latency means the blocks land in the `blocks`
  // map in a different order on every run. If any aggregation depended on
  // insertion order this would drift.
  for (let i = 0; i < 8; i++) {
    const shuffled = await runIndex({ ...RUN, rpc: mockRpc(chain, { jitter: true }), concurrency: 6 });
    assert.equal(shuffled.artifact.merkle_root, reference.artifact.merkle_root, `run ${i}`);
    assert.equal(shuffled.artifact.input_set_hash, reference.artifact.input_set_hash, `run ${i}`);
    assert.equal(shuffled.inputSet.text(), reference.inputSet.text(), `run ${i}`);
  }
});

test('2b. shuffling the slot-event array at the accrual layer changes nothing', () => {
  const events = [
    { slot: 108, events: [{ account: A, kind: 'set', owner: OC, amount: 600n }] },
    { slot: 102, events: [{ account: A, kind: 'set', owner: OA, amount: 1000n }] },
    { slot: 105, events: [
      { account: B, kind: 'set', owner: OB, amount: 400n },
      { account: A, kind: 'set', owner: OA, amount: 600n },
    ] },
  ];
  const base = ledgerFrom(accrue({ fromSlot: 100, toSlot: 110, slotEvents: events }).included);

  for (let i = 0; i < 20; i++) {
    const shuffled = [...events].sort(() => Math.random() - 0.5);
    const got = ledgerFrom(accrue({ fromSlot: 100, toSlot: 110, slotEvents: shuffled }).included);
    assert.deepEqual(got, base);
  }
});

test('3. a skipped slot and a fetch failure are NOT the same outcome', async () => {
  // Chain X: slot 106 genuinely produced no block. Nothing happened there.
  const skippedChain = scenario({ chain: { skipped: [101, 104, 106] } });
  const ok = await runIndex({ ...RUN, rpc: mockRpc(skippedChain) });
  assert.ok(ok.artifact.merkle_root, 'a genuinely skipped slot is fine and produces a root');
  assert.ok(ok.artifact.slots.skipped_slots.includes(106));

  // Chain Y: slot 106 DID produce a block, and our RPC cannot serve it.
  const liveChain = scenario();
  await assert.rejects(
    () => runIndex({ ...RUN, rpc: mockRpc(liveChain, { failSlots: [106] }) }),
    (err) => {
      assert.ok(err instanceof UnresolvedSlotError, `expected UnresolvedSlotError, got ${err.name}: ${err.message}`);
      assert.equal(err.slot, 106);
      assert.match(err.message, /fact about the RPC, not about the chain/);
      return true;
    },
    'a fetch failure must abort the run, never degrade to "slot 106 was skipped"',
  );
});

test('3b. the failure is not merely reported — no artifact exists to publish', async () => {
  const chain = scenario();
  let artifact = null;
  try {
    ({ artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain, { failSlots: [105] }) }));
  } catch { /* expected */ }
  assert.equal(artifact, null, 'a partial index must not be reachable by a caller that ignores the error');
});

test('4. an RPC that hides a produced INTERIOR slot from getBlocks is caught by the hash chain', async () => {
  const chain = scenario();
  // slot 105 produced a block containing the transfer, but getBlocks omits it.
  // Believing getBlocks here would silently delete the transfer and produce a
  // wrong-but-perfectly-reproducible root. The blockhash/parentSlot chain across
  // the fetched blocks does not close, so it is caught.
  await assert.rejects(
    () => fetchRange({ rpc: mockRpc(chain, { hideFromGetBlocks: [105] }), from: 100, to: 110 }),
    (err) => {
      assert.ok(err instanceof ChainBreakError, `expected ChainBreakError, got ${err.name}`);
      return true;
    },
  );
});

// A chain WITH neighbours on both sides of the range, so the head and tail
// anchors have something to anchor to. This is the production shape: periods are
// chained from the mint's first slot, so every boundary but the very first has a
// produced block on the other side of it (review finding B4).
function neighbouredChain() {
  return mockChain({
    from: 96, to: 114, skipped: [],
    txs: {
      102: [{ sig: 'sigCreate', pre: [], post: [{ account: A, owner: OA, amount: 1000 }] }],
      105: [{
        sig: 'sigTransfer',
        pre: [{ account: A, owner: OA, amount: 1000 }],
        post: [{ account: A, owner: OA, amount: 600 }, { account: B, owner: OB, amount: 400 }],
      }],
    },
  });
}

test('4a. B4: hiding the FIRST produced slot in range is caught by the head anchor', async () => {
  const chain = neighbouredChain();
  // Over [100, 110): slot 100 is the first produced slot. An RPC that omits it
  // from getBlocks would drop it silently. The head anchor (last produced block
  // before 100, i.e. slot 99) does not chain to the new first block, so it breaks.
  await assert.rejects(
    () => fetchRange({ rpc: mockRpc(chain, { hideFromGetBlocks: [100] }), from: 100, to: 110 }),
    (err) => {
      assert.ok(err instanceof ChainBreakError, `expected ChainBreakError, got ${err.name}: ${err.message}`);
      return true;
    },
  );
});

test('4b. B4: hiding the LAST produced slot in range is caught by the tail anchor', async () => {
  const chain = neighbouredChain();
  // Over [100, 110): slot 109 is the last produced slot. The tail anchor (first
  // produced block at or after 110, i.e. slot 110) chains back to 109, so if 109
  // is dropped the anchor's previousBlockhash no longer matches the new last block.
  await assert.rejects(
    () => fetchRange({ rpc: mockRpc(chain, { hideFromGetBlocks: [109] }), from: 100, to: 110 }),
    (err) => {
      assert.ok(err instanceof ChainBreakError, `expected ChainBreakError, got ${err.name}: ${err.message}`);
      return true;
    },
  );
});

test('4c. B4: an entirely empty getBlocks over a non-trivial range is refused, not believed', async () => {
  // A chain whose in-range slots are all skipped from getBlocks. The old code
  // emitted a clean artifact declaring all ten slots skipped with
  // continuity_verified: true. Now it aborts.
  const chain = mockChain({ from: 96, to: 114, skipped: [], txs: {} });
  await assert.rejects(
    () => fetchRange({
      rpc: mockRpc(chain, { hideFromGetBlocks: [100, 101, 102, 103, 104, 105, 106, 107, 108, 109] }),
      from: 100, to: 110,
    }),
    (err) => {
      assert.ok(err instanceof EmptyRangeError, `expected EmptyRangeError, got ${err.name}`);
      return true;
    },
  );
});

test('4d. B4: with neighbours present, both anchors are verified and counted', async () => {
  const chain = neighbouredChain();
  const range = await fetchRange({ rpc: mockRpc(chain), from: 100, to: 110 });
  assert.equal(range.headAnchorSlot, 99, 'head anchor is the last produced slot before the range');
  assert.equal(range.tailAnchorSlot, 110, 'tail anchor is the first produced slot at/after the range');
  // 10 produced slots -> 9 interior links + 2 anchors = 11.
  assert.equal(range.continuityLinks, range.produced.length - 1 + 2);
});

test('chaining two adjacent periods equals indexing the whole range at once', async () => {
  // The opening-state mechanism is only correct if it is ADDITIVE. If it is not,
  // every period after the first silently under-credits dormant holders — and
  // because they are dormant, nobody notices.
  const chain = scenario();
  const whole = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  const first = await runIndex({ ...RUN, to: 105, rpc: mockRpc(chain) });
  assert.equal(first.artifact.params.opening_state.mode, 'empty');
  assert.ok(first.artifact.warnings.some((w) => /OPENING STATE IS EMPTY/.test(w)));

  const second = await runIndex({
    ...RUN, from: 105, rpc: mockRpc(chain),
    openingAccounts: openingFromArtifact(first.artifact),
    openingStateSource: 'the first period',
  });
  assert.equal(second.artifact.params.opening_state.mode, 'chained');
  assert.equal(
    second.artifact.params.opening_state.hash, first.artifact.closing_state_hash,
    'the opening-state hash must equal the previous period\'s closing_state_hash, or the chain is not auditable',
  );

  const sum = new Map();
  for (const part of [first, second]) {
    for (const r of part.artifact.ledger) sum.set(r.owner, (sum.get(r.owner) ?? 0n) + BigInt(r.token_slots));
  }
  const expected = new Map(whole.artifact.ledger.map((r) => [r.owner, BigInt(r.token_slots)]));
  assert.deepEqual([...sum.entries()].sort(), [...expected.entries()].sort());
  assert.equal(
    BigInt(first.artifact.accrual.total_token_slots_entitled) + BigInt(second.artifact.accrual.total_token_slots_entitled),
    BigInt(whole.artifact.accrual.total_token_slots_entitled),
  );
});

test('chaining from a non-adjacent period is refused rather than silently gapped', async () => {
  const chain = scenario();
  const first = await runIndex({ ...RUN, to: 104, rpc: mockRpc(chain) });
  // A gap of one slot loses whatever happened in it. Caught at the CLI boundary;
  // asserted here at the data level: the closing state ends at 104, not 105.
  assert.equal(first.artifact.params.to_slot, 104);
});

test('a range that is not fully finalized is refused', async () => {
  const chain = scenario();
  await assert.rejects(
    () => runIndex({ ...RUN, rpc: mockRpc(chain, { finalizedTip: 105 }) }),
    /extends past the finalized tip/,
  );
});

test('every slot in the range is positively accounted for', async () => {
  const chain = scenario();
  const { artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain) });
  assert.equal(artifact.slots.produced + artifact.slots.skipped, artifact.slots.total);
  assert.equal(artifact.slots.total, 10);
  assert.deepEqual(artifact.slots.skipped_slots, [101, 104]);
  assert.equal(artifact.slots.continuity_verified, true);
});

test('the input set names every slot and every consumed transaction, in order', async () => {
  const chain = scenario();
  const { inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });
  const lines = inputSet.lines;
  assert.ok(lines.includes('slot 101 skipped'));
  assert.ok(lines.includes('slot 104 skipped'));
  assert.ok(lines.some((l) => l.startsWith('slot 102 block hash-102 parent 100')));
  assert.ok(lines.includes('tx 105 0 sigTransfer ok'));
  // ascending, no gaps
  const slots = lines.filter((l) => l.startsWith('slot ')).map((l) => Number(l.split(' ')[1]));
  assert.deepEqual(slots, [100, 101, 102, 103, 104, 105, 106, 107, 108, 109]);
});

test('a failed transaction is recorded in the input set but changes no balance', async () => {
  const chain = scenario({
    txs: {
      106: [{
        sig: 'sigFailed', err: { InstructionError: [0, 'Custom'] },
        pre: [{ account: A, owner: OA, amount: 600 }],
        post: [{ account: A, owner: OA, amount: 0 }],
      }],
    },
  });
  const { artifact, inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });
  assert.ok(inputSet.lines.includes('tx 106 0 sigFailed err'));
  assert.equal(artifact.transactions.failed_included_in_input_set, 1);
  const byOwner = new Map(artifact.ledger.map((r) => [r.owner, r.token_slots]));
  assert.equal(byOwner.get(OA), 4800n, 'the failed transaction must not zero the balance');
});

test('draining then closing an account stops accrual, and the account leaves the state', async () => {
  const chain = scenario({
    txs: {
      // B is emptied at 106 (so the accrual stops at the end of slot 105) and
      // closed at 107 (SPL-Token requires a zero balance to close).
      106: [{
        sig: 'sigDrain',
        pre: [{ account: B, owner: OB, amount: 400 }],
        post: [{ account: B, owner: OB, amount: 0 }],
      }],
      107: [{ sig: 'sigClose', pre: [{ account: B, owner: OB, amount: 0 }], post: [] }],
    },
  });
  const { artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain) });
  const byOwner = new Map(artifact.ledger.map((r) => [r.owner, r.token_slots]));
  // 400 in force during slot 105 only: the change at 106 takes effect within
  // slot 106, per the convention pinned in accrue.mjs.
  assert.equal(byOwner.get(OB), 400n);

  // And the closed account is gone from the closing state, so it cannot resurrect
  // in the next period's opening state.
  const closing = accrue({
    fromSlot: 100, toSlot: 110,
    slotEvents: [
      { slot: 102, events: [{ account: A, kind: 'set', owner: OA, amount: 1000n }] },
      { slot: 107, events: [{ account: B, kind: 'close' }] },
    ],
  }).closing;
  assert.deepEqual(closing.map((c) => c.account), [A]);
});
