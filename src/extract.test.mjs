// SPDX-License-Identifier: Apache-2.0
/**
 * extract.test.mjs — decoding a block into facts, including the cases where the
 * only correct behaviour is to refuse.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { extractBlock, resolveAccountKeys } from './extract.mjs';
import { pk, MINT, A, B, OA, OB } from './mockchain.test.mjs';

const bal = (ix, owner, amount, mint = MINT) => ({
  accountIndex: ix, mint, owner,
  uiTokenAmount: { amount: String(amount), decimals: 6, uiAmount: 0.1, uiAmountString: '0.1' },
});

const block = (txs) => ({ blockhash: 'h', previousBlockhash: 'p', parentSlot: 1, transactions: txs });

test('transactions that never touch the mint are not consumed', () => {
  const other = pk(250);
  const r = extractBlock(block([{
    transaction: { signatures: ['s1'], message: { accountKeys: [A] } },
    meta: { err: null, preTokenBalances: [bal(0, OA, 5, other)], postTokenBalances: [bal(0, OA, 6, other)] },
  }]), 5, MINT);
  assert.deepEqual(r.consumed, []);
  assert.deepEqual(r.events, []);
});

test('address-lookup-table accounts are resolved in the canonical index order', () => {
  const tx = {
    transaction: { signatures: ['s'], message: { accountKeys: [pk(1), pk(2)] } },
    meta: { loadedAddresses: { writable: [pk(3)], readonly: [pk(4)] }, err: null, preTokenBalances: [], postTokenBalances: [] },
  };
  assert.deepEqual(resolveAccountKeys(tx), [pk(1), pk(2), pk(3), pk(4)]);

  // A token balance at index 2 must resolve to the loaded writable address.
  const r = extractBlock(block([{
    ...tx,
    meta: { ...tx.meta, postTokenBalances: [bal(2, OA, 500)] },
  }]), 9, MINT);
  assert.equal(r.events[0].account, pk(3));
});

test('a post-balance with no owner is refused rather than guessed (D8)', () => {
  const bad = { accountIndex: 0, mint: MINT, uiTokenAmount: { amount: '1', decimals: 6 } };
  assert.throws(
    () => extractBlock(block([{
      transaction: { signatures: ['s'], message: { accountKeys: [A] } },
      meta: { err: null, preTokenBalances: [], postTokenBalances: [bad] },
    }]), 5, MINT),
    /has no `owner` field/,
  );
});

test('a non-integer amount string is refused', () => {
  const bad = { accountIndex: 0, mint: MINT, owner: OA, uiTokenAmount: { amount: '1.5', decimals: 6 } };
  assert.throws(
    () => extractBlock(block([{
      transaction: { signatures: ['s'], message: { accountKeys: [A] } },
      meta: { err: null, preTokenBalances: [], postTokenBalances: [bad] },
    }]), 5, MINT),
    /not a decimal integer string/,
  );
});

test('a token balance index beyond the resolved keys is refused, never dropped', () => {
  assert.throws(
    () => extractBlock(block([{
      transaction: { signatures: ['s'], message: { accountKeys: [A] } },
      meta: { err: null, preTokenBalances: [], postTokenBalances: [bal(4, OA, 1)] },
    }]), 5, MINT),
    /address-lookup-table expansion is missing/,
  );
});

test('several transactions in one slot fold to the end-of-slot state', () => {
  const r = extractBlock(block([
    {
      transaction: { signatures: ['s1'], message: { accountKeys: [A, B] } },
      meta: { err: null, preTokenBalances: [bal(0, OA, 1000)], postTokenBalances: [bal(0, OA, 700), bal(1, OB, 300)] },
    },
    {
      transaction: { signatures: ['s2'], message: { accountKeys: [A, B] } },
      meta: { err: null, preTokenBalances: [bal(0, OA, 700), bal(1, OB, 300)], postTokenBalances: [bal(0, OA, 100), bal(1, OB, 900)] },
    },
  ]), 5, MINT);

  assert.equal(r.consumed.length, 2);
  const byAccount = new Map(r.events.map((e) => [e.account, e]));
  assert.equal(byAccount.get(A).amount, 100n);
  assert.equal(byAccount.get(B).amount, 900n);
  assert.equal(r.supplyDelta, 0n, 'a pure transfer conserves supply');
});

test('a mint and a burn are detected and reported', () => {
  const minted = extractBlock(block([{
    transaction: { signatures: ['s'], message: { accountKeys: [A] } },
    meta: { err: null, preTokenBalances: [bal(0, OA, 100)], postTokenBalances: [bal(0, OA, 400)] },
  }]), 5, MINT);
  assert.equal(minted.supplyDelta, 300n);

  const burned = extractBlock(block([{
    transaction: { signatures: ['s'], message: { accountKeys: [A] } },
    meta: { err: null, preTokenBalances: [bal(0, OA, 400)], postTokenBalances: [bal(0, OA, 100)] },
  }]), 5, MINT);
  assert.equal(burned.supplyDelta, -300n);
});

test('present before and absent after is a close', () => {
  const r = extractBlock(block([{
    transaction: { signatures: ['s'], message: { accountKeys: [A] } },
    meta: { err: null, preTokenBalances: [bal(0, OA, 0)], postTokenBalances: [] },
  }]), 5, MINT);
  assert.deepEqual(r.events, [{ account: A, kind: 'close' }]);
});

test('a block fetched without full detail is refused, not silently treated as empty', () => {
  assert.throws(
    () => extractBlock(block([{ transaction: { signatures: ['s'], message: { accountKeys: [] } } }]), 5, MINT),
    /no meta — the block was fetched without full detail/,
  );
});
