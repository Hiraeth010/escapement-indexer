/**
 * mockchain.test.mjs — a synthetic chain, and the helpers every other test uses.
 *
 * This is a test file that mostly exports. It carries one self-test so that a
 * broken fixture fails here rather than as a confusing failure somewhere else.
 *
 * The fixture is deliberately built at the SHAPE OF THE RPC RESPONSE, not at the
 * shape of our internal types: blocks carry `blockhash` / `previousBlockhash` /
 * `parentSlot`, transactions carry `meta.preTokenBalances` /
 * `meta.postTokenBalances` with `uiTokenAmount.amount` as a decimal string. If
 * we mocked our own abstractions we would be testing our own opinions.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { b58encode } from './base58.mjs';

/** Deterministic distinct pubkeys. */
export function pk(n) {
  const b = new Uint8Array(32);
  b[0] = n & 0xff;
  b[1] = (n >> 8) & 0xff;
  b[31] = 7; // keep the tail non-trivial so byte ordering is actually exercised
  return b58encode(b);
}

export const MINT = pk(1);
export const CONFIG = pk(2);

/**
 * Build a mock chain.
 * @param {object} spec
 * @param {number} spec.from
 * @param {number} spec.to
 * @param {number[]} [spec.skipped] slots that produced no block
 * @param {Record<number, object[]>} [spec.txs] slot -> array of tx specs
 *        tx spec: { sig, err?, balances: [{account, owner, amount, closed?}] , preBalances?: [...] }
 */
export function mockChain({ from, to, skipped = [], txs = {} }) {
  const skippedSet = new Set(skipped);
  const produced = [];
  for (let s = from; s < to; s++) if (!skippedSet.has(s)) produced.push(s);

  const blocks = new Map();
  let prevHash = 'anchorhash';
  let prevSlot = from - 1;
  for (const slot of produced) {
    const list = txs[slot] ?? [];
    const transactions = list.map((t) => {
      const accounts = [...new Set([
        ...(t.pre ?? []).map((b) => b.account),
        ...(t.post ?? []).map((b) => b.account),
      ])];
      const idx = new Map(accounts.map((a, i) => [a, i]));
      const mk = (b) => ({
        accountIndex: idx.get(b.account),
        mint: b.mint ?? MINT,
        owner: b.owner,
        programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        uiTokenAmount: { amount: String(b.amount), decimals: 6, uiAmount: null, uiAmountString: String(b.amount) },
      });
      return {
        transaction: { signatures: [t.sig], message: { accountKeys: accounts } },
        meta: {
          err: t.err ?? null,
          preTokenBalances: (t.pre ?? []).map(mk),
          postTokenBalances: (t.post ?? []).map(mk),
        },
      };
    });
    const blockhash = `hash-${slot}`;
    blocks.set(slot, { blockhash, previousBlockhash: prevHash, parentSlot: prevSlot, transactions });
    prevHash = blockhash;
    prevSlot = slot;
  }

  return { from, to, produced, skipped: [...skippedSet].sort((a, b) => a - b), blocks };
}

/**
 * A fake Rpc with the same surface as `Rpc`.
 * @param {object} opts
 * @param {number[]} [opts.failSlots] slots whose getBlock throws (an RPC failure,
 *   NOT a skip — the whole point of D4 is that these are different)
 * @param {number[]} [opts.hideFromGetBlocks] slots omitted from getBlocks despite
 *   having produced a block — simulates a lying or damaged index
 * @param {boolean} [opts.jitter] randomise response latency so block arrival
 *   order varies between runs
 */
export function mockRpc(chain, { failSlots = [], hideFromGetBlocks = [], jitter = false, finalizedTip = null } = {}) {
  const fail = new Set(failSlots);
  const hide = new Set(hideFromGetBlocks);
  const stats = { calls: 0, retries: 0, bytes: 0, ms: 0 };
  return {
    url: 'https://mock.invalid',
    stats,
    async getFinalizedSlot() { stats.calls++; return finalizedTip ?? chain.to + 32; },
    async getBlocks(start, end) {
      stats.calls++;
      return chain.produced.filter((s) => s >= start && s <= end && !hide.has(s));
    },
    async getBlock(slot) {
      stats.calls++;
      if (jitter) await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 12)));
      if (fail.has(slot)) {
        const e = new Error(`Block not available for slot ${slot}`);
        e.code = -32004;
        throw e;
      }
      return chain.blocks.get(slot) ?? null;
    },
    async getVersion() { return { 'solana-core': 'mock' }; },
  };
}

/**
 * The canonical scenario used across the determinism tests.
 *
 *   slot 102  account A created holding 1000, owner OA
 *   slot 105  400 moves A -> B; A=600 (OA), B=400 (OB)
 *   slot 108  A's authority changes: owner becomes OC, balance unchanged at 600
 *
 * Over [100, 110) that integrates to:
 *   OA  1000×3 + 600×3 = 4800
 *   OB          400×5   = 2000
 *   OC          600×2   = 1200
 */
export const A = pk(10);
export const B = pk(11);
export const OA = pk(20);
export const OB = pk(21);
export const OC = pk(22);

export function scenario(overrides = {}) {
  return mockChain({
    from: 100,
    to: 110,
    skipped: [101, 104],
    txs: {
      102: [{ sig: 'sigCreate', pre: [], post: [{ account: A, owner: OA, amount: 1000 }] }],
      105: [{
        sig: 'sigTransfer',
        pre: [{ account: A, owner: OA, amount: 1000 }],
        post: [{ account: A, owner: OA, amount: 600 }, { account: B, owner: OB, amount: 400 }],
      }],
      108: [{
        sig: 'sigSetAuthority',
        pre: [{ account: A, owner: OA, amount: 600 }],
        post: [{ account: A, owner: OC, amount: 600 }],
      }],
      ...(overrides.txs ?? {}),
    },
    ...(overrides.chain ?? {}),
  });
}

export const OPEN_EXCLUSIONS = {
  hash: 'test-no-exclusions',
  canonical: { schema: 'escapement.exclusions/v1', version: 'test', mint: MINT, effective_from_slot: 0, policy: 'test: exclude nobody', undecided: [], entries: [] },
  entries: [],
  owners: new Set(),
  tokenAccounts: new Set(),
  acknowledgementGaps: [],
  classify: () => null,
};

test('fixture: the mock chain is internally consistent', () => {
  const c = scenario();
  assert.deepEqual(c.skipped, [101, 104]);
  assert.equal(c.produced.length, 8);
  let prev = 'anchorhash';
  for (const s of c.produced) {
    assert.equal(c.blocks.get(s).previousBlockhash, prev);
    prev = c.blocks.get(s).blockhash;
  }
});
