/**
 * accrue.mjs — token-slots held, integrated over a half-open slot range.
 *
 * This is the entitlement path. Everything in this file is BigInt. There is no
 * `Number` arithmetic on a balance, a duration, or a product of the two, and
 * `nofloat.test.mjs` fails the build if one appears.
 *
 * ---------------------------------------------------------------------------
 * WHY SLOTS AND NOT SECONDS (D6)
 * ---------------------------------------------------------------------------
 * `getBlockTime` is a validator-reported estimate. It is not monotonic, it is
 * not identical across providers, and it is not part of consensus. Integrating
 * balance against it makes the answer depend on which RPC you asked, which is
 * the one thing the design cannot tolerate. So the accumulator is TOKEN-SLOTS:
 *
 *     token_slots(addr) = sum over slots s in [from, to) of balance(addr, s)
 *
 * A slot is a consensus fact. "Token-seconds" is a human rendering of the same
 * quantity and is never the quantity itself. See README §"Token-seconds is a
 * unit conversion, not the unit" — this is a place where the published spec and
 * this code do not currently say the same thing.
 *
 * ---------------------------------------------------------------------------
 * WHEN A CHANGE TAKES EFFECT
 * ---------------------------------------------------------------------------
 * A slot is atomic for this purpose. Every balance change in slot S takes effect
 * at the START of the interval [S, S+1) — i.e. the balance in force during slot
 * S is the balance AFTER slot S's transactions. Sub-slot transaction order
 * therefore cannot affect the integral at all, which is deliberate: it removes
 * intra-block ordering (and hence any dependence on how a provider orders a
 * block's transactions) from the entitlement entirely.
 *
 * The alternative convention (changes take effect at S+1) is equally defensible
 * and produces a DIFFERENT number. It is pinned here, in writing, for that
 * reason.
 *
 * ---------------------------------------------------------------------------
 * OWNERSHIP (D8)
 * ---------------------------------------------------------------------------
 * Balance is attributed to the owner AT EACH SLOT, never to the current owner.
 * The state machine carries `owner` per token account and updates it whenever an
 * observation says it changed — which covers `SetAuthority(AccountOwner)`
 * without needing to decode the instruction, because a transaction that changes
 * an account's owner reports the new owner in its post-token-balance record.
 * Multiple token accounts per owner are summed per OWNER, not per account.
 */

import { comparePubkeys } from './base58.mjs';

/**
 * A token-account state table that can be iterated in a stated order.
 *
 * D11 forbids iterating a hash map. Summation of BigInts is exact and
 * commutative, so iteration order provably cannot change the numbers here — but
 * "provably cannot" is the argument that every silent-nondeterminism bug was
 * shipped with, so the order is pinned anyway: ascending by token-account
 * pubkey bytes. The sorted key list is cached and invalidated only when the key
 * SET changes, so the cost is amortised to nearly nothing.
 */
class AccountTable {
  constructor() {
    this.map = new Map(); // account b58 -> { owner, amount: bigint }
    this._sorted = null;
  }

  get(account) { return this.map.get(account); }

  set(account, owner, amount) {
    if (!this.map.has(account)) this._sorted = null;
    this.map.set(account, { owner, amount });
  }

  delete(account) {
    if (this.map.delete(account)) this._sorted = null;
  }

  /** Ascending by token-account pubkey bytes. The pinned iteration order. */
  keys() {
    if (this._sorted === null) this._sorted = [...this.map.keys()].sort(comparePubkeys);
    return this._sorted;
  }

  get size() { return this.map.size; }
}

/**
 * @typedef {object} AccountEvent
 * @property {string} account   token account, base58
 * @property {'set'|'close'} kind
 * @property {string=} owner    required for 'set'
 * @property {bigint=} amount   required for 'set' — ABSOLUTE post-transaction balance
 *
 * @typedef {object} SlotEvents
 * @property {number} slot
 * @property {AccountEvent[]} events   applied atomically; order within a slot is irrelevant
 */

/**
 * Integrate balances over [fromSlot, toSlot).
 *
 * @param {object} args
 * @param {number} args.fromSlot inclusive
 * @param {number} args.toSlot   exclusive
 * @param {{account: string, owner: string, amount: bigint}[]} args.openingAccounts
 *        Token-account state in force at `fromSlot`. See README §"The opening
 *        state problem" — an empty opening state is only correct when `fromSlot`
 *        precedes the mint's first token account.
 * @param {SlotEvents[]} args.slotEvents  need NOT be sorted; sorted here.
 * @param {(account: string, owner: string) => string|null} args.classify
 *        Returns null for "counts towards entitlement", or an exclusion bucket
 *        key for "does not". Called per span with the owner IN FORCE for that
 *        span, so an exclusion follows the authority change rather than the
 *        account.
 * @returns {{
 *   included: Map<string, bigint>,      owner -> token-slots (entitled)
 *   excluded: Map<string, bigint>,      bucket -> token-slots (removed by the exclusion set)
 *   totalIncluded: bigint,
 *   totalExcluded: bigint,
 *   closing: {account: string, owner: string, amount: string}[],
 *   spans: number,
 * }}
 */
export function accrue({ fromSlot, toSlot, openingAccounts = [], slotEvents = [], classify = () => null }) {
  if (!Number.isSafeInteger(fromSlot) || !Number.isSafeInteger(toSlot)) {
    throw new Error('accrue: slot bounds must be safe integers');
  }
  if (toSlot <= fromSlot) throw new Error(`accrue: empty or inverted range [${fromSlot}, ${toSlot})`);

  const state = new AccountTable();
  for (const a of openingAccounts) {
    if (typeof a.amount !== 'bigint') throw new Error(`accrue: opening balance for ${a.account} is not a bigint`);
    if (a.amount < 0n) throw new Error(`accrue: negative opening balance for ${a.account}`);
    state.set(a.account, a.owner, a.amount);
  }

  const included = new Map();
  const excluded = new Map();

  // Sorted by slot. Two entries for the same slot are merged in the order given;
  // since a slot is applied atomically and every event is an ABSOLUTE balance,
  // the only way order could matter within one slot is two events for the same
  // account, which cannot happen (extract.mjs emits one event per account per
  // transaction and folds a slot's transactions in block order).
  const ordered = [...slotEvents].sort((a, b) => a.slot - b.slot);
  for (const se of ordered) {
    if (se.slot < fromSlot || se.slot >= toSlot) {
      throw new Error(`accrue: event at slot ${se.slot} is outside [${fromSlot}, ${toSlot})`);
    }
  }

  let cursor = fromSlot;
  let spans = 0;

  const accrueSpan = (untilSlot) => {
    const width = BigInt(untilSlot - cursor);
    if (width < 0n) throw new Error(`accrue: cursor moved backwards (${cursor} -> ${untilSlot})`);
    if (width === 0n) return;
    spans++;
    for (const account of state.keys()) {
      const st = state.map.get(account);
      if (st.amount === 0n) continue;
      const contribution = st.amount * width; // exact, unbounded
      const bucket = classify(account, st.owner);
      if (bucket === null) {
        included.set(st.owner, (included.get(st.owner) ?? 0n) + contribution);
      } else {
        excluded.set(bucket, (excluded.get(bucket) ?? 0n) + contribution);
      }
    }
    cursor = untilSlot;
  };

  for (const { slot, events } of ordered) {
    accrueSpan(slot);
    for (const ev of events) {
      if (ev.kind === 'close') {
        state.delete(ev.account);
      } else if (ev.kind === 'set') {
        if (typeof ev.amount !== 'bigint') throw new Error(`accrue: event amount for ${ev.account} is not a bigint`);
        if (ev.amount < 0n) throw new Error(`accrue: negative balance for ${ev.account} at slot ${slot}`);
        state.set(ev.account, ev.owner, ev.amount);
      } else {
        throw new Error(`accrue: unknown event kind ${JSON.stringify(ev.kind)}`);
      }
    }
  }
  accrueSpan(toSlot);

  let totalIncluded = 0n;
  for (const v of included.values()) totalIncluded += v;
  let totalExcluded = 0n;
  for (const v of excluded.values()) totalExcluded += v;

  const closing = state.keys().map((account) => {
    const st = state.map.get(account);
    return { account, owner: st.owner, amount: st.amount.toString(10) };
  });

  return { included, excluded, totalIncluded, totalExcluded, closing, spans };
}

/**
 * The per-owner ledger, in the one pinned order (ascending by owner pubkey
 * bytes). Owners with zero token-slots are dropped: a zero leaf is a leaf that
 * costs rent to claim and pays nothing, and including it would change the root
 * for no benefit.
 */
export function ledgerFrom(included) {
  return [...included.entries()]
    .filter(([, v]) => v > 0n)
    .sort((a, b) => comparePubkeys(a[0], b[0]))
    .map(([owner, tokenSlots]) => ({ owner, tokenSlots }));
}
