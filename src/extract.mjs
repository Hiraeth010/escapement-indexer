/**
 * extract.mjs — a block in, mint-relevant facts out. Pure; no I/O.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS READS, AND WHY IT IS THAT AND NOT THE INSTRUCTIONS
 * ---------------------------------------------------------------------------
 * Every fact here comes from `meta.preTokenBalances` / `meta.postTokenBalances`,
 * which the validator records for every token account referenced by a
 * transaction. Each record carries `{accountIndex, mint, owner, uiTokenAmount}`
 * and the post record is an ABSOLUTE balance and the OWNER AS OF AFTER the
 * transaction.
 *
 * That gives three things for free, each of which is a bug in the alternative
 * (decoding SPL-Token instructions ourselves):
 *
 *   1. Absolute balances, so a missed transaction cannot corrupt all subsequent
 *      state the way a missed delta would. It under-counts a dormant account and
 *      self-heals on the next touch.
 *   2. `SetAuthority(AccountOwner)` for free (D8): if a transaction changes an
 *      account's owner, the pre and post records disagree about `owner`, with no
 *      instruction decoding at all.
 *   3. CPI-nested transfers for free. A transfer inside four levels of CPI moves
 *      the balance exactly the same way, and the balance record does not care.
 *
 * The cost, stated because it is real: this trusts the validator's token-balance
 * accounting rather than re-deriving it from instructions. That accounting is
 * part of what every explorer and every wallet already displays, and it is
 * produced by the same node software that produced consensus — but it is a
 * dependency, and it is named in the README under known limits.
 *
 * ---------------------------------------------------------------------------
 * WHAT COUNTS AS "CONSUMED" (D5)
 * ---------------------------------------------------------------------------
 * A transaction is consumed if it references the target mint in either its pre-
 * or its post-token-balance records, INCLUDING failed transactions. A failed
 * transaction changes no state, but recording it makes the input set a statement
 * about the block's contents rather than about our filtering, so a verifier who
 * disagrees learns which it is.
 */

const ZERO = 0n;

/** Account keys in canonical index order: static, then loaded writable, then loaded readonly. */
export function resolveAccountKeys(tx) {
  const stat = tx?.transaction?.message?.accountKeys ?? [];
  const loaded = tx?.meta?.loadedAddresses ?? null;
  if (!loaded) return stat;
  return [...stat, ...(loaded.writable ?? []), ...(loaded.readonly ?? [])];
}

function amountOf(rec, where) {
  const raw = rec?.uiTokenAmount?.amount;
  // `uiAmount` is a float and is never read. `amount` is the raw integer as a
  // decimal string, which is what a balance actually is.
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
    throw new Error(`${where}: token balance amount ${JSON.stringify(raw)} is not a decimal integer string`);
  }
  return BigInt(raw);
}

/**
 * @param {object} block  a `getBlock` result, encoding 'json'
 * @param {number} slot
 * @param {string} mint   base58
 * @returns {{
 *   slot: number,
 *   consumed: {slot: number, index: number, signature: string, ok: boolean}[],
 *   events: {account: string, kind: 'set'|'close', owner?: string, amount?: bigint}[],
 *   supplyDelta: bigint,   net mint/burn observed in this slot (0 for pure transfers)
 *   decimals: number|null,
 * }}
 */
export function extractBlock(block, slot, mint) {
  const consumed = [];
  /** account -> latest event in this slot, folded in block order */
  const folded = new Map();
  let supplyDelta = ZERO;
  let decimals = null;

  const txs = block?.transactions ?? [];
  for (let index = 0; index < txs.length; index++) {
    const tx = txs[index];
    const meta = tx?.meta;
    if (!meta) throw new Error(`slot ${slot} tx ${index}: no meta — the block was fetched without full detail`);

    const pre = (meta.preTokenBalances ?? []).filter((b) => b.mint === mint);
    const post = (meta.postTokenBalances ?? []).filter((b) => b.mint === mint);
    if (pre.length === 0 && post.length === 0) continue;

    const signature = tx?.transaction?.signatures?.[0];
    if (typeof signature !== 'string') throw new Error(`slot ${slot} tx ${index}: no signature`);

    const ok = meta.err === null || meta.err === undefined;
    consumed.push({ slot, index, signature, ok });
    if (!ok) continue; // a failed transaction changes nothing

    const keys = resolveAccountKeys(tx);
    const byIndex = (list) => new Map(list.map((b) => [b.accountIndex, b]));
    const preIx = byIndex(pre);
    const postIx = byIndex(post);

    let preSum = ZERO;
    let postSum = ZERO;
    for (const b of pre) preSum += amountOf(b, `slot ${slot} tx ${index} pre`);
    for (const b of post) postSum += amountOf(b, `slot ${slot} tx ${index} post`);
    supplyDelta += postSum - preSum;

    const indices = [...new Set([...preIx.keys(), ...postIx.keys()])].sort((a, b) => a - b);
    for (const ix of indices) {
      const account = keys[ix];
      if (typeof account !== 'string') {
        throw new Error(
          `slot ${slot} tx ${index}: token balance references account index ${ix} but only ` +
          `${keys.length} keys resolved — address-lookup-table expansion is missing from this block response`,
        );
      }
      const q = postIx.get(ix);
      if (!q) {
        // Present before, absent after: the account is no longer a token
        // account of this mint. In practice that is `closeAccount`.
        folded.set(account, { account, kind: 'close' });
        continue;
      }
      if (typeof q.owner !== 'string') {
        // Without an owner we cannot attribute the balance to anybody, and
        // guessing (e.g. from the current on-chain owner) is exactly the D8
        // trap. Refuse rather than guess.
        throw new Error(
          `slot ${slot} tx ${index}: post-token-balance for account index ${ix} has no \`owner\` field. ` +
          `This RPC's block responses cannot support owner attribution; use a node that reports it.`,
        );
      }
      if (decimals === null && Number.isInteger(q.uiTokenAmount?.decimals)) {
        decimals = q.uiTokenAmount.decimals;
      }
      folded.set(account, { account, kind: 'set', owner: q.owner, amount: amountOf(q, `slot ${slot} tx ${index} post`) });
    }
  }

  // One event per account per slot, in a stated order. The fold above already
  // guarantees the LAST transaction in block order wins, which is the state at
  // the end of the slot — and the end of the slot is what the accrual model
  // integrates. See accrue.mjs, "WHEN A CHANGE TAKES EFFECT".
  const events = [...folded.values()].sort((a, b) => (a.account < b.account ? -1 : a.account > b.account ? 1 : 0));

  return { slot, consumed, events, supplyDelta, decimals };
}
