/**
 * entitle.mjs — turning token-slots into lamports.
 *
 * One line does the work:
 *
 *     payout_i = floor( vault_lamports * token_slots_i / total_token_slots )
 *
 * in BigInt. Everything else in this file is the argument that the line is safe.
 *
 * ---------------------------------------------------------------------------
 * WHY FLOOR, AND WHY IT CANNOT FAVOUR THE CLAIMANT (A3)
 * ---------------------------------------------------------------------------
 * BigInt `/` truncates toward zero. Every operand here is non-negative, so
 * truncation IS floor. Therefore for every i:
 *
 *     payout_i <= vault * ts_i / total          (exact rational)
 *
 * Summing over i, and using sum(ts_i) = total exactly:
 *
 *     sum(payout_i) <= vault
 *
 * so `remainder = vault - sum(payout_i) >= 0`. The vault can never be
 * over-allocated by this function. The error is always in the direction of
 * stranding lamports in the vault, never of promising lamports that are not
 * there — which is the direction the on-chain solvency invariant I1 needs.
 *
 * The bound is tight: each discarded fraction is strictly less than 1, the exact
 * shares sum to exactly `vault`, so the discarded fractions sum to an integer
 * strictly less than n — hence `remainder <= n - 1`. Both facts are asserted at
 * runtime, not merely documented, because an assertion that has never run is a
 * comment with extra steps.
 *
 * The single dangerous case is `total_token_slots == 0`: every payout would be a
 * division by zero. That is not an error condition, it is a real state (nobody
 * held anything, or the exclusion set removed everyone), and it must produce an
 * empty distribution with the whole vault retained — not a crash and not a
 * silent zero-filled tree.
 *
 * ---------------------------------------------------------------------------
 * CUMULATIVE, NOT PER-PERIOD (G3)
 * ---------------------------------------------------------------------------
 * The leaf commits `cumulative` — everything ever owed to an address as of this
 * root — so a later root can never reduce what an earlier root granted. The
 * per-period payout is an intermediate, not the published quantity.
 */

import { comparePubkeys } from './base58.mjs';

/**
 * @param {object} args
 * @param {bigint} args.vaultLamports
 * @param {{owner: string, tokenSlots: bigint}[]} args.ledger  ordered; the order
 *   is not load-bearing for the arithmetic but IS load-bearing for the tree.
 * @param {Map<string, bigint>} [args.prior] owner -> cumulative already granted
 *   by the previous root.
 * @returns {{
 *   rows: {owner: string, tokenSlots: bigint, payout: bigint, cumulative: bigint}[],
 *   totalTokenSlots: bigint, distributed: bigint, remainder: bigint,
 *   totalOwedCumulative: bigint,
 * }}
 */
export function distribute({ vaultLamports, ledger, prior = new Map() }) {
  if (typeof vaultLamports !== 'bigint') throw new Error('distribute: vaultLamports must be a bigint');
  if (vaultLamports < 0n) throw new Error('distribute: vaultLamports is negative');

  let totalTokenSlots = 0n;
  for (const r of ledger) {
    if (typeof r.tokenSlots !== 'bigint') throw new Error(`distribute: tokenSlots for ${r.owner} is not a bigint`);
    if (r.tokenSlots <= 0n) throw new Error(`distribute: non-positive tokenSlots for ${r.owner}`);
    totalTokenSlots += r.tokenSlots;
  }

  const rows = [];
  let distributed = 0n;
  let totalOwedCumulative = 0n;

  for (const r of ledger) {
    // total == 0 implies ledger is empty, so this division is never reached
    // with a zero denominator; the guard is the loop, not a special case.
    const payout = (vaultLamports * r.tokenSlots) / totalTokenSlots;
    distributed += payout;
    const cumulative = (prior.get(r.owner) ?? 0n) + payout;
    totalOwedCumulative += cumulative;
    rows.push({ owner: r.owner, tokenSlots: r.tokenSlots, payout, cumulative });
  }

  // Owners who were credited by a previous root but held nothing this period
  // still carry their cumulative forward, or the new root would silently claw
  // back their entitlement (G3). They appear with a zero payout.
  const seen = new Set(ledger.map((r) => r.owner));
  for (const [owner, amount] of prior) {
    if (seen.has(owner)) continue;
    if (amount <= 0n) continue;
    totalOwedCumulative += amount;
    rows.push({ owner, tokenSlots: 0n, payout: 0n, cumulative: amount });
  }

  const remainder = vaultLamports - distributed;

  // The two invariants from the header, asserted.
  if (remainder < 0n) {
    throw new Error(`distribute: INVARIANT VIOLATED — over-allocated by ${-remainder} lamports`);
  }
  const bound = ledger.length === 0 ? 0n : BigInt(ledger.length - 1);
  if (ledger.length > 0 && remainder > bound) {
    throw new Error(
      `distribute: INVARIANT VIOLATED — remainder ${remainder} exceeds the n-1 truncation bound ${bound}`,
    );
  }
  if (ledger.length === 0 && remainder !== vaultLamports) {
    throw new Error('distribute: INVARIANT VIOLATED — empty ledger must retain the whole vault');
  }

  // One pinned order for everything that leaves this module.
  rows.sort((a, b) => comparePubkeys(a.owner, b.owner));

  return { rows, totalTokenSlots, distributed, remainder, totalOwedCumulative };
}
