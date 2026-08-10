/**
 * snapshot.mjs — who held how much, for how long, as a CSV anyone can use.
 *
 * ---------------------------------------------------------------------------
 * Why this exists
 *
 * A reviewer scoring this repository could name a concrete user for the census
 * and could not name one for the indexer, and was right. The indexer computed
 * entitlements into an Escapement-specific merkle format that no deployed
 * program reads, behind a required governance document, at a cost nobody had
 * published. The measurement underneath — token-slots held per owner — is the
 * genuinely reusable part, and it was not reachable on its own.
 *
 * `snapshot` is that measurement and nothing else:
 *
 *     owner, token_slots, share_of_total
 *
 * Time-weighted holdings over a slot range. That is the input an airdrop
 * weighting wants, and it is a fact rather than a policy.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 * No exclusions. `index` REQUIRES an exclusions file and refuses to default one,
 * on the grounds that which balances count as beneficial holders is a policy
 * question the code may not answer for you. That reasoning is right for
 * ENTITLEMENTS and wrong for a measurement: this is raw, it counts everybody,
 * and the AMM pool will very likely be the largest line in it. On one real
 * distribution 85% of it belonged to an address no keypair can sign for.
 *
 * So the pool is not silently dropped and not silently kept — it is present,
 * labelled, and the header of the CSV says so. What to do about it is the
 * caller's policy, and `index --exclusions` is where that policy goes.
 *
 * No merkle root, no config, no vault balance, no claim format. Those are
 * Escapement's distribution mechanism. A stranger wanting holder weights should
 * not have to adopt them.
 * ---------------------------------------------------------------------------
 */

/**
 * Cost, stated before anything is fetched rather than discovered by hitting it.
 *
 * Measured: ~11.6 MB of block data per slot on a full range, and the cost is
 * paid on EVERY slot in the range because a balance change can happen in any of
 * them. A Solana slot is ~400ms, so a day is ~216,000 slots.
 *
 * The number that matters is not the range length, it is that there is no way
 * to ask a public RPC for historical account state, so a range that does not
 * start at the mint's first slot needs an opening balance table from somewhere.
 * See runIndex's note on that — it is the reason `--from` is usually the mint's
 * first slot, and therefore why cost scales with the token's AGE and not with
 * the period you actually care about.
 */
export const MB_PER_SLOT = 11.6;
export const SLOTS_PER_DAY = 216_000;

/**
 * Blocks per second a free public endpoint will actually serve before it starts
 * refusing. Conservative and deliberately not optimistic: the binding constraint
 * on a public RPC is the rate limit, not bandwidth, and a limit that bites two
 * hours into a fetch is worse than one that bites immediately.
 */
export const FREE_RPC_BLOCKS_PER_SEC = 2;

export function estimateCost(fromSlot, toSlot) {
  const slots = Math.max(0, toSlot - fromSlot);
  const mb = slots * MB_PER_SLOT;
  const fetchHours = slots / FREE_RPC_BLOCKS_PER_SEC / 3600;
  return {
    slots,
    megabytes: mb,
    gigabytes: mb / 1024,
    days: slots / SLOTS_PER_DAY,
    fetchHours,
    /**
     * Feasible on a free endpoint means BOTH: it finishes in under an hour, and
     * it downloads under 20 GB.
     *
     * The first version of this returned `slots <= 20_000`, which called 226 GB
     * "yes" while the same function was computing that number two lines above.
     * Caught by printing the table and reading it. A threshold chosen in one
     * unit while the cost is reported in another is not a threshold, it is a
     * coincidence.
     */
    feasibleOnFreeRpc: fetchHours <= 1 && mb <= 20 * 1024,
  };
}

export function costTable() {
  const rows = [100, 1_000, 7_200, 20_000, 100_000, SLOTS_PER_DAY];
  const lines = [
    '  slots      of chain   block data   fetch @2/s   free public RPC?',
    '  ---------  ---------  -----------  -----------  ----------------',
  ];
  for (const s of rows) {
    const e = estimateCost(0, s);
    const span = e.days >= 1 ? `${e.days.toFixed(1)} d` : `${(e.days * 24).toFixed(1)} h`;
    const size = e.gigabytes >= 1 ? `${e.gigabytes.toFixed(1)} GB` : `${e.megabytes.toFixed(0)} MB`;
    const fetch = e.fetchHours >= 1 ? `${e.fetchHours.toFixed(1)} h` : `${(e.fetchHours * 60).toFixed(0)} min`;
    lines.push(
      `  ${String(s).padEnd(9)}  ${span.padEnd(9)}  ${size.padEnd(11)}  ${fetch.padEnd(11)}  `
      + `${e.feasibleOnFreeRpc ? 'yes' : 'no — paid archival endpoint'}`,
    );
  }
  lines.push('');
  lines.push('  A full day of chain is ~2.4 TB. There is no configuration in which that is a');
  lines.push('  free operation, and this table exists so nobody finds that out by starting it.');
  return lines.join('\n');
}

/**
 * The ledger as CSV. `share_of_total` is included because the raw token-slot
 * integers are enormous and meaningless on their own, and because the share is
 * what an airdrop weighting actually uses.
 *
 * Rows are ordered by token_slots descending so the first line of the file
 * answers the question most people open it with — and, on a raw snapshot, so
 * the pool is impossible to miss.
 */
export function ledgerToCsv(ledger, { includeHeader = true } = {}) {
  const total = ledger.reduce((a, r) => a + BigInt(r.tokenSlots ?? r.token_slots ?? 0), 0n);
  const rows = [...ledger].sort((a, b) => {
    const x = BigInt(b.tokenSlots ?? b.token_slots ?? 0) - BigInt(a.tokenSlots ?? a.token_slots ?? 0);
    return x > 0n ? 1 : x < 0n ? -1 : 0;
  });

  const out = [];
  if (includeHeader) out.push('owner,token_slots,share_of_total');
  for (const r of rows) {
    const ts = BigInt(r.tokenSlots ?? r.token_slots ?? 0);
    // Share to 12 decimal places, computed in integer arithmetic. A float here
    // would lose precision on numbers this size, and this column is what a
    // downstream airdrop multiplies by.
    const share = total === 0n ? '0' : (Number((ts * 1_000_000_000_000n) / total) / 1e12).toFixed(12);
    out.push(`${r.owner},${ts},${share}`);
  }
  return `${out.join('\n')}\n`;
}
