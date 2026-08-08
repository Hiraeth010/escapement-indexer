/**
 * run.mjs — the pipeline. Fetch, extract, accrue, exclude, distribute, commit.
 *
 * Everything load-bearing lives in the modules this imports; this file is the
 * order they go in and the artifact they produce. It is shared between
 * `index` and `verify` — see README §"What verification actually proves", which
 * says exactly what that costs.
 */

import { fetchRange } from './blocks.mjs';
import { extractBlock } from './extract.mjs';
import { accrue, ledgerFrom } from './accrue.mjs';
import { distribute } from './entitle.mjs';
import { buildTree } from './merkle.mjs';
import { LineHasher, hashValue, canonicalJson, sha256Hex } from './canonical.mjs';
import { environment, SCHEMA_VERSION } from './version.mjs';
import { comparePubkeys } from './base58.mjs';

const COMMITMENT = 'finalized';

/**
 * Build the input-set commitment (D5).
 *
 * Line-oriented on purpose. When two parties get different roots, the first
 * question is "do we disagree about the inputs or about the arithmetic", and the
 * answer must cost one `diff`, not an argument. Every line is a slot or a
 * transaction, in ascending order, so the first differing line IS the
 * disagreement.
 */
export function buildInputSet({ mint, from, to, produced, skipped, blocks, extracted, anchorPreviousBlockhash }) {
  const h = new LineHasher();
  h.push(`escapement-input-set v1`);
  h.push(`mint ${mint}`);
  h.push(`range ${from} ${to}`);
  h.push(`commitment ${COMMITMENT}`);
  h.push(`anchor-previous-blockhash ${anchorPreviousBlockhash ?? '-'}`);

  const producedSet = new Set(produced);
  const skippedSet = new Set(skipped);
  for (let slot = from; slot < to; slot++) {
    if (skippedSet.has(slot)) {
      h.push(`slot ${slot} skipped`);
      continue;
    }
    if (!producedSet.has(slot)) throw new Error(`buildInputSet: slot ${slot} is neither produced nor skipped`);
    const b = blocks.get(slot);
    h.push(`slot ${slot} block ${b.blockhash} parent ${b.parentSlot} prev ${b.previousBlockhash}`);
    for (const c of extracted.get(slot).consumed) {
      h.push(`tx ${c.slot} ${c.index} ${c.signature} ${c.ok ? 'ok' : 'err'}`);
    }
  }
  return h;
}

/**
 * @param {object} args
 * @param {import('./rpc.mjs').Rpc} args.rpc
 * @param {string} args.mint
 * @param {number} args.from inclusive
 * @param {number} args.to   exclusive
 * @param {ReturnType<import('./exclusions.mjs').parseExclusions>} args.exclusions
 * @param {string|null} args.configPubkey  required to produce a merkle root
 * @param {bigint|null} args.vaultLamports required to produce a merkle root
 * @param {Map<string,bigint>} [args.prior]
 * @param {{account,owner,amount}[]} [args.openingAccounts]
 * @param {string} [args.openingStateSource] where the opening accounts came from
 */
export async function runIndex({
  rpc, mint, from, to, exclusions,
  configPubkey = null, vaultLamports = null, vaultSource = null,
  prior = new Map(), priorSource = null,
  openingAccounts = [], openingStateSource = null,
  concurrency = 4, onProgress = null,
}) {
  // ---------------------------------------------------------------------
  // THE OPENING STATE
  //
  // Integrating balance over [from, to) needs the balance table AT `from`.
  // Block iteration only reveals an account when something touches it, so an
  // address that held tokens before `from` and is not touched inside the range
  // is invisible and accrues zero. There is no way to ask a public RPC for
  // historical account state, so the only honest answers are:
  //
  //   (a) start at the mint's first slot, where the correct opening state is
  //       provably empty; or
  //   (b) chain: feed in the previous period's closing state, whose hash is
  //       committed here so the chain is auditable link by link.
  //
  // Anything else silently under-credits dormant holders. The artifact records
  // which of the two this run used, and warns when it is neither.
  // ---------------------------------------------------------------------
  const openingState = {
    mode: openingAccounts.length > 0 ? 'chained' : 'empty',
    hash: sha256Hex(canonicalJson(
      [...openingAccounts]
        .sort((a, b) => comparePubkeys(a.account, b.account))
        .map((a) => ({ account: a.account, owner: a.owner, amount: a.amount })),
    )),
    accounts: openingAccounts.length,
    source: openingStateSource,
  };
  const startedAt = new Date().toISOString();

  // Extraction is streamed: each block is reduced to its mint-relevant facts and
  // then released. Memory therefore scales with the number of TRANSFERS in the
  // range, not with the number of megabytes in it.
  const range = await fetchRange({
    rpc, from, to, concurrency, onProgress,
    transform: (slot, block) => extractBlock(block, slot, mint),
  });

  const extracted = new Map();
  const slotEvents = [];
  let consumedTxs = 0;
  let failedTxs = 0;
  let supplyDelta = 0n;
  let decimals = null;

  for (const slot of range.produced) {
    const ex = range.blocks.get(slot).value;
    extracted.set(slot, ex);
    consumedTxs += ex.consumed.length;
    failedTxs += ex.consumed.filter((c) => !c.ok).length;
    supplyDelta += ex.supplyDelta;
    if (decimals === null) decimals = ex.decimals;
    if (ex.events.length) slotEvents.push({ slot, events: ex.events });
  }

  const inputSet = buildInputSet({
    mint, from, to,
    produced: range.produced, skipped: range.skipped,
    blocks: range.blocks, extracted,
    anchorPreviousBlockhash: range.anchorPreviousBlockhash,
  });

  const acc = accrue({
    fromSlot: from, toSlot: to,
    openingAccounts, slotEvents,
    classify: exclusions.classify,
  });

  const ledger = ledgerFrom(acc.included);

  const excludedRows = [...acc.excluded.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([bucket, tokenSlots]) => ({ bucket, token_slots: tokenSlots }));

  // The ledger hash: a commitment to the token-slot result alone, independent of
  // any vault amount or config pubkey. Two parties can compare this even when
  // one of them is not computing a payout at all.
  const ledgerHash = sha256Hex(canonicalJson({
    schema: 'escapement.ledger/v1',
    mint, from, to, commitment: COMMITMENT,
    exclusions_hash: exclusions.hash,
    opening_state: openingState,
    rows: ledger.map((r) => ({ owner: r.owner, token_slots: r.tokenSlots })),
  }));

  let dist = null;
  let tree = null;
  if (configPubkey !== null && vaultLamports !== null) {
    dist = distribute({ vaultLamports, ledger, prior });
    tree = buildTree(configPubkey, dist.rows.map((r) => ({ claimant: r.owner, cumulative: r.cumulative })));
  }

  const closingStateHash = sha256Hex(canonicalJson(acc.closing));

  const warnings = [];
  if (openingState.mode === 'empty') {
    warnings.push(
      'OPENING STATE IS EMPTY. Any address that held a balance at from_slot and was not touched anywhere ' +
      'in [from_slot, to_slot) accrued zero here. That is correct ONLY if from_slot is at or before the ' +
      'mint\'s first token account. For any later period, pass --opening-state <previous artifact> so the ' +
      'balance table is chained forward, and check that its closing_state_hash matches.',
    );
  }
  if (supplyDelta !== 0n) {
    warnings.push(
      `SUPPLY CHANGED by ${supplyDelta} base units inside this range (mint and/or burn). Token-slots are ` +
      'still conserved slot by slot, but the denominator moved during the period; that is a fact about the ' +
      'token, not an error, and it is recorded here so nobody has to discover it later.',
    );
  }
  if (exclusions.acknowledgementGaps.length) {
    warnings.push(
      `/spec §4.5 cases neither excluded nor declared undecided in the exclusion set: ` +
      `${exclusions.acknowledgementGaps.join(', ')}.`,
    );
  }

  const env = environment();

  const params = {
    schema: SCHEMA_VERSION,
    mint,
    from_slot: from,
    to_slot: to,
    range_convention: '[from_slot, to_slot) — half-open, start inclusive, end exclusive',
    commitment: COMMITMENT,
    config_pubkey: configPubkey,
    vault_lamports: vaultLamports === null ? null : vaultLamports,
    // House rule from ops/src/provenance.mjs: no number is published without
    // saying where it came from. The vault balance is an INPUT to this program,
    // not something it measures, so it must declare its own provenance or the
    // artifact would present a hypothesis in the same typeface as a measurement.
    vault_lamports_source: vaultLamports === null ? null : vaultSource,
    exclusions_hash: exclusions.hash,
    exclusions_version: exclusions.canonical.version,
    opening_state: openingState,
    prior_root_source: priorSource,
  };

  const manifest = {
    ...env,
    params,
    exclusions: exclusions.canonical,
    input_set_hash: inputSet.digest(),
  };
  const manifestHash = hashValue(manifest);

  const artifact = {
    schema: SCHEMA_VERSION,
    produced_at: startedAt,
    params,

    // --- the commitments, in the order the on-chain EpochRoot wants them (G6)
    merkle_root: tree ? tree.root : null,
    total_owed_cumulative: dist ? dist.totalOwedCumulative : null,
    input_set_hash: inputSet.digest(),
    manifest_hash: manifestHash,
    ledger_hash: ledgerHash,
    closing_state_hash: closingStateHash,
    indexer_source_hash: env.indexer_source_hash,
    indexer_git_commit: env.indexer_git_commit,

    warnings,

    // --- slot accounting (D4): every slot in range is one of these two, exactly
    slots: {
      total: to - from,
      produced: range.produced.length,
      skipped: range.skipped.length,
      skipped_slots: range.skipped,
      anchor_previous_blockhash: range.anchorPreviousBlockhash,
      finalized_tip_at_run: range.finalizedTip,
      continuity_verified: true,
    },

    transactions: {
      consumed: consumedTxs,
      failed_included_in_input_set: failedTxs,
      net_supply_delta: supplyDelta,
      supply_changed: supplyDelta !== 0n,
    },

    accrual: {
      unit: 'token-slots (raw token base units × slots)',
      decimals,
      total_token_slots_entitled: acc.totalIncluded,
      total_token_slots_excluded: acc.totalExcluded,
      owners_entitled: ledger.length,
      spans: acc.spans,
    },

    exclusions: {
      hash: exclusions.hash,
      version: exclusions.canonical.version,
      effective_from_slot: exclusions.canonical.effective_from_slot,
      policy: exclusions.canonical.policy,
      undecided: exclusions.canonical.undecided,
      entries: exclusions.canonical.entries,
      matched: excludedRows,
      acknowledgement_gaps: exclusions.acknowledgementGaps,
    },

    distribution: dist === null ? null : {
      vault_lamports: vaultLamports,
      distributed_lamports: dist.distributed,
      remainder_lamports: dist.remainder,
      remainder_bound_lamports: BigInt(Math.max(0, ledger.length - 1)),
      rounding: 'floor — truncation is retained by the vault, never paid out (see entitle.mjs)',
    },

    ledger: ledger.map((r) => ({ owner: r.owner, token_slots: r.tokenSlots })),

    // The balance table at to_slot. Feed this to the next period as
    // --opening-state, or that period silently under-credits every holder who
    // does not transact in it.
    closing_state: acc.closing,

    payouts: dist === null ? null : dist.rows.map((r) => ({
      owner: r.owner,
      token_slots: r.tokenSlots,
      payout_lamports: r.payout,
      cumulative_lamports: r.cumulative,
    })),

    environment: env,

    rpc_cost: {
      endpoint_host: new URL(rpc.url).host,
      calls: rpc.stats.calls,
      retries: rpc.stats.retries,
      response_bytes: rpc.stats.bytes,
      wall_ms: rpc.stats.ms,
    },
  };

  return { artifact, inputSet, tree, dist, ledger, range, extracted, manifest };
}

/**
 * The balance table to carry into the next period, from a previous artifact.
 * The caller must check `closing_state_hash` — this function trusts the file.
 */
export function openingFromArtifact(doc) {
  if (!Array.isArray(doc?.closing_state)) {
    throw new Error('opening state: the supplied artifact has no closing_state array');
  }
  return doc.closing_state.map((a) => ({ account: a.account, owner: a.owner, amount: BigInt(a.amount) }));
}

/** Sorted owner->cumulative map from a previous artifact, for G3 continuity. */
export function priorFromArtifact(doc) {
  const m = new Map();
  if (!doc?.payouts) return m;
  for (const p of doc.payouts) m.set(p.owner, BigInt(p.cumulative_lamports));
  return m;
}

/** Ledger rows from an artifact, in the pinned order, for diffing. */
export function ledgerFromArtifact(doc) {
  return (doc?.ledger ?? [])
    .map((r) => ({ owner: r.owner, tokenSlots: BigInt(r.token_slots) }))
    .sort((a, b) => comparePubkeys(a.owner, b.owner));
}
