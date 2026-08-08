// SPDX-License-Identifier: Apache-2.0
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
import { buildTree, commitmentDomain } from './merkle.mjs';
import { PREDICATE_BUCKET, UNDECIDED_BUCKET } from './exclusions.mjs';
import { RULES } from './predicate.mjs';
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

  // ---------------------------------------------------------------------
  // UNDECIDED HALTS THE RUN
  //
  // The predicate has three verdicts, not two. An address it cannot decide —
  // because the operator marked it contentious, or because the owner field is
  // not a well-formed address — is not quietly paid and not quietly dropped.
  // The run stops and names every such address at once, so the operator
  // resolves the whole set in one pass rather than one abort at a time.
  //
  // The failure mode this prevents is the reason it is an abort and not a
  // warning: an unanswered question that resolves itself into whichever default
  // is cheaper for the publisher is not an unanswered question, it is an answer
  // nobody wrote down.
  // ---------------------------------------------------------------------
  const undecided = [...acc.excluded.entries()].filter(([bucket]) => bucket.startsWith(UNDECIDED_BUCKET));
  if (undecided.length) {
    const lines = undecided
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([bucket, tokenSlots]) => {
        const owner = bucket.slice(bucket.indexOf(':') + 1);
        const v = exclusions.verdictFor(owner);
        return `  ${owner}  ${tokenSlots} token-slots  (${v.rule}: ${v.reason})`;
      });
    throw new Error(
      `the exclusion predicate returned UNDECIDED for ${undecided.length} address(es), so no artifact was ` +
      `produced:\n${lines.join('\n')}\n\n` +
      'Resolve each one in the exclusion document and re-run. Either give it a ' +
      '`predicate.overrides` entry with verdict "claimable" (it can claim; pay it) or an `entries` entry ' +
      '(it is a policy exclusion; do not pay it). There is deliberately no way to make this warning-only: ' +
      'an undecided address must never be resolved by whichever default happens to be cheaper.',
    );
  }

  const ledger = ledgerFrom(acc.included);

  const excludedRows = [...acc.excluded.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([bucket, tokenSlots]) => ({ bucket, token_slots: tokenSlots }));

  // Reported apart, always: how much of this distribution was moved by human
  // judgement, and how much by a rule anybody can recompute.
  const predicateRows = excludedRows.filter((r) => r.bucket.startsWith(PREDICATE_BUCKET));
  const policyRows = excludedRows.filter((r) => !r.bucket.startsWith(PREDICATE_BUCKET));
  const sumOf = (rows) => rows.reduce((t, r) => t + r.token_slots, 0n);
  const predicateExcluded = sumOf(predicateRows);
  const policyExcluded = sumOf(policyRows);

  // The ledger hash: a commitment to the token-slot result alone, independent of
  // any vault amount or config pubkey. Two parties can compare this even when
  // one of them is not computing a payout at all.
  const ledgerHash = sha256Hex(canonicalJson({
    schema: 'escapement.ledger/v2',
    mint, from, to, commitment: COMMITMENT,
    exclusions_hash: exclusions.hash,
    predicate_hash: exclusions.predicate.hash,
    policy_binding: exclusions.policyBinding,
    opening_state: openingState,
    rows: ledger.map((r) => ({ owner: r.owner, token_slots: r.tokenSlots })),
  }));

  let dist = null;
  let tree = null;
  let domain = null;
  if (configPubkey !== null && vaultLamports !== null) {
    // The leaf domain binds the deployment AND the policy. See merkle.mjs.
    domain = commitmentDomain(configPubkey, exclusions.policyBinding);
    dist = distribute({ vaultLamports, ledger, prior });
    tree = buildTree(domain, dist.rows.map((r) => ({ claimant: r.owner, cumulative: r.cumulative })));
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
  if (exclusions.predicate.rules.length === 0) {
    warnings.push(
      'NO PREDICATE RULES WERE APPLIED. `predicate.rules` is empty, so addresses with no possible claimant — ' +
      'program-derived pool authorities, burned-LP AMM pools — accrue and are paid. Their share of the pot is ' +
      'not distributed, it is stranded: the leaves exist and nothing can ever redeem them. This is a legal ' +
      'and visible choice, and it is recorded in the root, but it should be a deliberate one.',
    );
  }
  if (predicateExcluded > 0n) {
    // Stated as a fraction of what the predicate faced, using integer arithmetic
    // in basis points — no float reaches this artifact.
    const faced = acc.totalIncluded + predicateExcluded;
    const bps = faced === 0n ? 0n : (predicateExcluded * 10000n) / faced;
    warnings.push(
      `THE PREDICATE REMOVED ${predicateRows.length} ADDRESS(ES) HOLDING ${predicateExcluded} TOKEN-SLOTS — ` +
      `${bps} basis points of what would otherwise have been entitled. Each is listed under ` +
      '`predicate.excluded` with the rule that removed it. This is a mechanical exclusion, recomputable by ' +
      'anyone from the addresses alone, but it is large enough to be worth checking rather than assuming: ' +
      'see the predicate\'s documented false exclusions (smart-contract wallets, multisig vaults, ' +
      'program treasuries) in predicate.mjs, and the `predicate.overrides` escape hatch.',
    );
  }
  for (const o of exclusions.predicate.overrides) {
    warnings.push(
      `PREDICATE OVERRIDE in force: ${o.address} is treated as ${o.verdict} by operator declaration ` +
      `rather than by the rules. Justification: ${o.justification} Evidence: ${o.evidence}`,
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
    predicate_id: exclusions.predicate.id,
    predicate_rules: exclusions.predicate.rules,
    predicate_hash: exclusions.predicate.hash,
    // The one value that stands for "everything about who gets paid that is not
    // chain data". Bound into the merkle domain, so it cannot change silently.
    policy_binding: exclusions.policyBinding,
    merkle_domain: domain,
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

      // Discretionary exclusions only — what a human decided.
      policy_excluded_addresses: policyRows.length,
      policy_excluded_token_slots: policyExcluded,
    },

    // The mechanical half, reported on its own so its effect is never folded
    // into the discretionary total. Every address it removed is named, with what
    // it cost, so somebody who believes they were wrongly excluded can find
    // themselves here rather than having to reverse-engineer their absence.
    predicate: {
      id: exclusions.predicate.id,
      hash: exclusions.predicate.hash,
      rules: exclusions.predicate.rules,
      rule_descriptions: exclusions.predicate.rules.map((id) => ({ rule: id, summary: RULES[id].summary })),
      overrides: exclusions.predicate.canonical.overrides,
      excluded_addresses: predicateRows.length,
      excluded_token_slots: predicateExcluded,
      excluded: predicateRows
        .map((r) => {
          const rest = r.bucket.slice(PREDICATE_BUCKET.length);
          const cut = rest.indexOf(':');
          const owner = rest.slice(cut + 1);
          return { owner, rule: rest.slice(0, cut), token_slots: r.token_slots, reason: exclusions.verdictFor(owner).reason };
        })
        .sort((a, b) => (a.owner < b.owner ? -1 : 1)),
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
