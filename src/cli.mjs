#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * cli.mjs — `escapement index`, `escapement verify`, and the small tools around
 * them.
 *
 * Rule inherited from the threat model's key inventory (#9): this CLI accepts a
 * PUBLIC ADDRESS ONLY. It never reads a keypair path, never takes a private key,
 * never signs, and never sends a transaction. There is no code path in this
 * package that can move a lamport, and that is checkable by grepping for
 * `sendTransaction` and finding nothing.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Rpc, DEFAULT_ENDPOINTS } from './rpc.mjs';
import { loadExclusions, parseExclusions, diffExclusions, exclusionsTemplate } from './exclusions.mjs';
import { runIndex, priorFromArtifact, openingFromArtifact } from './run.mjs';
import { runVerify, hashInputSetText } from './verify.mjs';
import { prettyCanonical } from './canonical.mjs';
import { isPubkey } from './base58.mjs';
import { environment } from './version.mjs';
import { readVaultState, checkPot } from './pot.mjs';
import { ledgerToCsv, estimateCost, costTable } from './snapshot.mjs';

const USAGE = `escapement — deterministic token-slot entitlement indexer

  escapement index  --mint <pubkey> --from <slot> --to <slot> --exclusions <file> [options]
  escapement verify --root <hex> --mint <pubkey> --from <slot> --to <slot> --exclusions <file> [options]
  escapement preflight --config <pubkey> --vault <pubkey> --total <lamports> [--rpc <url>]
  escapement exclusions-diff <before.json> <after.json>
  escapement exclusions-template [--mint <pubkey>] [--from <slot>]
  escapement cost [--from <slot> --to <slot>]
  escapement env

BEFORE YOU START A RUN
  escapement cost --from <slot> --to <slot>

  Block data is ~11.6 MB PER SLOT and is paid on every slot in the range, so a
  day of chain is about 2.4 TB and roughly 30 hours of fetching on a public
  endpoint. Short ranges are genuinely cheap; a day is not, in any configuration.
  This is printed rather than discovered, because the only other way to find that
  wall is to run into it.

TO GET A HOLDER WEIGHTING OUT (rather than a merkle root)
  --csv <file>          writes the token-slot ledger as
                          owner,token_slots,share_of_total
                        ordered by holding, largest first. That is the input an
                        airdrop weighting wants, and using it does not require
                        adopting this project's distribution mechanism, its
                        merkle leaf format, or its config PDA.

                        The rows reflect the exclusions YOU supplied. If your
                        policy excludes nothing, the AMM pool is very likely the
                        first line — on one real distribution it was 85% of the
                        total, held at an address no keypair can sign for.

RANGE
  --from / --to define the half-open slot range [from, to). Both bounds must be
  finalized before the run starts; the run aborts otherwise.

REQUIRED, NO DEFAULT
  --exclusions <file>   the policy document. Two halves, both hashed into the root:
                          entries[]   DISCRETIONARY — addresses a human decided are
                                      not beneficial holders. No built-in list, no
                                      inference, justification and evidence required.
                          predicate   MECHANICAL — which unclaimable-address rules to
                                      apply. Also required, also never defaulted; the
                                      only rule in v1 removes owners that are off the
                                      ed25519 curve and therefore cannot be signed for.
                        See exclusions.mjs and predicate.mjs. A run whose predicate
                        returns UNDECIDED for any address aborts and writes nothing.

TO PRODUCE A MERKLE ROOT (otherwise only the token-slot ledger is produced)
  --config <pubkey>     the deployment's config PDA; domain-separates the leaves
  --vault-lamports <n>  the pot being distributed, in lamports (an INPUT, not a
                        measurement — the artifact labels it as one)
  --vault-source <s>    required with the above: chain | manual-attested | hypothetical
  --prior <artifact>    the PREVIOUS period's artifact, so leaves stay cumulative (G3).
                        On verify, this is the artifact BEFORE the one under test.
  --domain-tag <s>      the leaf namespace. Defaults to Escapement's. If you are
                        running this for your OWN distribution, pass your own —
                        otherwise your leaves commit to our namespace forever, and
                        our proofs and yours live in the same domain. Printable
                        ASCII, no spaces, 1-128 chars. It is written into the
                        artifact, so anyone holding the file can rebuild the root.

CHAINING PERIODS
  --opening-state <artifact>  the previous period's artifact, whose closing_state
                        becomes this period's opening balance table. Omit ONLY when
                        --from is at or before the mint's first token account; the
                        artifact carries a warning saying so either way.

OPTIONS
  --rpc <url>           default \${SOLANA_RPC_URL} or ${DEFAULT_ENDPOINTS.mainnet}
  --cluster <name>      mainnet | devnet | testnet — shorthand for --rpc
  --out <file>          artifact path (default ./artifacts/<mint>.<from>-<to>.json).
                        The input set is written alongside as <out>.input-set.txt
  --concurrency <n>     parallel getBlock calls (default 4)
  --min-interval-ms <n> client-side throttle between RPC calls (default 0; try
                        120 on a public endpoint)
  --artifact <file>     (verify) the published artifact, for localising a disagreement
  --input-set <file>    (verify) the published input set, for localising to a slot
  --quiet
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--quiet') { out.quiet = true; continue; }
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`missing value for --${k}`);
      out[k] = v;
      i++;
      continue;
    }
    out._.push(a);
  }
  return out;
}

function requireSlot(v, name) {
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`--${name} must be a non-negative integer slot, got ${JSON.stringify(v)}`);
  return n;
}

function requirePubkey(v, name) {
  if (typeof v !== 'string' || !isPubkey(v)) throw new Error(`--${name} must be a base58 pubkey, got ${JSON.stringify(v)}`);
  return v;
}

function makeRpc(args) {
  const url = args.rpc
    ?? (args.cluster ? DEFAULT_ENDPOINTS[args.cluster] : null)
    ?? process.env.SOLANA_RPC_URL
    ?? DEFAULT_ENDPOINTS.mainnet;
  if (!url) throw new Error(`unknown --cluster ${args.cluster}`);
  return new Rpc({
    url,
    minIntervalMs: args['min-interval-ms'] ? Number(args['min-interval-ms']) : 0,
    onRetry: ({ method, slot, attempt, delayMs, error }) => {
      process.stderr.write(`  retry ${attempt} ${method}${slot != null ? ` slot ${slot}` : ''} in ${delayMs}ms — ${error.message}\n`);
    },
  });
}

function writeArtifact(path, artifact, inputSet) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, prettyCanonical(artifact));
  const isPath = `${path.replace(/\.json$/, '')}.input-set.txt`;
  writeFileSync(isPath, inputSet.text());
  return { path, isPath };
}

/**
 * Load the previous period's closing balances. The `to_slot`/`from_slot` check
 * is not pedantry: chaining from a non-adjacent period silently omits every
 * transfer in the gap, and the resulting root would be wrong and reproducible.
 */
function loadOpeningState(args, from) {
  if (!args['opening-state']) return { openingAccounts: [], openingStateSource: null };
  const doc = JSON.parse(readFileSync(args['opening-state'], 'utf8'));
  if (doc.params?.to_slot !== from) {
    throw new Error(
      `--opening-state artifact ends at slot ${doc.params?.to_slot} but this run starts at ${from}. ` +
      'The periods must be adjacent; a gap means every transfer inside it is missing from the balance table.',
    );
  }
  return {
    openingAccounts: openingFromArtifact(doc),
    openingStateSource: `${args['opening-state']} (closing_state_hash ${doc.closing_state_hash})`,
  };
}

function progressBar(quiet) {
  if (quiet) return null;
  let last = 0;
  return ({ done, total }) => {
    if (done === total || done - last >= Math.max(1, Math.floor(total / 20))) {
      last = done;
      process.stderr.write(`  fetched ${done}/${total} blocks\n`);
    }
  };
}

async function cmdIndex(args) {
  const mint = requirePubkey(args.mint, 'mint');
  const from = requireSlot(args.from, 'from');
  const to = requireSlot(args.to, 'to');
  const exclusions = loadExclusions(args.exclusions, { mint, fromSlot: from });

  const configPubkey = args.config ? requirePubkey(args.config, 'config') : null;
  const vaultLamports = args['vault-lamports'] !== undefined ? BigInt(args['vault-lamports']) : null;
  if ((configPubkey === null) !== (vaultLamports === null)) {
    throw new Error('--config and --vault-lamports must be supplied together (both are needed for a merkle root)');
  }
  const VAULT_SOURCES = ['chain', 'manual-attested', 'hypothetical'];
  const vaultSource = args['vault-source'] ?? null;
  if (vaultLamports !== null && !VAULT_SOURCES.includes(vaultSource)) {
    throw new Error(
      `--vault-source is required with --vault-lamports and must be one of ${VAULT_SOURCES.join(' | ')}. ` +
      'The vault balance is an input, not something this program measures; the artifact records which it is ' +
      'so a hypothetical is never printed in the same typeface as a reading.',
    );
  }

  let prior = new Map();
  let priorSource = null;
  if (args.prior) {
    const doc = JSON.parse(readFileSync(args.prior, 'utf8'));
    prior = priorFromArtifact(doc);
    priorSource = `${args.prior} (root ${doc.merkle_root})`;
  }

  const { openingAccounts, openingStateSource } = loadOpeningState(args, from);

  const rpc = makeRpc(args);
  if (!args.quiet) {
    process.stderr.write(`escapement index\n  mint ${mint}\n  range [${from}, ${to}) — ${to - from} slots\n`);
    process.stderr.write(`  rpc ${new URL(rpc.url).host}\n  exclusions ${exclusions.path} (${exclusions.hash.slice(0, 16)}…, ${exclusions.entries.length} entries)\n`);
    process.stderr.write(
      `  predicate  ${exclusions.predicate.id} rules=[${exclusions.predicate.rules.join(', ') || 'none'}] ` +
      `overrides=${exclusions.predicate.overrides.length} (${exclusions.predicate.hash.slice(0, 16)}…)\n` +
      `  policy binding ${exclusions.policyBinding.slice(0, 16)}…\n`,
    );
    if (exclusions.acknowledgementGaps.length) {
      process.stderr.write(`  note: /spec §4.5 cases neither excluded nor listed as undecided: ${exclusions.acknowledgementGaps.join(', ')}\n`);
    }
  }

  const { artifact, inputSet } = await runIndex({
    rpc, mint, from, to, exclusions, configPubkey, vaultLamports, vaultSource, prior, priorSource,
    openingAccounts, openingStateSource,
    // Omitted, not defaulted-to-null: run.mjs owns the default, and passing null
    // here would override it with something commitmentDomain refuses outright.
    ...(args['domain-tag'] === undefined ? {} : { domainTag: args['domain-tag'] }),
    concurrency: args.concurrency ? Number(args.concurrency) : 4,
    onProgress: progressBar(args.quiet),
  });

  const out = resolve(args.out ?? `artifacts/${mint}.${from}-${to}.json`);
  const written = writeArtifact(out, artifact, inputSet);

  /**
   * `--csv` — the token-slot ledger as something a stranger can use.
   *
   * A reviewer could name a concrete user for the census in this project and
   * could not name one for the indexer. The reason was not the measurement, it
   * was the packaging: the only output was a JSON artifact carrying an
   * Escapement-domain merkle root that no deployed program reads. The genuinely
   * reusable part — who held how much, for how long — was in there and had no
   * way out.
   *
   * `owner,token_slots,share_of_total`, ordered by holding. That is the input an
   * airdrop weighting wants, and it does not require adopting any of this
   * project's distribution mechanism to use.
   */
  if (args.csv) {
    const csvPath = resolve(args.csv);
    const rows = artifact.ledger ?? artifact.entitlements ?? null;
    if (!rows) {
      process.stderr.write('\n  --csv: this artifact carries no ledger rows to write.\n');
    } else {
      writeFileSync(csvPath, ledgerToCsv(rows));
      if (!args.quiet) {
        process.stderr.write(`\n  csv       ${csvPath}  (${rows.length} owners, ordered by holding)\n`);
        process.stderr.write('            NOTE: these are RAW time-weighted holdings after the exclusions you\n');
        process.stderr.write('            supplied. If your policy excluded nothing, the AMM pool is very likely\n');
        process.stderr.write('            the first line — on one real distribution it was 85% of the total.\n');
      }
    }
  }

  if (!args.quiet) {
    const a = artifact;
    for (const w of a.warnings) process.stderr.write(`\n  WARNING: ${w}\n`);
    process.stderr.write(
      `\n  slots            ${a.slots.total} (${a.slots.produced} produced, ${a.slots.skipped} skipped, continuity verified)\n` +
      `  transactions     ${a.transactions.consumed} touching the mint (${a.transactions.failed_included_in_input_set} failed)\n` +
      `  owners entitled  ${a.accrual.owners_entitled}\n` +
      `  token-slots      ${a.accrual.total_token_slots_entitled} entitled / ${a.accrual.total_token_slots_excluded} excluded\n` +
      `  predicate        removed ${a.predicate.excluded_addresses} address(es), ${a.predicate.excluded_token_slots} token-slots\n` +
      `  policy set       removed ${a.exclusions.policy_excluded_addresses} bucket(s), ${a.exclusions.policy_excluded_token_slots} token-slots\n` +
      `  input_set_hash   ${a.input_set_hash}\n` +
      `  ledger_hash      ${a.ledger_hash}\n` +
      `  manifest_hash    ${a.manifest_hash}\n` +
      `  merkle_root      ${a.merkle_root ?? '(not computed — pass --config and --vault-lamports)'}\n` +
      (a.distribution ? `  distributed      ${a.distribution.distributed_lamports} lamports, ${a.distribution.remainder_lamports} retained as remainder (bound ${a.distribution.remainder_bound_lamports})\n` : '') +
      `  rpc cost         ${a.rpc_cost.calls} calls, ${a.rpc_cost.retries} retries, ${(a.rpc_cost.response_bytes / 1e6).toFixed(1)} MB, ${(a.rpc_cost.wall_ms / 1000).toFixed(1)}s\n` +
      `\n  artifact  ${written.path}\n  input set ${written.isPath}\n`,
    );
  }
  return 0;
}

async function cmdVerify(args) {
  const expectedRoot = args.root;
  if (typeof expectedRoot !== 'string' || !/^[0-9a-f]{64}$/.test(expectedRoot)) {
    throw new Error('--root must be a 64-character lowercase hex string');
  }
  const published = args.artifact ? JSON.parse(readFileSync(args.artifact, 'utf8')) : null;

  const mint = requirePubkey(args.mint ?? published?.params?.mint, 'mint');
  const from = requireSlot(args.from ?? published?.params?.from_slot, 'from');
  const to = requireSlot(args.to ?? published?.params?.to_slot, 'to');
  const configPubkey = requirePubkey(args.config ?? published?.params?.config_pubkey, 'config');

  // B7 — the pot is the one number a dishonest publisher would move, and the old
  // code defaulted it to whatever the artifact declared, so a green AGREE proved
  // nothing about it. Track its PROVENANCE: only a pot the verifier supplied
  // independently (or derived from chain via --vault) makes the AGREE cover it.
  const potFromOperator = args['vault-lamports'] !== undefined && args['vault-lamports'] !== null;
  const vaultRaw = args['vault-lamports'] ?? published?.params?.vault_lamports;
  if (vaultRaw === undefined || vaultRaw === null) throw new Error('--vault-lamports is required (or supply --artifact)');
  const vaultLamports = BigInt(vaultRaw);
  const potProvenance = potFromOperator ? 'operator-supplied' : 'read-from-artifact-under-review';

  const exclusions = loadExclusions(args.exclusions, { mint, fromSlot: from });
  if (published && published.params?.exclusions_hash && published.params.exclusions_hash !== exclusions.hash) {
    process.stderr.write(
      `\n  WARNING: the exclusion set you supplied hashes to ${exclusions.hash}\n` +
      `           but the artifact was produced with ${published.params.exclusions_hash}.\n` +
      `           Continuing so the difference is visible in the result, but this alone explains a differing root.\n\n`,
    );
  }

  let publishedInputSetText = null;
  if (args['input-set']) {
    publishedInputSetText = readFileSync(args['input-set'], 'utf8');
    const h = hashInputSetText(publishedInputSetText);
    if (published?.input_set_hash && h !== published.input_set_hash) {
      process.stderr.write(
        `  WARNING: the input-set file hashes to ${h} but the artifact claims ${published.input_set_hash}. ` +
        `One of the two files has been edited.\n`,
      );
    }
  }

  // The prior is the artifact BEFORE the one being verified. The published
  // artifact names it in params.prior_root_source.
  let prior = new Map();
  let priorSource = null;
  if (args.prior) {
    const doc = JSON.parse(readFileSync(args.prior, 'utf8'));
    prior = priorFromArtifact(doc);
    priorSource = `${args.prior} (root ${doc.merkle_root})`;
  }

  const rpc = makeRpc(args);
  if (!args.quiet) {
    process.stderr.write(
      `escapement verify\n  root ${expectedRoot}\n  mint ${mint}\n  range [${from}, ${to})\n` +
      `  rpc ${new URL(rpc.url).host}   <- use a DIFFERENT provider than the publisher, or this proves less\n`,
    );
  }

  const { openingAccounts, openingStateSource } = loadOpeningState(args, from);

  const res = await runVerify({
    rpc, mint, from, to, exclusions, configPubkey, vaultLamports, openingAccounts, openingStateSource,
    // Only consulted on the --root-only path; with --artifact the published file's
    // own tag wins, because verification re-derives what the PUBLISHER did.
    ...(args['domain-tag'] === undefined ? {} : { domainTag: args['domain-tag'] }),
    vaultSource: args['vault-source'] ?? published?.params?.vault_lamports_source ?? null,
    expectedRoot, publishedArtifact: published, publishedInputSetText, prior, priorSource,
    concurrency: args.concurrency ? Number(args.concurrency) : 4,
    onProgress: progressBar(args.quiet),
  });

  process.stdout.write(`\n${res.agree ? 'AGREE' : 'DISAGREE'}${potProvenance === 'read-from-artifact-under-review' ? ' (POT-AGNOSTIC)' : ''}\n\n`);
  for (const f of res.findings) {
    process.stdout.write(`  [${f.level}] ${f.where}\n    ${f.detail.replace(/\n/g, '\n    ')}\n`);
  }

  // B7 — say plainly what the AGREE does and does not cover for the pot.
  if (potProvenance === 'read-from-artifact-under-review') {
    process.stdout.write(
      `\n  [POT-AGNOSTIC] vault_lamports (${vaultLamports}) was read from the artifact under review,\n` +
      `    not supplied independently. This AGREE proves the root is consistent with THAT pot; it does\n` +
      `    NOT prove the pot is what the vault actually held. A publisher who under-declared the pot\n` +
      `    strands holders' money and still gets AGREE here. To close this, re-run with an independently\n` +
      `    sourced --vault-lamports, or run \`escapement preflight\` against chain state.\n`,
    );
  } else {
    process.stdout.write(`\n  [pot] vault_lamports ${vaultLamports} was operator-supplied, so this AGREE covers it.\n`);
  }
  process.stdout.write(
    `\n  Verification shares the fetch, decode and accrual code with the producer.\n` +
    `  A bug in that shared code passes this check. See README, "What verification actually proves".\n`,
  );
  if (args.out) writeArtifact(resolve(args.out), res.artifact, { text: () => '' });
  // A pot-agnostic AGREE is not a full pass: exit non-zero so a CI gate cannot
  // treat it as one.
  const potOk = potProvenance !== 'read-from-artifact-under-review';
  return res.agree && res.internallyConsistent && potOk ? 0 : 1;
}

/**
 * B7 — the publish preflight. Reads the vault balance and the on-chain Config
 * from chain, derives the maximum legal `total_owed_cumulative`, and refuses a
 * proposed total that the program would reject or that would strand money.
 *
 *   escapement preflight --config <pubkey> --vault <pubkey> --total <lamports> --rpc <url>
 *
 * Reads only. Signs nothing, sends nothing.
 */
async function cmdPreflight(args) {
  const configPubkey = requirePubkey(args.config, 'config');
  const vaultPubkey = requirePubkey(args.vault, 'vault');
  if (args.total === undefined) throw new Error('--total <lamports> is required (the proposed total_owed_cumulative)');
  const proposed = BigInt(args.total);

  const rpc = makeRpc(args);
  const state = await readVaultState(rpc, configPubkey, vaultPubkey);
  const verdict = checkPot(proposed, state);

  process.stdout.write(
    `escapement preflight\n` +
    `  config            ${configPubkey}\n` +
    `  vault             ${vaultPubkey}\n` +
    `  vault balance     ${state.vaultLamports} (rent-exempt min ${state.rentMin})\n` +
    `  total_claimed     ${state.totalClaimed}\n` +
    `  high_water        ${state.highWater}\n` +
    `  funded (derived)  ${verdict.funded}\n` +
    `  max delta (G2)    ${verdict.maxDelta}\n` +
    `  MAX LEGAL TOTAL   ${verdict.maxTotal}\n` +
    `  proposed total    ${proposed}\n\n` +
    `  ${verdict.ok ? 'OK' : `REFUSED (${verdict.reason})`} — ${verdict.detail}\n`,
  );
  return verdict.ok ? 0 : 1;
}

function cmdExclusionsDiff(args) {
  const [beforePath, afterPath] = args._;
  if (!beforePath || !afterPath) throw new Error('usage: escapement exclusions-diff <before.json> <after.json>');
  const a = parseExclusions(readFileSync(beforePath, 'utf8'), {});
  const b = parseExclusions(readFileSync(afterPath, 'utf8'), {});
  const d = diffExclusions(a, b);

  process.stdout.write(`${beforePath}  ${d.hashBefore}\n${afterPath}  ${d.hashAfter}\n\n`);
  if (d.identical) { process.stdout.write('IDENTICAL — the two sets hash the same, so they produce the same root.\n'); return 0; }
  process.stdout.write('DIFFERENT — this changes the root of every period it applies to.\n\n');

  if (!d.predicate.identical) {
    process.stdout.write('  PREDICATE (mechanical — who can possibly claim at all)\n');
    if (d.predicate.idBefore !== d.predicate.idAfter) {
      process.stdout.write(`    ~ id      ${d.predicate.idBefore} -> ${d.predicate.idAfter}\n`);
    }
    if (d.predicate.rulesChanged) {
      process.stdout.write(
        `    ~ rules   [${d.predicate.rulesBefore.join(', ')}] -> [${d.predicate.rulesAfter.join(', ')}]\n` +
        '              A rule added removes every address it matches from every distribution it covers.\n' +
        '              A rule removed pays them, and pays addresses that may not be able to claim.\n',
      );
    }
    for (const o of d.predicate.overridesAdded) {
      process.stdout.write(`    + override ${o.address} -> ${o.verdict}\n        ${o.justification}\n        evidence: ${o.evidence}\n`);
    }
    for (const o of d.predicate.overridesRemoved) {
      process.stdout.write(`    - override ${o.address} (was ${o.verdict}; the rules now decide it again)\n`);
    }
    process.stdout.write('\n');
  }

  for (const m of d.meta) process.stdout.write(`  ~ ${m.field}\n      before: ${JSON.stringify(m.before)}\n      after:  ${JSON.stringify(m.after)}\n`);
  for (const e of d.added) process.stdout.write(`  + ${e.scope} ${e.address}  [${e.kind}]\n      ${e.justification}\n      evidence: ${e.evidence}\n`);
  for (const e of d.removed) process.stdout.write(`  - ${e.scope} ${e.address}  [${e.kind}]  (this address is now PAID)\n`);
  for (const c of d.changed) process.stdout.write(`  ~ ${c.key}  fields changed: ${c.fields.join(', ')}\n`);
  process.stdout.write(
    '\n  An addition removes an address from every distribution it covers.\n' +
    '  A removal adds one. Both are governance events (threat model D9).\n' +
    `\n  policy binding ${d.bindingBefore}\n              -> ${d.bindingAfter}\n` +
    '  That value is bound into the merkle domain, so this change alters the root\n' +
    '  even where it alters nobody\'s payout.\n',
  );
  return 0;
}

export async function main(argv) {
  const cmd = argv[0];
  const args = parseArgs(argv.slice(1));
  switch (cmd) {
    case 'index': return await cmdIndex(args);
    case 'verify': return await cmdVerify(args);
    case 'preflight': return await cmdPreflight(args);
    case 'exclusions-diff': return cmdExclusionsDiff(args);
    /**
     * `cost` — what a range will actually take, before anybody starts one.
     *
     * The block data is ~11.6 MB per slot and it is paid on EVERY slot in the
     * range, so a day of chain is about 2.4 TB. That was measurable from the
     * repository's own numbers and was published nowhere, which meant the only
     * way to find the wall was to run into it — usually after hours of fetching.
     */
    case 'cost': {
      const f = args.from !== undefined ? Number(args.from) : null;
      const t = args.to !== undefined ? Number(args.to) : null;
      if (f !== null && t !== null) {
        const e = estimateCost(f, t);
        process.stdout.write(
          `range [${f}, ${t}) — ${e.slots} slots\n\n`
          + `  chain covered   ${e.days >= 1 ? `${e.days.toFixed(2)} days` : `${(e.days * 24).toFixed(1)} hours`}\n`
          + `  block data      ${e.gigabytes >= 1 ? `${e.gigabytes.toFixed(1)} GB` : `${e.megabytes.toFixed(0)} MB`}\n`
          + `  fetch at 2/s    ${e.fetchHours >= 1 ? `${e.fetchHours.toFixed(1)} hours` : `${(e.fetchHours * 60).toFixed(0)} minutes`}\n`
          + `  free public RPC ${e.feasibleOnFreeRpc ? 'plausible' : 'NO — this needs a paid archival endpoint'}\n\n`,
        );
      }
      process.stdout.write(`${costTable()}\n`);
      return 0;
    }
    case 'exclusions-template':
      process.stdout.write(exclusionsTemplate(args.mint ?? '<mint pubkey>', args.from ? Number(args.from) : 0));
      return 0;
    case 'env':
      process.stdout.write(prettyCanonical(environment()));
      return 0;
    case 'help': case '--help': case '-h': case undefined:
      process.stdout.write(USAGE);
      return 0;
    default:
      process.stderr.write(`unknown command ${JSON.stringify(cmd)}\n\n${USAGE}`);
      return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('cli.mjs')) {
  main(process.argv.slice(2))
    .then((code) => { process.exitCode = code; })
    .catch((err) => {
      process.stderr.write(`\nFAILED: ${err.message}\n`);
      if (process.env.ESCAPEMENT_DEBUG) process.stderr.write(`${err.stack}\n`);
      process.stderr.write(
        '\nNothing was written. A failed run produces no artifact — a partial index is a wrong root\n' +
        'that looks like a right one.\n',
      );
      process.exitCode = 1;
    });
}
