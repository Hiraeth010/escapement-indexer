#!/usr/bin/env node
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

const USAGE = `escapement — deterministic token-slot entitlement indexer

  escapement index  --mint <pubkey> --from <slot> --to <slot> --exclusions <file> [options]
  escapement verify --root <hex> --mint <pubkey> --from <slot> --to <slot> --exclusions <file> [options]
  escapement exclusions-diff <before.json> <after.json>
  escapement exclusions-template [--mint <pubkey>] [--from <slot>]
  escapement env

RANGE
  --from / --to define the half-open slot range [from, to). Both bounds must be
  finalized before the run starts; the run aborts otherwise.

REQUIRED, NO DEFAULT
  --exclusions <file>   which balances are not beneficial holders. There is no
                        built-in list and no inference. See exclusions.mjs.

TO PRODUCE A MERKLE ROOT (otherwise only the token-slot ledger is produced)
  --config <pubkey>     the deployment's config PDA; domain-separates the leaves
  --vault-lamports <n>  the pot being distributed, in lamports (an INPUT, not a
                        measurement — the artifact labels it as one)
  --vault-source <s>    required with the above: chain | manual-attested | hypothetical
  --prior <artifact>    the PREVIOUS period's artifact, so leaves stay cumulative (G3).
                        On verify, this is the artifact BEFORE the one under test.

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
    if (exclusions.acknowledgementGaps.length) {
      process.stderr.write(`  note: /spec §4.5 cases neither excluded nor listed as undecided: ${exclusions.acknowledgementGaps.join(', ')}\n`);
    }
  }

  const { artifact, inputSet } = await runIndex({
    rpc, mint, from, to, exclusions, configPubkey, vaultLamports, vaultSource, prior, priorSource,
    openingAccounts, openingStateSource,
    concurrency: args.concurrency ? Number(args.concurrency) : 4,
    onProgress: progressBar(args.quiet),
  });

  const out = resolve(args.out ?? `artifacts/${mint}.${from}-${to}.json`);
  const written = writeArtifact(out, artifact, inputSet);

  if (!args.quiet) {
    const a = artifact;
    for (const w of a.warnings) process.stderr.write(`\n  WARNING: ${w}\n`);
    process.stderr.write(
      `\n  slots            ${a.slots.total} (${a.slots.produced} produced, ${a.slots.skipped} skipped, continuity verified)\n` +
      `  transactions     ${a.transactions.consumed} touching the mint (${a.transactions.failed_included_in_input_set} failed)\n` +
      `  owners entitled  ${a.accrual.owners_entitled}\n` +
      `  token-slots      ${a.accrual.total_token_slots_entitled} entitled / ${a.accrual.total_token_slots_excluded} excluded\n` +
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
  const vaultRaw = args['vault-lamports'] ?? published?.params?.vault_lamports;
  if (vaultRaw === undefined || vaultRaw === null) throw new Error('--vault-lamports is required (or supply --artifact)');
  const vaultLamports = BigInt(vaultRaw);

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
    vaultSource: args['vault-source'] ?? published?.params?.vault_lamports_source ?? null,
    expectedRoot, publishedArtifact: published, publishedInputSetText, prior, priorSource,
    concurrency: args.concurrency ? Number(args.concurrency) : 4,
    onProgress: progressBar(args.quiet),
  });

  process.stdout.write(`\n${res.agree ? 'AGREE' : 'DISAGREE'}\n\n`);
  for (const f of res.findings) {
    process.stdout.write(`  [${f.level}] ${f.where}\n    ${f.detail.replace(/\n/g, '\n    ')}\n`);
  }
  process.stdout.write(
    `\n  Verification shares the fetch, decode and accrual code with the producer.\n` +
    `  A bug in that shared code passes this check. See README, "What verification actually proves".\n`,
  );
  if (args.out) writeArtifact(resolve(args.out), res.artifact, { text: () => '' });
  return res.agree && res.internallyConsistent ? 0 : 1;
}

function cmdExclusionsDiff(args) {
  const [beforePath, afterPath] = args._;
  if (!beforePath || !afterPath) throw new Error('usage: escapement exclusions-diff <before.json> <after.json>');
  const a = parseExclusions(readFileSync(beforePath, 'utf8'), {});
  const b = parseExclusions(readFileSync(afterPath, 'utf8'), {});
  const d = diffExclusions(a, b);

  process.stdout.write(`${beforePath}  ${d.hashBefore}\n${afterPath}  ${d.hashAfter}\n\n`);
  if (d.identical) { process.stdout.write('IDENTICAL — the two sets hash the same, so they produce the same root.\n'); return 0; }
  process.stdout.write('DIFFERENT — this changes every payout in every period it applies to.\n\n');
  for (const m of d.meta) process.stdout.write(`  ~ ${m.field}\n      before: ${JSON.stringify(m.before)}\n      after:  ${JSON.stringify(m.after)}\n`);
  for (const e of d.added) process.stdout.write(`  + ${e.scope} ${e.address}  [${e.kind}]\n      ${e.justification}\n      evidence: ${e.evidence}\n`);
  for (const e of d.removed) process.stdout.write(`  - ${e.scope} ${e.address}  [${e.kind}]  (this address is now PAID)\n`);
  for (const c of d.changed) process.stdout.write(`  ~ ${c.key}  fields changed: ${c.fields.join(', ')}\n`);
  process.stdout.write('\n  An addition removes an address from every distribution it covers.\n  A removal adds one. Both are governance events (threat model D9).\n');
  return 0;
}

export async function main(argv) {
  const cmd = argv[0];
  const args = parseArgs(argv.slice(1));
  switch (cmd) {
    case 'index': return await cmdIndex(args);
    case 'verify': return await cmdVerify(args);
    case 'exclusions-diff': return cmdExclusionsDiff(args);
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
