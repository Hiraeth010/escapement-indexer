/**
 * exclusions.mjs — the discretionary surface, made explicit.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS THE MOST IMPORTANT ONE IN THE REPOSITORY
 * ---------------------------------------------------------------------------
 * The arithmetic in `accrue.mjs` and `entitle.mjs` has no discretion in it. This
 * does. Deciding that an address is "the pool" and does not get paid moves real
 * money to everybody else, and it looks like maintenance while doing it. The
 * threat model (D9/T-05) names it as the one place a dishonest publisher would
 * hide manipulation.
 *
 * The design response is that the code takes NO POSITION and cannot:
 *
 *   - There is NO DEFAULT. `--exclusions` is required. A run cannot happen
 *     without a human stating the policy in a file.
 *   - There is no built-in address list, no heuristic, no "looks like a pool"
 *     detector, and no inference of any kind at runtime. Every excluded address
 *     is typed in by a person, with a justification and on-chain evidence.
 *   - The file's hash is committed into the artifact and into `manifest_hash`,
 *     so changing it changes the root, visibly.
 *   - `effective_from_slot` must not be after the period it is used for, which
 *     mechanises "announced before the epoch they apply to, never after".
 *   - Two versions can be diffed (`escapement exclusions-diff`), so a change is
 *     a reviewable event rather than an archaeology project.
 *
 * The published spec (/spec §4.5) marks four cases NOT DECIDED: the bonding
 * curve, the AMM pool with burned LP, exchange omnibus accounts, and lending
 * collateral. This file does not decide them either. It requires the operator to
 * ACKNOWLEDGE them — `undecided` is a mandatory field — so that the four open
 * questions travel with every run instead of quietly disappearing the first time
 * someone writes a config.
 */

import { readFileSync } from 'node:fs';
import { isPubkey } from './base58.mjs';
import { canonicalJson, sha256Hex } from './canonical.mjs';

export const SCHEMA = 'escapement.exclusions/v1';

/** The four cases /spec §4.5 leaves open. Required to be acknowledged, never decided here. */
export const KNOWN_OPEN_CASES = ['bonding_curve', 'amm_pool', 'cex_omnibus', 'lending_collateral'];

const SCOPES = new Set(['owner', 'token_account']);

function fail(msg) { throw new Error(`exclusions: ${msg}`); }

/**
 * Parse and validate an exclusion set. Every failure is loud; nothing is
 * defaulted, coerced, or inferred.
 *
 * @param {string} text  raw file contents
 * @param {object} ctx   {mint, fromSlot} — the run this set is being used for
 */
export function parseExclusions(text, { mint, fromSlot } = {}) {
  let doc;
  try { doc = JSON.parse(text); } catch (e) { fail(`file is not valid JSON: ${e.message}`); }

  if (doc?.schema !== SCHEMA) fail(`\`schema\` must be ${JSON.stringify(SCHEMA)}, got ${JSON.stringify(doc?.schema)}`);
  if (typeof doc.version !== 'string' || !doc.version.trim()) fail('`version` is required (a string you can cite)');
  if (typeof doc.mint !== 'string' || !isPubkey(doc.mint)) fail('`mint` must be a base58 pubkey');
  if (mint && doc.mint !== mint) {
    fail(`this set is for mint ${doc.mint} but the run is for ${mint}. An exclusion set is not portable between mints.`);
  }
  if (!Number.isSafeInteger(doc.effective_from_slot) || doc.effective_from_slot < 0) {
    fail('`effective_from_slot` must be a non-negative integer slot');
  }
  if (Number.isSafeInteger(fromSlot) && doc.effective_from_slot > fromSlot) {
    fail(
      `this set becomes effective at slot ${doc.effective_from_slot}, which is AFTER the start of the ` +
      `period being indexed (${fromSlot}). D9 requires exclusion changes to be announced before the epoch ` +
      `they apply to, never after. Refusing to apply it retroactively.`,
    );
  }
  if (typeof doc.policy !== 'string' || doc.policy.trim().length < 40) {
    fail(
      '`policy` must be a written statement (40+ characters) of what this set excludes and what it ' +
      'deliberately does not. An exclusion set with no stated policy is discretion with no record of itself.',
    );
  }
  if (doc.policy.includes('REPLACE THIS')) {
    fail('`policy` is still the template placeholder. Write the actual policy; it is hashed into the root.');
  }
  if (!Array.isArray(doc.undecided)) fail('`undecided` must be an array (may be empty only if genuinely nothing is open)');
  for (const u of doc.undecided) {
    if (typeof u !== 'string') fail('`undecided` entries must be strings');
  }
  const missing = KNOWN_OPEN_CASES.filter((c) => !doc.undecided.includes(c) && !doc.entries?.some?.((e) => e.kind === c));
  // Not an error — the operator may legitimately have decided one of them — but
  // it must be a conscious act, so it is surfaced rather than silently allowed.
  const acknowledgementGaps = missing;

  if (!Array.isArray(doc.entries)) fail('`entries` must be an array (empty is allowed, and means "exclude nobody")');

  const seen = new Set();
  const entries = [];
  for (let i = 0; i < doc.entries.length; i++) {
    const e = doc.entries[i];
    const at = `entries[${i}]`;
    if (typeof e?.address !== 'string' || !isPubkey(e.address)) fail(`${at}.address must be a base58 pubkey`);
    if (!SCOPES.has(e?.scope)) fail(`${at}.scope must be one of ${[...SCOPES].join(', ')}`);
    if (typeof e?.kind !== 'string' || !e.kind.trim()) fail(`${at}.kind is required (free text; the code never reads it)`);
    if (typeof e?.justification !== 'string' || e.justification.trim().length < 20) {
      fail(`${at}.justification must be at least 20 characters. "pool" is not a justification.`);
    }
    if (typeof e?.evidence !== 'string' || !e.evidence.trim()) {
      fail(`${at}.evidence is required — an account, a transaction signature, or a URL a stranger can check`);
    }
    const key = `${e.scope}:${e.address}`;
    if (seen.has(key)) fail(`${at} duplicates ${key}`);
    seen.add(key);
    entries.push({
      address: e.address, scope: e.scope, kind: e.kind.trim(),
      justification: e.justification.trim(), evidence: e.evidence.trim(),
    });
  }

  // Canonical form: what gets hashed. Sorted so that reordering the file cannot
  // change the hash, and so a diff of two versions is a diff of meaning.
  const canonical = {
    schema: doc.schema,
    version: doc.version,
    mint: doc.mint,
    effective_from_slot: doc.effective_from_slot,
    policy: doc.policy,
    undecided: [...doc.undecided].sort(),
    entries: [...entries].sort((a, b) => (a.scope + a.address < b.scope + b.address ? -1 : 1)),
  };

  const owners = new Set(entries.filter((e) => e.scope === 'owner').map((e) => e.address));
  const tokenAccounts = new Set(entries.filter((e) => e.scope === 'token_account').map((e) => e.address));

  return {
    canonical,
    hash: sha256Hex(canonicalJson(canonical)),
    entries,
    owners,
    tokenAccounts,
    acknowledgementGaps,
    /**
     * The classifier handed to `accrue`. Returns an exclusion bucket key, or
     * null for "this counts". Evaluated per span with the owner IN FORCE at that
     * time, so an owner-scoped exclusion follows a `SetAuthority` rather than
     * sticking to the account.
     */
    classify(account, owner) {
      if (tokenAccounts.has(account)) return `token_account:${account}`;
      if (owners.has(owner)) return `owner:${owner}`;
      return null;
    },
  };
}

export function loadExclusions(path, ctx) {
  if (!path) {
    throw new Error(
      'exclusions: --exclusions <file> is REQUIRED and has no default. Which balances are beneficial ' +
      'holders is a policy question the code is not permitted to answer for you. Write the file, state ' +
      'the policy in it, and cite it. `escapement exclusions-template` prints a starting point.',
    );
  }
  let text;
  try { text = readFileSync(path, 'utf8'); } catch (e) { throw new Error(`exclusions: cannot read ${path}: ${e.message}`); }
  const parsed = parseExclusions(text, ctx);
  return { ...parsed, path };
}

/**
 * Diff two exclusion sets. Requirement: "it must be possible to diff two
 * versions" — a governance change you cannot review is a governance change that
 * will not be reviewed.
 */
export function diffExclusions(a, b) {
  const key = (e) => `${e.scope}:${e.address}`;
  const A = new Map(a.entries.map((e) => [key(e), e]));
  const B = new Map(b.entries.map((e) => [key(e), e]));

  const added = [];
  const removed = [];
  const changed = [];
  for (const [k, e] of B) if (!A.has(k)) added.push(e);
  for (const [k, e] of A) if (!B.has(k)) removed.push(e);
  for (const [k, e] of A) {
    const f = B.get(k);
    if (!f) continue;
    const fields = ['kind', 'justification', 'evidence'].filter((x) => e[x] !== f[x]);
    if (fields.length) changed.push({ key: k, fields, before: e, after: f });
  }

  const meta = [];
  for (const f of ['version', 'mint', 'effective_from_slot', 'policy']) {
    if (JSON.stringify(a.canonical[f]) !== JSON.stringify(b.canonical[f])) {
      meta.push({ field: f, before: a.canonical[f], after: b.canonical[f] });
    }
  }
  if (JSON.stringify(a.canonical.undecided) !== JSON.stringify(b.canonical.undecided)) {
    meta.push({ field: 'undecided', before: a.canonical.undecided, after: b.canonical.undecided });
  }

  return {
    hashBefore: a.hash, hashAfter: b.hash,
    identical: a.hash === b.hash,
    meta, added: added.sort((x, y) => (key(x) < key(y) ? -1 : 1)),
    removed: removed.sort((x, y) => (key(x) < key(y) ? -1 : 1)),
    changed,
  };
}

export function exclusionsTemplate(mint = '<mint pubkey>', slot = 0) {
  return JSON.stringify({
    schema: SCHEMA,
    version: '1970-01-01.1',
    mint,
    effective_from_slot: slot,
    policy:
      'REPLACE THIS. State what this set excludes, what it deliberately does not exclude, and why. ' +
      'This text is hashed into the root; it is the record of the discretion exercised.',
    undecided: [...KNOWN_OPEN_CASES],
    entries: [],
  }, null, 2) + '\n';
}
