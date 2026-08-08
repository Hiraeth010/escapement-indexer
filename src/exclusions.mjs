// SPDX-License-Identifier: Apache-2.0
/**
 * exclusions.mjs — the discretionary surface, made explicit.
 *
 * ---------------------------------------------------------------------------
 * TWO KINDS OF EXCLUSION, KEPT APART ON PURPOSE
 * ---------------------------------------------------------------------------
 * An address can fail to get paid for two completely different reasons, and
 * conflating them is how a distribution stops being checkable:
 *
 *   POLICY      — a human decided this balance is not a beneficial holder.
 *                 That is discretion. It lives in `entries` below, it demands a
 *                 justification and evidence for every address, and everything
 *                 in this file's original design exists to fence it.
 *
 *   CORRECTNESS — no claimant for this address can possibly exist, so paying it
 *                 would strand the money rather than distribute it. That is not
 *                 discretion, it is a fact about the address, and it is decided
 *                 mechanically by the PREDICATE in `predicate.mjs`.
 *
 * Both are declared in this one document and both are hashed into the root, but
 * they are parsed, evaluated, and REPORTED separately, so a reader can always
 * see how much of a distribution was moved by judgement and how much by
 * arithmetic. The predicate is not a way to smuggle policy in: it has no address
 * list, its one rule is a pure function of the address bytes, and its only
 * manual escape hatch can add somebody back but never remove them.
 *
 * ---------------------------------------------------------------------------
 * WHY THE POLICY HALF IS THE MOST DANGEROUS PART OF THE REPOSITORY
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
import { parsePredicate, PREDICATE_SCHEMA, UNCLAIMABLE, UNDECIDED } from './predicate.mjs';

export const SCHEMA = 'escapement.exclusions/v2';

/** The schema this replaced. Named so the error message can be useful rather than terse. */
export const SUPERSEDED_SCHEMA = 'escapement.exclusions/v1';

/**
 * The domain tag for the policy commitment.
 *
 * `policy_binding` is the single 32-byte value that stands for "everything about
 * WHO GETS PAID that is not chain data": the discretionary exclusion set and the
 * mechanical predicate, together. `merkle.mjs` folds it into the tree's domain,
 * so changing either half changes the published root even when it changes
 * nobody's payout. Before this existed, an exclusion-set edit only moved the
 * root if it happened to move money — which meant a publisher could swap the
 * declared policy for a different one with the same effect and the root would
 * not notice.
 */
export const POLICY_BINDING_TAG = 'escapement.policy/v1';

/** The four cases /spec §4.5 leaves open. Required to be acknowledged, never decided here. */
export const KNOWN_OPEN_CASES = ['bonding_curve', 'amm_pool', 'cex_omnibus', 'lending_collateral'];

const SCOPES = new Set(['owner', 'token_account']);

/** Bucket-key prefixes. `undecided/` is load-bearing: `run.mjs` aborts on it. */
export const PREDICATE_BUCKET = 'predicate/';
export const UNDECIDED_BUCKET = 'undecided/';

/**
 * Bind the two halves of the policy into one commitment.
 * @param {string} exclusionsHash 64-hex — the discretionary set
 * @param {string} predicateHash  64-hex — the mechanical predicate
 */
export function policyBinding(exclusionsHash, predicateHash) {
  for (const [name, h] of [['exclusions', exclusionsHash], ['predicate', predicateHash]]) {
    if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) {
      throw new Error(`policyBinding: ${name} hash must be 64 lowercase hex characters, got ${JSON.stringify(h)}`);
    }
  }
  return sha256Hex(
    Buffer.from(POLICY_BINDING_TAG, 'utf8'),
    Buffer.from(exclusionsHash, 'hex'),
    Buffer.from(predicateHash, 'hex'),
  );
}

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

  if (doc?.schema === SUPERSEDED_SCHEMA) {
    fail(
      `this is a ${SUPERSEDED_SCHEMA} document. ${SCHEMA} adds a REQUIRED \`predicate\` block declaring which ` +
      'unclaimable-address rules the run applied. It is required rather than defaulted because a run that ' +
      'silently applied a predicate nobody declared would be exactly the invisible discretion this project ' +
      'exists to remove. Run `escapement exclusions-template` and copy the `predicate` block across.',
    );
  }
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

  // The mechanical half. Parsed and hashed separately from the discretionary
  // half so the artifact can report the two independently.
  const predicate = parsePredicate(doc.predicate);

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
    predicate: predicate.canonical,
  };

  const owners = new Set(entries.filter((e) => e.scope === 'owner').map((e) => e.address));
  const tokenAccounts = new Set(entries.filter((e) => e.scope === 'token_account').map((e) => e.address));

  const hash = sha256Hex(canonicalJson(canonical));

  // Memoised per owner. The predicate is a pure function of the address, so the
  // cache cannot change an answer; it only stops `accrue` from re-running field
  // arithmetic once per account per span.
  const verdicts = new Map();
  // A closure, not a method: `classify` is passed to `accrue` as a bare function
  // reference (`classify: exclusions.classify`), so anything reached through
  // `this` would be undefined at call time.
  const verdictFor = (owner) => {
    let v = verdicts.get(owner);
    if (v === undefined) {
      v = predicate.evaluate(owner);
      verdicts.set(owner, v);
    }
    return v;
  };

  return {
    canonical,
    hash,
    predicate,
    policyBinding: policyBinding(hash, predicate.hash),
    entries,
    owners,
    tokenAccounts,
    acknowledgementGaps,
    /** The predicate verdict for an owner, cached. Exposed for reporting. */
    verdictFor,
    /**
     * The classifier handed to `accrue`. Returns an exclusion bucket key, or
     * null for "this counts". Evaluated per span with the owner IN FORCE at that
     * time, so an owner-scoped exclusion follows a `SetAuthority` rather than
     * sticking to the account.
     *
     * Order is deliberate: the DISCRETIONARY entries are consulted first, so
     * that an address a human explicitly excluded is reported under the human's
     * reason rather than under the predicate's. A publisher must never be able
     * to present a policy exclusion as a mechanical one.
     */
    classify(account, owner) {
      if (tokenAccounts.has(account)) return `token_account:${account}`;
      if (owners.has(owner)) return `owner:${owner}`;
      const v = verdictFor(owner);
      if (v.verdict === UNCLAIMABLE) return `${PREDICATE_BUCKET}${v.rule}:${owner}`;
      if (v.verdict === UNDECIDED) return `${UNDECIDED_BUCKET}${v.rule}:${owner}`;
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

  // The predicate is diffed as its own section rather than folded into `meta`,
  // because "the rules changed" and "the policy prose changed" are different
  // kinds of event and a reviewer should not have to notice which is which.
  const predicate = {
    hashBefore: a.predicate.hash,
    hashAfter: b.predicate.hash,
    identical: a.predicate.hash === b.predicate.hash,
    idBefore: a.predicate.id,
    idAfter: b.predicate.id,
    rulesBefore: a.predicate.rules,
    rulesAfter: b.predicate.rules,
    rulesChanged: JSON.stringify(a.predicate.rules) !== JSON.stringify(b.predicate.rules),
    overridesAdded: b.predicate.overrides.filter((o) => !a.predicate.overrides.some((p) => p.address === o.address)),
    overridesRemoved: a.predicate.overrides.filter((o) => !b.predicate.overrides.some((p) => p.address === o.address)),
  };

  return {
    hashBefore: a.hash, hashAfter: b.hash,
    identical: a.hash === b.hash,
    bindingBefore: a.policyBinding, bindingAfter: b.policyBinding,
    meta, added: added.sort((x, y) => (key(x) < key(y) ? -1 : 1)),
    removed: removed.sort((x, y) => (key(x) < key(y) ? -1 : 1)),
    changed,
    predicate,
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
    predicate: {
      id: PREDICATE_SCHEMA,
      // Delete this rule id to apply no predicate at all. That is a legal
      // choice, it is hashed into the root like every other choice, and it
      // means unclaimable addresses are paid and the money is stranded.
      rules: ['off_curve_owner'],
      overrides: [],
    },
  }, null, 2) + '\n';
}
