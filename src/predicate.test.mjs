// SPDX-License-Identifier: Apache-2.0
/**
 * predicate.test.mjs — the exclusion predicate.
 *
 * The predicate replaced a curated address list. The whole argument for that
 * swap is that a predicate is REPRODUCIBLE and a list is not, so these tests are
 * mostly about reproducibility rather than about the rule itself: the same
 * inputs give the same exclusion set, an independent party derives the same set
 * from published data alone, and a change to the predicate cannot happen without
 * moving the root.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parsePredicate, nonePredicate, PREDICATE_SCHEMA, RULE_IDS, CLAIMABLE, UNCLAIMABLE, UNDECIDED } from './predicate.mjs';
import { parseExclusions, policyBinding } from './exclusions.mjs';
import { pubkeyOnCurve } from './curve.mjs';
import { runIndex } from './run.mjs';
import { scenario, mockRpc, MINT, CONFIG, OA, OB, onCurvePk, offCurvePk, pk } from './mockchain.test.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const RULES_ON = { id: PREDICATE_SCHEMA, rules: ['off_curve_owner'], overrides: [] };
const RULES_OFF = { id: PREDICATE_SCHEMA, rules: [], overrides: [] };

const doc = (over = {}) => JSON.stringify({
  schema: 'escapement.exclusions/v2',
  version: '2026-08-08.1',
  mint: MINT,
  effective_from_slot: 0,
  policy: 'Excludes nobody by hand. The predicate decides who can possibly claim; see predicate.mjs.',
  undecided: [],
  entries: [],
  predicate: RULES_ON,
  ...over,
});

const RUN = { mint: MINT, from: 100, to: 110, configPubkey: CONFIG, vaultLamports: 1_000_000n };

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

test('an on-curve address is NEVER excluded by the off-curve rule', () => {
  const p = parsePredicate(RULES_ON);
  // Real ed25519 public keys, plus the constructed on-curve fixtures, plus a
  // sweep of arbitrary values where the rule must agree with the curve test.
  for (let i = 0; i < 400; i++) {
    const a = onCurvePk(i);
    assert.equal(pubkeyOnCurve(a), true, 'fixture must be on-curve');
    assert.equal(p.evaluate(a).verdict, CLAIMABLE, `${a} was excluded despite being on the curve`);
  }
  for (let i = 0; i < 400; i++) {
    const a = pk(i * 7 + 1);
    const onCurve = pubkeyOnCurve(a);
    const verdict = p.evaluate(a).verdict;
    assert.equal(verdict === CLAIMABLE, onCurve === true, `${a}: on-curve=${onCurve} verdict=${verdict}`);
  }
});

test('an off-curve owner is excluded, and says why', () => {
  const p = parsePredicate(RULES_ON);
  const a = offCurvePk(1);
  const v = p.evaluate(a);
  assert.equal(v.verdict, UNCLAIMABLE);
  assert.equal(v.rule, 'off_curve_owner');
  assert.match(v.reason, /no secret key exists/);
});

test('with no rules declared, nothing is excluded at all', () => {
  const p = nonePredicate();
  for (let i = 0; i < 50; i++) assert.equal(p.evaluate(offCurvePk(i)).verdict, CLAIMABLE);
});

test('the predicate is deterministic across runs, instances and iteration order', () => {
  const addresses = Array.from({ length: 600 }, (_, i) => pk(i + 1));
  const run = () => {
    const p = parsePredicate(RULES_ON);
    return addresses.map((a) => `${a}:${p.evaluate(a).verdict}:${p.evaluate(a).rule}`);
  };
  const first = run();
  for (let i = 0; i < 5; i++) assert.deepEqual(run(), first, `run ${i} differed`);

  // Reversed evaluation order must give the same per-address answers: the rule
  // is a pure function of the address, so nothing may depend on what came before.
  const p = parsePredicate(RULES_ON);
  const reversed = [...addresses].reverse().map((a) => `${a}:${p.evaluate(a).verdict}:${p.evaluate(a).rule}`);
  assert.deepEqual(reversed.reverse(), first);

  // And the declaration hashes identically every time it is parsed.
  assert.equal(parsePredicate(RULES_ON).hash, parsePredicate(RULES_ON).hash);
});

test('the predicate reads nothing but the address', async () => {
  // The reproducibility argument rests on the rule being a pure function of 32
  // bytes: no account state, no slot, no clock, no network. If a future rule
  // reaches for any of those, two verifiers running a week apart get different
  // exclusion sets. This is that constraint, as a lint.
  const src = readFileSync(join(HERE, 'predicate.mjs'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
  for (const banned of ['fetch(', 'getAccountInfo', 'getBlock', 'rpc', 'Date.', 'Math.random', 'readFileSync', 'process.env']) {
    assert.ok(!src.includes(banned), `predicate.mjs must not reference ${banned} — the rule must be a pure function of the address`);
  }
});

// ---------------------------------------------------------------------------
// Declaration, versioning, escape hatch
// ---------------------------------------------------------------------------

test('the predicate contains no address list — that is the entire point of it', () => {
  const src = readFileSync(join(HERE, 'predicate.mjs'), 'utf8');
  const suspicious = src.match(/(?<![\w/.])[1-9A-HJ-NP-Za-km-z]{32,44}(?![\w/])/g) ?? [];
  assert.deepEqual(suspicious, [], `predicate.mjs must contain no hard-coded addresses, found: ${suspicious}`);
  // Nor a program id list, which is the narrower rule that was rejected.
  assert.ok(!/PROGRAM_IDS|KNOWN_POOLS|AMM_PROGRAMS/.test(src));
});

test('the predicate must be declared; it is never defaulted', () => {
  assert.throws(() => parsePredicate(undefined), /`predicate` is required/);
  assert.throws(() => parsePredicate(null), /`predicate` is required/);
});

test('an unimplemented predicate version is refused, not approximated', () => {
  assert.throws(() => parsePredicate({ id: 'escapement.unclaimable/v2', rules: [] }), /must be "escapement.unclaimable\/v1"/);
  assert.throws(() => parsePredicate({ id: PREDICATE_SCHEMA, rules: ['no_such_rule'] }), /unknown rule/);
  assert.throws(() => parsePredicate({ id: PREDICATE_SCHEMA, rules: ['off_curve_owner', 'off_curve_owner'] }), /declared twice/);
  assert.deepEqual(RULE_IDS, ['off_curve_owner']);
});

test('an override can reinstate an address but can never remove one', () => {
  const addr = offCurvePk(5);
  const reinstated = parsePredicate({
    id: PREDICATE_SCHEMA, rules: ['off_curve_owner'],
    overrides: [{
      address: addr, verdict: CLAIMABLE,
      justification: 'Squads multisig vault; the Squads program can CPI a claim on its behalf.',
      evidence: 'multisig account 4xyz, verified 2026-08-08',
    }],
  });
  assert.equal(reinstated.evaluate(addr).verdict, CLAIMABLE);
  assert.equal(reinstated.evaluate(addr).rule, 'operator_override');
  // Every other off-curve address is still excluded — an override is one address.
  assert.equal(reinstated.evaluate(offCurvePk(6)).verdict, UNCLAIMABLE);

  // The direction is the point: there is no way to hand-exclude here.
  assert.throws(() => parsePredicate({
    id: PREDICATE_SCHEMA, rules: [],
    overrides: [{ address: onCurvePk(1), verdict: UNCLAIMABLE, justification: 'x'.repeat(30), evidence: 'y' }],
  }), /deliberately no\s+"unclaimable" override|verdict must be one of/);
});

test('an override needs a justification and evidence, like every other discretion', () => {
  const bad = (o) => () => parsePredicate({ id: PREDICATE_SCHEMA, rules: [], overrides: [o] });
  const ok = { address: onCurvePk(1), verdict: CLAIMABLE, justification: 'a'.repeat(25), evidence: 'tx 5abc' };
  assert.throws(bad({ ...ok, justification: 'short' }), /at least 20 characters/);
  assert.throws(bad({ ...ok, evidence: '' }), /evidence is required/);
  assert.throws(bad({ ...ok, address: 'nope' }), /base58 pubkey/);
  assert.throws(() => parsePredicate({ id: PREDICATE_SCHEMA, rules: [], overrides: [ok, ok] }), /duplicates/);
});

test('the declaration hash depends on meaning, not on file layout', () => {
  const o = (address) => ({ address, verdict: CLAIMABLE, justification: 'j'.repeat(25), evidence: 'e' });
  const a = parsePredicate({ id: PREDICATE_SCHEMA, rules: [], overrides: [o(onCurvePk(1)), o(onCurvePk(2))] });
  const b = parsePredicate({ id: PREDICATE_SCHEMA, rules: [], overrides: [o(onCurvePk(2)), o(onCurvePk(1))] });
  assert.equal(a.hash, b.hash, 'reordering overrides must not change the hash');

  const c = parsePredicate({ id: PREDICATE_SCHEMA, rules: [], overrides: [o(onCurvePk(1))] });
  assert.notEqual(a.hash, c.hash, 'removing an override must change the hash');
  assert.notEqual(a.hash, parsePredicate({ id: PREDICATE_SCHEMA, rules: ['off_curve_owner'], overrides: a.overrides }).hash);
});

// ---------------------------------------------------------------------------
// The root
// ---------------------------------------------------------------------------

test('changing the predicate changes the root, even when it changes nobody\'s payout', async () => {
  // Every owner in the scenario is on-curve, so `off_curve_owner` excludes
  // nobody and the two runs produce an IDENTICAL ledger. If the predicate were
  // only in the root by way of its effect, the roots would match and a
  // publisher could swap the declared policy without the root noticing.
  const chain = scenario();
  const withRule = await runIndex({ ...RUN, rpc: mockRpc(chain), exclusions: parseExclusions(doc({ predicate: RULES_ON }), { mint: MINT, fromSlot: 100 }) });
  const without = await runIndex({ ...RUN, rpc: mockRpc(chain), exclusions: parseExclusions(doc({ predicate: RULES_OFF }), { mint: MINT, fromSlot: 100 }) });

  assert.deepEqual(withRule.artifact.ledger, without.artifact.ledger, 'the ledgers must be identical for this test to mean anything');
  assert.deepEqual(withRule.artifact.payouts, without.artifact.payouts, 'the payouts must be identical too');
  assert.notEqual(withRule.artifact.merkle_root, without.artifact.merkle_root, 'the predicate must be inside the root');
  assert.notEqual(withRule.artifact.params.policy_binding, without.artifact.params.policy_binding);
  assert.notEqual(withRule.artifact.params.merkle_domain, without.artifact.params.merkle_domain);

  // An override alone does it too.
  const withOverride = await runIndex({
    ...RUN, rpc: mockRpc(chain),
    exclusions: parseExclusions(doc({
      predicate: {
        ...RULES_ON,
        overrides: [{ address: offCurvePk(99), verdict: CLAIMABLE, justification: 'Contract wallet; can sign by CPI.', evidence: 'program 9xyz' }],
      },
    }), { mint: MINT, fromSlot: 100 }),
  });
  assert.notEqual(withOverride.artifact.merkle_root, withRule.artifact.merkle_root);
});

test('the policy binding covers both halves and refuses malformed input', () => {
  const h = (c) => c.repeat(64);
  assert.notEqual(policyBinding(h('1'), h('2')), policyBinding(h('2'), h('1')), 'the two halves must not be interchangeable');
  assert.equal(policyBinding(h('1'), h('2')), policyBinding(h('1'), h('2')));
  assert.throws(() => policyBinding('short', h('2')), /64 lowercase hex/);
  assert.throws(() => policyBinding(h('1'), 'short'), /64 lowercase hex/);
});

// ---------------------------------------------------------------------------
// End to end, through the pipeline
// ---------------------------------------------------------------------------

/** The scenario, with an extra account held by an owner that cannot sign. */
function scenarioWithPool(poolOwner) {
  return scenario({
    txs: {
      103: [{ sig: 'sigPool', pre: [], post: [{ account: pk(50), owner: poolOwner, amount: 5000 }] }],
    },
  });
}

test('an off-curve owner is removed from the ledger and reported with what it cost', async () => {
  const pool = offCurvePk(77);
  const chain = scenarioWithPool(pool);
  const ex = parseExclusions(doc({ predicate: RULES_ON }), { mint: MINT, fromSlot: 100 });
  const { artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain), exclusions: ex });

  assert.equal(artifact.ledger.some((r) => r.owner === pool), false, 'the pool must not be in the ledger');
  assert.equal(artifact.predicate.excluded_addresses, 1);
  assert.equal(artifact.predicate.excluded_token_slots, 5000n * 7n);
  assert.deepEqual(artifact.predicate.excluded.map((e) => e.owner), [pool]);
  assert.equal(artifact.predicate.excluded[0].rule, 'off_curve_owner');
  assert.equal(artifact.exclusions.policy_excluded_token_slots, 0n, 'nothing here was a discretionary exclusion');
  assert.ok(artifact.warnings.some((w) => /THE PREDICATE REMOVED 1 ADDRESS/.test(w)), 'the effect must be a warning, not a field to notice');

  // Without the rule, the same address is paid — which is the whole finding.
  const { artifact: paid } = await runIndex({
    ...RUN, rpc: mockRpc(chain),
    exclusions: parseExclusions(doc({ predicate: RULES_OFF }), { mint: MINT, fromSlot: 100 }),
  });
  assert.ok(paid.ledger.some((r) => r.owner === pool));
  assert.ok(paid.warnings.some((w) => /NO PREDICATE RULES WERE APPLIED/.test(w)));
});

test('an undecided address REFUSES the run — never silently included or excluded', async () => {
  const chain = scenario();
  const ex = parseExclusions(doc({
    predicate: {
      ...RULES_ON,
      overrides: [{
        address: OA, verdict: UNDECIDED,
        justification: 'Possibly an exchange omnibus account. We have not decided and will not guess.',
        evidence: 'inbound flow pattern, 2026-08-08',
      }],
    },
  }), { mint: MINT, fromSlot: 100 });

  await assert.rejects(
    () => runIndex({ ...RUN, rpc: mockRpc(chain), exclusions: ex }),
    (e) => {
      assert.match(e.message, /UNDECIDED for 1 address/);
      assert.match(e.message, new RegExp(OA));
      assert.match(e.message, /no artifact was produced/);
      // The default must be neither of the two cheap answers.
      assert.match(e.message, /never be resolved by whichever default happens to be cheaper/);
      return true;
    },
  );

  // Resolving it either way lets the run proceed — the halt is about the
  // absence of a decision, not about the decision.
  const resolved = parseExclusions(doc({
    predicate: {
      ...RULES_ON,
      overrides: [{ address: OA, verdict: CLAIMABLE, justification: 'Decided: ordinary wallet, it can sign.', evidence: 'tx 5abc' }],
    },
  }), { mint: MINT, fromSlot: 100 });
  const { artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain), exclusions: resolved });
  assert.ok(artifact.ledger.some((r) => r.owner === OA));
  assert.ok(artifact.warnings.some((w) => /PREDICATE OVERRIDE in force/.test(w)));
});

test('a discretionary exclusion is never reported as a mechanical one', async () => {
  // OB is on-curve, so the predicate has no opinion; a human excluded it. The
  // artifact must attribute that to the human.
  const chain = scenario();
  const ex = parseExclusions(doc({
    entries: [{
      address: OB, scope: 'owner', kind: 'cex_omnibus',
      justification: 'Believed to be an exchange omnibus account; beneficial owners are off chain.',
      evidence: 'account note, 2026-08-08',
    }],
  }), { mint: MINT, fromSlot: 100 });
  const { artifact } = await runIndex({ ...RUN, rpc: mockRpc(chain), exclusions: ex });

  assert.equal(artifact.predicate.excluded_addresses, 0);
  assert.equal(artifact.predicate.excluded_token_slots, 0n);
  assert.equal(artifact.exclusions.policy_excluded_addresses, 1);
  assert.ok(artifact.exclusions.policy_excluded_token_slots > 0n);
});

// ---------------------------------------------------------------------------
// Reproducibility from published data alone
// ---------------------------------------------------------------------------

test('the exclusion set is reproducible from chain state alone, by a stranger', () => {
  // The strongest form of the claim: take a COMMITTED artifact, throw away
  // everything except the addresses that appear in it, re-derive the exclusion
  // set from the published predicate declaration, and get exactly what the
  // artifact says was excluded. No RPC, no coordination, no list.
  const dir = join(HERE, '..', 'artifacts');
  if (!existsSync(dir)) return;
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
  assert.ok(files.length > 0, 'the demonstration artifacts must be committed');

  for (const f of files) {
    const art = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    const declared = art.params.predicate_rules ?? [];
    const p = parsePredicate({
      id: art.params.predicate_id,
      rules: declared,
      overrides: art.predicate.overrides,
    });
    assert.equal(p.hash, art.params.predicate_hash, `${f}: the declaration in the artifact must hash to the recorded value`);
    assert.equal(policyBinding(art.params.exclusions_hash, p.hash), art.params.policy_binding, `${f}: policy binding`);

    // Every address that accrued anything, from both sides of the decision.
    // (`closing_state` is deliberately NOT included: an address holding a zero
    // balance never accrues, so it appears in neither the ledger nor the
    // excluded list, and a predicate verdict for it would be a statement about
    // an address the distribution never considered.)
    const addresses = [
      ...art.ledger.map((r) => r.owner),
      ...art.predicate.excluded.map((e) => e.owner),
    ];
    const derived = new Set();
    for (const a of addresses) if (p.evaluate(a).verdict === UNCLAIMABLE) derived.add(a);

    const published = new Set(art.predicate.excluded.map((e) => e.owner));
    assert.deepEqual([...derived].sort(), [...published].sort(), `${f}: the derived exclusion set must equal the published one`);

    // And nobody who WAS paid may be derivable as unclaimable.
    for (const r of art.ledger) {
      assert.notEqual(p.evaluate(r.owner).verdict, UNCLAIMABLE, `${f}: ${r.owner} was paid but is derivably unclaimable`);
    }
  }
});

test('two independent derivations of the same artifact agree byte for byte', () => {
  const dir = join(HERE, '..', 'artifacts');
  if (!existsSync(dir)) return;
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const art = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    const derive = () => {
      const p = parsePredicate({ id: art.params.predicate_id, rules: art.params.predicate_rules, overrides: art.predicate.overrides });
      return art.ledger.concat(art.predicate.excluded.map((e) => ({ owner: e.owner })))
        .map((r) => `${r.owner} ${p.evaluate(r.owner).verdict}`)
        .sort()
        .join('\n');
    };
    assert.equal(derive(), derive(), `${f} derived differently on two passes`);
  }
});
