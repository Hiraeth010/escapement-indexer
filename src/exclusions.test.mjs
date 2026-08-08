/**
 * exclusions.test.mjs — the discretionary surface, fenced.
 *
 * These tests exist to make it hard to accidentally build the thing the threat
 * model warns about: an exclusion set that is easy to change and hard to notice.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { parseExclusions, diffExclusions, loadExclusions, exclusionsTemplate, KNOWN_OPEN_CASES } from './exclusions.mjs';
import { accrue, ledgerFrom } from './accrue.mjs';
import { pk, MINT, A, B, OA, OB, OC } from './mockchain.test.mjs';

const base = (over = {}) => JSON.stringify({
  schema: 'escapement.exclusions/v1',
  version: '2026-08-08.1',
  mint: MINT,
  effective_from_slot: 50,
  policy: 'Excludes nothing. All four /spec §4.5 cases remain open and are listed as undecided.',
  undecided: [...KNOWN_OPEN_CASES],
  entries: [],
  ...over,
});

const entry = (over = {}) => ({
  address: pk(30), scope: 'owner', kind: 'amm_pool',
  justification: 'PumpSwap pool authority; LP tokens burned, so no one can ever redeem this balance.',
  evidence: 'tx 5xyz... decoded 2026-08-08',
  ...over,
});

test('there is no default: a run without an exclusion file cannot happen', () => {
  assert.throws(() => loadExclusions(undefined, {}), /REQUIRED and has no default/);
  assert.throws(() => loadExclusions(null, {}), /policy question the code is not permitted to answer/);
});

test('the code contains no address list and takes no position on the four open cases', async () => {
  const src = await import('node:fs').then((fs) => fs.readFileSync(new URL('./exclusions.mjs', import.meta.url), 'utf8'));
  // A 32-44 character base58 run that is not part of an identifier or a URL
  // would be a hard-coded address. There must be none.
  const suspicious = src.match(/(?<![\w/.])[1-9A-HJ-NP-Za-km-z]{32,44}(?![\w/])/g) ?? [];
  assert.deepEqual(suspicious, [], `exclusions.mjs must contain no hard-coded addresses, found: ${suspicious}`);
  // And the four open cases appear only as names to be acknowledged.
  for (const c of KNOWN_OPEN_CASES) assert.ok(src.includes(c));
});

test('every entry needs a real justification and real evidence', () => {
  assert.throws(() => parseExclusions(base({ entries: [entry({ justification: 'pool' })] })), /at least 20 characters/);
  assert.throws(() => parseExclusions(base({ entries: [entry({ evidence: '' })] })), /evidence is required/);
  assert.throws(() => parseExclusions(base({ entries: [entry({ scope: 'maybe' })] })), /scope must be one of/);
  assert.throws(() => parseExclusions(base({ entries: [entry({ address: 'not-base58' })] })), /base58 pubkey/);
  assert.throws(() => parseExclusions(base({ policy: 'because' })), /must be a written statement/);
  assert.throws(() => parseExclusions(base({ entries: [entry(), entry()] })), /duplicates/);
});

test('an exclusion set cannot be applied retroactively (D9)', () => {
  const doc = base({ effective_from_slot: 500 });
  assert.throws(
    () => parseExclusions(doc, { mint: MINT, fromSlot: 400 }),
    /announced before the epoch they apply to/,
  );
  // Effective at or before the period start is fine.
  assert.ok(parseExclusions(base({ effective_from_slot: 400 }), { mint: MINT, fromSlot: 400 }));
});

test('an exclusion set is not portable between mints', () => {
  assert.throws(() => parseExclusions(base(), { mint: pk(99) }), /not portable between mints/);
});

test('the hash depends on meaning, not on file layout', () => {
  const a = parseExclusions(base({ entries: [entry({ address: pk(31) }), entry({ address: pk(32) })] }));
  const b = parseExclusions(base({ entries: [entry({ address: pk(32) }), entry({ address: pk(31) })] }));
  assert.equal(a.hash, b.hash, 'reordering entries must not change the hash');

  const c = parseExclusions(base({ entries: [entry({ address: pk(31) })] }));
  assert.notEqual(a.hash, c.hash, 'removing an entry must change the hash');

  const d = parseExclusions(base({ policy: 'A different policy, at least forty characters long, stating something else.' }));
  assert.notEqual(parseExclusions(base()).hash, d.hash, 'the policy text is part of the commitment');
});

test('two versions diff, and the diff says who starts getting paid', () => {
  const before = parseExclusions(base({ entries: [entry({ address: pk(31) })] }));
  const after = parseExclusions(base({ version: '2026-08-09.1', entries: [entry({ address: pk(32) })] }));
  const d = diffExclusions(before, after);

  assert.equal(d.identical, false);
  assert.equal(d.added.length, 1);
  assert.equal(d.added[0].address, pk(32));
  assert.equal(d.removed.length, 1);
  assert.equal(d.removed[0].address, pk(31));
  assert.ok(d.meta.some((m) => m.field === 'version'));

  assert.equal(diffExclusions(before, before).identical, true);
});

test('an owner-scoped exclusion follows a SetAuthority rather than sticking to the account', () => {
  // A is owned by OA until slot 108, then by OC. Excluding OC must remove only
  // the post-108 accrual, not the whole account's history.
  const ex = parseExclusions(base({ entries: [entry({ address: OC, scope: 'owner', kind: 'cex_omnibus' })] }));
  const res = accrue({
    fromSlot: 100, toSlot: 110,
    slotEvents: [
      { slot: 102, events: [{ account: A, kind: 'set', owner: OA, amount: 1000n }] },
      { slot: 105, events: [
        { account: A, kind: 'set', owner: OA, amount: 600n },
        { account: B, kind: 'set', owner: OB, amount: 400n },
      ] },
      { slot: 108, events: [{ account: A, kind: 'set', owner: OC, amount: 600n }] },
    ],
    classify: ex.classify,
  });

  const led = new Map(ledgerFrom(res.included).map((r) => [r.owner, r.tokenSlots]));
  assert.equal(led.get(OA), 4800n, 'OA keeps everything it accrued while it was the owner');
  assert.equal(led.has(OC), false);
  assert.equal(res.excluded.get(`owner:${OC}`), 1200n, 'exactly the excluded portion is reported, not hidden');
  assert.equal(res.totalExcluded, 1200n);
});

test('a token-account-scoped exclusion removes that account regardless of owner', () => {
  const ex = parseExclusions(base({ entries: [entry({ address: A, scope: 'token_account', kind: 'bonding_curve' })] }));
  const res = accrue({
    fromSlot: 100, toSlot: 110,
    slotEvents: [
      { slot: 102, events: [{ account: A, kind: 'set', owner: OA, amount: 1000n }] },
      { slot: 108, events: [{ account: A, kind: 'set', owner: OC, amount: 600n }] },
    ],
    classify: ex.classify,
  });
  assert.equal(res.totalIncluded, 0n);
  assert.equal(res.excluded.get(`token_account:${A}`), 1000n * 6n + 600n * 2n);
});

test('the template refuses to run until someone has actually written the policy', () => {
  const t = exclusionsTemplate(MINT, 100);
  assert.throws(() => parseExclusions(t, { mint: MINT, fromSlot: 100 }), /still the template placeholder/);
});

test('unmentioned §4.5 cases are surfaced rather than silently allowed', () => {
  const p = parseExclusions(base({ undecided: ['bonding_curve'] }), { mint: MINT, fromSlot: 100 });
  assert.deepEqual(p.acknowledgementGaps.sort(), ['amm_pool', 'cex_omnibus', 'lending_collateral']);
  const q = parseExclusions(base(), { mint: MINT, fromSlot: 100 });
  assert.deepEqual(q.acknowledgementGaps, []);
});
