/**
 * verify.test.mjs — the verifier agrees when it should, disagrees when it
 * should, and says WHERE.
 *
 * The localisation tests are the point. "Our roots differ" is not a useful
 * output; "we disagree at slot 105" is.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { runIndex } from './run.mjs';
import { runVerify, hashInputSetText } from './verify.mjs';
import { parseExclusions } from './exclusions.mjs';
import { scenario, mockRpc, MINT, CONFIG, OPEN_EXCLUSIONS, OA, pk } from './mockchain.test.mjs';
import { canonicalJson } from './canonical.mjs';

const RUN = { mint: MINT, from: 100, to: 110, exclusions: OPEN_EXCLUSIONS, configPubkey: CONFIG, vaultLamports: 1_000_000n };

/** Round-trip through the canonical serialiser, as a published artifact would be. */
const publish = (artifact) => JSON.parse(canonicalJson(artifact));

test('verify agrees with a root the indexer just produced', async () => {
  const chain = scenario();
  const { artifact, inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  const res = await runVerify({
    ...RUN, rpc: mockRpc(chain, { jitter: true }), concurrency: 5,
    expectedRoot: artifact.merkle_root,
    publishedArtifact: publish(artifact),
    publishedInputSetText: inputSet.text(),
  });

  assert.equal(res.agree, true);
  assert.equal(res.internallyConsistent, true, 'the two merkle implementations must agree');
  assert.equal(res.independentRoot, artifact.merkle_root);
});

test('verify disagrees with a fabricated root and says the arithmetic is not the issue', async () => {
  const chain = scenario();
  const { artifact, inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  // A dishonest publisher inflates one address's entitlement and republishes.
  const tampered = publish(artifact);
  tampered.merkle_root = 'f'.repeat(64);

  const res = await runVerify({
    ...RUN, rpc: mockRpc(chain),
    expectedRoot: tampered.merkle_root,
    publishedArtifact: tampered,
    publishedInputSetText: inputSet.text(),
  });

  assert.equal(res.agree, false);
  const where = res.findings.map((f) => f.where);
  assert.ok(where.includes('merkle_root'));
  // Inputs and ledger match, so the finding must point at the distribution layer.
  assert.ok(where.includes('distribution'), `expected a distribution finding, got ${where.join(', ')}`);
});

test('a disagreement about chain data localises to the exact slot', async () => {
  const chain = scenario();
  const { artifact, inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  // The publisher's input set claims slot 105 was skipped. Ours says it carried
  // the transfer. One line differs, and that line names the slot.
  const theirs = inputSet.text()
    .replace(/^slot 105 block .*$/m, 'slot 105 skipped')
    .replace(/^tx 105 .*$/m, '');
  const tampered = publish(artifact);
  tampered.input_set_hash = hashInputSetText(theirs);
  tampered.merkle_root = '0'.repeat(64);

  const res = await runVerify({
    ...RUN, rpc: mockRpc(chain),
    expectedRoot: tampered.merkle_root,
    publishedArtifact: tampered,
    publishedInputSetText: theirs,
  });

  assert.equal(res.agree, false);
  assert.ok(res.findings.some((f) => f.where === 'input_set_hash'));
  assert.ok(
    res.findings.some((f) => /first divergence is at slot 105/.test(f.detail)),
    `expected slot 105 to be named, got:\n${res.findings.map((f) => f.detail).join('\n')}`,
  );
});

test('a changed exclusion set is named as the cause before anything else', async () => {
  const chain = scenario();
  const { artifact, inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  const stricter = parseExclusions(JSON.stringify({
    schema: 'escapement.exclusions/v1',
    version: '2026-08-08.2',
    mint: MINT,
    effective_from_slot: 0,
    policy: 'Excludes one address that the previous version paid. This is the change under review.',
    undecided: [],
    entries: [{
      address: OA, scope: 'owner', kind: 'cex_omnibus',
      justification: 'Believed to be an exchange omnibus account; beneficial owners are off chain.',
      evidence: 'account note, 2026-08-08',
    }],
  }), { mint: MINT, fromSlot: 100 });

  const res = await runVerify({
    ...RUN, rpc: mockRpc(chain), exclusions: stricter,
    expectedRoot: artifact.merkle_root,
    publishedArtifact: publish(artifact),
    publishedInputSetText: inputSet.text(),
  });

  assert.equal(res.agree, false);
  const first = res.findings.find((f) => f.where.startsWith('params.'));
  assert.equal(first.where, 'params.exclusions_hash');
  assert.match(first.detail, /exclusions-diff/);
});

test('an accrual disagreement is distinguished from a data disagreement', async () => {
  const chain = scenario();
  const { artifact, inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });

  // Same inputs, same input-set hash, but the published ledger credits somebody
  // 10x. That is the signature of a manipulated aggregation, not bad data.
  const tampered = publish(artifact);
  tampered.ledger = tampered.ledger.map((r) => (r.owner === OA ? { ...r, token_slots: '48000' } : r));
  tampered.merkle_root = '1'.repeat(64);

  const res = await runVerify({
    ...RUN, rpc: mockRpc(chain),
    expectedRoot: tampered.merkle_root,
    publishedArtifact: tampered,
    publishedInputSetText: inputSet.text(),
  });

  assert.ok(res.findings.some((f) => f.where === `ledger[${OA}]`));
  assert.ok(res.findings.some((f) => /accrual disagreement, not a data disagreement/.test(f.detail)));
});

test('without the published artifact, verify says so rather than pretending to localise', async () => {
  const chain = scenario();
  const res = await runVerify({
    ...RUN, rpc: mockRpc(chain), expectedRoot: 'a'.repeat(64),
  });
  assert.equal(res.agree, false);
  assert.ok(res.findings.some((f) => /cannot be localised further than/.test(f.detail)));
});

test('an edited input-set file is detected by its own hash', async () => {
  const chain = scenario();
  const { inputSet } = await runIndex({ ...RUN, rpc: mockRpc(chain) });
  const text = inputSet.text();
  assert.equal(hashInputSetText(text), inputSet.digest());
  assert.notEqual(hashInputSetText(text.replace('sigTransfer', 'sigOther')), inputSet.digest());
});
