// SPDX-License-Identifier: Apache-2.0
/**
 * verify.mjs — a separate entry point that recomputes a published root and
 * localises a disagreement.
 *
 * ---------------------------------------------------------------------------
 * WHAT VERIFICATION ACTUALLY PROVES (read this before trusting a green tick)
 * ---------------------------------------------------------------------------
 * This shares `blocks.mjs`, `extract.mjs`, `accrue.mjs` and `entitle.mjs` with
 * the producer. A bug in any of those is present on both sides and therefore
 * PASSES verification. What a green result does prove:
 *
 *   - the published root is a function of the claimed slot range and no other
 *     range;
 *   - the exclusion set used was the one published, byte for byte;
 *   - the chain data behind it is what an independent RPC provider also reports,
 *     including which slots were skipped and which transactions were in them;
 *   - the merkle construction is agreed by two independently written
 *     implementations of D10 (`merkle.mjs` and `verify-merkle.mjs`).
 *
 * What it does not prove: that the specification of token-seconds accrual is
 * implemented correctly at all. For that you need a second implementation of the
 * accrual model by somebody who is not us, and there is not one. That gap is
 * stated on the README's front page, not buried here.
 *
 * The honest strong move a verifier can make TODAY is to run this against a
 * DIFFERENT RPC provider than the publisher used (`--rpc`), which is what makes
 * the input-set comparison meaningful.
 */

import { runIndex } from './run.mjs';
import { independentRoot, independentDomain } from './verify-merkle.mjs';
import { SCHEMA_VERSION } from './version.mjs';
import { DOMAIN_TAG } from './merkle.mjs';
import { LineHasher } from './canonical.mjs';

/**
 * @returns {{
 *   agree: boolean,
 *   computedRoot: string|null, expectedRoot: string,
 *   independentRoot: string|null, internallyConsistent: boolean,
 *   findings: {level: 'agree'|'differ'|'note', where: string, detail: string}[],
 *   artifact: object,
 * }}
 */
export async function runVerify({
  rpc, mint, from, to, exclusions, configPubkey, vaultLamports, vaultSource = null,
  expectedRoot, publishedArtifact = null, publishedInputSetText = null,
  prior = new Map(), priorSource = null,
  openingAccounts = [], openingStateSource = null,
  // Only used when there is no published artifact to read it from — i.e. the
  // `--root <hex>` path, where nothing on disk declares a namespace.
  domainTag = DOMAIN_TAG,
  concurrency = 4, onProgress = null,
}) {
  // The prior is the artifact BEFORE the one under verification, never the one
  // under verification — leaves are cumulative (G3), so feeding a root its own
  // payouts back in would double every entitlement and disagree with itself.
  // `params.prior_root_source` in the published artifact says which file to use.
  const preflight = [];
  if (publishedArtifact?.params?.prior_root_source && prior.size === 0) {
    preflight.push({
      level: 'note', where: 'prior',
      detail:
        `the published artifact was produced with a prior root (${publishedArtifact.params.prior_root_source}) ` +
        `but no prior was supplied to this verification. Cumulative leaves will be short by the previous ` +
        `period's amounts and the root will not match for that reason alone.`,
    });
  }

  /**
   * WHICH NAMESPACE ARE WE REBUILDING IN? The published artifact decides.
   *
   * Resolved BEFORE any RPC work, for two reasons. The cheap one: there is no
   * point spending a hundred megabytes to conclude that the root was never
   * reproducible. The load-bearing one: `commitmentDomain` defaults its tag, so
   * an artifact whose tag field was removed would be rebuilt in OURS and could
   * come back AGREE — a third party's file validating against Escapement's
   * namespace, which is the exact confusion the tag exists to prevent.
   *
   * The first version of this read the tag off `artifact`, the one runIndex had
   * just produced, rather than off `publishedArtifact`. That is our own tag by
   * construction, so it always matched and the refusal could never fire. Same
   * shape as every other fail-open here: a correct check pointed at the wrong
   * object. Two tests caught it.
   */
  let verifyTag = domainTag;
  if (publishedArtifact) {
    const claimed = publishedArtifact.params?.merkle_domain_tag;
    if (typeof claimed !== 'string' || claimed.length === 0) {
      return {
        agree: false,
        computedRoot: null,
        expectedRoot: expectedRoot ?? publishedArtifact.merkle_root ?? null,
        independentRoot: null,
        internallyConsistent: false,
        artifact: publishedArtifact,
        findings: [...preflight, {
          level: 'refuse',
          where: 'artifact.params.merkle_domain_tag',
          detail:
            'This artifact does not name the domain tag its leaves were built in, so its root cannot be '
            + 're-derived — not by us and not by anyone. Artifacts written before schema '
            + `${SCHEMA_VERSION} predate both the tag and the length prefix now inside the domain preimage, `
            + 'so their domain bytes are not reproducible under any tag. Regenerate with the current code '
            + 'rather than trusting a root nothing here can rebuild. This is a refusal to reach a verdict, '
            + 'not a finding that the arithmetic is wrong — those are different claims and must not print '
            + 'the same way.',
        }],
      };
    }
    verifyTag = claimed;
  }

  const { artifact, inputSet, dist } = await runIndex({
    rpc, mint, from, to, exclusions, configPubkey, vaultLamports, vaultSource,
    prior, priorSource, openingAccounts, openingStateSource, concurrency, onProgress,
    domainTag: verifyTag,
  });

  const findings = [...preflight];
  const computedRoot = artifact.merkle_root;

  // Cross-check the tree against the second implementation before comparing to
  // anything published. If these two disagree, the problem is ours and no
  // statement about the publisher is warranted.
  let indep = null;
  let internallyConsistent = true;
  if (dist) {
    // Two independent derivations of the leaf domain, then two independent
    // constructions of the tree over it. The domain is checked separately
    // because a domain mismatch and a tree mismatch have different causes and
    // reporting them as one finding would lose that.
    const ourDomain = artifact.params.merkle_domain;

    /**
     * The tag comes from the ARTIFACT, and its absence is a refusal.
     *
     * Verification means re-deriving what the PUBLISHER says they did, so
     * reading our own default here would be checking ourselves. Worse, the
     * parameter defaults to Escapement's tag, so an artifact that simply had
     * the field removed would sail through by being re-derived under OUR
     * namespace — a third party's stripped artifact validating against our
     * domain is precisely the confusion the tag exists to prevent.
     *
     * Pre-v3 artifacts also predate the length prefix, so their domain bytes
     * are not reproducible under any tag. Naming that explicitly beats letting
     * them fail as a mystery mismatch.
     */
    // `verifyTag` is the publisher's, resolved above and already proven present.
    const theirDomain = independentDomain(configPubkey, exclusions.policyBinding, verifyTag);
    if (ourDomain !== theirDomain) {
      internallyConsistent = false;
      findings.push({
        level: 'differ',
        where: 'internal.domain',
        detail:
          `merkle.mjs derived the leaf domain ${ourDomain} and verify-merkle.mjs derived ${theirDomain} from ` +
          `the same config pubkey and policy binding. These are two implementations of the same derivation in ` +
          `this repository and they disagree, so one of them is wrong. No conclusion about the published root ` +
          `is possible until this is fixed.`,
      });
    }
    indep = independentRoot(theirDomain, dist.rows.map((r) => ({ claimant: r.owner, cumulative: r.cumulative })));
    if (indep !== computedRoot) {
      internallyConsistent = false;
      findings.push({
        level: 'differ',
        where: 'internal',
        detail:
          `merkle.mjs computed ${computedRoot} and verify-merkle.mjs computed ${indep} over the same leaves. ` +
          `These are two implementations of D10 in this repository and they disagree, so one of them is wrong. ` +
          `No conclusion about the published root is possible until this is fixed.`,
      });
    }
  }

  const agree = computedRoot !== null && computedRoot === expectedRoot;
  findings.push({
    level: agree ? 'agree' : 'differ',
    where: 'merkle_root',
    detail: agree ? `root matches: ${expectedRoot}` : `expected ${expectedRoot}, recomputed ${computedRoot}`,
  });

  if (!agree) findings.push(...localise({ artifact, inputSet, publishedArtifact, publishedInputSetText }));

  return { agree, computedRoot, expectedRoot, independentRoot: indep, internallyConsistent, findings, artifact };
}

/**
 * Turn "our numbers differ" into "we disagree at slot X" (D5).
 *
 * The order matters: parameters first (a range mismatch explains everything
 * downstream and no other comparison is meaningful), then the input set, then
 * the ledger, then the arithmetic. Reporting the FIRST divergence in that chain
 * is the difference between a five-minute diagnosis and an argument.
 */
export function localise({ artifact, inputSet, publishedArtifact, publishedInputSetText }) {
  const out = [];

  if (!publishedArtifact) {
    out.push({
      level: 'note', where: 'localisation',
      detail:
        'no published artifact supplied (--artifact), so the disagreement cannot be localised further than ' +
        'the root. Re-run with the publisher\'s artifact and input-set files.',
    });
    return out;
  }

  // 1. Parameters.
  const pa = publishedArtifact.params ?? {};
  const pb = artifact.params;
  // `predicate_hash` is checked BEFORE `exclusions_hash` even though the
  // exclusion hash covers it. A predicate difference makes both differ, and
  // "your predicate is not ours" is a far more actionable sentence than "your
  // policy file is not ours".
  for (const k of ['mint', 'from_slot', 'to_slot', 'commitment', 'config_pubkey',
    'predicate_id', 'predicate_hash', 'exclusions_hash', 'opening_state']) {
    const same = k === 'opening_state'
      ? (pa[k]?.hash ?? null) === (pb[k]?.hash ?? null)
      : String(pa[k]) === String(pb[k]);
    if (!same) {
      out.push({
        level: 'differ', where: `params.${k}`,
        detail: `published ${JSON.stringify(pa[k])} vs recomputed ${JSON.stringify(pb[k])}. ` +
          (k === 'exclusions_hash'
            ? 'The exclusion set is not the one that produced the published root. Run `escapement exclusions-diff` on the two files.'
            : k === 'predicate_hash' || k === 'predicate_id'
              ? 'The unclaimable-address PREDICATE differs — a different rule set, or a different override list. ' +
                'That changes who is a claimant at all, so nothing downstream is comparable. `exclusions-diff` ' +
                'prints the predicate section separately.'
              : k === 'opening_state'
                ? 'The balance table carried in at from_slot differs. Supply the same --opening-state artifact the publisher used.'
                : 'Nothing downstream of this is comparable until it matches.'),
      });
      return out;
    }
  }

  // 2. Input set: which blocks and which transactions.
  if (publishedArtifact.input_set_hash !== artifact.input_set_hash) {
    out.push({
      level: 'differ', where: 'input_set_hash',
      detail: `published ${publishedArtifact.input_set_hash} vs recomputed ${artifact.input_set_hash}. ` +
        'The two runs consumed different chain data — this is a dispute about inputs, not about arithmetic.',
    });
    if (publishedInputSetText) {
      const theirs = publishedInputSetText.split('\n');
      const ours = inputSet.lines;
      const n = Math.max(theirs.length, ours.length);
      for (let i = 0; i < n; i++) {
        const a = theirs[i] ?? '<end of file>';
        const b = ours[i] ?? '<end of file>';
        if (a === b) continue;
        out.push({
          level: 'differ', where: `input-set line ${i + 1}`,
          detail: `published: ${a}\n  recomputed: ${b}`,
        });
        const slot = (a.match(/^(?:slot|tx) (\d+)/) ?? b.match(/^(?:slot|tx) (\d+)/))?.[1];
        if (slot) {
          out.push({
            level: 'note', where: 'localisation',
            detail: `first divergence is at slot ${slot}. Fetch that block from both providers and compare.`,
          });
        }
        return out;
      }
    } else {
      out.push({
        level: 'note', where: 'localisation',
        detail: 'supply the publisher\'s .input-set.txt with --input-set to localise this to a single slot.',
      });
    }
    return out;
  }

  // 3. The ledger: same inputs, different token-slots.
  const theirs = new Map((publishedArtifact.ledger ?? []).map((r) => [r.owner, String(r.token_slots)]));
  const ours = new Map(artifact.ledger.map((r) => [r.owner, String(r.token_slots)]));
  const owners = [...new Set([...theirs.keys(), ...ours.keys()])].sort();
  let ledgerDiffs = 0;
  for (const o of owners) {
    const a = theirs.get(o);
    const b = ours.get(o);
    if (a === b) continue;
    ledgerDiffs++;
    if (ledgerDiffs <= 10) {
      out.push({
        level: 'differ', where: `ledger[${o}]`,
        detail: `published ${a ?? '(absent)'} token-slots vs recomputed ${b ?? '(absent)'}`,
      });
    }
  }
  if (ledgerDiffs > 0) {
    out.push({
      level: 'note', where: 'localisation',
      detail: `the input sets are identical but ${ledgerDiffs} owner(s) accrue differently. ` +
        'That is an accrual disagreement, not a data disagreement: the exclusion classification, the ' +
        'owner attribution, or the span arithmetic differs.',
    });
    return out;
  }

  // 4. Same ledger, different root: the payout or tree layer.
  out.push({
    level: 'differ', where: 'distribution',
    detail: 'the input set and the per-owner ledger are identical, so the disagreement is in the vault ' +
      'amount, the prior-cumulative carry, the config pubkey, or the tree construction. Compare ' +
      'params.vault_lamports and total_owed_cumulative.',
  });
  const pv = String(publishedArtifact.params?.vault_lamports);
  const ov = String(artifact.params.vault_lamports);
  if (pv !== ov) {
    out.push({ level: 'differ', where: 'params.vault_lamports', detail: `published ${pv} vs supplied ${ov}` });
  }
  return out;
}

/** Recompute an input-set hash from a published input-set file, to check it is self-consistent. */
export function hashInputSetText(text) {
  const h = new LineHasher();
  h.discardLines();
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  for (const l of lines) h.push(l);
  return h.digest();
}
