// SPDX-License-Identifier: Apache-2.0
/**
 * predicate.mjs — the exclusion PREDICATE. Correctness, not discretion.
 *
 * =============================================================================
 * THE PROBLEM THIS EXISTS TO SOLVE
 * =============================================================================
 * The first real run of this indexer, over 20 mainnet slots of a live pump.fun
 * token, measured 84.99% of the distribution going to one address:
 * `Hgpbxqt…YomL`, the pool authority of the pump.fun AMM. The pool's LP tokens
 * are burned. There is no redeemer. Both of the obvious options were bad:
 *
 *   (a) pay it — the money is minted into a leaf nobody can ever claim, and the
 *       distribution silently strands 85% of itself forever; or
 *   (b) put it on a curated exclusion list — which is a human deciding who gets
 *       paid, which is discretion, which falsifies the trustless claim.
 *
 * The resolution is that these are not the only two options, because they share
 * a false premise: that excluding this address is a POLICY choice. It is not.
 * An address with no possible claimant is not a claimant. Removing it is the
 * same kind of act as removing a zero-balance row: a statement about the world,
 * checkable by anyone, not a preference.
 *
 * So exclusion-by-correctness is a PREDICATE — published, versioned, and
 * evaluated mechanically — and it lives here, separately from the discretionary
 * exclusion list in `exclusions.mjs`, which still exists and is still fenced.
 *
 * =============================================================================
 * THE RULE, AND THE ONE PROPERTY THAT FORCED IT
 * =============================================================================
 * v1 has exactly one rule:
 *
 *     off_curve_owner — the token account's OWNER is not a valid ed25519 point.
 *
 * A 32-byte value that is not on the curve cannot be the public key of any
 * ed25519 keypair. Not "unlikely to be"; cannot be. So no single key signs for
 * it, and `find_program_address` guarantees the converse: every PDA is off-curve
 * by construction. The check is arithmetic on the address itself (`curve.mjs`),
 * costs microseconds, and needs no RPC call.
 *
 * That last part is not a convenience, it is the constraint that eliminated
 * every other candidate rule. A predicate is only worth having if two strangers
 * derive the SAME exclusion set without coordinating. Consider what that rules
 * out:
 *
 *   - A rule that reads account state ("the owner is owned by program X", "the
 *     pool's LP supply is zero") must read it AS OF A PINNED SLOT, or two people
 *     running the same code a week apart get different sets. Public RPC cannot
 *     serve historical account state at all — that is the same wall the opening
 *     state problem hits (README, Known limits 1). Reading CURRENT state instead
 *     makes the exclusion set a function of when you ran, which is not a
 *     predicate, it is a timestamp.
 *   - A rule keyed on a program id ("owner is a PDA of the pump.fun AMM") is
 *     reproducible, but somebody has to write down which programs are on the
 *     list. That is a list. Lists are the thing being replaced.
 *
 * Off-curve-ness is a pure function of 32 bytes, immutable for all time, and
 * derivable offline from the ledger the artifact already publishes. It is the
 * only rule found that clears the bar. That is the whole argument.
 *
 * =============================================================================
 * WHAT THIS GETS WRONG — READ THIS PART
 * =============================================================================
 * Off-curve means no SINGLE KEY signs. It does not mean nobody benefits, and it
 * does not even mean nobody can sign: a PDA can be signed for by its owning
 * program through `invoke_signed`. So the rule has both kinds of error, and both
 * are real.
 *
 * FALSE EXCLUSIONS (excluded, but arguably should be paid):
 *
 *   1. Smart-contract wallets and multisigs. A Squads vault is a PDA. The Squads
 *      program CAN issue an arbitrary CPI on its behalf, so such a vault could
 *      in principle execute a claim. This rule excludes it anyway. It is the
 *      most serious error in the design and it is why the override in this file
 *      exists.
 *   2. Program treasuries belonging to real projects. A DAO whose treasury is a
 *      PDA of its own program has a beneficiary and possibly a claim path.
 *   3. Lending collateral. The collateral sits in the lending program's PDA; the
 *      depositor is a real person holding a receipt token. The rule excludes the
 *      PDA. The depositor cannot claim either — the lending program will not CPI
 *      into a distributor it has never heard of — so nothing is *stranded* by
 *      excluding it, but a beneficiary does exist and is not paid.
 *
 *   Note what these have in common: the beneficiary is one indirection away and
 *   the indirection is not visible in 32 bytes. No cheap rule separates them.
 *
 * FALSE INCLUSIONS (paid, but nobody can claim):
 *
 *   4. Burn sinks that happen to be on-curve. `1nc1nerator111…` and the various
 *      vanity dead addresses are on the curve; a key may exist, nobody has it,
 *      and it is not provable either way. Non-existence of a private key for an
 *      on-curve address is unfalsifiable, so no predicate can ever cover this.
 *   5. Lost keys. Same reason. Unknowable.
 *   6. Exchange omnibus accounts. On-curve, the exchange can sign, so this rule
 *      pays them — which is arguably right (they can claim) and arguably wrong
 *      (the beneficial holders are their customers). That is a policy question,
 *      it is `/spec` §4.5 case three, and it stays in the discretionary file
 *      where policy questions belong. The predicate takes no position on it.
 *
 * The rule is therefore BROADER than "unclaimable" on one side and NARROWER on
 * the other. It is not the truth; it is the best decidable approximation of it,
 * and its errors are enumerated above rather than discovered later.
 *
 * =============================================================================
 * WHY NOT NARROWER
 * =============================================================================
 * The narrower rule — "owner is a PDA of a known AMM program" — has strictly
 * fewer false exclusions: it would exclude the pump.fun pool and leave a Squads
 * vault alone. It was rejected, and the reason should be stated plainly rather
 * than implied: IT NEEDS A LIST. Somebody chooses which program ids are on it,
 * that choice moves money, and the choosing is exactly the discretion this file
 * was written to remove. Trading an address list for a program list makes the
 * list shorter and more defensible; it does not make it not-a-list.
 *
 * The design accepts the broader rule's false exclusions in exchange for having
 * no list, and then gives the false exclusions a named, auditable escape hatch:
 *
 * =============================================================================
 * THE ESCAPE HATCH, AND ITS DIRECTION
 * =============================================================================
 * `overrides` in the predicate declaration can carry two verdicts, and only two:
 *
 *   claimable  — "this off-curve address CAN claim; pay it." A reinstatement.
 *                Requires a justification and on-chain evidence, is hashed into
 *                the root, and is non-retroactive like every other part of the
 *                exclusion document.
 *   undecided  — "we know this address is contentious and we have NOT decided."
 *                A run that touches an address marked undecided REFUSES. It does
 *                not include it, it does not exclude it, it does not warn: it
 *                stops. An unanswered question must not resolve itself into
 *                whichever default happens to be cheaper for the publisher.
 *
 * There is deliberately no `unclaimable` override. Hand-marking an address as
 * unpayable is the discretionary exclusion list, that already exists in
 * `exclusions.mjs` with its own justification and evidence requirements, and
 * duplicating it here would let a publisher launder a policy exclusion as a
 * correctness one. Overrides only ever ADD somebody back.
 *
 * =============================================================================
 * VISIBILITY
 * =============================================================================
 * The predicate declaration is part of the exclusion document, so its hash is
 * bound into the merkle root (see `exclusions.mjs` → `policyBinding`, and
 * `merkle.mjs` → `commitmentDomain`). Changing the predicate — its id, its rule
 * list, or a single override — changes the root, even if it changes nobody's
 * payout. The artifact additionally prints every address the predicate removed,
 * with the token-slots each one cost, so a wrongly-excluded party can find
 * themselves in it and object.
 */

import { sha256Hex, canonicalJson } from './canonical.mjs';
import { isPubkey } from './base58.mjs';
import { pubkeyOnCurve } from './curve.mjs';

export const PREDICATE_SCHEMA = 'escapement.unclaimable/v1';

/** The verdicts. `claimable` is the default and is never a bucket. */
export const CLAIMABLE = 'claimable';
export const UNCLAIMABLE = 'unclaimable';
export const UNDECIDED = 'undecided';

/** Overrides may only reinstate or halt. See "THE ESCAPE HATCH" above. */
export const OVERRIDE_VERDICTS = new Set([CLAIMABLE, UNDECIDED]);

/**
 * The rule registry. A rule is a pure function of the owner ADDRESS STRING and
 * nothing else — no account state, no slot, no network. That signature is the
 * reproducibility guarantee, expressed as a type.
 *
 * A rule returns `null` for "no opinion", or a verdict. First opinion wins, in
 * the order the operator declared, so the order is part of the commitment.
 */
export const RULES = Object.freeze({
  off_curve_owner: {
    id: 'off_curve_owner',
    summary:
      'The token account owner is not a valid ed25519 point, so no keypair exists that can sign for it. ' +
      'Every program-derived address is off-curve by construction.',
    evaluate(owner) {
      const onCurve = pubkeyOnCurve(owner);
      if (onCurve === null) {
        // Not a 32-byte address at all. The curve test is undefined here, and
        // treating "I cannot evaluate this" as either verdict is the exact
        // failure mode this design refuses. Stop instead.
        return {
          verdict: UNDECIDED,
          reason: `owner ${JSON.stringify(owner)} is not a 32-byte base58 address, so the on-curve test is undefined`,
        };
      }
      if (onCurve) return null;
      return {
        verdict: UNCLAIMABLE,
        reason: 'owner is off the ed25519 curve: no secret key exists whose public key is this address',
      };
    },
  },
});

export const RULE_IDS = Object.freeze(Object.keys(RULES));

function fail(msg) { throw new Error(`predicate: ${msg}`); }

/**
 * Parse and validate a predicate declaration from an exclusion document.
 *
 * @param {object} spec  the `predicate` block of the exclusion file
 * @returns {{
 *   id: string,
 *   rules: string[],
 *   overrides: {address: string, verdict: string, justification: string, evidence: string}[],
 *   canonical: object,
 *   hash: string,
 *   evaluate: (owner: string) => {verdict: string, rule: string|null, reason: string|null},
 * }}
 */
export function parsePredicate(spec) {
  if (spec === undefined || spec === null) {
    fail(
      '`predicate` is required in the exclusion document. It states which unclaimable-address rules this ' +
      'run applied, and it is hashed into the merkle root. Declare `{"id": "' + PREDICATE_SCHEMA + '", ' +
      '"rules": [...], "overrides": []}`; `"rules": []` is a legal, and visible, way to apply none of them.',
    );
  }
  if (spec.id !== PREDICATE_SCHEMA) {
    fail(
      `\`predicate.id\` must be ${JSON.stringify(PREDICATE_SCHEMA)}, got ${JSON.stringify(spec.id)}. ` +
      'This build implements exactly one predicate version and refuses every other, so that an artifact ' +
      'produced under a predicate this code does not implement can never be silently reproduced under a ' +
      'different one.',
    );
  }
  if (!Array.isArray(spec.rules)) {
    fail('`predicate.rules` must be an array of rule ids (empty is allowed, and means "apply no rules")');
  }
  const rules = [];
  for (const r of spec.rules) {
    if (typeof r !== 'string' || !RULE_IDS.includes(r)) {
      fail(`unknown rule ${JSON.stringify(r)}. This build implements: ${RULE_IDS.join(', ')}`);
    }
    if (rules.includes(r)) fail(`rule ${r} is declared twice`);
    rules.push(r);
  }

  const rawOverrides = spec.overrides ?? [];
  if (!Array.isArray(rawOverrides)) fail('`predicate.overrides` must be an array (omit it or use [] for none)');

  const overrides = [];
  const seen = new Set();
  for (let i = 0; i < rawOverrides.length; i++) {
    const o = rawOverrides[i];
    const at = `predicate.overrides[${i}]`;
    if (typeof o?.address !== 'string' || !isPubkey(o.address)) fail(`${at}.address must be a base58 pubkey`);
    if (!OVERRIDE_VERDICTS.has(o?.verdict)) {
      fail(
        `${at}.verdict must be one of ${[...OVERRIDE_VERDICTS].join(', ')}. There is deliberately no ` +
        `"${UNCLAIMABLE}" override: marking an address unpayable by hand is a policy exclusion, it belongs ` +
        'in `entries` with its own justification and evidence, and allowing it here would let a policy ' +
        'exclusion be presented as a correctness one.',
      );
    }
    if (typeof o?.justification !== 'string' || o.justification.trim().length < 20) {
      fail(`${at}.justification must be at least 20 characters — an override reverses a mechanical result`);
    }
    if (typeof o?.evidence !== 'string' || !o.evidence.trim()) {
      fail(`${at}.evidence is required — an account, a transaction signature, or a URL a stranger can check`);
    }
    if (seen.has(o.address)) fail(`${at} duplicates an earlier override for ${o.address}`);
    seen.add(o.address);
    overrides.push({
      address: o.address, verdict: o.verdict,
      justification: o.justification.trim(), evidence: o.evidence.trim(),
    });
  }

  const canonical = {
    id: PREDICATE_SCHEMA,
    // NOT sorted: first opinion wins, so declaration order is meaning.
    rules: [...rules],
    // Sorted: overrides are a set, so file layout must not change the hash.
    overrides: [...overrides].sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0)),
  };

  const byAddress = new Map(overrides.map((o) => [o.address, o]));

  return {
    id: PREDICATE_SCHEMA,
    rules,
    overrides,
    canonical,
    hash: sha256Hex(canonicalJson(canonical)),

    /**
     * Evaluate one owner. Pure, total, and independent of everything except the
     * declaration and the 32 bytes of the address.
     */
    evaluate(owner) {
      const o = byAddress.get(owner);
      if (o) {
        return { verdict: o.verdict, rule: 'operator_override', reason: o.justification };
      }
      for (const id of rules) {
        const r = RULES[id].evaluate(owner);
        if (r === null) continue;
        return { verdict: r.verdict, rule: id, reason: r.reason };
      }
      return { verdict: CLAIMABLE, rule: null, reason: null };
    },
  };
}

/**
 * The empty declaration: a real, hashable statement that no rules were applied.
 *
 * Not a default — `parsePredicate(undefined)` still throws. This exists so that
 * "apply nothing" is something an operator must WRITE, and so the tests have a
 * name for it.
 */
export function nonePredicate() {
  return parsePredicate({ id: PREDICATE_SCHEMA, rules: [], overrides: [] });
}
