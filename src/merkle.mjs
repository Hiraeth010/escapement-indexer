// SPDX-License-Identifier: Apache-2.0
/**
 * merkle.mjs — the tree, fully pinned (threat model D10).
 *
 * Every choice here is a place where two implementations can silently differ,
 * so every choice is written down rather than left to "the obvious thing":
 *
 *   leaf     = sha256( 0x00 || domain[32] || claimant[32] || cumulative_u64_le )
 *   internal = sha256( 0x01 || min(l,r) || max(l,r) )                 // sorted pair
 *   ordering = leaves sorted ascending by claimant pubkey BYTES        // not base58 string
 *   odd node = PROMOTED UNCHANGED to the next level                    // not duplicated
 *   empty    = a domain-separated constant, never a hash of nothing
 *
 * ---------------------------------------------------------------------------
 * THE DOMAIN, AND WHY IT IS NO LONGER JUST THE CONFIG PUBKEY
 * ---------------------------------------------------------------------------
 * The first 32 bytes of a leaf preimage are a DOMAIN SEPARATOR. In v1 that was
 * the deployment's config PDA and nothing else, which separated deployments (a
 * devnet proof cannot verify against mainnet) but left one hole: the exclusion
 * policy entered the root only through its EFFECT. Two different policies that
 * happened to move the same money produced the same root, so the published root
 * was not a commitment to the policy that produced it.
 *
 * v2 closes that by binding the policy commitment into the domain:
 *
 *   domain = sha256( "escapement.merkle/v2:domain" || config_pubkey[32] || policy_binding[32] )
 *
 * where `policy_binding` covers the discretionary exclusion set AND the
 * unclaimable-address predicate (see `exclusions.mjs`). Changing the predicate
 * version, adding an override, or editing the policy prose now changes the root
 * whether or not it changes a payout. The leaf preimage keeps its exact v1
 * shape — same prefix byte, same 73 bytes, same proof structure — so an on-chain
 * verifier stores one extra 32-byte field per epoch and is otherwise unchanged.
 *
 * The 0x00 / 0x01 prefixes are the second-preimage defence (T-09): an internal
 * node can never be presented as a leaf, because their preimages start with
 * different bytes. The lengths already differ (73 vs 65), but incidental
 * separation is not separation.
 *
 * Sorted pairs mean a proof carries no direction bits, which removes an entire
 * class of "the verifier and the prover disagree about left/right" bug at the
 * cost of a slightly larger second-preimage surface — closed by the prefixes.
 *
 * `cumulative` is CUMULATIVE-EVER-OWED, not this period's amount (G3). A leaf is
 * a statement about a total, so a later root can never reduce an entitlement an
 * earlier root granted.
 */

import { sha256 } from './canonical.mjs';
import { pubkeyBytes, comparePubkeys, b58encode } from './base58.mjs';

export const LEAF_PREFIX = 0x00;
export const NODE_PREFIX = 0x01;

export const DOMAIN_TAG = 'escapement.merkle/v2:domain';

/**
 * THE TAG IS AN ARGUMENT, BECAUSE THIS TOOL SHOULD HAVE A USER WHO IS NOT US.
 *
 * A blind product review put this dimension below the launch bar for one
 * structural reason: the census has a nameable user and the indexer does not.
 * Part of why was right here — every leaf this thing can build carries the
 * string "escapement" in its preimage, so anyone running it for their own
 * distribution was committing to our namespace, in their tree, forever. That is
 * not a branding complaint. It is the difference between a general-purpose
 * merkle distributor and a piece of one project's plumbing published as if it
 * were a tool.
 *
 * The tag is now an explicit argument that defaults to ours. Everything else
 * about the leaf is unchanged: same prefix byte, same 73 bytes, same sorted
 * pairs, same proof shape. A third party gets their own domain and an on-chain
 * verifier written against this spec works for them unmodified.
 *
 * Two rules make that safe rather than merely possible:
 *
 *   - The tag is UTF-8 and length-prefixed into the hash. Without the length, a
 *     tag of "a" + a config key beginning 0x62 would hash identically to a tag
 *     of "ab" + a key one byte shorter — domain separation defeated by the very
 *     concatenation meant to provide it. Our own default is unaffected in
 *     meaning but its VALUE changes, which is why the pinned vector in
 *     merkle.test.mjs is recomputed rather than kept.
 *   - The tag must be non-empty and printable ASCII. An empty tag is the same
 *     as no separation at all, and a tag nobody can retype is a tag nobody can
 *     independently verify against.
 *
 * The empty root deliberately stays a single pinned constant, not per-tag: a
 * tree with no leaves commits to no entitlements, so there is nothing for a
 * cross-domain replay to steal. That reasoning is in the README and it holds
 * for a third party exactly as it holds for us.
 *
 * @param {string} configPubkey base58 — the deployment's config PDA (C3)
 * @param {string} policyBindingHex 64 lowercase hex — from `exclusions.mjs`
 * @param {string} [domainTag] the namespace; defaults to Escapement's
 * @returns {string} base58
 */
export function commitmentDomain(configPubkey, policyBindingHex, domainTag = DOMAIN_TAG) {
  if (typeof policyBindingHex !== 'string' || !/^[0-9a-f]{64}$/.test(policyBindingHex)) {
    throw new Error(`commitmentDomain: policy binding must be 64 lowercase hex characters, got ${JSON.stringify(policyBindingHex)}`);
  }
  assertDomainTag(domainTag);
  const tag = Buffer.from(domainTag, 'utf8');
  const len = Buffer.alloc(2);
  len.writeUInt16LE(tag.length);
  return b58encode(sha256(
    len,
    tag,
    pubkeyBytes(configPubkey, 'config'),
    Buffer.from(policyBindingHex, 'hex'),
  ));
}

/** Throws unless the tag is something a stranger could retype exactly. */
export function assertDomainTag(domainTag) {
  if (typeof domainTag !== 'string' || domainTag.length === 0) {
    throw new Error(`domain tag must be a non-empty string, got ${JSON.stringify(domainTag)}`);
  }
  if (domainTag.length > 128) {
    throw new Error(`domain tag must be at most 128 characters, got ${domainTag.length}`);
  }
  if (!/^[\x21-\x7e]+$/.test(domainTag)) {
    throw new Error(
      `domain tag must be printable ASCII with no spaces, got ${JSON.stringify(domainTag)}. `
      + 'A tag carrying whitespace, control characters or anything outside ASCII is a tag that will be '
      + 'transcribed wrong at least once, and a domain nobody can reproduce is a root nobody can check.',
    );
  }
}

/**
 * The root of an empty leaf set.
 *
 * Pinned as a domain-separated constant rather than, say, 32 zero bytes or
 * sha256(""), because both of those are values another system might produce for
 * a different reason. Nothing can hash to this by accident: the preimage is not
 * a leaf preimage (wrong prefix byte) and not a node preimage (wrong length).
 */
export const EMPTY_ROOT = Buffer.from(
  sha256(Buffer.from('escapement.merkle/v1:empty', 'utf8')),
).toString('hex');

/** u64 little-endian encoding of a BigInt. Throws rather than wrapping. */
export function u64le(value) {
  if (typeof value !== 'bigint') throw new Error(`u64le: expected bigint, got ${typeof value}`);
  if (value < 0n) throw new Error(`u64le: negative value ${value}`);
  if (value > 0xffffffffffffffffn) throw new Error(`u64le: ${value} overflows u64`);
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * A leaf hash.
 * @param {string} domain base58 32 bytes — from `commitmentDomain()`. Separates
 *   deployments (C3: a devnet proof must not verify against mainnet) and
 *   policies (a proof under one exclusion policy must not verify under another).
 * @param {string} claimant base58
 * @param {bigint} cumulative lamports ever owed to `claimant` as of this root
 */
export function leafHash(domain, claimant, cumulative) {
  return sha256(
    Uint8Array.of(LEAF_PREFIX),
    pubkeyBytes(domain, 'domain'),
    pubkeyBytes(claimant, 'claimant'),
    u64le(cumulative),
  );
}

function lexLess(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

/** An internal node over a sorted pair. */
export function nodeHash(l, r) {
  const [lo, hi] = lexLess(l, r) ? [l, r] : [r, l];
  return sha256(Uint8Array.of(NODE_PREFIX), lo, hi);
}

const hex = (u8) => Buffer.from(u8).toString('hex');

/**
 * Build a tree.
 *
 * @param {string} domain base58 32 bytes — from `commitmentDomain()`
 * @param {{claimant: string, cumulative: bigint}[]} entries — need NOT be sorted;
 *   this function sorts them by claimant bytes, which is the pinned order.
 * @returns {{ root: string, levels: Uint8Array[][], order: string[] }}
 */
export function buildTree(domain, entries) {
  const sorted = [...entries].sort((a, b) => comparePubkeys(a.claimant, b.claimant));

  for (let i = 1; i < sorted.length; i++) {
    if (comparePubkeys(sorted[i - 1].claimant, sorted[i].claimant) === 0) {
      // D10 says "no ties are possible because the key is unique". If a tie
      // reaches here the aggregation upstream failed to sum per owner, and a
      // silent duplicate leaf is exactly the bug that produces two roots from
      // one dataset. Refuse.
      throw new Error(`buildTree: duplicate claimant ${sorted[i].claimant} — aggregation did not sum per owner`);
    }
  }

  if (sorted.length === 0) {
    return { root: EMPTY_ROOT, levels: [[]], order: [] };
  }

  const leaves = sorted.map((e) => leafHash(domain, e.claimant, e.cumulative));
  const levels = [leaves];

  let cur = leaves;
  while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      // Odd node: PROMOTED UNCHANGED. Duplicating it instead would produce a
      // different, equally valid root — which is precisely why "obvious" is not
      // a specification.
      next.push(i + 1 < cur.length ? nodeHash(cur[i], cur[i + 1]) : cur[i]);
    }
    levels.push(next);
    cur = next;
  }

  return { root: hex(cur[0]), levels, order: sorted.map((e) => e.claimant) };
}

/** The sibling path for the leaf at `index` in the pinned order. */
export function proofFor(tree, index) {
  if (!Number.isInteger(index) || index < 0 || index >= tree.levels[0].length) {
    throw new Error(`proofFor: index ${index} out of range`);
  }
  const proof = [];
  let i = index;
  for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
    const level = tree.levels[lvl];
    const sibling = i % 2 === 0 ? i + 1 : i - 1;
    if (sibling < level.length) proof.push(hex(level[sibling]));
    // else: this node was promoted unchanged; there is no sibling to record.
    i >>= 1;
  }
  return proof;
}

/** Verify a leaf against a root. Mirrors what the on-chain program must do. */
export function verifyProof({ domain, claimant, cumulative, proof, root }) {
  let cur = leafHash(domain, claimant, cumulative);
  for (const sibHex of proof) {
    const sib = Uint8Array.from(Buffer.from(sibHex, 'hex'));
    if (sib.length !== 32) throw new Error('verifyProof: proof element is not 32 bytes');
    cur = nodeHash(cur, sib);
  }
  return hex(cur) === root;
}
