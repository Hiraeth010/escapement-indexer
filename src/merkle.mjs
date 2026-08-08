/**
 * merkle.mjs — the tree, fully pinned (threat model D10).
 *
 * Every choice here is a place where two implementations can silently differ,
 * so every choice is written down rather than left to "the obvious thing":
 *
 *   leaf     = sha256( 0x00 || config_pubkey[32] || claimant[32] || cumulative_u64_le )
 *   internal = sha256( 0x01 || min(l,r) || max(l,r) )                 // sorted pair
 *   ordering = leaves sorted ascending by claimant pubkey BYTES        // not base58 string
 *   odd node = PROMOTED UNCHANGED to the next level                    // not duplicated
 *   empty    = a domain-separated constant, never a hash of nothing
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
import { pubkeyBytes, comparePubkeys } from './base58.mjs';

export const LEAF_PREFIX = 0x00;
export const NODE_PREFIX = 0x01;

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
 * @param {string} configPubkey base58 — the deployment's config PDA. Domain
 *   separation across deployments (C3): a devnet proof must not verify against
 *   mainnet.
 * @param {string} claimant base58
 * @param {bigint} cumulative lamports ever owed to `claimant` as of this root
 */
export function leafHash(configPubkey, claimant, cumulative) {
  return sha256(
    Uint8Array.of(LEAF_PREFIX),
    pubkeyBytes(configPubkey, 'config'),
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
 * @param {{claimant: string, cumulative: bigint}[]} entries — need NOT be sorted;
 *   this function sorts them by claimant bytes, which is the pinned order.
 * @returns {{ root: string, levels: Uint8Array[][], order: string[] }}
 */
export function buildTree(configPubkey, entries) {
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

  const leaves = sorted.map((e) => leafHash(configPubkey, e.claimant, e.cumulative));
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
export function verifyProof({ configPubkey, claimant, cumulative, proof, root }) {
  let cur = leafHash(configPubkey, claimant, cumulative);
  for (const sibHex of proof) {
    const sib = Uint8Array.from(Buffer.from(sibHex, 'hex'));
    if (sib.length !== 32) throw new Error('verifyProof: proof element is not 32 bytes');
    cur = nodeHash(cur, sib);
  }
  return hex(cur) === root;
}
