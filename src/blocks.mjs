// SPDX-License-Identifier: Apache-2.0
/**
 * blocks.mjs — iterate BLOCKS, not addresses (D3), and account for every slot
 * positively (D4).
 *
 * ---------------------------------------------------------------------------
 * WHY NOT `getSignaturesForAddress`
 * ---------------------------------------------------------------------------
 * It caps at 1,000 results, paginates by signature, and different providers
 * prune history to different depths. Two honest verifiers on two providers can
 * therefore legitimately receive different transaction sets for the same
 * address and the same range, and neither can tell. Block iteration has no such
 * degree of freedom: a block either is or is not part of the finalized chain.
 *
 * ---------------------------------------------------------------------------
 * THE THING THIS FILE EXISTS TO PREVENT
 * ---------------------------------------------------------------------------
 * A skipped slot is a fact about Solana. A failed `getBlock` is a fact about
 * your RPC. Conflating them produces a WRONG root that REPRODUCES PERFECTLY —
 * every honest party who runs the same broken code against the same flaky
 * endpoint gets the same wrong answer, and reproducibility testing is
 * structurally blind to it. So:
 *
 *   1. `getBlocks(from, to-1)` returns the authoritative set of slots that
 *      produced a finalized block. That, and only that, decides "skipped".
 *   2. Every slot in that set MUST be fetched successfully. A failure after
 *      retries aborts the run. There is no code path that downgrades a failure
 *      to a skip.
 *   3. The blockhash chain is verified across the whole range: each produced
 *      block's `previousBlockhash` must equal the previous produced block's
 *      `blockhash`. A slot wrongly reported as skipped BREAKS THIS CHAIN, so
 *      step 1 is not merely trusted — it is checked against a second,
 *      independent property of the data.
 *
 * Point 3 is the part worth having. It converts "we asked the node which slots
 * were skipped and believed it" into "the blocks we fetched form an unbroken
 * chain, so nothing is missing between them".
 */

import { RpcError } from './rpc.mjs';

export class UnresolvedSlotError extends Error {
  constructor(slot, cause) {
    super(
      `slot ${slot} could not be resolved: the node listed it as producing a finalized block, ` +
      `but fetching it failed (${cause}). This is a fact about the RPC, not about the chain, ` +
      `and treating it as a skipped slot would silently drop real transfers. Aborting.`,
    );
    this.name = 'UnresolvedSlotError';
    this.slot = slot;
    this.cause = cause;
  }
}

export class ChainBreakError extends Error {
  constructor(slot, expected, got, prevSlot) {
    super(
      `blockhash chain broken at slot ${slot}: previousBlockhash ${got} does not match ` +
      `slot ${prevSlot}'s blockhash ${expected}. Either a slot that produced a block was reported ` +
      `as skipped, or the responses mix two forks. Aborting.`,
    );
    this.name = 'ChainBreakError';
    this.slot = slot;
  }
}

/**
 * Fetch every finalized block in [from, to) and prove nothing is missing.
 *
 * @param {object} args
 * @param {import('./rpc.mjs').Rpc} args.rpc
 * @param {number} args.from inclusive
 * @param {number} args.to   exclusive
 * @param {number} [args.concurrency]
 * @param {(p: object) => void} [args.onProgress]
 * @param {(slot: number, block: object) => any} [args.transform]
 *        Called once per block, in whatever order the blocks arrive. Its return
 *        value is retained; the raw block is released immediately afterwards.
 *        Mainnet blocks run to several megabytes each, so retaining them all
 *        makes the memory cost proportional to the range — which is exactly the
 *        thing that stops a verifier from checking a real epoch. Extraction is a
 *        pure function of one block, so streaming it changes no result. The
 *        determinism tests cover this by running with concurrency 1 and 6 and
 *        asserting identical roots.
 * @returns {Promise<{
 *   produced: number[], skipped: number[],
 *   blocks: Map<number, {blockhash: string, previousBlockhash: string, parentSlot: number, value: any}>,
 *   anchorPreviousBlockhash: string|null,
 *   finalizedTip: number,
 * }>}
 */
export async function fetchRange({ rpc, from, to, concurrency = 4, onProgress = null, transform = null }) {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to)) throw new Error('fetchRange: slots must be integers');
  if (to <= from) throw new Error(`fetchRange: empty or inverted range [${from}, ${to})`);

  // D1 + reorg exclusion: the whole range must already be finalized. A root over
  // slots that are merely confirmed can be invalidated by a reorg, and then the
  // "reproducible" root reproduces a fork that no longer exists.
  const finalizedTip = await rpc.getFinalizedSlot();
  if (typeof finalizedTip !== 'number') throw new Error('fetchRange: getSlot(finalized) did not return a slot');
  if (to - 1 > finalizedTip) {
    throw new Error(
      `fetchRange: range [${from}, ${to}) extends past the finalized tip (${finalizedTip}). ` +
      `Only finalized slots may be indexed — a confirmed slot can still be reorged out, ` +
      `which would make this root a commitment to a chain that does not exist.`,
    );
  }

  const producedList = await rpc.getBlocks(from, to - 1);
  if (!Array.isArray(producedList)) throw new Error('fetchRange: getBlocks did not return an array');
  const produced = [...producedList].sort((a, b) => a - b);
  for (const s of produced) {
    if (s < from || s >= to) throw new Error(`fetchRange: getBlocks returned slot ${s} outside [${from}, ${to})`);
  }
  const producedSet = new Set(produced);

  const skipped = [];
  for (let s = from; s < to; s++) if (!producedSet.has(s)) skipped.push(s);

  const blocks = new Map();
  let done = 0;
  let cursor = 0;

  const worker = async () => {
    for (;;) {
      const i = cursor++;
      if (i >= produced.length) return;
      const slot = produced[i];
      let block;
      try {
        block = await rpc.getBlock(slot);
      } catch (err) {
        // The ONLY place a fetch failure is handled, and it does not continue.
        throw new UnresolvedSlotError(slot, err instanceof RpcError ? `${err.code ?? ''} ${err.message}`.trim() : err.message);
      }
      if (block === null || block === undefined) {
        throw new UnresolvedSlotError(slot, 'getBlock returned null for a slot getBlocks listed as produced');
      }
      if (typeof block.blockhash !== 'string' || typeof block.previousBlockhash !== 'string') {
        throw new Error(`slot ${slot}: block response has no blockhash/previousBlockhash; cannot verify continuity`);
      }
      blocks.set(slot, {
        blockhash: block.blockhash,
        previousBlockhash: block.previousBlockhash,
        parentSlot: block.parentSlot,
        value: transform ? transform(slot, block) : block,
      });
      done++;
      if (onProgress) onProgress({ done, total: produced.length, slot });
    }
  };

  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, produced.length)) }, worker));

  // Independent check that the "skipped" set is real (see header, point 3).
  let anchorPreviousBlockhash = null;
  for (let i = 0; i < produced.length; i++) {
    const slot = produced[i];
    const b = blocks.get(slot);
    if (i === 0) {
      anchorPreviousBlockhash = b.previousBlockhash;
      continue;
    }
    const prevSlot = produced[i - 1];
    const prev = blocks.get(prevSlot);
    if (b.previousBlockhash !== prev.blockhash) {
      throw new ChainBreakError(slot, prev.blockhash, b.previousBlockhash, prevSlot);
    }
    if (b.parentSlot !== prevSlot) {
      throw new ChainBreakError(slot, `parentSlot ${prevSlot}`, `parentSlot ${b.parentSlot}`, prevSlot);
    }
  }

  return { produced, skipped, blocks, anchorPreviousBlockhash, finalizedTip };
}
