/**
 * memo-chain.mjs — compare what the chain says about the memo chain with what
 * the site says about it.
 *
 * Extracted from verify-canonical.mjs so it can be tested. The check it
 * implements closed a hole in that script's first version, and a check that has
 * never been shown to FAIL is a check nobody should trust — the whole point is
 * the failing case, and the failing case is unreachable end-to-end without
 * standing up a hostile origin.
 *
 * THE ATTACK THIS DEFENDS AGAINST
 *
 * Everything else in verify-canonical.mjs takes the memo INDEX from the site
 * being audited — the list comes from `${site}/canonical-memos.json`, which is
 * explicitly outside the hashed record and says so about itself. The chain was
 * never asked whether a higher-numbered memo existed, and the chain-link check
 * only looks BACKWARDS, which a truncated list satisfies trivially.
 *
 * So an attacker controlling the origin truncates the list to entries 1..k and
 * serves the record bytes that memo #k committed. Hash matches. URL matches.
 * MEMOS entry matches. prev-link matches. CLEAR — on a silently rolled-back
 * record.
 *
 * Post-launch that is the worst outcome available: rolling back restores
 * "Not yet minted. Any address claiming to be $ESCAPEMENT before this record
 * lists a mint is fraudulent", so the project's own canonical record declares
 * the real mint fraudulent while the project's own verifier vouches for the
 * page.
 *
 * The site may not be the authority on what the chain says.
 */

/**
 * @param {{n: number, signature: string}[]} chainMemos  memos decoded from the signer's own history
 * @param {{n: number, signature: string}[]} siteMemos   memos the site publishes
 */
export function compareMemoChains(chainMemos, siteMemos) {
  const chainMax = chainMemos.length ? Math.max(...chainMemos.map((x) => x.n)) : 0;
  const siteMax = siteMemos.length ? Math.max(...siteMemos.map((x) => x.n)) : 0;

  // Present on chain, absent from the published list. Catches truncation from
  // the end (rollback) and holes punched in the middle.
  const missing = chainMemos.filter((x) => !siteMemos.some((m) => m.n === x.n));

  // Published but not on chain: the site inventing history. Different attack,
  // same file, and the hash check would not necessarily catch it because the
  // site also chooses which entry is "newest".
  const fabricated = siteMemos.filter((m) => !chainMemos.some((x) => x.n === m.n));

  // A published entry whose signature disagrees with the chain's for that
  // number. Substitution rather than omission.
  const mismatched = siteMemos.filter((m) => {
    const onChain = chainMemos.find((x) => x.n === m.n);
    return onChain && onChain.signature !== m.signature;
  });

  return {
    chainMax,
    siteMax,
    truncated: chainMax > siteMax,
    missing,
    fabricated,
    mismatched,
    ok: chainMax <= siteMax && missing.length === 0 && fabricated.length === 0 && mismatched.length === 0,
  };
}
