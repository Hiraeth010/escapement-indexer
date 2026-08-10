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

  /**
   * Present on chain, absent from the published list.
   *
   * Compared by (number, SIGNATURE), not by number alone. Comparing by number
   * was a working fail-open, found by a blind review that landed the exploit and
   * got `VERIFY-CANONICAL CLEAR` out of the real script:
   *
   *   The chain holds memo #2. An attacker lands a SECOND memo also numbered #2,
   *   committing the hash of a record naming their mint. Every check passed —
   *   `missing` saw the number 2 in the published list and was satisfied,
   *   `mismatched` resolved the chain entry with `find()` and got the honest one,
   *   chainMax and siteMax were both 2 so nothing looked truncated. The site kept
   *   serving honestly, the script said CLEAR, and the project's own published
   *   doctrine is "if they differ, trust the memo".
   *
   * The identical attack numbered #3 was caught. The blind spot was exactly
   * duplicate numbering, which is also what an accidental double-send produces:
   * a permanently undetectable second attestation.
   *
   * ATTESTATION.md promised this in so many words — "fails if the chain holds a
   * memo this list omits" — and it did not.
   */
  const missing = chainMemos.filter(
    (x) => !siteMemos.some((m) => m.n === x.n && m.signature === x.signature),
  );

  /**
   * Two DIFFERENT on-chain memos carrying the same number.
   *
   * Reported separately from `missing` because the cause and the response
   * differ: a missing memo means the site is hiding something, while a duplicate
   * number means the CHAIN is ambiguous about what memo N is, and no amount of
   * republishing fixes that. The chain is append-only, so once two memos share a
   * number the only honest thing is to say so.
   *
   * Grouped by number so the report can name both signatures. A duplicate that
   * repeats the same signature is not a duplicate — that is one transaction seen
   * twice, which the harvester can legitimately produce.
   */
  const bySignature = (a, b) => (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0);
  const duplicated = [...new Set(chainMemos.map((x) => x.n))]
    .map((n) => {
      const entries = chainMemos.filter((x) => x.n === n);
      const signatures = [...new Set(entries.map((e) => e.signature))].sort();
      return { n, signatures, entries: entries.slice().sort(bySignature) };
    })
    .filter((g) => g.signatures.length > 1)
    .sort((a, b) => a.n - b.n);

  // Published but not on chain: the site inventing history. Different attack,
  // same file, and the hash check would not necessarily catch it because the
  // site also chooses which entry is "newest".
  const fabricated = siteMemos.filter((m) => !chainMemos.some((x) => x.n === m.n));

  /**
   * A published entry whose signature matches NO on-chain memo for that number.
   *
   * `find()` was wrong here for the same reason it was wrong above: with two
   * chain memos sharing a number it returned whichever came first, so a
   * published entry could be judged against an arbitrary one of them. `some()`
   * asks the question that was actually meant — is this published signature one
   * the chain really carries for this number.
   */
  const mismatched = siteMemos.filter((m) => {
    const forNumber = chainMemos.filter((x) => x.n === m.n);
    return forNumber.length > 0 && !forNumber.some((x) => x.signature === m.signature);
  });

  return {
    chainMax,
    siteMax,
    truncated: chainMax > siteMax,
    missing,
    fabricated,
    mismatched,
    duplicated,
    ok: chainMax <= siteMax && missing.length === 0 && fabricated.length === 0
      && mismatched.length === 0 && duplicated.length === 0,
  };
}
