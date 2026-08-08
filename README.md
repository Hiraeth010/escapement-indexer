# escapement-indexer

A deterministic indexer that computes **entitlement by token-slots held** from public Solana
block history, and commits it as a merkle root a third party can recompute byte-for-byte.

Zero runtime dependencies. Node 22+. Plain ESM JavaScript. Read-only: this package contains no
signing capability, constructs no transaction, and accepts a public address only — never a keypair
path, never a private key.

```
node src/cli.mjs index  --mint <pubkey> --from <slot> --to <slot> --exclusions <file>
node src/cli.mjs verify --root <hex>    --artifact <file> --exclusions <file> --rpc <a different provider>
```

---

## Why this exists

Escapement's entire trust model is one sentence: *the indexer is open source and you can recompute
our root*. Until this directory existed, there was no code behind that sentence — the load-bearing
claim was the one thing a reader could not check. This is the code.

It does not make the numbers trustworthy by itself. What it does is make them **falsifiable**: if
our root and yours differ, one command tells you whether we disagree about the chain data or about
the arithmetic, and at which slot. See *What verification actually proves* below for the limits,
which are real and are stated before the features.

---

## What it computes

For a mint and a half-open slot range `[from, to)`, for every address:

```
token_slots(addr) = Σ over slots s in [from, to) of balance(addr, s)
```

and then, given a pot:

```
payout(addr) = floor( vault_lamports × token_slots(addr) / Σ token_slots )
```

Everything is `BigInt`. There is no floating-point arithmetic anywhere on that path, and
`src/nofloat.test.mjs` fails the build if any appears.

The commitment is a merkle root over **cumulative** leaves:

```
leaf     = sha256( 0x00 || config_pubkey || claimant || cumulative_u64_le )
internal = sha256( 0x01 || min(l,r) || max(l,r) )
order    = ascending by claimant pubkey BYTES (not by the base58 string)
odd node = promoted unchanged to the next level (not duplicated)
empty    = sha256("escapement.merkle/v1:empty"), a pinned constant
```

`cumulative` is *everything ever owed to this address as of this root*, not this period's amount,
so a later root can never reduce an entitlement an earlier root granted.

### Slots, not seconds

The accumulator is **token-slots**. `getBlockTime` is a validator-reported estimate: it is not
monotonic, not part of consensus, and not guaranteed identical across providers. Integrating a
balance against it would make the answer depend on which RPC you asked. A slot is a consensus fact.

"Token-seconds" is a human rendering of the same quantity at an assumed slot duration. It is never
the quantity itself. **The published spec currently says token-seconds is the unit; it is not.**
See *Where this disagrees with the published spec*.

### What counts as a balance change

Absolute post-transaction balances and owners are read from each transaction's
`meta.preTokenBalances` / `meta.postTokenBalances`. That gives three things without decoding a
single instruction:

- **absolute** balances, so a missed transaction under-counts one account rather than corrupting
  every subsequent delta;
- **`SetAuthority(AccountOwner)` for free** — a transaction that changes an account's owner reports
  a different `owner` in its post record, so balance is attributed to the owner *at each slot*
  rather than back-attributed to whoever holds the account now (threat model D8);
- **CPI-nested transfers for free** — a transfer four levels deep inside a swap moves the balance
  identically, and a balance record does not care how it got there.

Account creation, `closeAccount`, multiple token accounts per owner (summed **per owner**), and
mint/burn inside the range are all handled and tested.

A slot is atomic: every change in slot *S* takes effect at the start of `[S, S+1)`. Sub-slot
transaction ordering therefore cannot affect the integral at all. The alternative convention
(effective at `S+1`) is equally defensible and produces a different number, which is exactly why it
is pinned in writing rather than left to "the obvious thing".

---

## Reproducing a root

```bash
git clone <repo> && cd indexer
node --test "src/*.test.mjs"          # 79 tests, no install step, no dependencies

node src/cli.mjs verify \
  --root 795643f063b5b6c7e0d185fe1ea405a2762d6309f4e86430d9d3ed2b72fad991 \
  --artifact artifacts/demo.F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump.437990500-437990520.json \
  --input-set artifacts/demo.F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump.437990500-437990520.input-set.txt \
  --exclusions exclusions/demo-2026-08-08.json \
  --rpc https://solana-rpc.publicnode.com \
  --concurrency 2 --min-interval-ms 150
```

Use a **different RPC provider** than the publisher used. Against the same provider, verification
mostly proves that the publisher can run their own code.

If the roots differ, `verify` walks a fixed chain of comparisons and reports the **first** one that
breaks, because everything downstream of a mismatch is noise:

1. **parameters** — range, mint, config pubkey, exclusion-set hash, opening-state hash;
2. **input set** — line by line, naming the first slot you disagree about;
3. **ledger** — the first owners whose token-slots differ, which distinguishes an *accrual*
   disagreement from a *data* disagreement;
4. **distribution** — vault amount, prior carry, tree construction.

---

## The three commitments, and why they are three

| Field | Covers | Must two verifiers agree? |
|---|---|---|
| `merkle_root` | chain data + exclusion set + config pubkey + vault amount | **Yes, byte-identical** |
| `input_set_hash` | the ordered list of slots and transactions actually consumed | **Yes** |
| `manifest_hash` | the above *plus* Node version, platform, indexer source hash | No — it records the environment |

Folding the toolchain into the root would be the obvious reading of D12 and it would be wrong: a
Node upgrade would then change the root for identical chain data, destroying the property the whole
design exists for. The threat model's G6 lists them as separate committed fields precisely so both
can be true at once.

`input_set_hash` is the highest-value item here and almost nobody ships it. It is written next to
the artifact as a plain line-oriented text file:

```
escapement-input-set v1
mint F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump
range 437990500 437990520
commitment finalized
anchor-previous-blockhash 8YiPxM4sWsM6XZQ8frE6sHieXiMp2AAoe4UErpFNTq53
slot 437990500 block APfsRUQQCWi3FbJPK6D12eNw166umv2W2gNPam5LCCWi parent 437990499 prev 8YiPxM4s…
tx 437990500 185 oNzteW8eFekLiveWap8nMRzetuZBGTE5cspz47gDK8De… err
tx 437990500 186 59AFmUwWDYeHpkBK9wAkqY9UcQRxuVtokEv4CMsGQVSh… ok
…
slot 437990517 skipped          ← a slot that produced no block, stated as such
```

(The `…` above are elisions for the README; the real file carries full signatures on one line each,
and the demonstration range happens to contain no skipped slots.)

Two parties who disagree run `diff` and get a slot number. Without it, "our numbers differ" is an
unfalsifiable argument.

---

## Skipped slots vs fetch failures

This is the trap the design is built around. A skipped slot is a fact about Solana. A failed
`getBlock` is a fact about your RPC. **Conflating them produces a wrong root that reproduces
perfectly** — every honest party running the same broken code against the same flaky endpoint gets
the same wrong answer, and reproducibility testing is structurally blind to it.

So:

1. `getBlocks(from, to-1, {commitment: 'finalized'})` returns the authoritative set of slots that
   produced a block. **That, and only that, decides "skipped".**
2. Every slot in that set must be fetched successfully. A failure after retries **aborts the run**.
   There is no code path that downgrades a failure to a skip, and a failed run writes no artifact.
3. The `blockhash` / `parentSlot` chain is verified across the whole range: each block's
   `previousBlockhash` must equal the previous produced block's `blockhash`. **A slot wrongly
   reported as skipped breaks this chain**, so step 1 is not merely believed — it is checked
   against an independent property of the data.

Point 3 is the part worth having. It converts "we asked the node which slots were skipped and
trusted the answer" into "the blocks we fetched form an unbroken chain, so nothing is missing
between them". `src/determinism.test.mjs` asserts all three, including that an RPC which hides a
produced slot from `getBlocks` is caught rather than believed.

Finality is pinned to `finalized`, never `confirmed`, never `processed`, and a range extending past
the finalized tip is refused — a root over a slot that can still be reorged out is a commitment to
a chain that may not exist.

---

## The exclusion set

`--exclusions <file>` is **required and has no default.** There is no built-in address list, no
heuristic, no "looks like a pool" detector, and no inference of any kind at runtime. A run cannot
happen unless a human has written the policy down in a file.

This is the one place in the system with discretion in it, and the threat model names it as where a
dishonest publisher would hide manipulation, because it looks like housekeeping. So:

- every entry carries a **scope** (`owner` or `token_account`), a **kind**, a **justification** of
  at least 20 characters, and **on-chain evidence** — all validated, all refused if missing;
- the file's canonical hash is committed in the artifact and in `manifest_hash`, so changing it
  changes the root, visibly;
- `effective_from_slot` may not be **after** the period it is applied to, which mechanises D9's
  "announced before the epoch they apply to, never after";
- `escapement exclusions-diff before.json after.json` prints what changed and, in words, who starts
  and stops getting paid as a result;
- the artifact reports how many token-slots each exclusion actually removed, so a no-op entry and a
  load-bearing one are distinguishable.

**The code does not decide the four open cases.** `/spec` §4.5 records the bonding curve, the AMM
pool with burned LP, exchange omnibus accounts and lending collateral as NOT DECIDED. This code
takes no position on any of them; the exclusion file must list them in `undecided` or exclude them
explicitly, and anything neither excluded nor declared is surfaced as a warning in the artifact.

An owner-scoped exclusion is evaluated **per span, against the owner in force at that time**, so it
follows a `SetAuthority` rather than sticking to an account.

---

## What verification actually proves

`verify` is a separate entry point, but it is not an independent implementation. Read this before
trusting a green result.

**Shared with the producer:** `blocks.mjs` (fetching, skipped-slot accounting, chain continuity),
`extract.mjs` (decoding a block into balance events), `accrue.mjs` (the integral), `entitle.mjs`
(the pro-rata split). **A bug in any of those is present on both sides and passes verification.**

**Not shared:** the merkle layer. `verify-merkle.mjs` is a second, deliberately unrelated
implementation of D10 — different data structures, different sorting, different u64 encoding, no
shared helper except `sha256` and base58 decoding. `verify` cross-checks the two and refuses to
report on the publisher at all if they disagree with each other.

So a green `AGREE` proves:

- the published root is a function of the claimed slot range and no other range;
- the exclusion set used was the one published, byte for byte;
- the chain data behind it is what an independent RPC provider also reports, including which slots
  were skipped and which transactions were in them;
- the merkle construction is agreed by two independently written implementations.

It does **not** prove that the accrual model is implemented correctly at all. For that you need a
second implementation of the model by somebody who is not us, and there is not one. Two
implementations by one author from one paragraph are worth something and are not worth what
independent implementations are worth.

---

## Known limits

**1. The opening-state problem.** Integrating balance over `[from, to)` requires the balance table
*at* `from`. Block iteration only reveals an account when something touches it, so an address that
held tokens before `from` and never transacts inside the range is invisible and accrues zero. There
is no way to ask a public RPC for historical account state. The two honest answers are:

- start at the mint's first slot, where the opening state is provably empty; or
- **chain**: pass `--opening-state <previous artifact>`, whose `closing_state_hash` is committed so
  the chain is auditable link by link. Adjacency is enforced; a gap is refused.

Every run that does neither carries a loud warning in the artifact. The practical consequence is
that **independently verifying period *N* means chaining from the mint's first slot**, not indexing
period *N* alone. That cost is real and is not currently described on the site.

**2. It trusts the validator's token-balance accounting.** We read `pre/postTokenBalances` rather
than re-deriving balances from instruction decoding. That accounting is what every explorer and
wallet already displays and is produced by the same software that produced consensus — but it is a
dependency, and a second implementation that decodes instructions would be a genuinely independent
check.

**3. Token-2022 is untested here.** The extraction is extension-agnostic in principle (it reads
balances, not account layouts), but nothing in this repository has been run against a Token-2022
mint, a transfer-fee extension, or a confidential-transfer balance. Escapement's own token is plain
SPL, so this is not on the critical path — but do not assume it works.

**4. Cost.** Blocks are large. The demonstration run below cost **98.6 MB and 6.6 s of RPC for 20
mainnet slots**, which extrapolates to roughly **5 MB per slot** — about 20 GB per hour of mainnet.
An epoch-length range needs an archival provider and patience. This is the reason §2.1 of the threat
model says almost nobody will recompute a root, and shipping this code does not change that.

**5. No `getBlock` availability guarantee.** Public endpoints prune. If your provider cannot serve a
slot in the range, the run aborts — correctly — and you need an archival node.

**6. Not published, not licensed.** `package.json` says `UNLICENSED` and `private: true`. Both must
change before this can be a public repository, and the licence is a decision nobody has made.

---

## The demonstration run

Real, against mainnet public RPC, over a real mint. Committed in `artifacts/` so a reader can
re-run it and get the same bytes.

The mint is **an unaffiliated third-party pump.fun token**, chosen because it was active in the
slot window. Escapement has no token; nothing of ours is deployed on any cluster.

```bash
node src/cli.mjs index \
  --mint F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump \
  --from 437990500 --to 437990520 \
  --exclusions exclusions/demo-2026-08-08.json \
  --config 11111111111111111111111111111111 \
  --vault-lamports 1000000000 --vault-source hypothetical \
  --rpc https://api.mainnet-beta.solana.com --concurrency 2 --min-interval-ms 150
```

| | |
|---|---|
| Range | `[437990500, 437990520)` — 20 slots, all finalized |
| Slots | 20 produced, 0 skipped, continuity verified |
| Transactions touching the mint | 979, of which 329 failed (recorded in the input set, no state change) |
| Owners entitled | 31 |
| Token-slots | 1,480,436,996,826,781 entitled, 0 excluded |
| `input_set_hash` | `fd5020ab57139049d1309e47470f18fe996805e5dd08b86f75e7ef6445dc906d` |
| `ledger_hash` | `7533a0a82f676bc93a4f852772a57c65c13ac7c5c5f5d406c5c07353331c9cf5` |
| `merkle_root` | `795643f063b5b6c7e0d185fe1ea405a2762d6309f4e86430d9d3ed2b72fad991` |
| Distribution | 999,999,987 lamports distributed, **13 lamports retained** as truncation remainder (bound: n−1 = 30) |
| Cost | 22 RPC calls, 0 retries, **98.6 MB**, 6.6 s |

`--config 11111111111111111111111111111111` is the all-zero pubkey, used as an obvious placeholder
because no config PDA exists — no program is deployed. `--vault-lamports 1000000000` is declared
`hypothetical` and the artifact records it as such; it is an input, not a measurement.

**Cross-provider check.** The same root was recomputed from a different provider
(`solana-rpc.publicnode.com`, an independent operator) and agreed:

```
AGREE
  [agree] merkle_root
    root matches: 795643f063b5b6c7e0d185fe1ea405a2762d6309f4e86430d9d3ed2b72fad991
```

That is the two-provider reproducibility test (AT-03), green, on real data. It is green on a
20-slot range, not on an epoch, and the difference matters.

**Chaining check, on real data.** The same range split in half and chained through
`--opening-state`:

| Range | Token-slots |
|---|---|
| `[437990500, 437990510)` | 697,032,592,055,371 |
| `[437990510, 437990520)` | 783,404,404,771,410 |
| **Sum** | **1,480,436,996,826,781** |
| Single run `[437990500, 437990520)` | **1,480,436,996,826,781** |

Exact. Both halves are committed in `artifacts/`.

**And the finding that matters most.** With an exclusion set that excludes nobody, a single address
takes **84.98%** of the distribution: `HgpbxqtHN8uuntiPsmpMGzJUhYLFfpC1H24M5phdYomL`, whose owning
program is `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` — the pump.fun AMM. That is `/spec` §4.5
case two, the AMM pool with burned LP tokens, measured rather than hypothesised. On this mint, over
this window, the unresolved exclusion question is not a footnote; it is 85% of the money.

---

## Where this disagrees with the published spec

The site is not allowed to describe behaviour the code does not have. These are the places where it
currently does. **The code is correct; the site needs to change.**

1. **§4.1, §4.3 — "token-seconds".** The unit of account is **token-slots**. Block time is a
   validator estimate, non-monotonic and provider-dependent; integrating against it would make the
   root depend on which RPC you asked. Token-seconds is a display conversion at an assumed slot
   duration, not the accrued quantity, and the two do not stay proportional across periods with
   different skip rates.

2. **§4.1 — "computed from public transfer history".** Transfers alone are not sufficient. The
   computation also consumes account creation, account closure, **owner/authority changes**, and
   mint/burn events. An indexer that read only transfers would produce a wrong answer, and D8 says
   so explicitly.

3. **§5.1 — "a merkle root over (address, amount) leaves".** The leaf is
   `sha256(0x00 || config_pubkey || address || cumulative_u64_le)`. Two substantive differences:
   the deployment's config pubkey is inside the leaf (so a devnet proof cannot verify against
   mainnet), and the amount is **cumulative ever owed**, not the period's amount.

4. **§5.3 — "how the indexer treats chain reorganisations and where it puts the finality boundary
   … is not chosen".** It is now chosen and implemented: `finalized` only, ranges past the finalized
   tip refused, block continuity verified by blockhash and parentSlot chaining. The site understates
   what exists.

5. **§4.4 — "It rolls into the next period".** The code **retains** the remainder in the vault; it
   does not implement any roll-forward. Whether the remainder enters the next period's pot is an
   operator decision about what is passed as `--vault-lamports`, not a guarantee the code makes.
   (The `n − 1` bound itself is correct and is now asserted at runtime over 5,000 randomised
   distributions.)

6. **§7 — "the indexer is public so anyone can recompute what the next root should be".** Two
   problems. The indexer is not public yet. And recomputing a period requires the balance table at
   its start, which means chaining from the mint's first slot — see *Known limits* 1. "Recompute
   the period" understates the work by the age of the token.

7. **§4.5 — "a changed set produces a different root that anybody recomputing will notice".** True
   only if the exclusion **file** is published, not merely its hash. A hash detects that something
   changed; it does not let anyone audit what. The file must be in the public repository, which is
   what `exclusions/` is for.

8. **§5.3 constraint set — "the indexer is public and reproducible by a third party".** Half done.
   It is reproducible across two providers on a 20-slot range on one machine. It has never been run
   by a third party, on a different machine, and there is no independent implementation of the
   accrual model. The constraint should be read as unmet until somebody outside the project has run
   it.

---

## Layout

```
src/
  cli.mjs           the two entry points and the small tools around them
  run.mjs           the pipeline: fetch → extract → accrue → exclude → distribute → commit
  verify.mjs        the separate verifier and the disagreement localiser
  blocks.mjs        block iteration; skipped vs failed; continuity proof
  rpc.mjs           read-only JSON-RPC; four methods; no signing capability
  extract.mjs       one block → mint-relevant balance events
  accrue.mjs        the integral. BigInt only
  entitle.mjs       floor pro-rata, with the rounding argument and its assertions
  exclusions.mjs    the discretionary surface, fenced
  merkle.mjs        D10, fully pinned
  verify-merkle.mjs a second implementation of the same
  canonical.mjs     one serialisation; refuses floats and undefined
  base58.mjs        no dependencies
  version.mjs       source hash, environment manifest
  *.test.mjs        79 tests, colocated, `node --test`
exclusions/         exclusion sets. Versioned, hashed, diffable
artifacts/          the demonstration run, committed
```
