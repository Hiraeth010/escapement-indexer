# escapement-indexer

A deterministic indexer that computes **entitlement by token-slots held** from public Solana
block history, and commits it as a merkle root a third party can recompute byte-for-byte.

Zero runtime dependencies. Node 22+. Plain ESM JavaScript. Apache-2.0. Read-only: this package
contains no signing capability, constructs no transaction, and accepts a public address only —
never a keypair path, never a private key.

```bash
git clone <repo> && cd indexer
node --test "src/*.test.mjs"     # 113 tests, no install step, no dependencies

node src/cli.mjs index  --mint <pubkey> --from <slot> --to <slot> --exclusions <file>
node src/cli.mjs verify --root <hex>    --artifact <file> --exclusions <file> --rpc <a different provider>
```

**If you recompute one of our roots and get a different answer, that is the most valuable thing
anyone can contribute to this repository.** [`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to
report it so that it is actionable in one pass.

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
domain   = sha256( "escapement.merkle/v2:domain" || config_pubkey || policy_binding )
leaf     = sha256( 0x00 || domain || claimant || cumulative_u64_le )
internal = sha256( 0x01 || min(l,r) || max(l,r) )
order    = ascending by claimant pubkey BYTES (not by the base58 string)
odd node = promoted unchanged to the next level (not duplicated)
empty    = sha256("escapement.merkle/v1:empty"), a pinned constant
```

`cumulative` is *everything ever owed to this address as of this root*, not this period's amount,
so a later root can never reduce an entitlement an earlier root granted.

`policy_binding` is `sha256("escapement.policy/v1" || exclusions_hash || predicate_hash)` — the
one 32-byte value standing for everything about *who gets paid* that is not chain data. It is
inside the domain so that changing the policy changes the root **even when it changes nobody's
payout**. Before that, a publisher could swap the declared policy for a different one with the same
effect and the root would not notice.

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

## Reproducing a root, end to end

Nothing below needs anything from us except the three files in `artifacts/` and `exclusions/`,
which are committed here.

```bash
# 1. Clone, and run the tests. There is no install step.
git clone <repo> && cd indexer
node --version                        # must be >= 22
node --test "src/*.test.mjs"          # expect: pass 113, fail 0

# 2. Recompute the demonstration root from a provider we did not use.
node src/cli.mjs verify \
  --root f2a915906003a2822050077c6a7cdb994009265a8959f383ffd4ca48c61d2787 \
  --artifact  artifacts/demo.F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump.437990500-437990520.json \
  --input-set artifacts/demo.F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump.437990500-437990520.input-set.txt \
  --exclusions exclusions/demo-2026-08-08.json \
  --rpc https://solana-rpc.publicnode.com \
  --concurrency 2 --min-interval-ms 150

# expect:
#   AGREE
#     [agree] merkle_root
#       root matches: f2a915906003a2822050077c6a7cdb994009265a8959f383ffd4ca48c61d2787
```

Use a **different RPC provider** than the publisher used. Against the same provider, verification
mostly proves that the publisher can run their own code. The run above costs about 99 MB of
`getBlock` responses and a few seconds; see *Cost*.

To produce a root rather than check one, `index` takes the same arguments plus the pot:

```bash
node src/cli.mjs index \
  --mint F1XdReoHL3GweeCG4sgoZGAdsUNt8sda8n5EE2TNpump \
  --from 437990500 --to 437990520 \
  --exclusions exclusions/demo-2026-08-08.json \
  --config 11111111111111111111111111111111 \
  --vault-lamports 1000000000 --vault-source hypothetical \
  --rpc https://api.mainnet-beta.solana.com --concurrency 2 --min-interval-ms 150
```

If the roots differ, `verify` walks a fixed chain of comparisons and reports the **first** one that
breaks, because everything downstream of a mismatch is noise:

1. **parameters** — range, mint, config pubkey, predicate id and hash, exclusion-set hash,
   opening-state hash;
2. **input set** — line by line, naming the first slot you disagree about;
3. **ledger** — the first owners whose token-slots differ, which distinguishes an *accrual*
   disagreement from a *data* disagreement;
4. **distribution** — vault amount, prior carry, tree construction.

---

## The three commitments, and why they are three

| Field | Covers | Must two verifiers agree? |
|---|---|---|
| `merkle_root` | chain data + policy binding (exclusion set **and** predicate) + config pubkey + vault amount | **Yes, byte-identical** |
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

## Who does not get paid, and by which of the two mechanisms

An address can fail to be paid for two completely different reasons. Conflating them is how a
distribution stops being checkable, so they are declared, evaluated and reported separately.

### 1. Policy — discretion, fenced

`--exclusions <file>` is **required and has no default.** Its `entries` array is the discretionary
half: addresses a human decided are not beneficial holders. There is no built-in address list, no
heuristic, and no inference of any kind at runtime.

This is where a dishonest publisher would hide manipulation, because it looks like housekeeping. So:

- every entry carries a **scope** (`owner` or `token_account`), a **kind**, a **justification** of
  at least 20 characters, and **on-chain evidence** — all validated, all refused if missing;
- the file's canonical hash goes into the policy binding, which is inside the merkle domain, so
  changing the file changes the root, visibly, whether or not it changes a payout;
- `effective_from_slot` may not be **after** the period it is applied to, which mechanises D9's
  "announced before the epoch they apply to, never after";
- `escapement exclusions-diff before.json after.json` prints what changed and, in words, who starts
  and stops getting paid as a result;
- the artifact reports how many token-slots each exclusion actually removed, so a no-op entry and a
  load-bearing one are distinguishable.

An owner-scoped exclusion is evaluated **per span, against the owner in force at that time**, so it
follows a `SetAuthority` rather than sticking to an account.

**The code does not decide the four open cases.** `/spec` §4.5 records the bonding curve, the AMM
pool with burned LP, exchange omnibus accounts and lending collateral as NOT DECIDED as *policy*
questions. This code takes no position on any of them; the exclusion file must list them in
`undecided` or exclude them explicitly, and anything neither excluded nor declared is surfaced as a
warning in the artifact.

### 2. The predicate — correctness, mechanical

The other half is `predicate`, also required and also never defaulted. It is not a policy choice.
It answers one question: **can any claimant for this address possibly exist?** An address with no
possible claimant is not a claimant, and paying one strands the money rather than distributing it.

`escapement.unclaimable/v1` has exactly one rule:

> **`off_curve_owner`** — the token account's owner is not a valid ed25519 point, so no keypair
> exists that can sign for it. Every program-derived address is off-curve by construction.

The rule is a **pure function of the 32 bytes of the address**. No account state, no slot, no
clock, no network — which is what makes it reproducible: two strangers derive the same exclusion
set without coordinating, offline, from the ledger the artifact already publishes. That constraint
is enforced by a test, and it is what eliminated every other candidate rule:

- A rule that reads account state ("the owner is owned by program X", "the pool's LP supply is
  zero") must read it **as of a pinned slot**, or two people running a week apart get different
  answers. Public RPC cannot serve historical account state at all — the same wall *Known limits 1*
  hits. Reading *current* state instead makes the exclusion set a function of when you ran.
- A rule keyed on a program id ("owner is a PDA of the pump.fun AMM") is reproducible, but somebody
  has to write down which programs are on the list. **That is a list, and a list is the thing being
  replaced.** A program list is shorter and more defensible than an address list; it is not
  not-a-list, and this README is not going to pretend otherwise.

#### What the rule gets wrong

Off-curve means no *single key* signs. It does not mean nobody benefits, and it does not even mean
nobody can sign — a PDA can be signed for by its owning program via `invoke_signed`. So:

**False exclusions** (removed, but arguably should be paid):

| | |
|---|---|
| **Smart-contract wallets and multisigs** | A Squads vault is a PDA, and the Squads program can issue an arbitrary CPI on its behalf, so it *could* execute a claim. This rule removes it anyway. This is the most serious error in the design and the reason `predicate.overrides` exists. |
| **Program treasuries of real projects** | A DAO whose treasury is a PDA of its own program has a beneficiary and possibly a claim path. |
| **Lending collateral** | The collateral sits in the lending program's PDA; the depositor is a real person holding a receipt. Nothing is *stranded* by removing it — the lending program will not CPI into a distributor it has never heard of — but a beneficiary exists and is not paid. |

**False inclusions** (paid, but nobody can claim):

| | |
|---|---|
| **On-curve burn sinks** | `1nc1nerator111…` and vanity dead addresses are on the curve. Non-existence of a private key for an on-curve address is unfalsifiable, so no predicate can ever cover this. |
| **Lost keys** | Same reason. Unknowable. |
| **Exchange omnibus accounts** | On-curve, and the exchange can sign, so this rule pays them. Whether it *should* is a policy question — `/spec` §4.5 case three — and it stays in the discretionary file where policy questions belong. |

The rule is therefore broader than the truth in one direction and narrower in the other. It is not
the truth; it is the best decidable approximation of it, and its errors are enumerated rather than
discovered later. `src/predicate.mjs` carries the full argument.

#### The escape hatch, and its direction

`predicate.overrides` accepts exactly two verdicts:

- **`claimable`** — a reinstatement. "This off-curve address can claim; pay it." Needs a
  justification and on-chain evidence, is hashed into the root, and is non-retroactive.
- **`undecided`** — "we know this address is contentious and we have not decided." A run that
  touches an address marked undecided **refuses**. It does not include it, does not exclude it,
  does not warn: it aborts and writes no artifact, naming every such address at once.

There is deliberately **no `unclaimable` override**. Hand-marking an address as unpayable is a
policy exclusion; that mechanism already exists in `entries`, and duplicating it here would let a
publisher launder a policy exclusion as a correctness one. Overrides only ever add somebody back.

#### Visibility

The predicate declaration is inside the exclusion document, so its hash is bound into the merkle
domain. Changing the id, the rule list, or a single override changes the root, even if it changes
nobody's payout — asserted in `src/predicate.test.mjs`. The artifact additionally prints every
address the predicate removed, with the rule and the token-slots it cost, and raises a warning
stating what fraction of the entitlement it took. A wrongly-excluded party can find themselves in
it and object; see `CONTRIBUTING.md`.

---

## What verification actually proves

`verify` is a separate entry point, but it is not an independent implementation. Read this before
trusting a green result.

**Shared with the producer:** `blocks.mjs` (fetching, skipped-slot accounting, chain continuity),
`extract.mjs` (decoding a block into balance events), `accrue.mjs` (the integral), `entitle.mjs`
(the pro-rata split), `predicate.mjs` and `exclusions.mjs` (who is a claimant at all).
**A bug in any of those is present on both sides and passes verification.**

**Not shared:** the merkle layer. `verify-merkle.mjs` is a second, deliberately unrelated
implementation of D10 and of the domain derivation — different data structures, different sorting,
different u64 encoding, its own base58 encoder, no shared helper except `sha256`. `verify`
cross-checks the two and refuses to report on the publisher at all if they disagree with each
other.

So a green `AGREE` proves:

- the published root is a function of the claimed slot range and no other range;
- the exclusion set and the predicate used were the ones published, byte for byte;
- the chain data behind it is what an independent RPC provider also reports, including which slots
  were skipped and which transactions were in them;
- the merkle construction is agreed by two independently written implementations.

It does **not** prove that the accrual model is implemented correctly at all, and it does **not**
prove the predicate is the right rule — only that the same rule was applied on both sides. For the
first you need a second implementation of the model by somebody who is not us, and there is not
one. Two implementations by one author from one paragraph are worth something and are not worth
what independent implementations are worth.

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
mint, a transfer-fee extension, or a confidential-transfer balance. A confidential balance in
particular is not a number this code can read, and a transfer-fee extension changes what a
recipient's post-balance means relative to the sender's delta. Escapement's own token is plain SPL,
so this is not on the critical path — but **do not assume it works**.

**4. Cost — this is the limit that decides who can check us.** The demonstration run below cost
**98.6 MB and 6.6 s of RPC for 20 mainnet slots**: **4.93 MB per slot**, measured, not estimated.
That extrapolates to roughly **44 GB per hour of mainnet** at a nominal 400 ms slot, and **about
2.1 TB for a 432,000-slot epoch**. Two consequences a stranger should hear before starting:

- an epoch-length range **needs an archival provider**, patience, and a plan for the bandwidth.
  Public endpoints will rate-limit you long before you finish;
- combined with limit 1, verifying a late period means chaining from the mint's first slot, so the
  true cost scales with the *age of the token*, not with the length of the period.

This is why §2.1 of the threat model says almost nobody will recompute a root, and shipping this
code does not change that. It changes who *can*.

**5. No `getBlock` availability guarantee.** Public endpoints prune. If your provider cannot serve
a slot in the range, the run aborts — correctly — and you need an archival node.

**6. The predicate's known errors.** See *What the rule gets wrong* above. They are not edge cases
that might exist; multisig vaults and program treasuries are common, and this rule removes them.

**7. One author, one implementation of the model.** Nobody outside this project has run this code.
There is no independent implementation of the accrual model. Treat "reproducible by a third party"
as unmet until somebody outside the project has done it.

---

## The demonstration run

Real, against mainnet public RPC, over a real mint. Committed in `artifacts/` so a reader can
re-run it and get the same bytes.

The mint is **an unaffiliated third-party pump.fun token**, chosen because it was active in the
slot window. Escapement has no token of its own.

> **Correction (2026-08-08, review finding B9).** An earlier version of this line read "nothing of ours is
> deployed on any cluster." That was false: the vault program
> `BBLABjcv74dbcoc3gSsKkSW5PyswweTJJChQxoc2VVbF` is deployed on **devnet** (with 184 landed program
> transactions against the pre-fix build). The security-fix binary is not yet redeployed — that is gated on
> deploy SOL — so the currently deployed devnet bytes are the pre-fix build; the fixed program's evidence is
> the reproducible litesvm run in `onchain/tests-litesvm/`.

| | |
|---|---|
| Range | `[437990500, 437990520)` — 20 slots, all finalized |
| Slots | 20 produced, 0 skipped, continuity verified |
| Transactions touching the mint | 979, of which 329 failed (recorded in the input set, no state change) |
| Owners entitled | 29 |
| Token-slots | 201,511,759,341,094 entitled; 1,278,925,237,485,687 removed by the predicate; 0 by policy |
| `predicate_hash` | `54b978f8890fbfdbcbe9aa88dece607411fc5818bc27fa097f5d6f9fcae7da20` |
| `exclusions_hash` | `76d1e943c2ce7033ddb4ad99cf546815468ec837693c0a0ba00f662e95a818a8` |
| `policy_binding` | `dec037c9237352c1b91648e7c18de880598af99b542f1e819b2c75e980d1dd93` |
| `merkle_domain` | `8uEHp52XsyDMvkqcQMLSSDKHpKPNLKjnfheXi9qaynAV` |
| `input_set_hash` | `fd5020ab57139049d1309e47470f18fe996805e5dd08b86f75e7ef6445dc906d` |
| `ledger_hash` | `6dcb4ad2446040d50680aceebeff6de15249f3f485ec1f0973bde2f31bd3ddf1` |
| `merkle_root` | `f2a915906003a2822050077c6a7cdb994009265a8959f383ffd4ca48c61d2787` |
| Distribution | 999,999,986 lamports distributed, **14 lamports retained** as truncation remainder (bound: n−1 = 28) |
| Cost | 22 RPC calls, 0 retries, **98.6 MB**, 6.6 s |

`--config 11111111111111111111111111111111` is the all-zero pubkey, used as an obvious placeholder
because no config PDA exists — no program is deployed. `--vault-lamports 1000000000` is declared
`hypothetical` and the artifact records it as such; it is an input, not a measurement.

All three artifacts were produced from commit `43d091c` with a clean `src/`
(`indexer_git_dirty: false` in each), so a reader checking out that commit runs the same bytes.

### The finding that motivated the predicate, and what it looks like now

With the predicate **off** (`"rules": []`), a single address takes **84.99%** of the distribution:
`HgpbxqtHN8uuntiPsmpMGzJUhYLFfpC1H24M5phdYomL`, whose owning program is
`pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` — the pump.fun AMM. Its LP tokens are burned, so
that balance can never be redeemed by anyone.

With the predicate **on**, that address is off the ed25519 curve, so no keypair can sign for it, so
it is not a claimant. Two addresses are removed:

| Owner | Owning program | Token-slots removed | Share it would have taken |
|---|---|---|---|
| `HgpbxqtHN8uuntiPsmpMGzJUhYLFfpC1H24M5phdYomL` | `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` (pump.fun AMM) | 1,258,188,404,039,547 | 84.99% |
| `AiJncJexFGbpTa3y8jkuzVLXUMuAyf88VZYPmUqz42ue` | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` (Meteora DLMM) | 20,736,833,446,140 | 1.40% |

**86.39%** of the entitlement (8,638 basis points) went to addresses that cannot claim. What is
left is a distribution among 29 real holders:

| Rank | Owner | Share | Payout (of 1 SOL) |
|---|---|---|---|
| 1 | `6Jtc91o51YXUzezsC8ZLaqYYfh3aPWJQBvfzwYea7jUo` | **45.94%** | 459,361,887 lamports |
| 2 | `D93hBBFx39pEBxdAR3AzRsiZsN2J1pJk9W6PuXxADw5v` | 25.37% | |
| 3 | `CpZLVv63mUSRruto9RtciDumV3GAahUJrbDffRokTvUU` | 10.10% | |
| 4 | `7Eow5GYXX6oDVhHBhCYc26mDmuqcHyZK9jzLTFZC3wqi` | 5.29% | |
| 5 | `kEFiAX3jo5NmemysQov342TZ9mGh6yp92GDRjhA8XDf` | 4.93% | |

The top holder's share moves from **84.99% to 45.94%**. Note what that is and is not: the
concentration did not go away, it was *unmasked*. A distribution that looked like "one pool and a
long tail" is really "one large real holder and a shorter tail". The 45.94% is a live wallet that
can claim, so it is a fact about the token rather than a defect in the mechanism — but anybody
reading the 84.99% figure as "the problem is the pool" should read this line too.

The two removed addresses are the observable half of `/spec` §4.5 cases one and two. **The predicate
does not answer §4.5 as a policy question.** It removes addresses that could not claim under any
answer. Exchange omnibus accounts are on-curve and are therefore *paid* by this run, which is
exactly the arguable outcome that case is about.

**Cross-provider check.** The same root was recomputed from a different provider
(`solana-rpc.publicnode.com`, an independent operator) and agreed — the log is committed at
`artifacts/verify-second-provider.log`:

```
AGREE
  [agree] merkle_root
    root matches: f2a915906003a2822050077c6a7cdb994009265a8959f383ffd4ca48c61d2787
```

That is the two-provider reproducibility test (AT-03), green, on real data. It is green on a
20-slot range, not on an epoch, and the difference matters.

**Chaining check, on real data.** The same range split in half and chained through
`--opening-state`:

| Range | Token-slots entitled |
|---|---|
| `[437990500, 437990510)` | 56,721,822,865,548 |
| `[437990510, 437990520)` | 144,789,936,475,546 |
| **Sum** | **201,511,759,341,094** |
| Single run `[437990500, 437990520)` | **201,511,759,341,094** |

Exact. Both halves are committed in `artifacts/`.

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

3. **§4.5 — the whole section is now partly out of date.** See *Which sentences of §4.5 must
   change* below; it is the largest gap and is listed separately.

4. **§5.1 — the leaf.** The site says `leaf = sha256(0x00 ‖ config_pubkey ‖ claimant ‖
   cumulative_u64_le)`. The first 32 bytes are no longer the bare config pubkey: they are
   `sha256("escapement.merkle/v2:domain" ‖ config_pubkey ‖ policy_binding)`. The preimage keeps its
   shape and its length; what changed is that the exclusion policy and the predicate are now inside
   the root by construction rather than only by effect. The site's two stated properties — config
   inside the leaf, cumulative amount — both remain true.

5. **§5.1 — "the empty tree is a pinned constant".** Still true, and now worth a caveat: the empty
   root is *not* policy-separated, because a tree with no leaves commits to no entitlements and
   there is nothing to replay.

6. **§5.3 — "how the indexer treats chain reorganisations and where it puts the finality boundary
   … is not chosen".** It is now chosen and implemented: `finalized` only, ranges past the finalized
   tip refused, block continuity verified by blockhash and parentSlot chaining. The site understates
   what exists.

7. **§4.4 — "It rolls into the next period".** The code **retains** the remainder in the vault; it
   does not implement any roll-forward. Whether the remainder enters the next period's pot is an
   operator decision about what is passed as `--vault-lamports`, not a guarantee the code makes.
   (The `n − 1` bound itself is correct and is now asserted at runtime over 5,000 randomised
   distributions.)

8. **§7 — "the indexer is public so anyone can recompute what the next root should be".** Two
   problems. The indexer is not published yet (it is now licensed and ready to be). And recomputing
   a period requires the balance table at its start, which means chaining from the mint's first
   slot — see *Known limits* 1. "Recompute the period" understates the work by the age of the token.

9. **§5.3 constraint set — "the indexer is public and reproducible by a third party".** Half done.
   It is reproducible across two providers on a 20-slot range on one machine. It has never been run
   by a third party, on a different machine, and there is no independent implementation of the
   accrual model. The constraint should be read as unmet until somebody outside the project has run
   it.

### Which sentences of §4.5 must change

The predicate changed behaviour that §4.5 describes. Listed precisely, because "update the section"
is not a reviewable instruction.

**Must change — the section states things that are now false:**

1. **The demonstration figure and its caption.** "Share of one real distribution taken by one
   address nobody can claim for — **84.9876%**" is now the figure for a run with the predicate
   *disabled*. The current run's headline is 84.99% removed as unclaimable, top *paid* holder
   45.94%. The caption's "Second place took 6.25%, third 3.45%" are pre-exclusion figures and are
   now 25.37% and 10.10% of the paid distribution. The whole figure block needs re-cutting against
   the new artifact, or relabelling as "with no predicate applied".
2. **"Of 999,999,987 lamports distributed across 31 owners, a single address took … lamports."**
   Now 999,999,986 lamports across 29 owners, and the single address takes nothing.
3. **"Two options exist and both cost something. Pay every balance … Or exclude those addresses,
   and you need an exclusion set — which is discretion."** This sentence states a false dichotomy
   and it is the one the predicate exists to break. There is a third option: exclude only addresses
   that *cannot possibly claim*, by a published rule evaluated from the address itself, which is
   correctness rather than discretion. The paragraph needs rewriting around that.
4. **"We have not chosen."** For the mechanical part, we now have. The four §4.5 rows remain
   undecided *as policy*, but the code now removes off-curve owners as unclaimable, and the site
   must say so rather than implying nothing is applied.
5. **"its hash is committed with the root, so changing it changes the root."** This was aspirational
   when written — a policy change only moved the root if it moved money. It is now literally true,
   via `policy_binding` inside the merkle domain. The sentence can stay, but it should say *why* it
   is true rather than leaving it as an assertion.
6. **The `Treatment` column, rows one and two.** "The bonding curve … Nobody can sign for it" and
   "The automated market maker … nobody can ever redeem that balance" both read **NOT DECIDED**.
   The clause "nobody can sign for it" is now *exactly the predicate's rule*, and both rows are in
   fact removed mechanically. They should read something like "REMOVED AS UNCLAIMABLE by
   `escapement.unclaimable/v1`; the residual policy question — what happens to the value — remains
   open", not "NOT DECIDED".

**Must be added — §4.5 does not currently describe behaviour the code now has:**

7. The predicate itself: its id, its one rule, that it is required and never defaulted, and that it
   is bound into the root.
8. Its **false exclusions**, in the section's own voice. Multisig vaults and program treasuries are
   removed and can arguably claim. A section whose subject is "balances that are not beneficial
   holders" cannot omit that the mechanism also removes some that are.
9. The `undecided` verdict and that it **halts the run**. That is a governance property and belongs
   on the page.

**May stay unchanged:** rows three (exchange omnibus) and four (lending collateral) are correctly
still NOT DECIDED. Omnibus accounts are on-curve and are paid; lending collateral is off-curve and
is removed, but the *policy* question of whether the depositor should have been paid is untouched
by the predicate and remains open. Row five (ordinary wallets) is unchanged.

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
  exclusions.mjs    the discretionary surface, fenced; and the policy binding
  predicate.mjs     the mechanical surface: who can possibly claim. No address list
  curve.mjs         ed25519 on-curve test — the one fact the predicate rests on
  merkle.mjs        D10, fully pinned
  verify-merkle.mjs a second implementation of the same, and of the domain
  canonical.mjs     one serialisation; refuses floats and undefined
  base58.mjs        no dependencies
  version.mjs       source hash, environment manifest
  *.test.mjs        113 tests, colocated, `node --test`
exclusions/         policy documents. Versioned, hashed, diffable
artifacts/          the demonstration run, committed:
                      *.json            the artifact
                      *.input-set.txt   the D5 commitment, in diffable form
                      verify-second-provider.log  the cross-provider check, as it ran
LICENSE, NOTICE     Apache-2.0
CONTRIBUTING.md     how to report a disagreement in a root
```

---

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Apache-2.0 rather than MIT deliberately: this code defines a distribution mechanism that other
people are expected to reimplement in order to check it, and Section 3's express patent grant is
the part that matters for that. A permissive licence without one would leave a reimplementer worse
off than the original author.
