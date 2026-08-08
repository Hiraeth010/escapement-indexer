# Contributing

**The most valuable contribution anyone can make to this repository is a
disagreement about a root.** That is what the whole thing is for. Everything
else in this document is secondary to it, so it goes first.

---

## Reporting a disagreement in a root

If you recomputed one of our roots and got a different answer, we want the
report. A disagreement is not a nuisance — it is the only evidence that the
falsifiability claim on the tin is real. Two outcomes are both good: either you
found a bug in our indexer, or you found a bug in the reasoning that says
verification means anything. Both are worth more to us than a feature.

### 1. Get the localisation output

Do not open an issue that says "our roots differ". The tool exists to turn that
sentence into a slot number. Run:

```bash
node src/cli.mjs verify \
  --root      <the published root> \
  --artifact  <the published artifact .json> \
  --input-set <the published .input-set.txt> \
  --exclusions <the published exclusions file> \
  --rpc       <YOUR provider, not ours> \
  --concurrency 2 --min-interval-ms 150
```

`verify` walks a fixed chain of comparisons and stops at the **first** one that
breaks, because everything downstream of a mismatch is noise:

| It reported | What that means | What to put in the report |
|---|---|---|
| `params.*` | You and the publisher ran different jobs | Which parameter, both values |
| `predicate_id` / `predicate_hash` | Different unclaimable-address rules or overrides | Output of `exclusions-diff` on the two files |
| `exclusions_hash` | Different policy file | Output of `exclusions-diff` on the two files |
| `input_set_hash` + a line number | **A data disagreement.** Your RPC and theirs report different chain contents | The named slot, both providers' hosts, the two differing lines |
| `ledger[<owner>]` | **An accrual disagreement.** Same inputs, different arithmetic | The owner, both token-slot figures |
| `distribution` | Same ledger, different tree or vault input | `total_owed_cumulative` and `vault_lamports` from both sides |
| `internal` or `internal.domain` | **Our two implementations disagree with each other.** This is a bug in this repository and needs nothing else from you | Both hashes, and the artifact |

An `internal` finding is the highest-priority report we can receive and needs no
further work from you — it means `merkle.mjs` and `verify-merkle.mjs` disagree,
so at least one of them is wrong and no claim about anybody's root is warranted
until it is fixed.

### 2. Say which RPC provider you used

This is not optional context, it is half the finding. Verifying against the same
provider the publisher used mostly proves the publisher can run their own code.
A data disagreement between two independent providers is a much more interesting
object than a disagreement with ourselves, and we cannot tell which one you have
unless you say.

### 3. Include the environment, and expect it not to matter

Paste `node src/cli.mjs env`. The Node version, platform and source hash are
recorded in `manifest_hash`, which is **expected** to differ between verifiers —
it is a record of what produced a root, not part of the root. If a root changes
when only the environment changed, that is itself a serious bug and should be
reported as one.

### 4. Attach your artifact

`verify --out <file>` writes the artifact your run produced. Attach it. The two
artifacts side by side are usually enough to close the question without a
conversation.

### What we cannot act on

- "The numbers look wrong" with no recomputation behind it.
- A disagreement where you used a different slot range, a different exclusion
  file, or omitted `--opening-state` when the publisher chained. `verify` tells
  you when this happened; please read its output before filing.
- A disagreement produced by a non-archival provider that could not serve every
  block in the range. That is a failed run, not a differing root, and the tool
  aborts rather than producing one.

---

## Reporting a wrongly excluded address

The exclusion predicate (`src/predicate.mjs`) removes addresses that cannot
possibly claim. It has **known, documented false exclusions**: multisig vaults,
smart-contract wallets and program treasuries are all off-curve and are all
removed, even though some of them could execute a claim by CPI.

If you were excluded and you can demonstrate that you can sign for the address,
that is a concrete, checkable report and we want it. Include:

- the address, and the artifact and period it was excluded in (it is listed
  under `predicate.excluded` with the rule and the token-slots it cost);
- evidence of a claim path — the program that controls the PDA and the
  instruction that can CPI on its behalf, ideally a transaction signature where
  it has done so.

The remedy is a `predicate.overrides` entry with verdict `claimable`. Note that
overrides are **non-retroactive**, like everything else in the exclusion
document: a fix applies from the period it was announced in, never backwards
into a root that has already been published.

The reverse report — "this address is still being paid and nobody can claim it"
— is also welcome but is much harder to act on, because non-existence of a
private key for an on-curve address is unfalsifiable. See the false-inclusion
list in `predicate.mjs`.

---

## Code contributions

### Ground rules that are not negotiable

1. **Zero runtime dependencies.** `dependencies` is `{}` and stays `{}`. A
   stranger must be able to clone this directory and run `node --test` with no
   install step. Adding a dependency to this package adds it to everyone who
   audits a root.
2. **No signing capability.** This package accepts a public address only. It
   reads no keypair path, constructs no transaction, and has no code path that
   can move a lamport. `grep -r sendTransaction src/` must find nothing.
3. **No floating point on the entitlement path.** `src/nofloat.test.mjs` fails
   the build if any appears in the modules it names. If you need to add a module
   to that path, add it to the list too.
4. **Determinism over convenience.** Anything that could make two honest parties
   compute different roots from the same chain data is a defect, including
   iteration over an unordered map, a wall-clock read, or a value that depends on
   which RPC answered. `src/determinism.test.mjs` is where these are asserted.
5. **The predicate is a pure function of the address.** A rule in
   `src/predicate.mjs` may read the 32 bytes and nothing else — no account state,
   no slot, no clock, no network. This is enforced by a test. The reason is in
   that file's header and is the entire justification for having a predicate
   rather than a list.

### Changing anything that changes a root

Changes to `merkle.mjs`, `accrue.mjs`, `entitle.mjs`, `extract.mjs`,
`predicate.mjs` or `exclusions.mjs` can change published roots. Such a change
needs, in the pull request:

- a statement of **which committed artifacts it invalidates**;
- regenerated artifacts, or an explicit note that they were not regenerated;
- a matching change in `verify-merkle.mjs` if it touched the tree — and the two
  must remain **independently written**. Do not refactor a shared helper out of
  them; the duplication is the feature.

### Adding a predicate rule

A new rule is a new predicate version. It must:

- be a pure function of the address (see above);
- return `undecided` rather than guess, wherever it cannot decide;
- come with its **false exclusions and false inclusions enumerated in prose**,
  in the same style as `off_curve_owner`. A rule whose errors are not written
  down is not finished;
- bump `PREDICATE_SCHEMA`, because the id is refused if this build does not
  implement it, which is what stops an artifact being silently reproduced under
  a different rule set than the one it declares.

### Tests

`node --test "src/*.test.mjs"`. No install step, no runner config, no coverage
threshold to satisfy. Tests are colocated with the module they test and are
excluded from `indexer_source_hash`, deliberately: a verifier who adds a test
must still compute the same root, and if adding a test changed the recorded
source hash we would have built an incentive not to add tests.

### Style

Long explanatory headers are the house style, not clutter. Where a choice could
reasonably have gone the other way — the odd-node promotion, the slot-atomicity
convention, sorted merkle pairs, token-slots over token-seconds — the file says
so and says why. If you change one of those, change the paragraph that argues
for it in the same commit.

### Licence

Contributions are accepted under Apache-2.0 (see `LICENSE`). New source files
carry `// SPDX-License-Identifier: Apache-2.0` on the first line, after the
shebang where there is one.
