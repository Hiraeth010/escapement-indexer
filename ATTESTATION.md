# Canonical record attestation

**A second, independent place to check the Escapement canonical record against.**

This file is published at
[github.com/Hiraeth010/escapement-indexer](https://github.com/Hiraeth010/escapement-indexer/blob/main/ATTESTATION.md).
The copy in the project tree is the source; the published copy is the point.

---

## Why this exists

The canonical record at
`https://site-seven-tan-44.vercel.app/canonical.json` is attested by a chain of
Solana memo transactions, each committing the SHA-256 of the record at the time
it was written. That chain is signed by a single key:

```
25gkHLxJGxUfqtrhrMUQYfBML2MHh6pL4RcxQbVjkotS
```

**One key is a single point of failure, and this file exists because of it.**
Anyone who obtains that key can sign a memo that is correctly linked to the
previous one, from the wallet the site names as authoritative, committing the
hash of a record they control. Nothing about that transaction would look wrong,
because the only authority test the memo chain performs is *did this signer sign
it*.

So the hash is published here as well, under a **different credential** — a
GitHub account, not a Solana keypair. An attacker who steals one does not
thereby hold the other.

**Be precise about what that buys.** This is not a stronger attestation than the
chain. It is a *differently-held* one, and the value is entirely in the
disagreement:

- Both agree → the record is what we say it is.
- **They disagree → do not trust either one.** Assume compromise, and wait for
  the project to explain the discrepancy in public before acting on anything.

This file is not cryptographically signed by us. It is hosted by GitHub under
our account, and its integrity rests on GitHub's access control and on the
commit history being public and append-only. Saying that plainly is more useful
than implying a guarantee it does not have.

---

## The memo chain, in full

Every memo ever landed for this record. Append-only. If a memo exists on chain
that is not listed here, treat it as hostile until we have explained it.

| # | Signature | SHA-256 of `/canonical.json` | Bytes | Slot | Landed |
|---|---|---|---|---|---|
| 1 | `i8s8PjdhgmrN2jnPcc8hx6z37eNshkckQyK5pGpvfxYtLCBbUQM7KBEj8F1TjyJY5BHEuq2U6kyuYaRfMnZaT1W` | `06d2b97abfc5298b2d9e1e6b5932402b5da155f6b8856e7af09e6242bdaf10d5` | 6,210 | 438,247,595 | 2026-08-09 |
| 2 | `EoizfE2h3t5egmd97CBsLfdWcpQkM5r3LvgKfmHNFgncPe6y7YVfpTd8sSSKgxJTpugvi7pvUhcAjzaG4wh5qvc` | `f3aea8abf3c2c421a0b34287ae5c2a62c612f84aaefb8a9f825fc7da9d068586` | 7,563 | 438,263,705 | 2026-08-09 |

**Memo #2 is the current one.** It commits the record being served now, and its
`prev` field names memo #1, so the chain is checkable link by link without
trusting this table.

Memo #1 states, in the transaction itself:

> Not yet minted. Any address claiming to be $ESCAPEMENT before this record
> lists a mint is fraudulent.

That sentence is on chain, timestamped by consensus, and it protects a reader
who never loads our website at all.

### Why there is already a second memo

Memo #2 exists because the record changed on the day memo #1 landed: the apex
domain `escapement.so` was permanently disavowed rather than left described as
something we intended to register.

Worth being precise about what happened in between, because it is the mechanism
rather than an incident. For roughly fifteen thousand slots the served record
matched **no** memo. `verify-canonical.mjs` failed closed for the whole
interval, and abort criterion A8 blocked the launch for its duration. Nobody had
to notice, which is the point: a record change is allowed, an *unattested* one
is not, and the gap is measured by a script rather than remembered by a person.

The cost is real, and it is why record changes should be batched rather than
dribbled out one at a time.

### A record update may be in flight

The canonical record is *expected* to change — most importantly at launch, when
the mint address and creator fee address stop being `null`. During the interval
between a record changing and the next memo landing, **the live record will not
match the newest memo listed above, and that is not evidence of compromise.**

You can check that yourself with the commands below — nothing here asks you to
take our word for it.

> **Corrected 2026-08-09.** This section previously told you to run
> `node launch/verify-canonical.mjs`. **That script is not published anywhere you
> can get it.** It lives in a private repository, so the instruction was
> unrunnable by every single person who might have wanted to use it — a
> verification step in a security document that no reader can execute is worse
> than no step, because it looks like an answer. It was found by an outside
> reviewer trying to follow it. The manual commands below have always worked and
> are now the primary path. Publishing a dependency-free version of the script
> is tracked and not yet done.

**One more thing that script does and the manual check cannot:** it enumerates
the signer's own transaction history and fails if the chain holds a memo this
list omits. Without that, an attacker who controlled the origin could serve an
*older* attested record together with a truncated list, and every hash would
still match. If you are checking by hand, the equivalent is to look at the
signer's account on any explorer and confirm the newest memo it has ever written
is the one at the top of the table above.

---

## Verify it yourself, without trusting us

```
curl -s https://site-seven-tan-44.vercel.app/canonical.json | sha256sum
```

Compare with the newest row above, and with the memo on chain:

```
solana confirm -v <signature> --url https://api.mainnet-beta.solana.com
```

Three sources, none of which requires believing anything we assert: the bytes
being served, this file, and the chain.

---

## If the key is compromised

Written *before* it happens, because a policy published afterwards is worth
nothing.

**What we will do.** State it here first, in this repository, in a commit whose
timestamp and history are public. Then everywhere else. The repository is the
channel that does not depend on the compromised key.

**What we will never do**, and what should therefore be treated as proof of
compromise no matter how convincing it looks:

- Announce a new contract address, a V2 token, or a migration.
- Ask anyone to connect a wallet, claim, verify, unlock, or swap anything.
- Contact you first — in a DM, a reply, an email, or anywhere else.

**What a successor key would look like.** Any replacement signer would be
announced here and in the canonical record *together*, with the new key named in
a commit that predates its first memo. A new key that appears only on chain, or
only on the website, is not ours.

**What you should do.** Nothing. There is no action a real compromise would ever
require you to take urgently, and urgency is itself the tell. If the two
channels disagree, wait.

---

## Provenance

Apache-2.0, same as the rest of this repository. Escapement's canonical record,
threat model and impersonation playbook are published in full, including the
parts that describe this design's weaknesses — of which the single-key memo
signer is the largest, and is recorded as a knowingly accepted risk rather than
an oversight.
