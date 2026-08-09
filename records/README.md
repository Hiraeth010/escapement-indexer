# Archived canonical records

Every version of `/canonical.json` that an on-chain memo has ever committed to,
byte for byte.

## Why this exists

The memo chain publishes a SHA-256 for each version of the canonical record. That
proves what the record said and when — but only to someone who has the bytes. A
hash without its input is not auditable by a third party; they can see the
commitment and can never reproduce it.

Memo #1's bytes were archived nowhere. The first link of an append-only chain was
permanently uncheckable by anyone outside the project, which was found by an
outside security reviewer rather than by us.

They are here now, recovered from git commit `ef6ca1a` and confirmed against the
hash the chain already carried. The route that serves this record is
`force-static` with pinned serialisation — no clock, no chain read, no
request-time input — so the bytes are a pure function of the committed source,
which is what made recovery possible. That property is worth preserving for its
own sake.

## The records

| memo | file | bytes | sha256 | on-chain signature |
|---|---|---|---|---|
| 1 | `canonical-memo-1.json` | 6,210 | `06d2b97abfc5298b2d9e1e6b5932402b5da155f6b8856e7af09e6242bdaf10d5` | `i8s8PjdhgmrN2jnPcc8hx6z37eNshkckQyK5pGpvfxYtLCBbUQM7KBEj8F1TjyJY5BHEuq2U6kyuYaRfMnZaT1W` |
| 2 | `canonical-memo-2.json` | 7,563 | `f3aea8abf3c2c421a0b34287ae5c2a62c612f84aaefb8a9f825fc7da9d068586` | `EoizfE2h3t5egmd97CBsLfdWcpQkM5r3LvgKfmHNFgncPe6y7YVfpTd8sSSKgxJTpugvi7pvUhcAjzaG4wh5qvc` |

## Check any of them yourself

```
sha256sum canonical-memo-1.json
solana confirm -v <signature> --url https://api.mainnet-beta.solana.com
```

The memo text carries `sha256=<digest>`. It should equal the file's digest. No
part of this asks you to trust the table above — the table is only an index.

## What changed between them

Memo #1 described `escapement.so` as the apex domain this project intended to
use. Memo #2 disavows it permanently: it is not ours, will never be ours, and if
it ever resolves it is an impersonator. Publishing an unregistered domain as your
canonical home advertises a cheap impersonation asset that your own documentation
vouches for.

That is also why archiving matters. Without these bytes, the only public evidence
of what memo #1 said would be our own description of it.

## Rule going forward

A record change lands a memo, and the superseded bytes are archived here in the
same change. `verify/verify-canonical.mjs` fails closed if the served record has
drifted from the newest memo, and abort criterion A8 blocks the launch while it
does.
