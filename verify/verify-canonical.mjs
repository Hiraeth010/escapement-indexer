#!/usr/bin/env node
// verify-canonical.mjs — does the record we are serving still match the record
// the chain attests, and has the pre-launch window actually elapsed?
//
//   node launch/verify-canonical.mjs \
//     --site https://site-seven-tan-44.vercel.app \
//     --rpc  https://api.mainnet-beta.solana.com \
//     --expect-signer 25gkHLxJGxUfqtrhrMUQYfBML2MHh6pL4RcxQbVjkotS
//
// Offline-hostile by design: it reads the live site and the live chain, because
// the two things it compares are only meaningful as observations.
//
// ---------------------------------------------------------------------------
// Why this file exists
//
// The anti-impersonation design tells users, in published copy at
// site/src/app/canonical/page.tsx: "If they differ, this site is compromised —
// trust the memo." Until now, nothing in this repository ever performed that
// comparison. preflight.mjs §G checked that /canonical.json returns 200 and
// printed "NOT CHECKED HERE" for the hash.
//
// That is not merely an untested path. It is a SCHEDULED FALSE ALARM. At launch
// the canonical record MUST change: `$ESCAPEMENT mint` and `Creator fee address`
// are both null today and both become real addresses the moment the token
// exists. The instant that deploys, every user who follows our own published
// verification gets MISMATCH — and we have told them that means the site is
// compromised. The users who follow the security guidance most carefully would
// be the first to be told, by us, that we had been breached, at the exact hour
// impersonators are most active.
//
// So the rule this file enforces is not "the hash matches". It is:
//
//     THE RECORD AND THE NEWEST MEMO MOVE TOGETHER, OR THE LAUNCH STOPS.
//
// Changing the record is allowed. Changing it without landing the memo that
// attests the new bytes is not.
// ---------------------------------------------------------------------------

import { createHash } from 'node:crypto';
import { compareMemoChains } from './memo-chain.mjs';

/**
 * NO DEPENDENCIES, DELIBERATELY.
 *
 * This file used to import @solana/web3.js. That was fine here and useless
 * everywhere else: `ATTESTATION.md` — the public, second-channel artifact whose
 * whole job is to be checkable by a stranger — told readers to run this script,
 * and it lives in a private repository. A verification instruction nobody can
 * execute is worse than none, because it looks like an answer.
 *
 * Publishing it into `escapement-indexer` was blocked by exactly one thing: that
 * repository has ZERO npm dependencies, which is a property worth more than the
 * convenience of a library. So the library went instead. Everything below uses
 * Node's built-in `fetch` against public JSON-RPC, and base58 is decoded by the
 * function already in this file.
 *
 * One implementation, publishable as-is. Not a second copy that can drift from
 * this one — that is the mistake `binding.mjs` was extracted to end and that
 * `census/rpc.mjs` was moved to avoid.
 */
async function rpcCall(method, params, url) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC ${method}: HTTP ${res.status}`);
  const json = await res.json();
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
  return json.result;
}

/** base58 shape check. Not a curve check — this only rejects impossible strings. */
const isBase58Address = (s) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);

const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

/**
 * How long the record must be attested before launch.
 *
 * CHANGED 2026-08-09 from 14 days to 0, by founder decision, and the reasoning
 * is recorded because the number was never the point.
 *
 * What the window was FOR: making an impersonator self-refuting. Any address
 * claiming to be $ESCAPEMENT before the mint exists is contradicted by a
 * consensus-timestamped record saying "not yet minted".
 *
 * That property comes from the memo EXISTING BEFORE THE MINT, not from any
 * particular amount of elapsed time. Memo #1 landed at slot 438,247,595. Every
 * impersonator from that moment on is already refuted. Fourteen days added no
 * cryptographic strength whatsoever.
 *
 * What it did add was time for the record to be FOUND — indexed, archived,
 * seen by someone before the token existed. That is worth something to a
 * project with an audience. This project has no X account, no community and no
 * traffic, so fourteen days of a record nobody reads buys close to nothing, and
 * the honest thing is to say so rather than keep a number because it sounds
 * prudent.
 *
 * WHAT IS STILL ENFORCED, and it is the part that matters: memo #1 must have
 * landed, the served record must hash to what the newest memo committed, the
 * chain must show no memo the site is hiding, and the signer must be the wallet
 * the site publishes. A launch still cannot happen against an unattested or
 * drifted record. Only the waiting is gone.
 */
const PRE_LAUNCH_DAYS = Number(process.env.ESCAPEMENT_PRE_LAUNCH_DAYS ?? 0);

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? d : process.argv[i + 1]; };
const flag = (n) => process.argv.includes(`--${n}`);

const refuse = (...lines) => {
  for (const l of lines) console.log(`REFUSE  ${l}`);
  console.log('\nRefused. Nothing was checked; do not proceed.');
  process.exit(2);
};

function requiredStr(n, why) {
  const v = arg(n);
  if (v === undefined || v === null || v.startsWith('--')) refuse(`--${n} was not supplied`, why);
  return v;
}

const site = requiredStr('site',
  'the origin actually being served. There is no default: a defaulted origin lets this gate pass '
  + 'against a deployment nobody is looking at, which is the fail-open HM-6 already records for preflight.').replace(/\/$/, '');
const rpc = arg('rpc', 'https://api.mainnet-beta.solana.com');
const expectSigner = requiredStr('expect-signer',
  'the wallet the site publishes as authoritative. A memo signed by anyone else attests nothing, and '
  + 'checking the hash without checking who committed it would accept an impersonator\'s memo.');
if (!isBase58Address(expectSigner)) {
  refuse(`--expect-signer=${expectSigner} is not a base58 Solana address`,
    'A malformed signer would make every comparison below vacuously false, which is a different'
    + ' failure from "the memo was signed by someone else" and must not be reported as one.');
}

let fail = 0;
const check = (ok, label, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  — ${detail}` : ''}`);
  if (!ok) fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// ---------------------------------------------------------------------------
section('the record being served');

const recUrl = `${site}/canonical.json`;
let recBytes;
try {
  const r = await fetch(recUrl, { headers: { accept: 'application/json' } });
  if (!r.ok) refuse(`${recUrl} returned ${r.status}`, 'The canonical record must be reachable to be verified.');
  recBytes = Buffer.from(await r.arrayBuffer());
} catch (e) {
  refuse(`could not fetch ${recUrl} — ${e.message}`);
}
const liveHash = createHash('sha256').update(recBytes).digest('hex');
console.log(`        ${recUrl}`);
console.log(`        ${recBytes.length} bytes, sha256 ${liveHash}`);

// ---------------------------------------------------------------------------
section('the memo chain the site publishes');

const memoUrl = `${site}/canonical-memos.json`;
let memos;
try {
  const r = await fetch(memoUrl, { headers: { accept: 'application/json' } });
  if (!r.ok) refuse(`${memoUrl} returned ${r.status}`);
  memos = await r.json();
} catch (e) {
  refuse(`could not fetch ${memoUrl} — ${e.message}`);
}
const list = Array.isArray(memos) ? memos : (memos.memos ?? []);

// @enforces A8 canonical-record-has-at-least-one-memo
check(list.length > 0, 'the memo chain is not empty',
  list.length ? `${list.length} memo(s)` : 'no memo has ever been landed, so the record is not attested by anything');
if (!list.length) { console.log('\nVERIFY-CANONICAL FAILED.'); process.exit(1); }

const newest = list.reduce((a, b) => (b.n > a.n ? b : a));
console.log(`        newest is memo #${newest.n}, ${newest.signature}`);

// ---------------------------------------------------------------------------
section('what the chain actually says');

let tx;
try {
  tx = await rpcCall('getTransaction', [newest.signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed' }], rpc);
} catch (e) {
  refuse(`getTransaction(${newest.signature}) failed — ${e.message}`);
}

// @enforces A8 newest-memo-is-on-chain-and-succeeded
check(tx !== null && tx.meta?.err === null, 'the newest memo is a landed, successful transaction',
  tx === null ? 'not found on this cluster' : `err=${JSON.stringify(tx.meta?.err)} slot=${tx.slot}`);
if (!tx) { console.log('\nVERIFY-CANONICAL FAILED.'); process.exit(1); }

const msg = tx.transaction.message;
const keys = (msg.staticAccountKeys ?? msg.accountKeys ?? []).map((k) => (k.toBase58 ? k.toBase58() : String(k)));

// @enforces A8 newest-memo-was-signed-by-the-published-wallet
check(keys[0] === expectSigner, 'the memo was signed by the wallet the site publishes',
  `fee payer ${keys[0]}`);

// Pull the memo text out of the instruction data rather than out of the logs:
// logs are truncated by some RPCs, instruction data is not.
let memoText = null;
for (const ix of msg.compiledInstructions ?? msg.instructions ?? []) {
  const pid = keys[ix.programIdIndex];
  if (pid !== MEMO_PROGRAM) continue;
  const data = ix.data;
  memoText = Buffer.from(typeof data === 'string' ? bs58Decode(data) : data).toString('utf8');
}
// Minimal base58 decode — avoids adding a dependency to a launch-critical script.
function bs58Decode(s) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const ch of s) { const i = A.indexOf(ch); if (i < 0) throw new Error(`bad base58 char ${ch}`); n = n * 58n + BigInt(i); }
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 255n)); n >>= 8n; }
  for (const ch of s) { if (ch === '1') out.unshift(0); else break; }
  return Uint8Array.from(out);
}

// @enforces A8 newest-memo-carries-a-parseable-payload
check(memoText !== null, 'the transaction invokes the memo program with a readable payload',
  memoText === null ? 'no memo instruction found' : `${Buffer.byteLength(memoText)} bytes`);
if (memoText === null) { console.log('\nVERIFY-CANONICAL FAILED.'); process.exit(1); }

const field = (k) => (memoText.match(new RegExp(`^${k}=(.+)$`, 'm')) ?? [])[1] ?? null;
const committedHash = field('sha256');
const committedUrl = field('url');
const committedPrev = field('prev');
const committedDate = field('date');

console.log(`        committed sha256 ${committedHash}`);
console.log(`        committed url    ${committedUrl}`);

// ---------------------------------------------------------------------------
section('does the chain know about memos the site is not showing');

// ADDED 2026-08-09, closing a hole in the first version of this file.
//
// Everything above takes the memo INDEX from the site being audited: the list
// comes from `${site}/canonical-memos.json`, and `newest` is the highest entry
// in that list. The chain was never asked whether a HIGHER-numbered memo exists,
// and the link check below only looks BACKWARDS — which a truncated list
// satisfies trivially.
//
// So an attacker who controls the origin (Vercel account, deploy token, CI —
// exactly the threat this design exists for) could truncate the list to entries
// 1..k, serve the record bytes memo #k committed, and pass every single check.
// VERIFY-CANONICAL CLEAR, on a silently rolled-back record.
//
// Post-launch that is the worst outcome available. Rolling back to the
// pre-launch record restores the sentence "Not yet minted. Any address claiming
// to be $ESCAPEMENT before this record lists a mint is fraudulent" — so the
// project's own canonical record declares the genuine mint fraudulent, and the
// project's own verifier confirms the page is authentic.
//
// The fix is to derive the chain's view independently: enumerate the signer's
// transactions, decode every memo it has ever written, and fail if the chain
// knows a memo the site is not showing. The site may not be the authority on
// what the chain says.
/**
 * THIS HARVESTER MUST FAIL CLOSED, and its first version did not.
 *
 * It did `if (!t) continue` — a null getTransaction was FATAL for the
 * site-nominated newest memo and SILENTLY SKIPPED for chain-discovered ones.
 * That is backwards: the chain-discovered set is the entire trust anchor. Any
 * memo the RPC declined to return simply vanished from `chainMemos`, `chainMax`
 * dropped, `truncated` went false, and the script printed
 * "PASS — the site is showing every memo the chain has" having failed to look.
 *
 * An attacker does not need to influence the RPC for this to bite; an ordinary
 * 429 under load is enough, and the busiest moment is launch day.
 *
 * `rpcCall` was also unguarded here — a rate-limit threw an unhandled rejection
 * and a Node stack trace, which verify-launch's own comment names as the thing
 * an operator reads as broken tooling and routes around.
 *
 * And there was no pagination: `limit: 1000` is a page, not the history. A
 * signer with more than a thousand transactions would silently lose its oldest
 * memos — which is the direction that hides a rollback.
 */
const chainMemos = [];
const sigs = [];
let before;
for (let page = 0; page < 20; page++) {
  let got;
  try {
    got = await rpcCall('getSignaturesForAddress',
      [expectSigner, before ? { limit: 1000, before } : { limit: 1000 }], rpc);
  } catch (e) {
    refuse(`getSignaturesForAddress(${expectSigner}) failed — ${e.message}`,
      "Without the signer's history this script cannot tell a complete memo chain from a truncated one,",
      'and reporting CLEAR on an unchecked chain is the failure this section exists to prevent.');
  }
  sigs.push(...got);
  if (got.length < 1000) break;
  before = got[got.length - 1].signature;
  if (page === 19) {
    refuse(`the signer has more than 20,000 transactions; this script stopped paginating.`,
      'It will not report on a history it has not finished reading.');
  }
}
console.log(`        ${sigs.length} transaction(s) on the signer`);

for (const s of sigs) {
  if (s.err) continue;
  let t;
  try {
    t = await rpcCall('getTransaction', [s.signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed' }], rpc);
  } catch (e) {
    refuse(`getTransaction(${s.signature}) failed — ${e.message}`,
      'This transaction is in the signer\'s history and could not be read, so it cannot be ruled out as a memo.',
      'Skipping it would let an unreadable transaction hide a memo the site is not showing.');
  }
  if (!t) {
    refuse(`getTransaction(${s.signature}) returned null though it is in the signer's history.`,
      'A transaction that cannot be fetched cannot be ruled out as a memo, and silently skipping it is exactly',
      'how a truncation check comes to pass without having looked.');
  }
  const m = t.transaction.message;
  const ks = (m.staticAccountKeys ?? m.accountKeys ?? []).map((k) => (k.toBase58 ? k.toBase58() : String(k)));

  /**
   * THE SIGNER CHECK. Without it this loop is a remote, permanent denial of
   * service on our own launch, purchasable by any stranger for ~5,000 lamports.
   *
   * `getSignaturesForAddress` returns every transaction in which the address
   * appears in ANY account-key position — not only the ones it signed. The
   * wallet's own funding transaction is in this list and was paid for by
   * somebody else.
   *
   * So an attacker sends one transaction containing a 1-lamport transfer to our
   * wallet plus a memo reading "escapement canonical v1\nmemo=999". It shows up
   * here. `chainMax` becomes 999, `siteMax` stays 2, `truncated` goes true, and
   * every run — local AND the published copy ATTESTATION.md tells every stranger
   * to run — reports "THE CHAIN HAS MEMO #999 AND THE SITE STOPS AT #2 … treat
   * this origin as compromised". Abort A8 fails, A1 fires, and the launch is
   * blocked. The chain is append-only, so they re-bump the number after every
   * legitimate memo. There is no recovery path in the design.
   *
   * Worse than the denial of service: the project publishes "if they differ,
   * trust the memo", so the attacker would hold a consensus-timestamped object
   * that our own tooling treats as chain truth.
   *
   * This file states the correct principle at the top of the argument list — "a
   * memo signed by anyone else attests nothing" — and did not apply it in the
   * one loop described as the entire trust anchor. It survived the commit whose
   * message was "four fail-opens, in the two files that decide whether the
   * launch worked".
   *
   * ks[0] is the fee payer, which for a v0 message is the first required signer.
   */
  if (ks[0] !== expectSigner) continue;

  for (const ix of m.compiledInstructions ?? m.instructions ?? []) {
    if (ks[ix.programIdIndex] !== MEMO_PROGRAM) continue;
    const d = ix.data;
    const text = Buffer.from(typeof d === 'string' ? bs58Decode(d) : d).toString('utf8');
    if (!text.startsWith('escapement canonical v1')) continue;
    const n = Number((text.match(/^memo=(\d+)$/m) ?? [])[1]);
    if (Number.isInteger(n)) chainMemos.push({ n, signature: s.signature });
  }
}

const cmp = compareMemoChains(chainMemos, list);

// @enforces A8 site-memo-list-is-not-truncated
check(!cmp.truncated, 'the site is showing every memo the chain has',
  !cmp.truncated
    ? `chain's highest is #${cmp.chainMax}, site shows #${cmp.siteMax}`
    : `THE CHAIN HAS MEMO #${cmp.chainMax} AND THE SITE STOPS AT #${cmp.siteMax}. The served record may have been `
      + 'rolled back to an earlier attested state. Every other check in this script would still pass, because '
      + 'they all take the memo index from the site. Treat this origin as compromised until explained.');

// @enforces A8 every-on-chain-memo-appears-in-the-published-list
check(cmp.missing.length === 0, 'every memo on chain appears in the published list',
  cmp.missing.length === 0 ? `${chainMemos.length} memo(s) cross-checked`
    : `on chain but not published: ${cmp.missing.map((x) => `#${x.n} ${x.signature.slice(0, 12)}…`).join(', ')}`);

// @enforces A8 no-published-memo-is-fabricated
check(cmp.fabricated.length === 0, 'no published memo is missing from the chain',
  cmp.fabricated.length === 0 ? 'none invented'
    : `published but never landed: ${cmp.fabricated.map((x) => `#${x.n}`).join(', ')}`);

// @enforces A8 published-memo-signatures-match-the-chain
check(cmp.mismatched.length === 0, 'each published signature matches the chain for that memo number',
  cmp.mismatched.length === 0 ? 'signatures agree'
    : `substituted: ${cmp.mismatched.map((x) => `#${x.n}`).join(', ')}`);

// ---------------------------------------------------------------------------
section('do the record and the chain agree');

// THE check. Everything else in this file exists to make this line meaningful.
//
// @enforces A8 live-canonical-record-matches-the-newest-on-chain-memo
check(committedHash === liveHash, 'the served record hashes to what the newest memo committed',
  committedHash === liveHash
    ? 'exact match'
    : `served ${liveHash} but memo #${newest.n} committed ${committedHash} — the record changed and the memo did not follow. `
      + 'Land memo #' + (newest.n + 1) + ' for the new bytes BEFORE this deployment goes to users, or every user running '
      + 'our own published check is told this site is compromised.');

// @enforces A8 newest-memo-commits-the-origin-being-served
check(committedUrl === recUrl, 'the memo commits the URL actually serving the record',
  `memo says ${committedUrl}`);

// @enforces A8 memo-record-agrees-with-the-published-chain
check(newest.sha256 === liveHash, 'the site\'s own MEMOS entry agrees with the served bytes',
  newest.sha256 === liveHash ? 'consistent' : `canonical-memos.json claims ${newest.sha256}`);

// A break in the chain means a memo was landed that the site is not showing, or
// the site is showing a chain that was not landed. Either is a integrity failure.
if (list.length > 1) {
  const prevEntry = list.find((m) => m.n === newest.n - 1);
  // @enforces A8 memo-chain-is-linked
  check(prevEntry != null && committedPrev === prevEntry.signature, 'the newest memo links to its predecessor',
    `memo says prev=${committedPrev}`);
} else {
  check(committedPrev === 'none', 'the first memo declares no predecessor', `memo says prev=${committedPrev}`);
}

// ---------------------------------------------------------------------------
section(`the ${PRE_LAUNCH_DAYS}-day pre-launch window (RUNBOOK §6.5)`);

// Measured from memo #1 — the first moment the record was attested by consensus,
// not the first moment it was deployed. A record served from a host we do not
// control proves nothing about when it appeared; the memo does.
const first = list.reduce((a, b) => (b.n < a.n ? b : a));
const firstTx = first.n === newest.n ? tx : await rpcCall('getTransaction', [first.signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed' }], rpc);

// blockTime is the validator's estimate, not consensus. It is right for a
// 14-day window measured in days and would be wrong for anything finer; the
// indexer keys on slots for exactly that reason.
const firstTime = firstTx?.blockTime ? new Date(firstTx.blockTime * 1000) : null;
if (!firstTime) {
  check(false, `memo #${first.n} has a block time to measure the window from`, 'blockTime unavailable');
} else {
  const days = (Date.now() - firstTime.getTime()) / 86_400_000;
  const earliest = new Date(firstTime.getTime() + PRE_LAUNCH_DAYS * 86_400_000);
  // @enforces A8 pre-launch-window-has-elapsed
  check(days >= PRE_LAUNCH_DAYS, `at least ${PRE_LAUNCH_DAYS} days have elapsed since memo #${first.n}`,
    `${days.toFixed(2)} days elapsed (memo #${first.n} landed ${firstTime.toISOString().slice(0, 10)}, `
    + `earliest permitted launch ${earliest.toISOString().slice(0, 10)})`);
  if (committedDate && committedDate !== firstTime.toISOString().slice(0, 10)) {
    console.log(`        note: memo #${first.n} states date=${committedDate}, chain block time is ${firstTime.toISOString().slice(0, 10)}`);
  }
}

// ---------------------------------------------------------------------------
console.log('');
if (fail) {
  console.log(`VERIFY-CANONICAL FAILED — ${fail} check(s).`);
  process.exit(1);
}
console.log('VERIFY-CANONICAL CLEAR.');
if (flag('quiet')) process.exit(0);
console.log('');
console.log('  This says the record being served is the record the chain attests, by the wallet the');
console.log('  site names, and that the pre-launch window has elapsed. It does NOT say the record is');
console.log('  true — only that it has not changed behind the attestation.');
process.exit(0);
