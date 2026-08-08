// SPDX-License-Identifier: Apache-2.0
/**
 * rpc.mjs — read-only Solana JSON-RPC.
 *
 * This module contains no signing capability, constructs no transaction, and
 * imports no keypair. It calls exactly four methods: `getSlot`, `getBlocks`,
 * `getBlock`, `getVersion`. Nothing here can move a lamport.
 *
 * The error classification is the whole point of the file. Downstream, D4
 * requires that a skipped slot and a failed fetch never become the same thing,
 * so this layer must not paper over a failure by returning `null`.
 */

export class RpcError extends Error {
  constructor(message, { method, httpStatus = null, code = null, slot = null } = {}) {
    super(message);
    this.name = 'RpcError';
    this.method = method;
    this.httpStatus = httpStatus;
    this.code = code;
    this.slot = slot;
  }

  /** The endpoint structurally refuses this call. Retrying will not help. */
  get isRefusal() {
    if (this.httpStatus === 401 || this.httpStatus === 403 || this.httpStatus === 410) return true;
    if (this.code === -32601) return true; // method not found
    return /disabled|not (?:supported|enabled|available)|unauthoriz|requires? .*(?:plan|tier)/i.test(this.message);
  }

  /** Transient. Back off and retry. */
  get isTransient() {
    if (this.httpStatus === 429 || (this.httpStatus >= 500 && this.httpStatus <= 599)) return true;
    return /rate.?limit|too many requests|timeout|aborted|fetch failed|socket|ECONNRESET|EAI_AGAIN|network|terminated/i
      .test(this.message);
  }

  /**
   * The node is telling us it does not have this block.
   *
   * DELIBERATELY NOT the same as "the slot was skipped". Codes -32007 and -32009
   * both carry the message "Slot N was skipped, or missing due to ledger jump to
   * recent snapshot" / "...missing in long-term storage" — the word "or" in the
   * node's own error string is the entire problem. This predicate exists so the
   * caller can say "the node does not have it" without ever concluding "the
   * chain does not have it". Only `getBlocks` may conclude the latter.
   */
  get isBlockUnavailable() {
    return this.code === -32004 || this.code === -32007 || this.code === -32009 || this.code === -32014;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const DEFAULT_ENDPOINTS = {
  mainnet: 'https://api.mainnet-beta.solana.com',
  devnet: 'https://api.devnet.solana.com',
  testnet: 'https://api.testnet.solana.com',
};

export class Rpc {
  /**
   * @param {object} opts
   * @param {string} opts.url
   * @param {number} [opts.minIntervalMs] simple client-side throttle. Public
   *   endpoints rate-limit aggressively and a 429 storm looks exactly like an
   *   outage; pacing turns it into a slow success.
   */
  constructor({ url, timeoutMs = 30_000, retries = 5, baseDelayMs = 600, minIntervalMs = 0, onRetry = null } = {}) {
    if (!url) throw new Error('Rpc: url is required');
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.retries = retries;
    this.baseDelayMs = baseDelayMs;
    this.minIntervalMs = minIntervalMs;
    this.onRetry = onRetry;
    this.stats = { calls: 0, retries: 0, bytes: 0, ms: 0 };
    this._gate = Promise.resolve();
    this._lastAt = 0;
  }

  async _throttle() {
    if (this.minIntervalMs <= 0) return;
    const prev = this._gate;
    let release;
    this._gate = new Promise((r) => { release = r; });
    await prev;
    const wait = this._lastAt + this.minIntervalMs - Date.now();
    if (wait > 0) await sleep(wait);
    this._lastAt = Date.now();
    release();
  }

  async call(method, params, { slot = null } = {}) {
    let lastErr = null;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      await this._throttle();
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
      const t0 = Date.now();
      try {
        this.stats.calls++;
        const res = await fetch(this.url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
          signal: ctrl.signal,
        });
        const text = await res.text();
        this.stats.bytes += text.length;
        let json = null;
        try { json = JSON.parse(text); } catch { /* handled below */ }

        if (!res.ok) {
          throw new RpcError(`${method} HTTP ${res.status}: ${json?.error?.message || text.slice(0, 160)}`, {
            method, httpStatus: res.status, code: json?.error?.code ?? null, slot,
          });
        }
        if (json === null) throw new RpcError(`${method}: non-JSON response`, { method, httpStatus: res.status, slot });
        if (json.error) {
          throw new RpcError(`${method}: ${json.error.message}`, {
            method, httpStatus: res.status, code: json.error.code ?? null, slot,
          });
        }
        return json.result;
      } catch (err) {
        lastErr = err instanceof RpcError ? err : new RpcError(`${method}: ${err.message}`, { method, slot });
        // A block the node does not have is not a transient condition; retrying
        // the same node forever will not conjure it. Surface it immediately so
        // the caller can decide (and the caller's only honest decision is to
        // abort, per D4).
        if (lastErr.isRefusal || lastErr.isBlockUnavailable || attempt === this.retries || !lastErr.isTransient) break;
        this.stats.retries++;
        const delay = Math.round(this.baseDelayMs * 2 ** attempt * (0.5 + Math.random()));
        if (this.onRetry) this.onRetry({ method, slot, attempt: attempt + 1, delayMs: delay, error: lastErr });
        await sleep(delay);
      } finally {
        clearTimeout(t);
        this.stats.ms += Date.now() - t0;
      }
    }
    throw lastErr;
  }

  /** Highest FINALIZED slot. D1: never `confirmed`, never `processed`. */
  async getFinalizedSlot() {
    return await this.call('getSlot', [{ commitment: 'finalized' }]);
  }

  /**
   * The authoritative list of slots in [start, end] that PRODUCED a block, at
   * finalized commitment.
   *
   * This single call is what makes D4 mechanical rather than aspirational: a
   * slot's absence from this list is a statement about the chain, and a
   * `getBlock` failure on a slot that IS in this list is a statement about the
   * RPC. Nothing else in the pipeline is permitted to decide that a slot was
   * skipped.
   */
  async getBlocks(start, end) {
    if (end < start) return [];
    if (end - start >= 500_000) throw new Error('getBlocks: range must be under 500,000 slots');
    return await this.call('getBlocks', [start, end, { commitment: 'finalized' }]);
  }

  /**
   * A finalized block with full transaction detail.
   *
   * `encoding: 'json'` rather than `jsonParsed`: we read only
   * `meta.pre/postTokenBalances` and the account-key list, both of which are
   * present and stable in `json`, and `jsonParsed` adds megabytes of
   * program-specific interpretation that differs between node versions. Less
   * surface, less to disagree about.
   *
   * `rewards: false` for the same reason — a validator's reward record has
   * nothing to do with entitlement and is a needless byte.
   */
  async getBlock(slot) {
    return await this.call('getBlock', [slot, {
      commitment: 'finalized',
      encoding: 'json',
      transactionDetails: 'full',
      maxSupportedTransactionVersion: 0,
      rewards: false,
    }], { slot });
  }

  async getVersion() {
    try { return await this.call('getVersion', []); } catch { return null; }
  }
}
