// SPDX-License-Identifier: Apache-2.0
/**
 * pot.mjs — fence `--vault-lamports` (review finding B7).
 *
 * The single number that decides how much money moves in an epoch —
 * `--vault-lamports` — was a free operator argument tagged
 * `chain | manual-attested | hypothetical`, with no derivation and no check that
 * it equalled what the vault could legally distribute. Worse, `verify` defaulted
 * it to the value inside the artifact under review, so a green AGREE proved
 * nothing about the one number a dishonest publisher would move.
 *
 * This module makes the legal value COMPUTABLE from chain state and refusable:
 *
 *   1. `deriveMaxLegalTotal(...)` — a pure function of the vault balance, the
 *      config's counters and the compiled-in caps, returning the largest
 *      `total_owed_cumulative` the on-chain `publish_root` would accept. It is the
 *      exact conjunction of I1 (solvency) and G2 (both delta caps), so a preflight
 *      that passes it will not be rejected by the program, and a proposal it
 *      rejects would strand holders' money or bounce on chain.
 *   2. `readVaultState(rpc, ...)` — reads the vault balance and decodes the
 *      on-chain `Config` (via the mirrored policy fields from B6), so a verifier
 *      can obtain the pot INDEPENDENTLY instead of trusting the artifact.
 *
 * Nothing here signs or sends. `readVaultState` uses `getAccountInfo`, a
 * read-only RPC method.
 */

/**
 * The largest `total_owed_cumulative` the on-chain program will accept for the
 * next root, given live state. Pure; no I/O.
 *
 * @param {object} s
 * @param {bigint} s.vaultLamports    current vault balance (lamports)
 * @param {bigint} s.rentMin          rent-exempt minimum for the vault account
 * @param {bigint} s.totalClaimed     config.total_claimed
 * @param {bigint} s.highWater        config.high_water_allocated
 * @param {bigint} s.maxAbsDelta      MAX_ROOT_DELTA_LAMPORTS
 * @param {bigint} s.divisor          MAX_ROOT_DELTA_DIVISOR
 * @returns {{ funded: bigint, maxDelta: bigint, maxTotal: bigint }}
 */
export function deriveMaxLegalTotal({ vaultLamports, rentMin, totalClaimed, highWater, maxAbsDelta, divisor }) {
  for (const [k, v] of Object.entries({ vaultLamports, rentMin, totalClaimed, highWater, maxAbsDelta, divisor })) {
    if (typeof v !== 'bigint') throw new Error(`deriveMaxLegalTotal: ${k} must be a bigint`);
  }
  if (divisor <= 0n) throw new Error('deriveMaxLegalTotal: divisor must be positive');
  // I1: total_owed_cumulative <= total_funded_observed = free + total_claimed.
  const free = vaultLamports > rentMin ? vaultLamports - rentMin : 0n;
  const funded = free + totalClaimed;
  // G2: delta = total - high_water <= min(maxAbsDelta, funded / divisor).
  const fractionalCap = funded / divisor;
  const maxDelta = maxAbsDelta < fractionalCap ? maxAbsDelta : fractionalCap;
  // The binding total is the smaller of the I1 ceiling and (high_water + G2 delta).
  const g2Total = highWater + maxDelta;
  const maxTotal = funded < g2Total ? funded : g2Total;
  return { funded, maxDelta, maxTotal };
}

/**
 * Would the on-chain `publish_root` accept `proposedTotal`? Returns a verdict and
 * the derived ceiling, so a `publish` preflight can refuse before spending a
 * signature and a `verify` can recompute the pot rather than reading it.
 *
 * @param {bigint} proposedTotal  the artifact's `total_owed_cumulative`
 * @param {object} state          the same fields as `deriveMaxLegalTotal`
 */
export function checkPot(proposedTotal, state) {
  if (typeof proposedTotal !== 'bigint') throw new Error('checkPot: proposedTotal must be a bigint');
  const d = deriveMaxLegalTotal(state);
  if (proposedTotal < state.highWater) {
    return { ok: false, reason: 'AllocationWentBackwards', ...d,
      detail: `proposed ${proposedTotal} is below the high-water mark ${state.highWater}; the program rejects a decrease.` };
  }
  if (proposedTotal > d.maxTotal) {
    return { ok: false, reason: proposedTotal > d.funded ? 'RootExceedsFunded' : 'RootDeltaExceedsFraction', ...d,
      detail: `proposed ${proposedTotal} exceeds the maximum legal total ${d.maxTotal} ` +
        `(funded ${d.funded}, high-water ${state.highWater}, max delta ${d.maxDelta}).` };
  }
  return { ok: true, reason: null, ...d,
    detail: `proposed ${proposedTotal} is within the legal ceiling ${d.maxTotal}.` };
}

// --- on-chain Config layout, from escapement-vault/src/lib.rs -----------------
// After the 8-byte Anchor discriminator:
//   mint 0..32, publisher 32..64, guardian 64..96,
//   total_claimed 96, high_water_allocated 104, epoch_count 112,
//   last_cutoff_slot 120, last_published_slot 128,
//   claim_window_start 136, claimed_in_window 144,
//   challenge_window_seconds 152, claim_window_seconds 160,
//   max_root_delta_lamports 168, max_root_delta_divisor 176,
//   max_claim_window_divisor 184, min_publish_interval_slots 192,
//   min_claim_lamports 200, bump 208, vault_bump 209
const OFF = {
  total_claimed: 96, high_water_allocated: 104, epoch_count: 112,
  last_cutoff_slot: 120, last_published_slot: 128,
  max_root_delta_lamports: 168, max_root_delta_divisor: 176,
  max_claim_window_divisor: 184, min_publish_interval_slots: 192,
  min_claim_lamports: 200,
};

function readU64LE(buf, off) {
  return buf.readBigUInt64LE(8 + off);
}

/** Decode the mirrored policy + counters out of a raw on-chain Config account. */
export function decodeConfig(dataBase64) {
  const buf = Buffer.from(dataBase64, 'base64');
  const out = {};
  for (const [k, off] of Object.entries(OFF)) out[k] = readU64LE(buf, off);
  return out;
}

/**
 * Read the pot independently from chain: the vault balance and the config
 * counters + mirrored caps, so a verifier never has to trust the artifact for
 * the one number that decides how much money moves.
 *
 * @param {import('./rpc.mjs').Rpc} rpc  must expose getAccountInfo (read-only)
 * @param {string} configPubkey
 * @param {string} vaultPubkey
 */
export async function readVaultState(rpc, configPubkey, vaultPubkey) {
  const [cfgInfo, vaultInfo] = await Promise.all([
    rpc.getAccountInfo(configPubkey),
    rpc.getAccountInfo(vaultPubkey),
  ]);
  if (!cfgInfo) throw new Error(`readVaultState: config ${configPubkey} not found on chain`);
  if (!vaultInfo) throw new Error(`readVaultState: vault ${vaultPubkey} not found on chain`);
  const cfg = decodeConfig(cfgInfo.data[0]);
  const vaultLamports = BigInt(vaultInfo.lamports);
  const rentMin = BigInt(await rpc.getMinimumBalanceForRentExemption(vaultInfo.data ? Buffer.from(vaultInfo.data[0], 'base64').length : 41));
  return {
    vaultLamports,
    rentMin,
    totalClaimed: cfg.total_claimed,
    highWater: cfg.high_water_allocated,
    maxAbsDelta: cfg.max_root_delta_lamports,
    divisor: cfg.max_root_delta_divisor === 0n ? 4n : cfg.max_root_delta_divisor,
    epochCount: cfg.epoch_count,
    lastCutoffSlot: cfg.last_cutoff_slot,
  };
}
