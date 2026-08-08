/**
 * version.mjs — pin the environment (D12), and separate what may vary from what
 * may not.
 *
 * There are two hashes and they are not the same hash, deliberately:
 *
 *   merkle_root    depends ONLY on chain data + the exclusion set + the config
 *                  pubkey + the vault amount. It must be identical for two
 *                  honest parties on different machines, different Node
 *                  versions, different operating systems, different RPC
 *                  providers. Nothing about the environment enters it.
 *
 *   manifest_hash  commits the environment: this source tree's hash, the Node
 *                  version, the exclusion-set version, the run parameters. It
 *                  is EXPECTED to differ between two verifiers, and that is
 *                  fine — it is a record of what produced a root, not part of
 *                  the root.
 *
 * Folding the toolchain version into the root would be the obvious reading of
 * D12 and it would be wrong: it would make a Node upgrade produce a different
 * root for identical chain data, which destroys the property the whole design
 * exists for. G6 lists `manifest_hash` and `merkle_root` as separate committed
 * fields precisely so both can be true at once.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { sha256Hex } from './canonical.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

export const SCHEMA_VERSION = 'escapement.artifact/v1';

/**
 * A hash over this source tree's non-test modules.
 *
 * Tests are excluded on purpose: a verifier who adds a test must still compute
 * the same root, and if adding a test changed the recorded source hash we would
 * have built an incentive not to add tests.
 */
export function sourceHash() {
  const files = readdirSync(HERE)
    .filter((f) => f.endsWith('.mjs') && !f.endsWith('.test.mjs'))
    .sort();
  const parts = files.map((f) => `${f} ${sha256Hex(readFileSync(join(HERE, f)))}`);
  return { hash: sha256Hex(parts.join('\n')), files: parts };
}

/** The git commit this ran from, or null. Recorded, never required. */
export function gitCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: HERE, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch { return null; }
}

/**
 * Is this package's source uncommitted or modified?
 *
 * Scoped to `src/`, and UNTRACKED FILES COUNT. A tree where the whole package is
 * untracked is not "clean" — it is unpublished, which is worse, and the earlier
 * version of this function said `false` for exactly that case.
 */
export function gitDirty() {
  try {
    const out = execFileSync('git', ['status', '--porcelain', '--', HERE], {
      cwd: HERE, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return out.trim().length > 0;
  } catch { return null; }
}

export function environment() {
  const src = sourceHash();
  return {
    schema: SCHEMA_VERSION,
    indexer_source_hash: src.hash,
    indexer_source_files: src.files,
    indexer_git_commit: gitCommit(),
    indexer_git_dirty: gitDirty(),
    node_version: process.version,
    platform: `${process.platform}-${process.arch}`,
  };
}
