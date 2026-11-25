import { applyCappedMigrations, migrationInventory } from '../p0305-browser-smoke/launch.mjs';

/**
 * Applies the pinned S0 cap: the reviewed 21-migration prefix of the current
 * chain, verified byte-for-byte against the public SHA-256 manifest. The 022–024
 * P05 migrations are NOT applied and are reported explicitly, never hidden.
 *
 * `prisma migrate deploy` cannot be used here because it would apply the whole
 * chain; the reviewed scripts are executed directly and the real Prisma history
 * rows are written with the pinned checksums.
 */
export async function deploy(migrator) {
  const plan = await migrationInventory();
  const history = await applyCappedMigrations(migrator, plan);
  return Object.freeze({ applied: history.applied, chain: history.chain, excluded: history.excluded,
    historyManifestDigest: history.historyManifestDigest });
}
