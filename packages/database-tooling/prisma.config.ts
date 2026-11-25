import { defineConfig } from 'prisma/config';

/* ---------------------------------------------------------------------------
 * P05-02 S4: opt-in synthetic test-orchestrator datasource guard.
 *
 * Default (dev) behaviour is unchanged: the URL is taken verbatim from
 * FIXLEVELUP_MIGRATION_URL and no validation is added, so `db:deploy` on the
 * dev contour keeps working exactly as before.
 *
 * Under FIXLEVELUP_SYNTHETIC_ORCHESTRATOR=1 the same config becomes strict:
 * `db:deploy` (and every other Prisma command) may only ever point at the
 * dedicated synthetic test targets on the exact loopback endpoint. A working
 * target — `fixlevelup_dev` first of all, but also any other name outside the
 * synthetic allowlist — is refused before Prisma starts, so this mode can never
 * migrate, reset or repair a working database.
 * ------------------------------------------------------------------------- */

const SYNTHETIC_FLAG = 'FIXLEVELUP_SYNTHETIC_ORCHESTRATOR';
const HOST = '127.0.0.1';
const PORT = '55432';
/** Same disposable allowlist as scripts/migration-local.mjs — keep the two in sync.
 * These are the historical generated test names the ten sibling migration proofs
 * hard-code; the working database is refused separately below. */
const DISPOSABLE_DATABASE = /^fixlevelup_p017a_(?:fresh|upgrade|shadow)_[a-f0-9]{12}$/;

function refuse(reason: string): never {
  throw new Error(`Synthetic orchestrator refused the Prisma datasource: ${reason}`);
}

/** Parses and validates one synthetic URL; returns it unchanged when exact. */
function requireSyntheticUrl(raw: string, label: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    refuse(`${label} is not a valid URL`);
  }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    refuse(`${label} is not a PostgreSQL URL`);
  }
  if (url.hostname !== HOST) { refuse(`${label} host must be ${HOST}`); }
  if (url.port !== PORT) { refuse(`${label} port must be ${PORT}`); }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ''));
  if (database === 'fixlevelup_dev') { refuse(`${label} must never target the working database`); }
  if (!DISPOSABLE_DATABASE.test(database)) { refuse(`${label} is outside the disposable test allowlist`); }
  if (url.username !== 'fixlevelup_migrator') { refuse(`${label} user must be fixlevelup_migrator`); }
  return raw;
}

const synthetic = process.env[SYNTHETIC_FLAG] === '1';
const migrationUrl = process.env['FIXLEVELUP_MIGRATION_URL'];
const shadowUrl = process.env['FIXLEVELUP_SHADOW_URL'];

if (synthetic) {
  if (!migrationUrl) { refuse('FIXLEVELUP_MIGRATION_URL is required in synthetic mode'); }
  requireSyntheticUrl(migrationUrl, 'FIXLEVELUP_MIGRATION_URL');
  if (shadowUrl) { requireSyntheticUrl(shadowUrl, 'FIXLEVELUP_SHADOW_URL'); }
}

export default defineConfig({
  schema: '../../prisma/schema.prisma',
  migrations: { path: process.env['FIXLEVELUP_MIGRATIONS_DIR'] ?? '../../prisma/migrations' },
  ...(migrationUrl
    ? { datasource: {
      url: migrationUrl,
      ...(shadowUrl ? { shadowDatabaseUrl: shadowUrl } : {}),
    } }
    : {}),
});
