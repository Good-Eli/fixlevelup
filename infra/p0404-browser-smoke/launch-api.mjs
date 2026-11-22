import { createApi } from '../../apps/api/dist/bootstrap/factories.js';
import { SafeLogger } from '../../apps/api/dist/runtime/safe-logger.js';
import { loadConfig } from '../../apps/api/dist/runtime/config.js';
import { RuntimeDatabase } from '../../apps/api/dist/infrastructure/database/runtime-database.js';
import { loadWebAuthConfig } from '../../apps/api/dist/auth/web-auth.config.js';
import { registerShutdown } from '../../apps/api/dist/runtime/lifecycle.js';
import { apiPort, connection, host, isolated, origin, Pool, token, verifyIdentity } from './isolation.mjs';

let app;
try {
  const namespace = await isolated();
  const database = Object.freeze(connection(namespace, 'fixlevelup_runtime', process.env['P0404_RUNTIME_PASSWORD']));
  const guard = new Pool({ ...database, connectionTimeoutMillis: 1000, statement_timeout: 2000, max: 1 });
  try { await verifyIdentity(guard, namespace, 'fixlevelup_runtime', 'runtime'); }
  finally { await guard.end(); }
  // Test-only config (the production loader still refuses all names except fixlevelup_dev).
  // No monkeypatching, replacement providers, mock routes, or altered readiness predicates.
  const config = loadConfig({ NODE_ENV: 'production', APP_HOST: host, APP_PORT: String(apiPort) });
  const auth = loadWebAuthConfig({ WEB_AUTH_ENABLED: '1', WEB_AUTH_ORIGIN: origin, WEB_AUTH_CSRF_SECRET: token(), WEB_AUTH_THROTTLE_SECRET: token() });
  const logger = new SafeLogger('api');
  app = await createApi(config, logger, database, auth);
  const db = app.get(RuntimeDatabase);
  if (!await db.ready() || !await db.catalogManagementReady()) { throw new Error('Compiled P03/P04 database readiness failed'); }
  registerShutdown(app, config, logger);
  if (typeof process.send !== 'function') { throw new Error('Missing private fixture launch IPC'); }
  process.send({ ready: true });
} catch {
  await app?.close();
  process.exitCode = 1;
}
