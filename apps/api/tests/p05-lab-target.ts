import 'reflect-metadata';
import { Client } from 'pg';
import { createApi } from '../src/bootstrap/factories.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { loadWebAuthConfig } from '../src/auth/web-auth.config.js';
import { loadTelegramAuthConfig } from '../src/auth/telegram-auth.config.js';
import { loadRuntimeAdmission } from '../src/infrastructure/admission/runtime-admission.js';
import { admitProcess } from '../src/infrastructure/admission/process-admission.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';

/** Script-owned test contract; never read production credentials or accept a remote endpoint. */
export function loadP05LabTarget(env: NodeJS.ProcessEnv = process.env) {
  const database = env['FIXLEVELUP_LAB_DATABASE'] ?? '';
  const oid = Number(env['FIXLEVELUP_LAB_DATABASE_OID']);
  const runId = env['FIXLEVELUP_SESSION_RUN_ID'] ?? '';
  const cluster = env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
  const adminPassword = env['FIXLEVELUP_LAB_ORCHESTRATOR_PASSWORD'] ?? '';
  const runtimePassword = env['FIXLEVELUP_RUNTIME_PASSWORD'] ?? '';
  const migratorPassword = env['FIXLEVELUP_MIGRATOR_PASSWORD'] ?? '';
  const adminRole = 'fixlevelup_lab_orchestrator';
  if (env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || env['FIXLEVELUP_LAB_ORCHESTRATOR_ROLE'] !== adminRole
    || !/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/.test(cluster) || !/^[a-f0-9]{12}$/.test(runId)
    || !/^fixlevelup_p05_[a-z0-9_]{1,48}$/.test(database) || !/^\d+$/.test(env['FIXLEVELUP_LAB_DATABASE_OID'] ?? '')
    || !Number.isInteger(oid) || oid < 1 || oid > 0xffffffff
    || ![adminPassword, runtimePassword, migratorPassword].every((value) => /^[a-f0-9]{64}$/.test(value))) {
    throw new Error('Invalid isolated P05 lab binding');
  }
  const applicationName = `fixlevelup-p05s4-${runId}`;
  const endpoint = { host: '127.0.0.1' as const, port: 55432 };
  const runtime: DatabaseConfig = Object.freeze({ ...endpoint, database, user: 'fixlevelup_runtime', password: runtimePassword });
  const migrator = Object.freeze({ ...endpoint, database, user: 'fixlevelup_migrator', password: migratorPassword,
    application_name: applicationName });
  const client = (options: { database: string; user: string; password: string }) => new Client({
    ...endpoint, ...options, application_name: applicationName, connectionTimeoutMillis: 3000, statement_timeout: 3000,
  });
  const attest = async (connection: Client, expectedDb: string, role: string) => {
    const result = await connection.query<{ valid: boolean }>(`SELECT
      current_database() = $1 AND current_user = $2 AND session_user = $2
      AND current_setting('cluster_name') = $3 AND current_setting('server_version_num') = '180007'
      AND host(inet_server_addr()) = '127.0.0.1' AND inet_server_port() = 55432
      AND EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = $4 AND oid = $5::oid)
      AS valid`, [expectedDb, role, cluster, database, oid]);
    if (result.rows[0]?.valid !== true) { throw new Error('Isolated P05 lab identity mismatch'); }
  };
  return Object.freeze({ runtime, migrator, applicationName, oid,
    async openMaintenance(): Promise<Client> {
      const maintenance = client({ database: 'postgres', user: adminRole, password: adminPassword });
      const target = client(runtime);
      try {
        await maintenance.connect();
        await attest(maintenance, 'postgres', adminRole);
        await target.connect();
        await attest(target, database, runtime.user);
        await target.end();
        return maintenance;
      } catch {
        await Promise.allSettled([target.end(), maintenance.end()]);
        throw new Error('Unable to attest isolated P05 lab');
      }
    },
  });
}

/** Invoke only from the lab's supervised test child; no standalone bypass. */
export async function startP05LabApi(env: NodeJS.ProcessEnv = process.env) {
  if (!process.connected || typeof process.send !== 'function') { throw new Error('Missing isolated lab launcher IPC'); }
  const databaseName = env['FIXLEVELUP_LAB_DATABASE'] ?? '';
  const password = env['DB_PASSWORD'] ?? '';
  if (!/^fixlevelup_p05_[a-z0-9_]{1,48}$/.test(databaseName) || !/^[a-f0-9]{64}$/.test(password)) {
    throw new Error('Invalid isolated P05 child runtime binding');
  }
  const database: DatabaseConfig = { host: '127.0.0.1', port: 55432, database: databaseName,
    user: 'fixlevelup_runtime', password };
  const admission = loadRuntimeAdmission(env, { database, requiredConsumer: 'API' });
  const authorization = await admitProcess(admission, { database,
    approvalTimeoutMs: 10000 });
  return await createApi(loadConfig(env), new SafeLogger('api'), database,
    loadWebAuthConfig(env), loadTelegramAuthConfig(env), authorization);
}
