import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';

const requireApi = createRequire(new URL('../../apps/api/package.json', import.meta.url));
export const { Pool } = requireApi('pg');
export const host = '127.0.0.1';
export const pgPort = 55432;
export const apiPort = 4174;
export const webPort = 4175;
export const tlsPort = 4176;
export const proofPort = 4177;
export const origin = `https://${host}:${tlsPort}`;
export const token = () => randomBytes(32).toString('hex');
export const isToken = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const isUuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);

export async function isolated() {
  const marker = process.env['P0404_NAMESPACE'];
  if (process.platform !== 'linux' || process.version !== 'v24.22.3'
    || process.env['P0404_ISOLATED_BROWSER'] !== '1' || !/^[a-f0-9]{24}$/.test(marker ?? '')) {
    throw new Error('Disposable Linux fixture required');
  }
  const interfaces = (await readFile('/proc/net/dev', 'utf8')).trim().split('\n').slice(2);
  if (interfaces.length !== 1 || !/^\s*lo:/.test(interfaces[0])) { throw new Error('Not a loopback-only namespace'); }
  return Object.freeze({ database: `fixlevelup_p04_browser_test_${marker}`, cluster: `p0404-${marker}`, marker });
}

export function connection(namespace, user, password) {
  if (!isToken(password)) { throw new Error('Disposable database credential missing'); }
  return { host, port: pgPort, database: namespace.database, user, password, ssl: false };
}

// Evaluated in PostgreSQL as the actual connection user, before privileged work
// or handing a runtime config to the compiled Nest factory. Checking the remote
// peer and cluster marker rules out accidental attachment to a local work DB.
export async function verifyIdentity(pool, namespace, user, state) {
  const initial = state === 'fresh';
  const runtime = user === 'fixlevelup_runtime';
  const proof = await pool.query(`SELECT current_database()=$1 AND current_user=$2 AND session_user=$2
      AND current_setting('server_version_num')='180007' AND current_setting('cluster_name')=$3
      AND current_setting('listen_addresses')='127.0.0.1' AND inet_server_addr()='127.0.0.1'::inet
      AND inet_client_addr()='127.0.0.1'::inet AND inet_server_port()=55432
      AND (SELECT pg_get_userbyid(datdba)=$4 FROM pg_database WHERE datname=current_database())
      AND NOT EXISTS (SELECT FROM pg_database WHERE datname NOT IN ($1,'postgres','template0','template1'))
      AND ${initial ? `NOT EXISTS (SELECT FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','pg_toast','public','information_schema'))
        AND NOT EXISTS (SELECT FROM pg_class WHERE relnamespace='public'::regnamespace)
        AND NOT EXISTS (SELECT FROM pg_roles WHERE rolname !~ '^pg_' AND rolname<>$2)` :
      `EXISTS (SELECT FROM pg_namespace WHERE nspname='foundation' AND pg_get_userbyid(nspowner)='fixlevelup_migrator')
        AND (SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
          FROM pg_roles WHERE rolname=current_user)
        AND NOT EXISTS (SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))`}
      ${runtime ? `AND NOT has_function_privilege(current_user,'foundation.issue_p04_synthetic_permissions()','EXECUTE')` : ''} AS ok`,
  [namespace.database, user, namespace.cluster, initial ? 'p0404_postgres' : 'fixlevelup_migrator']);
  if (proof.rows[0]?.ok !== true) { throw new Error('Refusing database identity or state'); }
}
