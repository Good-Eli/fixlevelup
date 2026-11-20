import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
const target = new URL('../../../infra/dev-s3/.env', import.meta.url);
if (existsSync(target)) {
  console.log('Existing local S3 credentials preserved.');
} else {
  const values = {
    GARAGE_RPC_SECRET: randomBytes(32).toString('hex'),
    S3_ACCESS_KEY_ID: `GK${randomBytes(12).toString('hex')}`,
    S3_SECRET_ACCESS_KEY: randomBytes(32).toString('hex'),
    S3_READONLY_ACCESS_KEY_ID: `GK${randomBytes(12).toString('hex')}`,
    S3_READONLY_SECRET_ACCESS_KEY: randomBytes(32).toString('hex'),
  };
  writeFileSync(target, Object.entries(values).map(([key,value]) => `${key}=${value}`).join('\n')+'\n', { flag: 'wx', mode: 0o600 });
  console.log('Local S3 credentials generated in ignored .env; values suppressed.');
}
