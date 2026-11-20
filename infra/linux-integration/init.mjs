import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
const path = new URL('.env',import.meta.url);
if (existsSync(path)) { throw new Error('Isolated integration credentials already exist; refusing overwrite'); }
const values={POSTGRES_PASSWORD:randomBytes(32).toString('hex'),GARAGE_RPC_SECRET:randomBytes(32).toString('hex'),
  S3_ACCESS_KEY_ID:`GK${randomBytes(12).toString('hex')}`,S3_SECRET_ACCESS_KEY:randomBytes(32).toString('hex'),
  S3_READONLY_ACCESS_KEY_ID:`GK${randomBytes(12).toString('hex')}`,S3_READONLY_SECRET_ACCESS_KEY:randomBytes(32).toString('hex')};
writeFileSync(path,Object.entries(values).map(([k,v])=>`${k}=${v}`).join('\n')+'\n',{flag:'wx',mode:0o600});
console.log('New isolated Linux integration credentials generated; values suppressed.');
