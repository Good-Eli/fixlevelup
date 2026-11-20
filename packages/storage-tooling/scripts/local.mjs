import { readFileSync } from 'node:fs';
import { S3Client } from '@aws-sdk/client-s3';

export function loadStorageConfig(readonly = false) {
  const source = readFileSync(new URL('../../../infra/dev-s3/.env', import.meta.url), 'utf8');
  const prefix = readonly ? 'S3_READONLY_' : 'S3_';
  const get = (name, pattern) => {
    const value = new RegExp(`^${prefix}${name}=([^\\r\\n]+)$`, 'm').exec(source)?.[1];
    if (!value || !pattern.test(value)) { throw new Error('Invalid local S3 credentials'); }
    return value;
  };
  return { endpoint: 'http://127.0.0.1:3900', region: 'garage', bucket: 'fixlevelup-dev-private',
    accessKeyId: get('ACCESS_KEY_ID', /^GK[a-f0-9]{24}$/), secretAccessKey: get('SECRET_ACCESS_KEY', /^[a-f0-9]{64}$/) };
}

export function makeClient(config = loadStorageConfig()) {
  if (config.endpoint !== 'http://127.0.0.1:3900' || config.region !== 'garage' || config.bucket !== 'fixlevelup-dev-private') {
    throw new Error('S3 target outside dev allowlist');
  }
  return new S3Client({ endpoint: config.endpoint, region: config.region, forcePathStyle: true,
    credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey },
    maxAttempts: 1, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED',
    requestHandler: { connectionTimeout: 2000, requestTimeout: 5000, throwOnRequestTimeout: true, socketTimeout: 5000 } });
}
