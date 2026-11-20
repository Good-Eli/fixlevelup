import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { loadStorageConfig, makeClient } from './local.mjs';

const proof = new URL('../../../node_modules/.cache/s3-persistence.json', import.meta.url);
const config = loadStorageConfig(), client = makeClient(config);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
try {
  if (process.argv[2] === 'write') {
    const bytes = randomBytes(4096), key = `synthetic/persistence/${randomBytes(12).toString('hex')}.bin`;
    await client.send(new PutObjectCommand({ Bucket: config.bucket, Key: key, Body: bytes,
      Metadata: { sha256: hash(bytes), fixture: 'persistence' } }));
    mkdirSync(new URL('../../../node_modules/.cache/', import.meta.url), { recursive: true });
    writeFileSync(proof, JSON.stringify({ key, sha256: hash(bytes), bytes: bytes.toString('base64') })+'\n');
    console.log('Synthetic S3 persistence marker written; local evidence saved without credentials.');
  } else if (process.argv[2] === 'verify') {
    const expected = JSON.parse(readFileSync(proof, 'utf8'));
    if (!/^synthetic\/persistence\/[a-f0-9]{24}\.bin$/.test(expected.key)) { throw new Error('Invalid marker'); }
    const response = await client.send(new GetObjectCommand({ Bucket: config.bucket, Key: expected.key }));
    const bytes = await response.Body?.transformToByteArray();
    if (!bytes || hash(bytes) !== expected.sha256 || !Buffer.from(bytes).equals(Buffer.from(expected.bytes, 'base64'))
      || response.Metadata?.sha256 !== expected.sha256) { throw new Error('Persistence mismatch'); }
    console.log('S3 persistence bytes/SHA256/metadata after restart: PASS');
  } else { throw new Error('Expected write or verify'); }
} catch {
  console.error('S3 persistence proof failed safely; response and credentials suppressed.');
  process.exitCode = 1;
} finally { client.destroy(); }
