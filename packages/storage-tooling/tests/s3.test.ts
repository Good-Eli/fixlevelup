import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import {
  CreateBucketCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadStorageConfig, makeClient } from '../scripts/local.mjs';

// Never propagate SDK errors or HTTP bodies: either can echo credentials or signed URLs.
function statusOf(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('$metadata' in error)) {
    return undefined;
  }
  const metadata: unknown = error.$metadata;
  if (typeof metadata !== 'object' || metadata === null || !('httpStatusCode' in metadata)) {
    return undefined;
  }
  return typeof metadata.httpStatusCode === 'number' ? metadata.httpStatusCode : undefined;
}

async function safeCall<T>(label: string, action: () => Promise<T>): Promise<T> {
  try {
    return await action();
  } catch (error: unknown) {
    const status = statusOf(error);
    // Raw SDK cause may contain credentials/signed URLs; retain only the status.
    // eslint-disable-next-line preserve-caught-error
    throw new Error(`${label} failed (HTTP ${status === undefined ? 'unavailable' : String(status)}).`);
  }
}

async function rejectedStatus(action: () => Promise<unknown>): Promise<number | undefined> {
  try {
    await action();
    return undefined;
  } catch (error: unknown) {
    return statusOf(error);
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readBody(body: { transformToByteArray(): Promise<Uint8Array> } | undefined): Promise<Uint8Array> {
  if (!body) {
    throw new Error('Signed GET returned no object body.');
  }
  return safeCall('Read signed object body', () => body.transformToByteArray());
}

type HttpMethod = 'GET' | 'HEAD' | 'PUT';

async function request(url: URL, method: HttpMethod, body?: Uint8Array): Promise<Response> {
  return safeCall(`HTTP ${method}`, () => fetch(url, {
    method,
    ...(body === undefined ? {} : { body: Buffer.from(body) }),
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
  }));
}

async function expectHttpDenied(url: URL, method: HttpMethod, body?: Uint8Array): Promise<void> {
  const response = await request(url, method, body);
  try {
    expect(response.status).toBe(403);
  } finally {
    // Do not parse or print Garage XML error bodies.
    await safeCall('Discard denied response body', async () => { await response.body?.cancel(); });
  }
}

async function expectExpired(url: URL): Promise<void> {
  const response = await request(url, 'GET');
  expect(response.status).toBe(400);
  const body = await safeCall('Read expiration code', () => response.text());
  // Tagged Garage 2.5 returns InvalidRequest/Date is too old for expiry.
  // Never include the XML resource (or signed URL) in assertion diagnostics.
  expect(/<Code>InvalidRequest<\/Code>/.test(body)).toBe(true);
  expect(/<Message>Bad request: Date is too old<\/Message>/.test(body)).toBe(true);
}

async function responseBytes(response: Response): Promise<Uint8Array> {
  return safeCall('Read presigned object body', async () => new Uint8Array(await response.arrayBuffer()));
}

describe('real local Garage S3 contract', () => {
  let config: ReturnType<typeof loadStorageConfig>;
  let client: S3Client | undefined;
  const fixturePrefix = `synthetic/storage-contract/${randomUUID()}/`;
  const payload = randomBytes(128 * 1024);
  const digest = sha256(payload);
  const fixtureKey = `${fixturePrefix}payload.bin`;
  const metadata = { sha256: digest, fixture: 'synthetic-storage-contract' };

  function runtimeClient(): S3Client {
    if (!client) {
      throw new Error('Garage test client is not initialized.');
    }
    return client;
  }

  function objectUrl(key: string): URL {
    const url = new URL(config.endpoint);
    url.pathname = `/${encodeURIComponent(config.bucket)}/${key.split('/').map(encodeURIComponent).join('/')}`;
    return url;
  }

  function bucketUrl(): URL {
    const url = new URL(config.endpoint);
    url.pathname = `/${encodeURIComponent(config.bucket)}`;
    url.searchParams.set('list-type', '2');
    url.searchParams.set('prefix', fixturePrefix);
    return url;
  }

  async function signedUrl(key = fixtureKey, expiresIn = 60, signingDate?: Date): Promise<URL> {
    const url = await safeCall('Presign GET', () => getSignedUrl(
      runtimeClient(),
      new GetObjectCommand({ Bucket: config.bucket, Key: key }),
      { expiresIn, ...(signingDate === undefined ? {} : { signingDate }) },
    ));
    return new URL(url);
  }

  beforeAll(async () => {
    try {
      config = loadStorageConfig();
      client = makeClient(config);
      const result = await safeCall('Create synthetic fixture', () => runtimeClient().send(new PutObjectCommand({
        Bucket: config.bucket,
        Key: fixtureKey,
        Body: payload,
        ContentType: 'application/octet-stream',
        Metadata: metadata,
      })));
      expect(result.$metadata.httpStatusCode).toBe(200);
    } catch {
      client?.destroy();
      throw new Error('Garage fixture setup failed; verify local storage configuration and availability.');
    }
  });

  afterAll(() => {
    client?.destroy();
  });

  it('round-trips a signed 128 KiB object with metadata, bytes and SHA-256 intact', async () => {
    const head = await safeCall('Signed HEAD', () => runtimeClient().send(new HeadObjectCommand({
      Bucket: config.bucket, Key: fixtureKey,
    })));
    expect(head.$metadata.httpStatusCode).toBe(200);
    expect(head.ContentLength).toBe(payload.byteLength);
    expect(head.ContentType).toBe('application/octet-stream');
    expect(head.Metadata).toEqual(metadata);

    const result = await safeCall('Signed GET', () => runtimeClient().send(new GetObjectCommand({
      Bucket: config.bucket, Key: fixtureKey,
    })));
    expect(result.$metadata.httpStatusCode).toBe(200);
    expect(result.Metadata).toEqual(metadata);
    const received = await readBody(result.Body);
    expect(Buffer.from(received).equals(payload)).toBe(true);
    expect(sha256(received)).toBe(digest);
  });

  it('lists only a unique prefix and traverses every page with MaxKeys=1', async () => {
    const prefix = `${fixturePrefix}pagination/`;
    const keys = ['first.bin', 'second.bin', 'third.bin'].map((name) => `${prefix}${name}`);
    for (const key of keys) {
      await safeCall('Create pagination fixture', () => runtimeClient().send(new PutObjectCommand({
        Bucket: config.bucket, Key: key, Body: randomBytes(32),
      })));
    }

    const listed: string[] = [];
    const tokens = new Set<string>();
    let token: string | undefined;
    let pages = 0;
    for (;;) {
      const page = await safeCall('List synthetic prefix', () => runtimeClient().send(new ListObjectsV2Command({
        Bucket: config.bucket,
        Prefix: prefix,
        MaxKeys: 1,
        ...(token === undefined ? {} : { ContinuationToken: token }),
      })));
      expect(page.$metadata.httpStatusCode).toBe(200);
      expect(page.Contents).toHaveLength(1);
      expect(page.KeyCount).toBe(1);
      for (const entry of page.Contents ?? []) {
        if (entry.Key === undefined) {
          throw new Error('ListObjectsV2 returned an entry without a key.');
        }
        expect(entry.Key.startsWith(prefix)).toBe(true);
        listed.push(entry.Key);
      }
      pages += 1;
      expect(pages).toBeLessThanOrEqual(keys.length);
      if (!page.IsTruncated) {
        break;
      }
      const next = page.NextContinuationToken;
      if (!next) {
        throw new Error('Truncated ListObjectsV2 page has no continuation token.');
      }
      expect(tokens.has(next)).toBe(false);
      tokens.add(next);
      token = next;
    }
    expect(pages).toBe(keys.length);
    expect([...listed].sort()).toEqual([...keys].sort());
    expect(new Set(listed).size).toBe(keys.length);
  });

  it('rejects anonymous GET, HEAD, LIST and PUT with HTTP 403', async () => {
    await expectHttpDenied(objectUrl(fixtureKey), 'GET');
    await expectHttpDenied(objectUrl(fixtureKey), 'HEAD');
    await expectHttpDenied(bucketUrl(), 'GET');
    await expectHttpDenied(objectUrl(`${fixturePrefix}anonymous-put.bin`), 'PUT', randomBytes(32));
  });

  it.each(['access key', 'secret'] as const)('rejects a wrong %s with HTTP 403', async (credential) => {
    const invalidClient = new S3Client({
      endpoint: config.endpoint,
      region: config.region,
      forcePathStyle: true,
      maxAttempts: 1,
      requestHandler: { connectionTimeout: 2_000, requestTimeout: 5_000, throwOnRequestTimeout: true, socketTimeout: 5_000 },
      credentials: {
        accessKeyId: credential === 'access key' ? `GK${randomBytes(12).toString('hex')}` : config.accessKeyId,
        secretAccessKey: credential === 'secret' ? randomBytes(32).toString('hex') : config.secretAccessKey,
      },
    });
    try {
      const status = await rejectedStatus(() => invalidClient.send(new GetObjectCommand({
        Bucket: config.bucket, Key: fixtureKey,
      })));
      expect(status).toBe(403);
    } finally {
      invalidClient.destroy();
    }
  });

  it('allows readonly signed GET but denies PUT without creating an object', async () => {
    let readonlyClient: S3Client | undefined;
    try {
      try {
        readonlyClient = makeClient(loadStorageConfig(true));
      } catch {
        throw new Error('Readonly Garage configuration is unavailable or invalid.');
      }
      const reader = readonlyClient;
      const result = await safeCall('Readonly signed GET', () => reader.send(new GetObjectCommand({
        Bucket: config.bucket, Key: fixtureKey,
      })));
      expect(result.$metadata.httpStatusCode).toBe(200);
      const received = await readBody(result.Body);
      expect(Buffer.from(received).equals(payload)).toBe(true);
      expect(sha256(received)).toBe(digest);
      const key = `${fixturePrefix}readonly-put-${randomUUID()}.bin`;
      const denied = await rejectedStatus(() => reader.send(new PutObjectCommand({
        Bucket: config.bucket, Key: key, Body: randomBytes(32),
      })));
      expect(denied).toBe(403);
      const absent = await rejectedStatus(() => runtimeClient().send(new GetObjectCommand({
        Bucket: config.bucket, Key: key,
      })));
      expect(absent).toBe(404);
    } finally {
      readonlyClient?.destroy();
    }
  });

  it('serves a presigned GET with the same bytes and SHA-256', async () => {
    const response = await request(await signedUrl(), 'GET');
    expect(response.status).toBe(200);
    const received = await responseBytes(response);
    expect(Buffer.from(received).equals(payload)).toBe(true);
    expect(sha256(received)).toBe(digest);
  });

  it('rejects a presigned URL whose object key is tampered with', async () => {
    const url = await signedUrl();
    url.pathname = `${url.pathname}.tampered`;
    await expectHttpDenied(url, 'GET');
  });

  it('rejects a presigned URL whose signature is tampered with', async () => {
    const url = await signedUrl();
    const signature = url.searchParams.get('X-Amz-Signature');
    if (!signature) {
      throw new Error('Presigner did not provide a signature.');
    }
    url.searchParams.set('X-Amz-Signature', `${signature.startsWith('0') ? '1' : '0'}${signature.slice(1)}`);
    await expectHttpDenied(url, 'GET');
  });

  it('rejects an already expired URL without waiting', async () => {
    const url = await signedUrl(fixtureKey, 1, new Date(Date.now() - 120_000));
    await expectExpired(url);
  });

  it('serves a live one-second URL, then rejects it after real expiration', async () => {
    const url = await signedUrl(fixtureKey, 1);
    const live = await request(url, 'GET');
    expect(live.status).toBe(200);
    const received = await responseBytes(live);
    expect(Buffer.from(received).equals(payload)).toBe(true);
    expect(sha256(received)).toBe(digest);
    await delay(2_000);
    await expectExpired(url);
  });

  it('denies bucket creation to the runtime read/write key', async () => {
    // Never target the provisioned bucket with a destructive bucket operation.
    const status = await rejectedStatus(() => runtimeClient().send(new CreateBucketCommand({
      Bucket: `flup-noowner-${randomUUID()}`,
    })));
    expect(status).toBe(403);
  });

  it('returns HTTP 404 for a signed GET of a missing synthetic key', async () => {
    const status = await rejectedStatus(() => runtimeClient().send(new GetObjectCommand({
      Bucket: config.bucket, Key: `${fixturePrefix}missing-${randomUUID()}.bin`,
    })));
    expect(status).toBe(404);
  });

  it('deletes only its own synthetic object and returns HTTP 404 afterwards', async () => {
    const key = `${fixturePrefix}delete-only-${randomUUID()}.bin`;
    await safeCall('Create deletion fixture', () => runtimeClient().send(new PutObjectCommand({
      Bucket: config.bucket, Key: key, Body: randomBytes(32),
    })));
    const before = await safeCall('HEAD deletion fixture', () => runtimeClient().send(new HeadObjectCommand({
      Bucket: config.bucket, Key: key,
    })));
    expect(before.$metadata.httpStatusCode).toBe(200);
    const deleted = await safeCall('Delete own fixture', () => runtimeClient().send(new DeleteObjectCommand({
      Bucket: config.bucket, Key: key,
    })));
    expect(deleted.$metadata.httpStatusCode).toBe(204);
    const status = await rejectedStatus(() => runtimeClient().send(new GetObjectCommand({
      Bucket: config.bucket, Key: key,
    })));
    expect(status).toBe(404);
  });
});
