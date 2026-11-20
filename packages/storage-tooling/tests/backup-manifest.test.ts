import { describe, expect, it } from 'vitest';
import { sha256, validateManifest } from '../scripts/backup-manifest.mjs';

const suffix = '012345abcdef';
const payload = Buffer.from('Synthetic restore-drill fixture; not real user data.');
const digest = sha256(payload);
const safeMessage = 'Invalid backup manifest.';

function objectFixture(index = 0) {
  const file = `${index.toString(16).padStart(32, '0')}.bin`;
  return {
    key: `synthetic/restore/${suffix}/${file}`,
    file,
    bytes: payload.byteLength,
    sha256: digest,
    contentType: 'application/octet-stream',
    metadata: { sha256: digest, fixture: 'restore-drill' },
  };
}

function fixture(count = 1) {
  return {
    version: 1,
    suffix,
    source: { endpoint: 'http://127.0.0.1:3900', bucket: 'fixlevelup-dev-private', region: 'garage' },
    objects: Array.from({ length: count }, (_, index) => objectFixture(index)),
  };
}

function withObject(patch: Record<string, unknown>): unknown {
  return { ...fixture(), objects: [{ ...objectFixture(), ...patch }] };
}

function withSource(patch: Record<string, unknown>): unknown {
  return { ...fixture(), source: { ...fixture().source, ...patch } };
}

function without(value: object, field: string): unknown {
  const copy: Record<string, unknown> = { ...value };
  return Object.fromEntries(Object.entries(copy).filter(([key]) => key !== field));
}

function expectInvalid(value: unknown, ...expectedSuffix: [] | [unknown]): void {
  let caught: unknown;
  try {
    validateManifest(value, expectedSuffix.length === 0 ? suffix : expectedSuffix[0]);
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(Error);
  if (!(caught instanceof Error)) {
    throw new Error('Expected manifest validation to reject.');
  }
  expect(caught.name).toBe('Error');
  expect(caught.message).toBe(safeMessage);
  expect('cause' in caught).toBe(false);
  expect(Object.getOwnPropertyNames(caught).sort()).toEqual(['message', 'stack']);
}

describe('backup manifest SHA-256', () => {
  it('uses standard lower-case SHA-256 for Buffer and Uint8Array bytes', () => {
    expect(sha256(Buffer.alloc(0))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256(Buffer.from('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256(new Uint8Array([97, 98, 99]))).toBe(sha256(Buffer.from('abc')));
  });

  it('hashes the supplied view rather than its whole backing buffer', () => {
    const bytes = Buffer.from('!abc?');
    expect(sha256(bytes.subarray(1, 4))).toBe(sha256(Buffer.from('abc')));
    expect(sha256(payload)).not.toBe(sha256(Buffer.from('different synthetic fixture')));
  });
});

describe('strict synthetic backup manifest', () => {
  it.each([1, 10])('accepts %i unique objects and returns the original validated manifest', (count) => {
    const value = fixture(count);
    const snapshot = structuredClone(value);
    const validated = validateManifest(value, suffix);
    expect(validated).toBe(value);
    expect(validated).toEqual(snapshot);
    expect(validated.objects[0]?.sha256).toBe(digest);
  });

  it.each([0, 1_048_576])('accepts the inclusive byte bound %i', (bytes) => {
    const value = withObject({ bytes });
    expect(validateManifest(value, suffix)).toBe(value);
  });

  it('accepts a manifest parsed as JSON and records with null prototypes', () => {
    const parsed: unknown = JSON.parse(JSON.stringify(fixture()));
    expect(validateManifest(parsed, suffix)).toBe(parsed);
    const value = fixture();
    Object.setPrototypeOf(value, null);
    Object.setPrototypeOf(value.source, null);
    for (const object of value.objects) {
      Object.setPrototypeOf(object, null);
      Object.setPrototypeOf(object.metadata, null);
    }
    expect(validateManifest(value, suffix)).toBe(value);
  });

  it('does not mutate a deeply frozen manifest', () => {
    const value = fixture();
    for (const object of value.objects) {
      Object.freeze(object.metadata);
      Object.freeze(object);
    }
    Object.freeze(value.objects);
    Object.freeze(value.source);
    Object.freeze(value);
    expect(validateManifest(value, suffix)).toBe(value);
  });

  it.each([
    undefined, null, true, false, 1, 'manifest', [], new Date(0), new Map(),
  ])('rejects a non-record root %#', (value: unknown) => { expectInvalid(value); });

  it.each(['version', 'suffix', 'source', 'objects'])('requires root field %s', (field) => {
    expectInvalid(without(fixture(), field));
  });

  it.each([0, 2, -1, '1', null, undefined, true])('rejects version %#', (version: unknown) => {
    expectInvalid({ ...fixture(), version });
  });

  it.each([
    undefined, null, 123, '', '012345abcde', '012345abcdef0', '012345ABCDEF',
    '012345abcdeg', '012345abcdef\n', '012345abcdef\r', '../012345abc',
    '012345abcde/', 'https://test', new String(suffix),
  ])('requires a strict caller suffix %#', (invalidSuffix: unknown) => {
    expectInvalid(fixture(), invalidSuffix);
  });

  it.each([
    undefined, null, 123, '', 'fedcba543210', '012345ABCDEF', '012345abcdef\n', '../012345abc',
  ])('rejects a missing, malformed or mismatched manifest suffix %#', (invalidSuffix: unknown) => {
    expectInvalid({ ...fixture(), suffix: invalidSuffix });
  });

  it.each([undefined, null, [], 'source', 1, new Date(0)])('rejects invalid source %#', (source: unknown) => {
    expectInvalid({ ...fixture(), source });
  });

  it.each(['endpoint', 'bucket', 'region'])('requires source field %s', (field) => {
    expectInvalid({ ...fixture(), source: without(fixture().source, field) });
  });

  it.each([
    'http://127.0.0.1:13900', 'http://localhost:3900', 'https://127.0.0.1:3900',
    'http://127.0.0.1:3900/', 'http://127.0.0.1:3900?token=synthetic-canary',
    'http://synthetic-user:synthetic-password@127.0.0.1:3900',
    'http://127.0.0.1:3900.evil.invalid', 'http://192.0.2.1:3900', '', null,
  ])('rejects any source endpoint outside the exact source allowlist %#', (endpoint: unknown) => {
    expectInvalid(withSource({ endpoint }));
  });

  it.each(['fixlevelup-restore-private', 'other-bucket', 'fixlevelup-dev-private/', '', null])(
    'rejects the wrong source bucket %#', (bucket: unknown) => { expectInvalid(withSource({ bucket })); },
  );

  it.each(['Garage', 'us-east-1', '', null])('rejects the wrong source region %#', (region: unknown) => {
    expectInvalid(withSource({ region }));
  });

  it.each([undefined, null, {}, 'objects', [], fixture(11).objects, Array(1)])(
    'requires a dense array of 1..10 objects %#', (objects: unknown) => {
      expectInvalid({ ...fixture(), objects });
    },
  );

  it.each([undefined, null, [], 'object', 1, new Date(0)])('rejects invalid object records %#', (object: unknown) => {
    expectInvalid({ ...fixture(), objects: [object] });
  });

  it.each(['key', 'file', 'bytes', 'sha256', 'contentType', 'metadata'])('requires object field %s', (field) => {
    expectInvalid({ ...fixture(), objects: [without(objectFixture(), field)] });
  });

  it.each([
    '../payload.bin', '/payload.bin', 'C:\\payload.bin', '\\\\host\\share\\payload.bin',
    'https://example.invalid/payload.bin', `../${objectFixture().file}`, `${'a'.repeat(32)}.bin/extra`,
    `${'a'.repeat(32)}.BIN`, `${'A'.repeat(32)}.bin`, `${'g'.repeat(32)}.bin`,
    `${'a'.repeat(31)}.bin`, `${'a'.repeat(33)}.bin`, `${'a'.repeat(32)}.bin\n`,
    `${'a'.repeat(32)}%2ebin`, `${'a'.repeat(32)}.bin\0`, '', null, 1,
  ])('rejects paths, URLs and malformed filenames %#', (file: unknown) => { expectInvalid(withObject({ file })); });

  it.each([
    `synthetic/restore/fedcba543210/${objectFixture().file}`,
    `synthetic/storage-contract/${suffix}/${objectFixture().file}`,
    `synthetic/persistence/${suffix}/${objectFixture().file}`,
    `synthetic/restore/${suffix}/${objectFixture(1).file}`,
    `synthetic/restore/${suffix}/../${objectFixture().file}`,
    `synthetic/restore/${suffix}/%2e%2e/${objectFixture().file}`,
    `/synthetic/restore/${suffix}/${objectFixture().file}`,
    `https://example.invalid/synthetic/restore/${suffix}/${objectFixture().file}`,
    `synthetic\\restore\\${suffix}\\${objectFixture().file}`,
    `${objectFixture().key}?token=synthetic-canary`, `${objectFixture().key}\n`, '', null, 1,
  ])('rejects keys outside the exact suffix and filename %#', (key: unknown) => { expectInvalid(withObject({ key })); });

  it.each([-1, 1_048_577, 0.5, NaN, Infinity, -Infinity, '0', null, undefined, true, 0n])(
    'rejects invalid byte sizes %#', (bytes: unknown) => { expectInvalid(withObject({ bytes })); },
  );

  it.each(['', 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), 'A'.repeat(64), `${digest}\n`, null, 1])(
    'rejects malformed checksums %#', (checksum: unknown) => {
      expectInvalid(withObject({ sha256: checksum, metadata: { sha256: checksum, fixture: 'restore-drill' } }));
    },
  );

  it.each(['text/plain', 'application/octet-stream; charset=utf-8', '', null, 1])(
    'requires the exact binary content type %#', (contentType: unknown) => { expectInvalid(withObject({ contentType })); },
  );

  it.each([undefined, null, [], 'metadata', new Date(0)])('rejects invalid metadata %#', (metadata: unknown) => {
    expectInvalid(withObject({ metadata }));
  });

  it.each(['sha256', 'fixture'])('requires metadata field %s', (field) => {
    expectInvalid(withObject({ metadata: without(objectFixture().metadata, field) }));
  });

  it('requires matching metadata checksum and the restore-drill fixture marker', () => {
    expectInvalid(withObject({ metadata: { sha256: sha256(Buffer.from('other fixture')), fixture: 'restore-drill' } }));
    for (const marker of ['synthetic-storage-contract', 'Restore-drill', '', null]) {
      expectInvalid(withObject({ metadata: { sha256: digest, fixture: marker } }));
    }
  });

  it('rejects duplicate keys and filenames, including separately allocated records', () => {
    expectInvalid({ ...fixture(), objects: [objectFixture(), objectFixture()] });
    const duplicateFile = { ...objectFixture(1), file: objectFixture().file };
    expectInvalid({ ...fixture(), objects: [objectFixture(), duplicateFile] });
    const duplicateKey = { ...objectFixture(1), key: objectFixture().key };
    expectInvalid({ ...fixture(), objects: [objectFixture(), duplicateKey] });
  });

  it.each(['credentials', 'accessKeyId', 'secretAccessKey', 'sessionToken', 'signedUrl', 'path', 'unexpected'])(
    'rejects unknown field %s at every record level without echoing it', (field) => {
      const extra = { [field]: 'SYNTHETIC_NOT_A_CREDENTIAL_CANARY' };
      expectInvalid({ ...fixture(), ...extra });
      expectInvalid(withSource(extra));
      expectInvalid(withObject(extra));
      expectInvalid(withObject({ metadata: { ...objectFixture().metadata, ...extra } }));
    },
  );

  it('rejects hidden and symbol fields, even when JSON would omit them', () => {
    const records = [fixture(), fixture().source, objectFixture(), objectFixture().metadata];
    const wrap = [
      (record: unknown) => record,
      (record: unknown) => ({ ...fixture(), source: record }),
      (record: unknown) => ({ ...fixture(), objects: [record] }),
      (record: unknown) => withObject({ metadata: record }),
    ];
    records.forEach((record, index) => {
      Object.defineProperty(record, 'hiddenSecret', { value: 'synthetic-hidden-canary' });
      const wrapper = wrap[index];
      if (!wrapper) { throw new Error('Missing record wrapper.'); }
      expectInvalid(wrapper(record));
      const symbolRecord = { ...record, [Symbol('synthetic-secret')]: 'synthetic-canary' };
      expectInvalid(wrapper(symbolRecord));
    });
  });

  it('rejects inherited fields and non-plain records', () => {
    const inherited: unknown = Object.create(fixture());
    expectInvalid(inherited);
    const source = { ...fixture().source };
    Object.setPrototypeOf(source, { unexpected: 'synthetic-canary' });
    expectInvalid({ ...fixture(), source });
    const object = objectFixture();
    Object.setPrototypeOf(object, { unexpected: 'synthetic-canary' });
    expectInvalid({ ...fixture(), objects: [object] });
    const metadata = { ...objectFixture().metadata };
    Object.setPrototypeOf(metadata, { unexpected: 'synthetic-canary' });
    expectInvalid(withObject({ metadata }));
  });

  it('rejects accessor fields without invoking them', () => {
    let invoked = false;
    const value = fixture();
    Object.defineProperty(value.source, 'endpoint', { enumerable: true, get() {
      invoked = true;
      throw new Error('SYNTHETIC_ACCESSOR_CANARY');
    } });
    expectInvalid(value);
    expect(invoked).toBe(false);
  });

  it('rejects arrays with extra, hidden, symbol or accessor properties', () => {
    const extra = fixture();
    Object.defineProperty(extra.objects, 'secretAccessKey', { value: 'synthetic-canary' });
    expectInvalid(extra);
    const symbol = fixture();
    Object.defineProperty(symbol.objects, Symbol('extra'), { value: 'synthetic-canary' });
    expectInvalid(symbol);
    const inherited = fixture();
    Object.setPrototypeOf(inherited.objects, { secretAccessKey: 'synthetic-canary' });
    expectInvalid(inherited);
    const accessor = fixture();
    Object.defineProperty(accessor.objects, '0', { enumerable: true, get() {
      throw new Error('SYNTHETIC_ARRAY_ACCESSOR_CANARY');
    } });
    expectInvalid(accessor);
  });

  it('sanitizes native errors from hostile or revoked objects without retaining a cause', () => {
    const hostile = new Proxy({}, { ownKeys() { throw new Error('SYNTHETIC_PROXY_CANARY'); } });
    expectInvalid(hostile);
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    expectInvalid(revoked.proxy);
  });
});
