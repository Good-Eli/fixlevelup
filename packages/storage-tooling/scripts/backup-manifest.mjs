import { createHash } from 'node:crypto';

/**
 * @typedef {{ key: string, file: string, bytes: number, sha256: string,
 *   contentType: 'application/octet-stream',
 *   metadata: { sha256: string, fixture: 'restore-drill' } }} BackupObject
 * @typedef {{ version: 1, suffix: string,
 *   source: { endpoint: 'http://127.0.0.1:3900', bucket: 'fixlevelup-dev-private', region: 'garage' },
 *   objects: BackupObject[] }} BackupManifest
 */

const invalidMessage = 'Invalid backup manifest.';
const suffixPattern = /^[a-f0-9]{12}$/;
const filePattern = /^[a-f0-9]{32}\.bin$/;
const hashPattern = /^[a-f0-9]{64}$/;

/** @param {Uint8Array} bytes @returns {string} */
export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Accept only ordinary records with exactly these own, enumerable data fields.
 * Inherited fields, accessors and symbol fields cannot hide additional secrets.
 * @param {unknown} value
 * @param {string[]} fields
 * @returns {asserts value is Record<string, unknown>}
 */
function assertRecord(value, fields) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(invalidMessage);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(invalidMessage);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
    throw new Error(invalidMessage);
  }
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new Error(invalidMessage);
    }
  }
}

/**
 * Validate a bounded, synthetic source-only manifest, never a restore target or
 * arbitrary filesystem path. No IO or credentials are needed to validate it.
 * @param {unknown} value
 * @param {unknown} suffix
 * @returns {BackupManifest}
 */
export function validateManifest(value, suffix) {
  try {
    if (typeof suffix !== 'string' || suffix.length !== 12 || !suffixPattern.test(suffix)) {
      throw new Error(invalidMessage);
    }
    assertRecord(value, ['version', 'suffix', 'source', 'objects']);
    if (value.version !== 1 || value.suffix !== suffix) {
      throw new Error(invalidMessage);
    }
    assertRecord(value.source, ['endpoint', 'bucket', 'region']);
    if (value.source.endpoint !== 'http://127.0.0.1:3900'
      || value.source.bucket !== 'fixlevelup-dev-private' || value.source.region !== 'garage') {
      throw new Error(invalidMessage);
    }
    if (!Array.isArray(value.objects) || Object.getPrototypeOf(value.objects) !== Array.prototype
      || value.objects.length < 1 || value.objects.length > 10) {
      throw new Error(invalidMessage);
    }
    // JSON arrays cannot carry extra properties, holes, symbols or accessors.
    const arrayKeys = Reflect.ownKeys(value.objects);
    if (arrayKeys.length !== value.objects.length + 1) {
      throw new Error(invalidMessage);
    }
    const keys = new Set();
    const files = new Set();
    for (let index = 0; index < value.objects.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value.objects, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new Error(invalidMessage);
      }
      const object = descriptor.value;
      assertRecord(object, ['key', 'file', 'bytes', 'sha256', 'contentType', 'metadata']);
      if (typeof object.file !== 'string' || object.file.length !== 36 || !filePattern.test(object.file)
        || object.key !== `synthetic/restore/${suffix}/${object.file}`
        || keys.has(object.key) || files.has(object.file)
        || !Number.isInteger(object.bytes) || object.bytes < 0 || object.bytes > 1_048_576
        || typeof object.sha256 !== 'string' || object.sha256.length !== 64 || !hashPattern.test(object.sha256)
        || object.contentType !== 'application/octet-stream') {
        throw new Error(invalidMessage);
      }
      assertRecord(object.metadata, ['sha256', 'fixture']);
      if (object.metadata.sha256 !== object.sha256 || object.metadata.fixture !== 'restore-drill') {
        throw new Error(invalidMessage);
      }
      keys.add(object.key);
      files.add(object.file);
    }
    return /** @type {BackupManifest} */ (value);
  } catch {
    // Never echo supplied fields or retain a cause: they may contain secrets.
    throw new Error(invalidMessage);
  }
}
