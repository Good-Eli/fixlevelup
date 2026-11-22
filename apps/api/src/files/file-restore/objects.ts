import { GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import { createS3Client, validateConfig, type PrivateQuarantineStorageConfig } from '../storage/config.js';
import type { StorageTarget } from '../storage/attempt.js';
import type { RestoreObject } from './contract.js';
import { refuseRestore } from './contract.js';
import { sha256, targetId } from './records.js';

const stopped = (value: AbortSignal): boolean => value.aborted;

/** Trusted synthetic snapshot/copy tool only. Original endpoint is always GET-only. */
export function createRestoreObjectIO(input: { readonly source: PrivateQuarantineStorageConfig;
  readonly destination: PrivateQuarantineStorageConfig; readonly maxObjectBytes: number }) {
  const source = validateConfig(input.source);
  const destination = validateConfig(input.destination);
  if (!/^fixlevelup-restore-[a-f0-9]{24}$/.test(destination.bucket)
    || (source.endpoint === destination.endpoint && source.bucket === destination.bucket)
    || !Number.isSafeInteger(input.maxObjectBytes) || input.maxObjectBytes < 1 || input.maxObjectBytes > 16_777_216) {refuseRestore('RESTORE_INPUT');}
  const sourceClient = createS3Client(source);
  const destinationClient = createS3Client(destination);
  const maximum = input.maxObjectBytes;
  const exact = (item: RestoreObject): number => {
    const prefix = `${item.kind === 'RAW' ? 'quarantine' : 'sanitized'}/${item.attemptId}/`;
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(item.attemptId)
      || !item.key.startsWith(prefix) || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(item.key.slice(prefix.length))
      || targetId(item.target) !== targetId(source) || item.disposition !== 'COPY' || item.bytes === null
      || !Number.isSafeInteger(item.bytes) || item.bytes < 1 || item.bytes > maximum || item.sha256 === null) {return refuseRestore('RESTORE_OBJECT');}
    return item.bytes;
  };
  const read = async (fromSource: boolean, item: RestoreObject, signal: AbortSignal): Promise<Uint8Array> => {
    const size = exact(item);

    const config = fromSource ? source : destination;
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(config.operationTimeoutMs)]);
    const response = await (fromSource ? sourceClient : destinationClient).send(new GetObjectCommand({ Bucket: config.bucket, Key: item.key }), { abortSignal: deadline });
    const { Body } = response;
    if (!(Body instanceof Readable)) {return refuseRestore('RESTORE_OBJECT');}
    const stop = (): void => { Body.destroy(); };
    deadline.addEventListener('abort', stop, { once: true });
    try {
      if (deadline.aborted || response.$metadata.httpStatusCode !== 200 || response.ContentRange !== undefined
        || response.ContentLength !== size) {return refuseRestore('RESTORE_OBJECT');}
      const buffer = new Uint8Array(size);
      let offset = 0;
      for await (const chunk of Body as AsyncIterable<unknown>) {
        if (!(chunk instanceof Uint8Array) || offset + chunk.byteLength > size || stopped(deadline)) {return refuseRestore('RESTORE_OBJECT');}
        buffer.set(chunk, offset);
        offset += chunk.byteLength;
      }
      if (offset !== size || sha256(buffer) !== item.sha256 || stopped(deadline)) {return refuseRestore('RESTORE_OBJECT');}
      return buffer;
    } finally { deadline.removeEventListener('abort', stop); stop(); }
  };
  const spent = new Set<string>();
  let copying = false;
  return Object.freeze({
    async exportSource(item: RestoreObject, signal: AbortSignal): Promise<Uint8Array> {
      try { return await read(true, item, signal); } catch { return refuseRestore('RESTORE_OBJECT'); }
    },
    async copyToFreshTarget(target: StorageTarget, item: RestoreObject, bytes: Uint8Array, signal: AbortSignal): Promise<void> {
      if (copying || targetId(target) !== targetId(destination) || spent.has(item.key) || bytes.byteLength !== exact(item)
        || sha256(bytes) !== item.sha256 || signal.aborted) {refuseRestore('RESTORE_OBJECT');}
      spent.add(item.key); // Never retries an uncertain PUT, even within this private tool.
      copying = true;
      try {
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(destination.operationTimeoutMs)]);
        const response = await destinationClient.send(new PutObjectCommand({ Bucket: destination.bucket, Key: item.key,
          ContentLength: bytes.byteLength, ContentType: 'application/octet-stream', IfNoneMatch: '*', Body: bytes }), { abortSignal: deadline });
        if (response.$metadata.httpStatusCode !== 200 || stopped(deadline)) {refuseRestore('RESTORE_OBJECT');}
        await read(false, item, deadline);
      } catch { refuseRestore('RESTORE_OBJECT'); }
      finally { copying = false; }
    },
    close() { sourceClient.destroy(); destinationClient.destroy(); },
  });
}