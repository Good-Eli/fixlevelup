import type { PoolClient } from 'pg';
import type { ImageMime, ReadyFileView } from './contract.js';
import { SANITIZED_ATTEMPTS } from './budget.js';
import { refuseLifecycle } from './errors.js';

export const PUBLICATIONS = 'foundation.file_publications';
export const SHA256 = /^[0-9a-f]{64}$/;

export function isImageMime(value: unknown): value is ImageMime {
  return value === 'image/jpeg' || value === 'image/png' || value === 'image/webp';
}

export interface Publication {
  readonly id: string;
  readonly intent_id: string;
  readonly quarantine_id: string;
  readonly raw_bytes: string;
  readonly raw_sha256: string;
  readonly sanitized_attempt_id: string;
  readonly mime: ImageMime;
  readonly served_bytes: string;
  readonly served_sha256: string;
  readonly published_at: string;
  readonly object_key: string;
  readonly storage_endpoint: string;
  readonly storage_bucket: string;
  readonly storage_region: string;
}

/** The enclosing intent lock serializes publication; these historical rows cannot be updated/deleted. */
export async function selectPublication(client: PoolClient, intentId: string): Promise<Publication | undefined> {
  const { rows: [row] } = await client.query<Publication>(`SELECT p.id,p.intent_id,p.quarantine_id,p.raw_bytes::text,p.raw_sha256,
    p.sanitized_attempt_id,p.mime,p.served_bytes::text,p.served_sha256,p.published_at::text,
    a.object_key,a.storage_endpoint,a.storage_bucket,a.storage_region
    FROM ${PUBLICATIONS} p JOIN ${SANITIZED_ATTEMPTS} a ON a.intent_id=p.intent_id AND a.id=p.sanitized_attempt_id
    WHERE p.intent_id=$1 AND a.state='VERIFIED' AND a.mime=p.mime AND a.quarantine_id=p.quarantine_id
      AND a.verified_bytes=p.served_bytes AND a.verified_sha256=p.served_sha256`, [intentId]);
  return row;
}

export function toReadyFileView(publication: Pick<Publication, 'id' | 'mime' | 'served_bytes'>): ReadyFileView {
  const bytes = Number(publication.served_bytes);
  if (!Number.isSafeInteger(bytes) || bytes < 1 || !isImageMime(publication.mime)) {
    refuseLifecycle('CONFLICT');
  }
  return Object.freeze({ fileId: publication.id, state: 'READY', mime: publication.mime, bytes });
}
