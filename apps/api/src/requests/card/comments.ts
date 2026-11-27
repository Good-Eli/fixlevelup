import { randomUUID } from 'node:crypto';
import { parseP04JsonText, requireP04JsonScalar } from '@fixlevelup/p03-contracts/p04-json';
import { parseP05Etag } from '@fixlevelup/p03-contracts/p05';
import type { P05Context } from '../../authz/authorization.service.js';
import { canonicalJson } from '../../infrastructure/admission/proof.js';
import { idempotencyHmac, openManagedPayload, sealManagedPayload, verifyIdempotencyHmac } from '../crypto/payload-cipher.js';
import type { PayloadCiphertext } from '../crypto/payload-cipher.js';
import type { KeyringConfig } from '../crypto/keyring.js';
import type { PayloadKeySlots } from '../crypto/payload-key-directory.js';
import { deny } from '../intake/errors.js';
import type { WriteInput } from '../intake/service.js';
import type { RequestRow } from '../intake/store.js';

export const COMMENT_BODY_BYTES = 8192;
export const COMMENT_KEY_ENVIRONMENT = 'p06-comments';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const command = 'P06_ADD_INTERNAL_COMMENT';
const utf8 = new TextDecoder('utf-8', { fatal:true,ignoreBOM:true });

export interface CommentConfig {
  readonly ring: KeyringConfig;
  readonly keySlots: PayloadKeySlots;
}

interface CommentIdentity {
  readonly id: string;
  readonly version: number;
  readonly createdAt: string;
}

function slot(requestId: string, comment: Pick<CommentIdentity, 'id' | 'version'>) {
  return { environment:COMMENT_KEY_ENVIRONMENT, requestId, cellId:comment.id, revision:comment.version, kind:'DETAILS' as const };
}

function decodeText(bytes: Uint8Array): string {
  if (!bytes.byteLength || bytes.byteLength > COMMENT_BODY_BYTES) { return deny('INVALID_REQUEST'); }
  try {
    const body = parseP04JsonText(utf8.decode(bytes));
    if (body !== null && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 1
      && typeof body['text'] === 'string') {
      const text = body['text'].replaceAll('\r\n','\n').normalize('NFC').trim();
      requireP04JsonScalar(text);
      let length = 0;
      for (const character of text) {
        const code = character.charCodeAt(0);
        if ((code < 32 && code !== 9 && code !== 10) || code === 127 || ++length > 2000) { return deny('INVALID_REQUEST'); }
      }
      if (length > 0) { return text; }
    }
  } catch { return deny('INVALID_REQUEST'); }
  return deny('INVALID_REQUEST');
}

/** A separate explicit grant in the isolated CRM composition, checked under the P05 policy lock. */
export async function commentGrant(staff: P05Context, row: RequestRow) {
  const { rows:[grant] } = await staff.client.query<{ canRead: boolean; canWrite: boolean }>(`
    SELECT can_read AS "canRead",can_write AS "canWrite" FROM p06_crm.comment_grants
    WHERE staff_id=$1 AND city_id=$2`, [staff.staffId,row.city_id]);
  return grant;
}

export async function authorizeComments(staff: P05Context, row: RequestRow, write: boolean) {
  const grant = await commentGrant(staff,row);
  if (!grant?.canRead || (write && !grant.canWrite)) { return deny('FORBIDDEN'); }
}

export async function readInternalComments(staff: P05Context, request: RequestRow, config: CommentConfig,
  beforeOpen?: () => Promise<void>) {
  const { rows } = await staff.client.query<CommentIdentity & PayloadCiphertext>(`SELECT id,request_version AS version,nonce,
    ciphertext,auth_tag AS "authTag",aad_context AS "aadContext",
    to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"
    FROM p06_crm.comments WHERE request_id=$1 ORDER BY created_at DESC,id DESC LIMIT 50`, [request.id]);
  const items = [];
  for (const comment of rows) {
    const ref = slot(request.id,comment);
    // Missing, foreign or tampered external slots are availability failures.
    // Keep beforeOpen outside this catch: authorization/basis denials must retain
    // their 401/403/409 semantics rather than becoming NOT_READY.
    const wrap = await config.keySlots.read(ref).catch(() => deny('NOT_READY'));
    // Revalidate the external evidence issuer and locked staff proof after slot I/O,
    // immediately before plaintext can enter process memory.
    await beforeOpen?.();
    let plaintext: Buffer;
    try { plaintext = openManagedPayload(ref,config.ring,comment,wrap); }
    catch { return deny('NOT_READY'); }
    try {
      items.push({ id:comment.id,version:comment.version,createdAt:comment.createdAt,text:utf8.decode(plaintext).trimEnd() });
    } catch { return deny('NOT_READY'); }
    finally { plaintext.fill(0); }
  }
  return { items };
}

export async function writeInternalComment(staff: P05Context, row: RequestRow, config: CommentConfig,
  input: WriteInput, etag: string, sessionToken: string) {
  if (!uuid.test(input.key)) { return deny('INVALID_REQUEST'); }
  if (input.ifMatch === undefined) { return deny('PRECONDITION_REQUIRED'); }
  if (parseP05Etag(input.ifMatch) === null) { return deny('INVALID_REQUEST'); }
  const text = decodeText(input.bytes);
  const namespace = `${command}:${staff.staffId}:${row.id}`;
  const canonicalIntent = canonicalJson({ text,tag:input.ifMatch });
  const { rows:[prior] } = await staff.client.query<CommentIdentity & { keyId: string; fingerprint: Buffer }>(`
    SELECT id,request_version AS version,idem_key_id AS "keyId",fingerprint,
      to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"
    FROM p06_crm.comments WHERE request_id=$1 AND author_id=$2 AND idempotency_key=$3`, [row.id,staff.staffId,input.key]);
  if (prior) {
    if (!verifyIdempotencyHmac({ ring:config.ring,keyId:prior.keyId,namespace,canonicalIntent,digest:prior.fingerprint })) {
      return deny('IDEMPOTENCY_KEY_REUSED');
    }
    return { data:{ id:prior.id,version:prior.version,createdAt:prior.createdAt },replayed:true };
  }
  if (input.ifMatch !== etag) { return deny('PRECONDITION_FAILED'); }
  const id = randomUUID();
  const ref = slot(row.id,{ id,version:row.row_version });
  const plaintext = Buffer.from(text.padEnd(16,' '),'utf8');
  const sealed = (() => {
    try { return sealManagedPayload(ref,config.ring,plaintext); }
    finally { plaintext.fill(0); }
  })();
  await config.keySlots.create(ref, {keyId:sealed.keyId,wrappedDek:sealed.wrappedDek});
  const persistedWrap = await config.keySlots.read(ref).catch(() => deny('DEPENDENCY_UNAVAILABLE'));
  if (persistedWrap.keyId !== sealed.keyId || !persistedWrap.wrappedDek.equals(sealed.wrappedDek)) {
    return deny('DEPENDENCY_UNAVAILABLE');
  }
  const fingerprint = idempotencyHmac({ring:config.ring,namespace,canonicalIntent});
  const { rows:[data] } = await staff.client.query<CommentIdentity>(`SELECT id,request_version AS version,
      to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"
    FROM p06_crm.insert_internal_comment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
  [id,row.id,staff.staffId,staff.sessionId,sessionToken,row.row_version,input.key,fingerprint.keyId,fingerprint.digest,
    sealed.nonce,sealed.ciphertext,sealed.authTag,sealed.aadContext,randomUUID()])
    .catch(() => deny('NOT_READY'));
  if (!data) { return deny('NOT_READY'); }
  return { data,replayed:false };
}
