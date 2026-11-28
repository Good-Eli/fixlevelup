import { randomUUID } from 'node:crypto';
import { decodeP05FContact } from '@fixlevelup/p03-contracts/p05';
import { parseP04JsonText } from '@fixlevelup/p03-contracts/p04-json';
import type { P05Context } from '../../authz/authorization.service.js';
import type { PoolClient } from 'pg';
import type { GuardedPool } from '../../infrastructure/admission/pool-guard.js';
import { requireRequestEffectsPool } from '../../infrastructure/admission/pool-guard.js';
import { MANAGED_PAYLOAD_KEY_MARKER, openManagedPayload } from '../crypto/payload-cipher.js';
import type { PayloadCiphertext } from '../crypto/payload-cipher.js';
import { deny } from '../intake/errors.js';
import { activePhone, modeOf } from '../intake/store.js';
import type { RequestRow, Snapshots } from '../intake/store.js';

const operation = 'P06_READ_REQUEST_CONTACT';

export interface ContactAudit {
  record(input: { staffId: string; requestId: string; contactRevisionId: string }): Promise<void>;
}

/** A distinct admitted connection confirms the audit before ciphertext is selected. */
export function createContactAudit(pool: GuardedPool): ContactAudit {
  requireRequestEffectsPool(pool);
  return { async record(input) {
    const client = await pool.connect().catch(() => deny('DEPENDENCY_UNAVAILABLE'));
    let discard = false;
    try {
      await client.query('BEGIN');
      await client.query('SET LOCAL synchronous_commit=on');
      await client.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
        [randomUUID(),operation,randomUUID(),JSON.stringify(input)]);
      discard = true;
      if ((await client.query('COMMIT')).command !== 'COMMIT') { return deny('DEPENDENCY_UNAVAILABLE'); }
      discard = false;
    } catch {
      if (!discard) {
        try { await client.query('ROLLBACK'); } catch { discard = true; }
      }
      return deny('DEPENDENCY_UNAVAILABLE');
    } finally { client.release(discard); }
  } };
}

export async function hasContactGrant(staff: P05Context, cityId: string): Promise<boolean> {
  const result = await staff.client.query(`SELECT 1 FROM p06_crm.contact_grants
    WHERE staff_id=$1 AND city_id=$2 AND capability='customer.pii.read'`, [staff.staffId,cityId]);
  return result.rowCount === 1;
}

export async function readContactDetails(staff: P05Context, row: RequestRow, config: Snapshots, audit: ContactAudit,
  recheck: () => Promise<void>) {
  const contactRevisionId = row.current_contact_revision_id;
  if (!contactRevisionId) { return deny('NOT_READY'); }
  await audit.record({ staffId:staff.staffId,requestId:row.id,contactRevisionId });
  await recheck();
  const revealPhone = await modeOf(staff.client,row) === 'PHONE' && await activePhone(staff.client,row) !== undefined;
  const { name,phone } = await readStoredContact(staff.client,row,config,recheck);
  return { name,phone:revealPhone ? phone : null };
}

/** Caller establishes its own authority before accessing an encrypted snapshot. */
export async function readStoredContact(client: PoolClient, row: Pick<RequestRow,'id'|'current_contact_revision_id'>,
  config: Snapshots, beforeOpen?: () => Promise<void>) {
  const { rows:[cell] } = await client.query<PayloadCiphertext & { id: string; revision: number }>(`SELECT payload.id,
      revision.revision,payload.nonce,payload.ciphertext,payload.auth_tag AS "authTag",payload.aad_context AS "aadContext"
    FROM foundation.request_contact_revisions revision JOIN foundation.request_payload_cells payload
      ON payload.id=revision.payload_cell_id AND payload.request_id=revision.request_id AND payload.revision=revision.revision
    WHERE revision.request_id=$1 AND revision.id=$2 AND payload.kind='CONTACT' AND payload.key_id=$3`,
  [row.id,row.current_contact_revision_id,MANAGED_PAYLOAD_KEY_MARKER]);
  if (!cell) { return deny('DEPENDENCY_UNAVAILABLE'); }
  const ref = { environment:config.environment,requestId:row.id,cellId:cell.id,revision:cell.revision,kind:'CONTACT' as const };
  const wrap = await config.keySlots.read(ref).catch(() => deny('DEPENDENCY_UNAVAILABLE'));
  await beforeOpen?.();
  try {
    const plaintext = openManagedPayload(ref,config.ring,cell,wrap);
    try {
      const parsed = parseP04JsonText(new TextDecoder('utf-8',{fatal:true}).decode(plaintext));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) { return deny('DEPENDENCY_UNAVAILABLE'); }
      return decodeP05FContact({ name:parsed['name'],phone:parsed['phone'] });
    } finally { plaintext.fill(0); }
  } catch { return deny('DEPENDENCY_UNAVAILABLE'); }
}
