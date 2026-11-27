import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { P05FContact } from '@fixlevelup/p03-contracts/p05';
import type { GuardedPool } from '../../infrastructure/admission/pool-guard.js';
import { requireRequestEffectsPool } from '../../infrastructure/admission/pool-guard.js';
import { readStoredContact } from '../card/contacts.js';
import { lockConsent } from '../intake/basis.js';
import type { StaffEvidence } from '../intake/basis.js';
import { deny, RequestFailure } from '../intake/errors.js';
import type { RequestRow, Snapshots } from '../intake/store.js';
import { livePhonePermission, readRegistryEvidence, registryBasisJoins, registryVisibilitySql } from '../registry/store.js';
import { normalizeSearchName } from './contract.js';
import type { SearchKind } from './contract.js';

type Target = Pick<RequestRow,'id'|'city_id'|'current_contact_revision_id'>;
const searchFence = '734306,1';
const nullUuid = '00000000-0000-0000-0000-000000000000';

export class ContactSearchIndex {
  private readonly key: Buffer;

  constructor(private readonly pool: GuardedPool, private readonly environment: string,
    private readonly generation: string, key: Uint8Array) {
    requireRequestEffectsPool(pool);
    if (key.length !== 32 || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(generation)) {
      throw new Error('Invalid contact search key configuration');
    }
    this.key = Buffer.from(key);
  }

  private digest(context: readonly string[]): Buffer {
    return createHmac('sha256',this.key).update(JSON.stringify(['p06-contact-search-v1',this.environment,this.generation,...context])).digest();
  }

  token(kind: 'name'|'phone', cityId: string, value: string): Buffer {
    return this.digest(['token',cityId,kind,value]);
  }

  async lock(client: PoolClient) {
    await client.query(`SELECT pg_catalog.pg_advisory_xact_lock_shared(${searchFence})`);
  }

  async assertCurrent(client: PoolClient) {
    const { rows:[active] } = await client.query<{ generation:string; key_check:Buffer }>(
      'SELECT generation,key_check FROM p06_crm.search_generation WHERE singleton');
    if (active?.generation !== this.generation || !timingSafeEqual(this.digest(['generation-check']),active.key_check)) {
      return deny('NOT_READY');
    }
  }

  async setContact(client: PoolClient, row: Target, contact: P05FContact, phoneEnabled: boolean) {
    await this.assertCurrent(client);
    await client.query('DELETE FROM p06_crm.contact_search WHERE request_id=$1',[row.id]);
    await this.insertContact(client,row,contact,phoneEnabled);
  }

  private async insertContact(client: PoolClient, row: Target, contact: P05FContact, phoneEnabled: boolean) {
    const name = this.token('name',row.city_id,normalizeSearchName(contact.name));
    const phone = phoneEnabled ? this.token('phone',row.city_id,contact.phone) : null;
    const result = await client.query(`INSERT INTO p06_crm.contact_search
      (request_id,city_id,contact_revision_id,created_at,public_number,name_token,phone_token)
      SELECT id,city_id,current_contact_revision_id,created_at,public_number,$4,$5 FROM foundation.requests
      WHERE id=$1 AND city_id=$2 AND current_contact_revision_id=$3`,[row.id,row.city_id,row.current_contact_revision_id,name,phone]);
    if (result.rowCount !== 1) { return deny('NOT_READY'); }
  }

  async removePhone(client: PoolClient, row: Target) {
    await client.query('UPDATE p06_crm.contact_search SET phone_token=NULL WHERE request_id=$1 AND contact_revision_id=$2',
      [row.id,row.current_contact_revision_id]);
  }

  async removeProcessingConsent(client: PoolClient, sessionId: string, consentId: string) {
    await client.query(`DELETE FROM p06_crm.contact_search token USING foundation.request_session_submits submit
      WHERE submit.session_id=$1 AND submit.consent_id=$2 AND token.request_id=submit.request_id`,[sessionId,consentId]);
  }

  /** Quota consumption and attempt audit survive a later read denial or connection failure. */
  async admit(staffId: string, cityId: string, kind: SearchKind) {
    const client = await this.pool.connect().catch(() => deny('DEPENDENCY_UNAVAILABLE'));
    let discard = false;
    try {
      await client.query('BEGIN');
      await client.query('SET LOCAL synchronous_commit=on');
      await this.useBudget(client,'CITY',cityId,cityId,240);
      await this.useBudget(client,'STAFF',cityId,staffId,24);
      await client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)`,
        [randomUUID(),'P06_SEARCH_REQUESTS',randomUUID(),JSON.stringify({staffId,cityId,kind})]);
      discard = true;
      if ((await client.query('COMMIT')).command !== 'COMMIT') { return deny('DEPENDENCY_UNAVAILABLE'); }
      discard = false;
    } catch (error) {
      if (!discard) {
        try { await client.query('ROLLBACK'); } catch { discard = true; }
      }
      if (error instanceof RequestFailure) { throw error; }
      return deny('DEPENDENCY_UNAVAILABLE');
    } finally { client.release(discard); }
  }

  private async useBudget(client: PoolClient, scope: 'CITY'|'STAFF', cityId: string, subjectId: string, limit: number) {
    const { rowCount } = await client.query(`
      INSERT INTO p06_crm.search_budget AS budget(scope,city_id,subject_id,minute,used)
      VALUES ($1,$2,$3,date_trunc('minute',CURRENT_TIMESTAMP),1)
      ON CONFLICT (scope,city_id,subject_id) DO UPDATE SET minute=GREATEST(budget.minute,excluded.minute),
        used=CASE WHEN budget.minute < excluded.minute THEN 1 ELSE budget.used+1 END
      WHERE budget.minute < excluded.minute OR budget.used < $4`,[scope,cityId,subjectId,limit]);
    if (rowCount !== 1) { return deny('QUOTA'); }
  }

  /** Maintenance caller supplies an isolated owner transaction and the authoritative evidence view. */
  async rebuild(client: PoolClient, config: Snapshots, openEvidence: (client: PoolClient) => Promise<(evidence: StaffEvidence) => boolean>) {
    await client.query(`SELECT pg_catalog.pg_advisory_xact_lock(${searchFence})`);
    if (!await lockConsent(client,undefined,'shared')) { return deny('NOT_READY'); }
    const isCurrent = await openEvidence(client);
    await client.query('DELETE FROM p06_crm.contact_search');
    let after = nullUuid;
    for (;;) {
      const { rows } = await client.query<Target & { evidenceId:string|null; procedureRevision:string|null;
        validUntil:Date|null; phoneEnabled:boolean }>(`
        SELECT request.id,request.city_id,request.current_contact_revision_id,
          manual.id AS "evidenceId",manual.procedure_revision AS "procedureRevision",manual.valid_until AS "validUntil",
          ${livePhonePermission} AS "phoneEnabled"
        FROM foundation.requests AS request ${registryBasisJoins}
        WHERE request.id > $1::uuid AND request.current_contact_revision_id IS NOT NULL AND ${registryVisibilitySql(true)}
        ORDER BY request.id LIMIT 100`,[after]);
      for (const row of rows) {
        const evidence = readRegistryEvidence(row);
        if (evidence && !isCurrent(evidence)) { continue; }
        const checkEvidence = evidence ? async () => {
          const { rows:[sample] } = await client.query<{ now:Date }>('SELECT clock_timestamp() AS now');
          if (!sample || evidence.validUntil.getTime() <= sample.now.getTime() || !isCurrent(evidence)) {
            return deny('CONSENT_REQUIRED');
          }
        } : undefined;
        let contact: P05FContact;
        try { contact = await readStoredContact(client,row,config,checkEvidence); }
        catch (error) {
          if (error instanceof RequestFailure && error.code === 'CONSENT_REQUIRED') { continue; }
          throw error;
        }
        await this.insertContact(client,row,contact,row.phoneEnabled);
      }
      const last = rows.at(-1);
      if (!last || rows.length < 100) { break; }
      after = last.id;
    }
    await client.query(`INSERT INTO p06_crm.search_generation(singleton,generation,key_check) VALUES (true,$1,$2)
      ON CONFLICT (singleton) DO UPDATE SET generation=excluded.generation,key_check=excluded.key_check`,
    [this.generation,this.digest(['generation-check'])]);
  }
}
