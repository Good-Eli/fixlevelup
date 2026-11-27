import { readFile } from 'node:fs/promises';
import type { RbacFixture } from './rbac-fixture.js';
import { lockAccessPolicy } from '../src/authz/rbac-lock.js';

export async function installCommentFixture(lab: RbacFixture) {
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1'
    || (process.env['FIXLEVELUP_P06_COMMENT_PROOF'] !== '1' && process.env['FIXLEVELUP_P06_SEARCH_PROOF'] !== '1')
    || !/^fixlevelup_configuration_test_[0-9a-f]{24}$/.test(lab.database)) {
    throw new Error('P06 comments fixture requires its isolated database');
  }
  const schema = await readFile(new URL('../../../infra/p06-lab/crm-v1.sql',import.meta.url),'utf8');
  await lab.db.query(schema);
}

export async function grantCommentFixture(lab: RbacFixture, staffId: string, cityId: string, write: boolean) {
  await changeGrants(lab, `INSERT INTO p06_crm.comment_grants(staff_id,city_id,can_read,can_write) VALUES ($1,$2,true,$3)`,
    [staffId,cityId,write]);
}

export async function grantContactFixture(lab: RbacFixture, staffId: string, cityId: string) {
  await changeGrants(lab, `INSERT INTO p06_crm.contact_grants(staff_id,city_id,capability) VALUES ($1,$2,'customer.pii.read') ON CONFLICT DO NOTHING`,
    [staffId,cityId]);
}

async function changeGrants(lab: RbacFixture, sql: string, parameters: (string | boolean)[]) {
  const client = await lab.db.connect();
  try {
    await client.query('BEGIN');
    await lockAccessPolicy(client,'write');
    await client.query(sql,parameters);
    await client.query('COMMIT');
  } finally {
    try { await client.query('ROLLBACK'); } finally { client.release(); }
  }
}
