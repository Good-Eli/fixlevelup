import { randomBytes, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect } from 'vitest';
import { lockAccessPolicy } from '../src/authz/rbac-lock.js';
import { acquireCompanySettingsLock } from '../src/settings/configuration/company-lock.js';
import { hashPassword } from '../src/staff/password.js';
import type { RbacFixture, Web } from './rbac-fixture.js';

// Literal §7 permission inventory; not imported from the authorization evaluator.
const grants = ['requests.read','requests.create','requests.review','requests.contact.manage',
  'requests.coverage.assess','requests.ready','requests.cancel'] as const;
export type StaffProof = Pick<Web,'id'|'cookie'|'token'>;

export async function withHttpMatrixActors<T>(lab: RbacFixture, city: string, run: (actors: {
  readonly global: StaffProof; readonly cityAdmin: StaffProof; readonly manager: StaffProof; readonly custom: StaffProof;
  readonly reader: StaffProof; readonly actionOnly: StaffProof; readonly technicianToken: string; readonly wrong: StaffProof;
  readonly noCity: StaffProof;
  setAdminScope(scope: 'GLOBAL' | 'CITY' | 'MIXED'): Promise<void>;
  revokeCity(staff: StaffProof): Promise<void>;
}) => Promise<T>): Promise<T> {
  const adminRole=await lab.systemRole('ADMIN');
  const managerRole=await lab.systemRole('MANAGER');
  const otherCity=randomUUID();
  const customRole=randomUUID(), readRole=randomUUID(), actionRole=randomUUID();
  const provision=async (write: (client: PoolClient) => Promise<void>) => {
    const client=await lab.db.connect();
    try {
      await client.query('BEGIN');
      await lockAccessPolicy(client,'write');
      await write(client);
      await client.query('COMMIT');
    } finally { try { await client.query('ROLLBACK'); } finally { client.release(); } }
  };
  await provision(async client => {
    await acquireCompanySettingsLock(client);
    // DRAFT administrative membership is real, but leaves SINGLE_CITY intact.
    await client.query('INSERT INTO foundation.service_cities(id,code) VALUES ($1,$2)',[otherCity,`matrix-${otherCity.slice(0,8)}`]);
    await client.query(`INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type)
      SELECT $1,c,'CITY' FROM unnest($2::text[]) c ON CONFLICT (role_id,permission_code) DO NOTHING`,[managerRole,grants]);
    for (const [id,codes] of [[customRole,grants],[readRole,['requests.read']],[actionRole,grants.slice(1)]] as const) {
      await client.query(`INSERT INTO foundation.roles(id,code,name) VALUES ($1,$2,'Synthetic matrix role')`,
        [id,`CUSTOM_P05_${id.slice(0,8).toUpperCase()}`]);
      await client.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
        SELECT $1,c,'CITY' FROM unnest($2::text[]) c`,[id,codes]);
    }
  });
  const actor=async (roleId:string, kind:'ADMIN'|'MANAGER', assignment?: string) => {
    const id=randomUUID();
    const login=randomBytes(24).toString('hex'), password=randomBytes(24).toString('hex');
    const passwordHash=await hashPassword(password);
    await provision(async client => {
      await client.query(`INSERT INTO foundation.staff(id,role,employment_state,auth_version) VALUES ($1,$2,'ACTIVE',0)`,[id,kind]);
      // ADMIN must already have a Web credential at the role transaction's
      // deferred COMMIT check. CITY membership needs both facts at INSERT.
      await client.query(`INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES ($1,$2,$3)`,[id,login,passwordHash]);
      await client.query(`INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id) VALUES ($1,$2,$3)`,[randomUUID(),id,roleId]);
      if (assignment) {
        await client.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by) VALUES ($1,$2,$3,$4)`,
          [randomUUID(),id,assignment,lab.admin.id]);
      }
    });
    return await lab.login(id,login,password);
  };
  const cityAdmin=await actor(adminRole,'ADMIN',city);
  const manager=await actor(managerRole,'MANAGER',city);
  const custom=await actor(customRole,'MANAGER',city);
  const wrong=await actor(managerRole,'MANAGER',otherCity);
  const noCity=await actor(customRole,'MANAGER');
  const reader=await actor(readRole,'MANAGER',city);
  const actionOnly=await actor(actionRole,'MANAGER',city);
  const technicianId=await lab.createStaff('TECHNICIAN');
  const technicianToken=(await lab.tg(technicianId)).token;
  const setAdminScope = (scope:'GLOBAL'|'CITY'|'MIXED') => provision(async client => {
    expect((await client.query(`DELETE FROM foundation.role_permissions WHERE role_id=$1 AND permission_code=ANY($2::text[])`,
      [adminRole,grants])).rowCount).toBe(grants.length);
    expect((await client.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      SELECT $1,c,CASE WHEN $2='MIXED' THEN CASE WHEN c='requests.read' THEN 'GLOBAL' ELSE 'CITY' END ELSE $2 END
      FROM unnest($3::text[]) c`,[adminRole,scope,grants])).rowCount).toBe(grants.length);
  });
  const revokeCity = (staff: StaffProof) => provision(async client => {
    expect((await client.query(`UPDATE foundation.staff_admin_city_assignments SET revoked_at=clock_timestamp(),revoked_by=$2
      WHERE staff_id=$1 AND city_id=$3 AND revoked_at IS NULL`,[staff.id,lab.admin.id,city])).rowCount).toBe(1);
  });
  try {
    return await run({global:lab.admin,cityAdmin,manager,custom,reader,actionOnly,technicianToken,wrong,noCity,setAdminScope,revokeCity});
  } finally { await setAdminScope('GLOBAL'); }
}
