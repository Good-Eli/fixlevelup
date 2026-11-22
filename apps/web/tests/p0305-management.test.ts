import { expect, it } from 'vitest';
import { decodeP03Readiness, P03_CAPABILITIES, P03_CAPABILITY_METADATA, type P03Capability } from '@fixlevelup/p03-contracts';
import { type Access, type Permission, type Role } from '../app/crm/access/api';
import { changeMapping, hoursFromForm, reviewedPublication } from '../app/crm/access/geography';
import { geoAdmins, geoAreaVersions, geoCoverage, geoTechAreas, geoTechCities } from '../app/crm/access/geography-wire';
import { managementCommand, p03Tabs } from '../app/crm/access/management';
import { allowedScopes, canEditGrant, delegable, hasP03, p03ReplacementAllowed } from '../app/crm/access/workspace';

const a = '11111111-1111-4111-8111-111111111111';
const b = '22222222-2222-4222-8222-222222222222';
const c = '33333333-3333-4333-8333-333333333333';
const role: Role = { id:b, code:'MANAGER', type:'SYSTEM', status:'ACTIVE', name:'Синтетическая роль', description:null,version:1,updatedAt:'',updatedBy:null,assignedCount:null,activeAssignedCount:null,permissions:[] };
const admin: Access = { staffId:a, role:{id:a,code:'ADMIN',type:'SYSTEM'},permissions:['roles.permissions.manage'] };
function catalog(code: P03Capability): Permission {
  const p = P03_CAPABILITY_METADATA[code]; return { code,scope:p.scopes[0] ?? 'GLOBAL',...p,scopes:[...p.scopes] };
}

it('exposes no new workspace tab or authority solely from ADMIN label or staff permissions', () => {
  expect(P03_CAPABILITIES).toHaveLength(18);
  expect(p03Tabs(admin)).toEqual([]);
  expect(hasP03({...admin,permissions:['legal.read']},'legal.read')).toBe(false);
  const weak: Access = { staffId:b,role,permissions:[],p03Permissions:[{code:'legal.read',scope:'GLOBAL'},{code:'content.read',scope:'CITY'},{code:'settings.readiness.read',scope:'GLOBAL'}] };
  expect(p03Tabs(weak).map(t => t.id)).toEqual(['content','readiness']);
  expect(p03Tabs({...weak,role:{...role,code:'TECHNICIAN'}})).toEqual([]);
});
it('applies actual role/catalog restrictions to all 18 codes, including four company reference pairs', () => {
  const custom: Role = {...role,type:'CUSTOM',code:'CUSTOM_TEST'};
  const technician = {...role,code:'TECHNICIAN'};
  for (const code of P03_CAPABILITIES) {
    const p = catalog(code);
    expect(allowedScopes(technician,p)).toEqual([]);
    const meta = P03_CAPABILITY_METADATA[code];
    const expected = meta.systemAdminOnly ? [] : meta.globalSystemAdminOnly ? ['CITY'] : ['GLOBAL'];
    expect(allowedScopes(role,p)).toEqual(expected);
    expect(allowedScopes(custom,p)).toEqual(expected);
    expect(allowedScopes({...role,...admin.role},p)).toEqual(meta.scopes);
  }
});
it('allows retention on another role, never converts retention or CITY possession into a new grant', () => {
  const grant = { code:'content.read',scope:'CITY' } as const;
  const existing = {...role,permissions:[grant]};
  expect(canEditGrant(admin,existing,catalog(grant.code),false)).toBe(true);
  expect(p03ReplacementAllowed(admin,existing,[grant])).toBe(true);
  expect(p03ReplacementAllowed(admin,role,[grant])).toBe(false);
  expect(p03ReplacementAllowed(admin,{...existing,id:admin.role.id,code:'ADMIN'},[grant])).toBe(false);
  expect(p03ReplacementAllowed(admin,{...existing,code:'ADMIN'},[{...grant,scope:'GLOBAL'}])).toBe(false);
  expect(delegable({...admin,p03Permissions:[grant]},existing)).toBe(false);
  const global = {...admin,p03Permissions:[{...grant,scope:'GLOBAL'} as const]};
  expect(delegable(global,existing)).toBe(true);
  expect(p03ReplacementAllowed(global,role,[grant])).toBe(true);
});
it('uses closed scope/type routes and strict receipt shape for versioned callback publish', () => {
  managementCommand((spec, body) => {
    expect(spec.path).toBe(`settings/references/callback_interval/${b}/versions?cityId=${a}`);
    expect(spec.version).toBe(8);
    expect(body).toMatchObject({cityVersionId:c,interval:{startMinute:0,endMinute:60}});
    expect(spec.read({id:b,version:9})).toBeNull();
    expect(spec.read({id:b,version:9,revisionId:c,revisionVersion:1})).toMatchObject({revisionId:c});
  },'referencePublish',{label:'X',sourceRef:'Ref',validFrom:'2026-11-22T00:00:00.000Z',validUntil:null,cityVersionId:c,interval:{startMinute:0,endMinute:60}},
  {type:'callback_interval',id:b},8,{cityId:a});
});
it('preserves off-page/archived district mappings during arbitrary picker edits', () => {
  const original = [{districtId:b,relation:'PARTIAL' as const,description:'Вне страницы'}];
  const edited = changeMapping(original,c,{districtId:c,relation:'FULL',description:null});
  expect(edited).toEqual([...original,{districtId:c,relation:'FULL',description:null}]);
  expect(changeMapping(edited,c,null)).toEqual(original);
  expect(geoCoverage({areaVersionId:a,version:4,items:edited})?.items).toEqual(edited);
  expect(geoCoverage({areaVersionId:a,version:4,items:edited,pageInfo:{hasMore:true,nextCursor:'other'}})).toBeNull();
});
it('accepts staff v0 histories but rejects v0 geography catalog snapshots', () => {
  const page = {version:0,items:[],pageInfo:{hasMore:false,nextCursor:null}};
  expect(geoAdmins(page)).toEqual(page);
  expect(geoTechCities(page)).toEqual(page);
  expect(geoTechAreas(page)).toEqual(page);
  expect(geoAreaVersions(page)).toBeNull();
  expect(geoCoverage({areaVersionId:a,version:0,items:[]})).toBeNull();
});
it('requires full same-revision coverage to publish the reviewed area snapshot', () => {
  const revision = {id:a,version:1};
  expect(reviewedPublication(revision,null,2)).toBeNull();
  expect(reviewedPublication(revision,{areaVersionId:b,version:1},2)).toBeNull();
  expect(reviewedPublication(revision,{areaVersionId:a,version:2},2)).toBeNull();
  expect(reviewedPublication(revision,{areaVersionId:a,version:1},2)).toEqual({version:1,expectedAreaVersion:2});
});
it('uses explicit seven weekdays and validates sorted no-overlap office-hours intervals', () => {
  const form = new FormData(); form.set('hours0','09:00–12:00, 13:00-24:00');
  expect(hoursFromForm(form)).toEqual([[[540,720],[780,1440]],[],[],[],[],[],[]]);
  form.set('hours1','09:00–13:00, 12:00–18:00'); expect(() => hoursFromForm(form)).toThrow();
});
it('cannot decode extra sensitive settings in the safe readiness projection', () => {
  const dto = {items:[],pageInfo:{hasMore:false,nextCursor:null},sections:[{section:'P04',status:'NOT_IMPLEMENTED',missing:[]}]};
  // The contract may require the complete set of fixed unsupported sections, never an arbitrary internal projection.
  expect(decodeP03Readiness({...dto,primaryCityId:a,ready:true})).toBeNull();
  expect(decodeP03Readiness({...dto,sections:[{section:'COMPANY_SETTINGS',status:'MISSING',missing:['SYNTHETIC-SECRET-REF']}]})).toBeNull();
});
