import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, errorMessage, ApiError, type Access, type Role } from '../app/crm/access/api';
import { canEditGrant, canTarget, load } from '../app/crm/access/workspace';

const actor = '22222222-2222-4222-8222-222222222222';
const target = '33333333-3333-4333-8333-333333333333';
const token = 'x'.repeat(43);
const person = { id:target, roleId:target, role:'TECHNICIAN', roleName:'Мастер', employmentState:'ACTIVE' as const, displayName:null, version:2 };
const role: Role = { id:target, code:'CUSTOM_1', type:'CUSTOM', status:'ACTIVE', name:'Тест', description:'', version:3, updatedAt:'test', updatedBy:null, activeAssignedCount:0, assignedCount:0, permissions:[] };
const principal: Access = { staffId:actor, role:{id:actor,code:'ADMIN',type:'SYSTEM'}, permissions:[] };
const res = (data: unknown, status=200) => Response.json({data}, {status});
const client = (csrf?: string) => api(new AbortController().signal, csrf);
const stub = () => { const fn = vi.fn<typeof fetch>(); vi.stubGlobal('fetch',fn); return fn; };
afterEach(() => { vi.unstubAllGlobals(); });

describe('CRM typed API boundary', () => {
  it('uses same-origin HTTPS proxy path, no-store, session CSRF, distinct login barrier and strong versions', async () => {
    const fn = stub(); fn.mockResolvedValueOnce(res({staffId:actor,csrfToken:token})).mockResolvedValueOnce(res({id:target,version:2})).mockResolvedValueOnce(res({id:role.id,version:3})).mockResolvedValueOnce(new Response(null,{status:204}));
    const c = client(token); await c.login('synthetic','fixture'); await c.assign(target,1,actor); await c.permissions(role,[]); await c.logout();
    const routes = fn.mock.calls.map(([path, init]) => {
      expect(init).toMatchObject({credentials:'same-origin', mode:'same-origin', cache:'no-store', redirect:'error'});
      expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
      return [path,init?.method,new Headers(init?.headers).get('x-csrf-token'),new Headers(init?.headers).get('if-match'),init?.body];
    });
    expect(routes).toEqual([['/api/v1/auth/login','POST','login',null,JSON.stringify({login:'synthetic',password:'fixture'})],
      [`/api/v1/staff/${target}/role`,'PUT',token,'"staff-v1"',JSON.stringify({roleId:actor})],
      [`/api/v1/roles/${target}/permissions`,'PUT',token,'"role-v3"','{"permissions":[]}'],['/api/v1/auth/logout','POST',token,null,'{}']]);
  });
  it('does not send unauthenticated mutations, invalid IDs or unsafe versions', async () => {
    const fn = stub(); await expect(client().createRole('r','')).rejects.toThrow('Missing CSRF');
    expect(() => client(token).assign('../auth/me',1,target)).toThrow(); expect(() => client(token).deactivate(target,-1)).toThrow(); expect(fn).not.toHaveBeenCalled();
  });
  it('fails closed on an invalid identity/envelope and never includes server error text', async () => {
    const fn = stub(); fn.mockResolvedValueOnce(res({staffId:actor, csrfToken:''})).mockResolvedValueOnce(res({message:'never-render-this'},412));
    await expect(client().me()).rejects.toThrow(); expect(new Headers(fn.mock.calls[0]?.[1]?.headers).get('x-auth-request')).toBe('1');
    await expect(client(token).deactivate(target,1)).rejects.toMatchObject({status:412}); expect(errorMessage(new ApiError(412))).toContain('Версия'); expect(fn).toHaveBeenCalledTimes(2);
  });
});
describe('effective grants govern reads and actions independently', () => {
  it('can open a workspace with only staff.create; no roles, staff or self enumeration', async () => {
    const fn = stub(); fn.mockResolvedValueOnce(res({...principal,permissions:['staff.create']}));
    const snapshot = await load(client(token),actor); expect(snapshot.self).toBeNull(); expect(snapshot.people).toEqual([]);
    expect(fn.mock.calls.map(call => call[0])).toEqual(['/api/v1/access']);
  });
  it('rejects response for another actor without querying protected lists', async () => {
    const fn = stub(); fn.mockResolvedValueOnce(res({...principal,staffId:target,permissions:['roles.read','staff.read']}));
    await expect(load(client(token),actor)).rejects.toThrow('Session changed'); expect(fn).toHaveBeenCalledTimes(1);
  });
  it('keeps self grants separate, stops custom roles masquerading as ADMIN and locks protected/self escalation', () => {
    const manager: Access = {...principal, role:{id:actor,code:'MANAGER',type:'SYSTEM'}, permissions:['staff.update']};
    expect(canTarget(manager,person)).toBe(true); expect(canTarget(manager,{...person,id:actor})).toBe(false); expect(canTarget(manager,{...person,role:'ADMIN'})).toBe(false);
    const a = {...principal,permissions:['roles.permissions.manage','staff.update']}; expect(canEditGrant(a,role,'staff.update',false)).toBe(true);
    expect(canEditGrant(a,role,'staff.create',false)).toBe(false);
    expect(canEditGrant(a,{...role,permissions:[{code:'staff.create',scope:'GLOBAL'}]},'staff.create',false)).toBe(true);
    expect(canEditGrant(a,role,'roles.archive',true)).toBe(false); expect(canEditGrant(a,{...role,id:actor},'staff.create',false)).toBe(false);
    expect(canEditGrant({...a,role:{...a.role,type:'CUSTOM'}},role,'staff.update',false)).toBe(false);
  });
});
