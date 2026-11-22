import { afterEach, expect, it, vi } from 'vitest';
import { decodeP03ContentRevision, decodeP03Page, decodeP03ContentSummary, decodeP03Receipt } from '@fixlevelup/p03-contracts';
import { ApiError } from '../app/crm/access/api';
import { FormError, SessionChanged, guardedRead, isUncertain, p03Read, prepareCommand, sendCommand } from '../app/crm/access/p0305-client';

const id = '11111111-1111-4111-8111-111111111111';
const other = '22222222-2222-4222-8222-222222222222';
const actor = { staffId:id, csrf:'x'.repeat(43), authVersion:1 };
const data = (v: unknown) => Response.json({data:v, meta:{requestId:id}});
const session = (a = actor) => data({staffId:a.staffId, csrfToken:a.csrf,authVersion:a.authVersion});
const signal = () => new AbortController().signal;
const fetchMock = () => { const fn = vi.fn<typeof fetch>(); vi.stubGlobal('fetch',fn); return fn; };
afterEach(() => { vi.unstubAllGlobals(); });

it('reuses exact immutable wire receipt arguments after a network loss or malformed 2xx', async () => {
  const f = fetchMock();
  f.mockRejectedValueOnce(new Error('synthetic network interruption'))
    .mockResolvedValueOnce(data({id,version:4,unexpected:'private'}))
    .mockResolvedValueOnce(data({id,version:4,revisionId:other,revisionVersion:1}));
  const draft = { title:'Черновик', body:'<script>plain</script>', sourceRef:'synthetic' };
  const command = prepareCommand({path:`content/blocks/${id}/publish`,version:3,read:v => decodeP03Receipt(v,'contentPublish'),limit:'content'},draft,actor);
  const body = JSON.stringify(draft);
  draft.body = 'changed after dispatch';
  await expect(sendCommand(signal(),actor,command)).rejects.toThrow();
  await expect(sendCommand(signal(),actor,command)).rejects.toThrow();
  await expect(sendCommand(signal(),actor,command)).resolves.toEqual({id,version:4,revisionId:other,revisionVersion:1});
  expect(command.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
  expect(f).toHaveBeenCalledTimes(3);
  for (const [url, init] of f.mock.calls) {
    expect(url).toBe(`/api/v1/content/blocks/${id}/publish`);
    expect(init).toMatchObject({method:'POST',body,credentials:'same-origin',mode:'same-origin',cache:'no-store',redirect:'error'});
    const headers = new Headers(init?.headers);
    expect(headers.get('idempotency-key')).toBe(command.idempotencyKey);
    expect(headers.get('if-match')).toBe('"p03-v3"');
    expect(headers.get('x-csrf-token')).toBe(actor.csrf);
  }
});
it('does not disclose stale actor data when the cookie or actor changes during a read', async () => {
  const f = fetchMock();
  f.mockResolvedValueOnce(session()).mockResolvedValueOnce(session({...actor,csrf:'z'.repeat(43)}));
  const read = vi.fn().mockResolvedValue('protected');
  await expect(guardedRead(signal(),actor,read)).rejects.toBeInstanceOf(SessionChanged);
  expect(read).toHaveBeenCalledOnce();
  const command = prepareCommand({path:'settings/versions',version:1,read:v => decodeP03Receipt(v,'companyPublish')},{},actor);
  expect(() => sendCommand(signal(),{...actor,staffId:other},command)).toThrow(SessionChanged);
  expect(() => sendCommand(signal(),{...actor,authVersion:2},command)).toThrow(SessionChanged);
  expect(f).toHaveBeenCalledTimes(2);
});
it('rejects a late successful response from an aborted generation', async () => {
  const f = fetchMock().mockResolvedValueOnce(session()).mockResolvedValueOnce(session());
  const generation = new AbortController();
  await expect(guardedRead(generation.signal,actor,() => { generation.abort(); return Promise.resolve('discarded'); })).rejects.toMatchObject({name:'AbortError'});
  // Mocked fetch ignores the signal; the client must still refuse to apply stale data.
  expect(f).toHaveBeenCalledTimes(2);
});
it('distinguishes geo and p03 preconditions and rejects oversized UTF-8 JSON before transport', () => {
  const f = fetchMock();
  const spec = {path:'settings/service-cities',read:() => ({id,version:1}),version:9,family:'geo' as const};
  expect(prepareCommand(spec,{},actor).ifMatch).toBe('"geo-v9"');
  expect(() => prepareCommand(spec,{x:'😀'.repeat(1100)},actor)).toThrow(FormError);
  expect(() => prepareCommand({...spec,path:'settings/../auth/me'},{},actor)).toThrow(FormError);
  expect(f).not.toHaveBeenCalled();
});
it('sends geo-v0 only for an explicitly marked staff aggregate and accepts only positive receipts', async () => {
  const f = fetchMock().mockResolvedValueOnce(data({id,version:1}));
  const staff = {path:`settings/service-cities/${id}/technicians/${other}/city-memberships`,version:0,read:(v: unknown) => decodeP03Receipt(v,'companyPublish'),family:'geo' as const};
  expect(() => prepareCommand(staff,{},actor)).toThrow(FormError);
  expect(() => prepareCommand({...staff,family:'p03',allowZeroVersion:true},{},actor)).toThrow(FormError);
  expect(() => prepareCommand({...staff,version:-1,allowZeroVersion:true},{},actor)).toThrow(FormError);
  const command = prepareCommand({...staff,allowZeroVersion:true},{},actor);
  expect(command.ifMatch).toBe('"geo-v0"');
  await expect(sendCommand(signal(),actor,command)).resolves.toEqual({id,version:1});
  expect(new Headers(f.mock.calls[0]?.[1]?.headers).get('if-match')).toBe('"geo-v0"');
  expect(staff.read({id,version:0})).toBeNull();
});
it('decodes bounded lists and exact content independently; never treats summary text as a revision', async () => {
  const f = fetchMock();
  const row = { id,blockId:other,title:'Название',version:1,publishedAt:'2026-11-22T00:00:00.000Z' };
  const dec = (v: unknown) => decodeP03Page(v,decodeP03ContentSummary);
  f.mockResolvedValueOnce(data({items:[row],pageInfo:{hasMore:true,nextCursor:'xyz'}}))
    .mockResolvedValueOnce(data({items:[{...row,body:'prohibited'}],pageInfo:{hasMore:false,nextCursor:null}}))
    .mockResolvedValueOnce(data({...row,body:'<img src=x onerror=alert(1)>',sourceRef:'javascript:example'}));
  await expect(p03Read(signal(),'content/blocks/example/revisions',dec)).resolves.toMatchObject({pageInfo:{hasMore:true,nextCursor:'xyz'}});
  await expect(p03Read(signal(),'content/blocks/example/revisions',dec)).rejects.toThrow();
  await expect(p03Read(signal(),'content/blocks/example/revisions/one',decodeP03ContentRevision)).resolves.toMatchObject({body:'<img src=x onerror=alert(1)>',sourceRef:'javascript:example'});
});
it('refuses an oversized body even when content-length understates it', async () => {
  const f = fetchMock();
  f.mockResolvedValueOnce(new Response(JSON.stringify({data:{id,version:1},meta:{requestId:id}}),{headers:{'Content-Length':'1'}}));
  await expect(p03Read(signal(),'settings/versions',v => decodeP03Receipt(v,'companyPublish'),16)).rejects.toThrow('Invalid response size');
  expect([400,401,403,404,409,412,413,428].every(status => !isUncertain(new ApiError(status)))).toBe(true);
  expect(isUncertain(new ApiError(500))).toBe(true);
});
