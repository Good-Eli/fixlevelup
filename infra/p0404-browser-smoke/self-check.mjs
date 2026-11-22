import { randomUUID } from 'node:crypto';
import { signIn } from './commission.mjs';
import { host, origin, proofPort } from './isolation.mjs';

// Standalone real HTTP/SQL fixture-contract proof; deliberately not browser acceptance.
export async function selfCheck(fixture, proofToken, progress = () => {}) {
  const proof = (body, headers = {}) => fetch(`http://${host}:${proofPort}/proof`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${proofToken}`, ...headers },
    body, signal: AbortSignal.timeout(5000), redirect: 'error',
  });
  for (const [body, headers] of [['{}', { authorization: 'Bearer incorrect' }], ['{}', { origin }], [' '.repeat(8193), {}]]) {
    const response = await proof(body, headers);
    if (response.status !== 404) { throw new Error('Observer confinement failed'); }
    await response.body?.cancel();
  }
  const snapshot = async input => {
    const res = await proof(JSON.stringify(input));
    if (res.status !== 200 || res.headers.get('cache-control') !== 'no-store') { throw new Error('Observer read-back unavailable'); }
    return res.json();
  };
  const admin = await signIn(fixture.administrator);
  const manager = await signIn(fixture.manager);
  const base = `/settings/service-cities/${fixture.cityId}`;
  const writes = [];
  const command = async (actor, method, path, expected, etag, body, proof) => {
    const key = randomUUID();
    const call = actor === 'admin' ? admin : manager;
    const result = await call(path, expected, { method, etag, body, key });
    if (proof) { writes.push({ actor, ...result.data, ...proof, key }); }
    return result;
  };
  progress('item and price');
  const item = await command('admin','POST','/catalog/items',201,undefined,{ kind: 'PART', code: 'fixture-part', unit: 'piece' });
  await command('admin','POST',`/catalog/items/${item.data.id}/versions`,201,item.etag,
    { kind: 'PART', title: 'Synthetic Part', technicianVisible: true, publicVisible: false }, { kind: 'item' });
  const price = { amountMinor: '9223372036854775807', currency: 'RUB', sourceRef: 'synthetic-only',
    validFrom: new Date(Date.now() + 3600_000).toISOString() };
  await command('manager','POST',`/pricing/cities/${fixture.cityId}/items/${item.data.id}/price-versions`,201,'"p04-v0"',
    price, { kind: 'price', itemId: item.data.id });
  progress('district and coverage');
  const district = await command('admin','POST',`${base}/administrative-districts`,201,(await admin(base,200)).etag,
    { code: 'fixture-district', name: 'Synthetic District' }, { kind: 'district' });
  const area = await command('admin','POST',`${base}/service-areas`,201,(await admin(base,200)).etag,{ code: 'fixture-zone' });
  const areaPath = `${base}/service-areas/${area.data.id}/versions`;
  const revision = await command('admin','POST',areaPath,201,area.etag,{ name: 'Synthetic Zone' });
  await command('admin','PUT',`${areaPath}/${revision.data.id}/district-coverage`,200,revision.etag,
    { districts: [{ districtId: district.data.id, relation: 'FULL' }] },
    { kind: 'coverage', areaId: area.data.id, districtId: district.data.id });
  progress('FAQ and published contacts');
  const faq = await command('admin','POST','/content/blocks',201,undefined,
    { code: 'fixture-faq', kind: 'FAQ', scope: 'COMPANY', allowCompanyFallback: false });
  await command('admin','POST',`/content/blocks/${faq.data.id}/publish`,201,faq.etag,
    { title: 'Synthetic question', body: 'Synthetic answer', sourceRef: 'synthetic-only' }, { kind: 'faq' });
  const contact = await command('admin','POST',`${base}/versions`,201,(await admin(base,200)).etag,
    { displayName: 'P04 Primary', addressDisplay: 'Synthetic street 2', timezone: 'Europe/Moscow', publicContact: '+70000000001',
      officeHours: Array.from({ length: 7 }, () => [[540, 1080]]) });
  await command('admin','POST',`${base}/versions/${contact.data.id}/publish`,200,contact.etag,{}, { kind: 'contact', revisionId: contact.data.id });
  const deniedKey = randomUUID();
  const input = { writes, deniedKeys: [deniedKey] };
  progress('baseline read-back');
  const before = await snapshot(input);
  if (Object.keys(before.writes).length !== 6 || Object.values(before.writes).some(w => !w.exact)) {
    // Report only fixed-vocabulary labels and booleans/counts (never supplied inputs).
    console.log(JSON.stringify(before));
    throw new Error('Expected exact command evidence');
  }
  progress('outside CITY denied and unchanged read-back');
  await manager(`/pricing/cities/${fixture.outsideCityId}/items/${item.data.id}/price-versions`,404,
    { method: 'POST', etag: '"p04-v0"', body: price, key: deniedKey });
  const after = await snapshot(input);
  if (before.deniedReceipts !== 0 || JSON.stringify(before) !== JSON.stringify(after)) { throw new Error('Denied request changed persisted state'); }
  console.log(JSON.stringify(after));
}
