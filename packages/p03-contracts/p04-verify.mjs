import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { p04Dist, renderP04 } from './generate-p04.mjs';
import {
  P04_PREFIX, P04_ROUTES, P04BodyLimit, createP04Client, decodeP04Body, decodeP04Data,
  decodeP04Params, decodeP04Query, matchP04Route,
} from './dist/p04.js';

for (const [file, content] of Object.entries(renderP04())) {
  assert.equal(readFileSync(new URL(file, p04Dist), 'utf8'), content, `${file} is reproducible`);
}
const artifact = JSON.parse(readFileSync(new URL('p04-openapi.json', p04Dist), 'utf8'));
assert.equal(artifact.openapi, '3.1.0');
assert.equal(P04_PREFIX, '/api/v1');
const id = 'a1234567-1234-4321-8123-123456789012';
const id2 = 'b1234567-1234-4321-8123-123456789012';
const at = '2030-01-02T03:04:05.000Z';
const envelope = (data) => ({ data, meta: { requestId: id } });
const page = { items: [], pageInfo: { nextCursor: null } };
const only = (fn) => assert.throws(fn, TypeError);

// Independent §2 inventory: check exact method, path and operation, not just generated parity.
const expected = {};
function family(name, base, routes) {
  for (const [action, method, suffix] of routes) {
    expected[name + action] = [method, `/api/v1${base}${suffix}`];
  }
}
const directory = [
  ['List', 'GET', ''], ['Get', 'GET', '/{id}'], ['Versions', 'GET', '/{id}/versions'], ['Version', 'GET', '/{id}/versions/{versionId}'],
  ['Create', 'POST', ''], ['Publish', 'POST', '/{id}/versions'], ['Archive', 'POST', '/{id}/archive'],
];
for (const [name, segment] of [['category','categories'],['brand','brands'],['model','models'],['fault','faults'],['item','items']]) {
  family(name, `/catalog/${segment}`, directory);
}
family('mapping', '/catalog/fault-service-mappings', [
  ...directory.filter(([action]) => ['List','Get','Create','Archive'].includes(action)), ['Publish','POST','/{id}/publish'],
]);
family('rule', '/pricing/rules', directory.filter(([action]) => ['List','Get','Create','Archive'].includes(action)));
family('city', '/pricing/cities', [
  ['List','GET',''], ['Categories','GET','/{cityId}/categories'], ['Items','GET','/{cityId}/items'], ['Rules','GET','/{cityId}/rules'],
]);
family('pricing', '/pricing/readiness', [['Readiness','GET','']]);
const stream = [['List','GET',''],['Get','GET','/{versionId}'],['Publish','POST',''],['Close','POST','/{versionId}/close'],['Replace','POST','/{versionId}/replace']];
const cityBase = '/pricing/cities/{cityId}';
family('fixed', `${cityBase}/items/{itemId}/price-versions`, stream);
family('ruleVersion', `${cityBase}/rules/{ruleId}/versions`, stream);
family('policy', `${cityBase}/policy-versions`, stream);
const estimates = `${cityBase}/public-estimates`;
family('estimate', estimates, [['List','GET',''],['Get','GET','/{estimateId}'],['Create','POST',''],['Archive','POST','/{estimateId}/archive']]);
family('estimate', `${estimates}/{estimateId}/versions`, stream.map(([name, method, suffix]) => [name === 'List' ? 'Versions' : name === 'Get' ? 'Version' : name, method, suffix]));
family('avito', '/content/external-reviews', directory);
assert.deepEqual(Object.keys(P04_ROUTES).sort(), Object.keys(expected).sort());
const component = (schema) => schema.$ref ? artifact.components.schemas[schema.$ref.split('/').at(-1)] : schema;
const getData = (schema) => component(schema).properties.data;
const fields = (schema) => component(schema).properties;
const versionReceiptOps = Object.keys(expected).filter(op => (op.endsWith('Publish') && op !== 'mappingPublish') || op.endsWith('Replace'));
const mutationOps = Object.keys(expected).filter(op => expected[op][0] === 'POST');
assert.equal(Object.values(artifact.paths).reduce((n, methods) => n + Object.keys(methods).length, 0), Object.keys(expected).length);
for (const [op, [method, path]] of Object.entries(expected)) {
  const route = P04_ROUTES[op];
  const spec = artifact.paths[path][method.toLowerCase()];
  assert.equal(spec.operationId, op);
  assert.equal(route.method, method);
  assert.equal(route.path, path);
  const params = Object.fromEntries([...path.matchAll(/\{([a-zA-Z]+)\}/gu)].map((match, i) => [match[1], i % 2 ? id2 : id]));
  const actual = path.replace(/\{([a-zA-Z]+)\}/gu, (_, name) => params[name]);
  assert.deepEqual(matchP04Route(method, actual), { operation: op, params });
  assert.deepEqual(decodeP04Params(op, params), params);
  only(() => decodeP04Params(op, { ...params, idempotencyKey: id }));
  for (const alias of [`${actual}/`, `${actual}?`, `${actual}#`, `${actual}\n`, actual.replace('/api/', '/API/'), actual.replace('/v1/', '/v1//'), actual.replace('/v1/', '/v1/%2e/'), actual.replace('/catalog/', '/%63atalog/').replace('/pricing/', '/%70ricing/').replace('/content/', '/%63ontent/')]) {
    assert.equal(matchP04Route(method, alias), null, alias);
  }
  assert.equal(matchP04Route(method.toLowerCase(), actual), null);
  assert.equal(matchP04Route('HEAD', actual), null);
  if (Object.keys(params).length) {
    assert.equal(matchP04Route(method, actual.replace(id, id.toUpperCase())), null);
    assert.equal(matchP04Route(method, actual.replace(id, id.replace('-4', '-0'))), null);
    assert.equal(matchP04Route(method, actual.replace(id, id.replace('-8', '-7'))), null);
    assert.equal(matchP04Route(method, actual.replace(id, '%61' + id.slice(1))), null);
  }
  assert.equal(spec.responses[route.status].headers['Cache-Control'].schema.enum[0], 'no-store');
  assert(getData(spec.responses[route.status].content['application/json'].schema));
  assert.deepEqual(decodeP04Query(op, {}), {});
  for (const bad of [{ cityId: id }, { sort: 'id' }, { limit: '01' }, { limit: '51' }, { cursor: 'a'.repeat(513) }, { cursor: 'AA=' }, { includeArchived: '1' }]) {
    only(() => decodeP04Query(op, bad));
  }
  const headers = new Map(spec.parameters.filter(p => p.in === 'header').map(p => [p.name, p]));
  if (method === 'GET') {
    assert.equal(route.bodyLimit, 0);
    assert.equal(route.responseLimit, route.query.length ? 262144 : 65536);
    assert.deepEqual(spec.security, [{ staffSession: [] }]);
    assert(!headers.has('Idempotency-Key') && !headers.has('If-Match'));
    assert(!headers.get('Origin').required);
    only(() => decodeP04Body(op, {}));
    continue;
  }
  assert.equal(route.status, /Create$|Publish$|Replace$/u.test(op) ? 201 : 200);
  assert.equal(route.responseLimit, 4096);
  assert.equal(route.bodyLimit, op.startsWith('avito') ? P04BodyLimit.Avito
    : ['policyPublish','policyReplace'].includes(op) ? P04BodyLimit.Policy : P04BodyLimit.Standard);
  assert.equal(route.bodyTimeoutMs, 10000);
  assert.equal(route.contentEncoding, 'identity');
  assert.equal(route.versioned, !op.endsWith('Create'));
  assert.equal(route.allowZero, ['fixedPublish','ruleVersionPublish','policyPublish'].includes(op));
  assert.deepEqual(spec.security, [{ staffSession: [], sessionCsrf: [] }]);
  assert(headers.get('Origin').required && headers.get('Idempotency-Key').required && spec.requestBody.required);
  assert.equal(headers.has('If-Match'), route.versioned);
  if (route.versioned) { assert(headers.get('If-Match').required); assert(spec.responses[428] && spec.responses[412]); }
  assert(spec.responses[200].headers.ETag.required && spec.responses[409]);
  assert.equal(route.permissions.length, op === 'avitoPublish' ? 3 : 2);
  const base = { id, version: 1 };
  const revision = { ...base, revisionId: id2, revisionVersion: 1 };
  const hasRevision = versionReceiptOps.includes(op);
  const receipt = hasRevision ? revision : base;
  assert.deepEqual(decodeP04Data(op, receipt), receipt);
  only(() => decodeP04Data(op, hasRevision ? base : revision));
  only(() => decodeP04Data(op, { ...receipt, version: 0 }));
  only(() => decodeP04Data(op, { ...receipt, version: 2147483648 }));
  only(() => decodeP04Data(op, { ...receipt, requestSha256: 'private' }));
}
assert.equal(mutationOps.length, 37);
const migration = readFileSync(new URL('../../prisma/migrations/20261122000700_catalog_management/migration.sql', import.meta.url), 'utf8');
const permissionInsert = migration.split('INSERT INTO foundation.permissions(code,module,description,protected,active)')[1]?.split(';')[0] ?? '';
const permissionCodes = [...permissionInsert.matchAll(/\('([a-z.]+)',/gu)].map(([, code]) => code).sort();
assert.deepEqual(permissionCodes, [...new Set(Object.values(P04_ROUTES).flatMap(route => route.permissions))].sort());
assert.equal(permissionCodes.length, 9);
const sqlCheck = (name) => migration.split(`CONSTRAINT p04_command_receipts_${name}_check`)[1]?.split(/\b(?:CONSTRAINT|THEN)\b/u)[0] ?? '';
const quotedOperations = (sql) => [...sql.matchAll(/'([a-zA-Z]+)'/gu)].map(([, op]) => op).sort();
assert.deepEqual(quotedOperations(sqlCheck('operation')), [...mutationOps].sort());
assert.deepEqual(quotedOperations(sqlCheck('revision')), [...versionReceiptOps].sort());
assert.deepEqual(quotedOperations(sqlCheck('city')), mutationOps.filter(op => P04_ROUTES[op].scope === 'CITY').sort());
assert.deepEqual(quotedOperations(sqlCheck('target_version')), mutationOps.filter(op => P04_ROUTES[op].params.includes('versionId')).sort());

for (const op of ['fixedList','ruleVersionList','policyList']) {
  assert.deepEqual(decodeP04Data(op, { version: 0, ...page }), { version: 0, ...page });
}
only(() => decodeP04Data('estimateVersions', { version: 0, ...page }));
const city = { id, code: 'test-city', name: 'Synthetic city' };
const cityPage = { ...page, items: [city] };
assert.deepEqual(decodeP04Data('cityList', cityPage), cityPage);
only(() => decodeP04Data('cityList', { ...cityPage, items: [{...city, assignmentId: id}] }));
only(() => decodeP04Data('cityList', { ...cityPage, items: Array(51).fill(city) }));
only(() => decodeP04Data('pricingReadiness', { ...page, items: [{ ...city, fixed: 'READY', policy: 'MISSING' }] }));
assert.deepEqual(decodeP04Query('avitoList', { cursor: 'abc', limit: '50', includeArchived: 'true', kind: 'REVIEW' }), { cursor: 'abc', limit: '50', includeArchived: 'true', kind: 'REVIEW' });
only(() => decodeP04Query('categoryList', { kind: 'CATEGORY' }));
only(() => decodeP04Query('cityRules', { includeArchived: 'true' }));
only(() => decodeP04Query('itemGet', { limit: '20' }));

const sample = {
  categoryCreate: { code: 'fridges' }, modelCreate: { code: 'fridge', categoryId: id, brandId: id2 },
  itemCreate: { code: 'test-work', unit: 'unit', kind: 'WORK', categoryId: id },
  itemPublish: { title: 'Test part', kind: 'PART', technicianVisible: true, publicVisible: false },
  mappingPublish: {}, fixedClose: { at },
  fixedPublish: { amountMinor: '9223372036854775807', sourceRef: 'fixture', currency: 'RUB', validFrom: at },
  ruleVersionPublish: { kind: 'EVENING', title: 'Fixture', method: 'RATE', base: 'WORKS', currency: 'RUB', rateBps: 50,
    startMinute: 1200, endMinute: 30, wrapsMidnight: true, categoryIds: [id], sourceRef: 'fixture', validFrom: at },
  policyReplace: { at, sourceRef: 'fixture', currency: 'RUB', taxDisplay: 'fixture', roundingMode: 'HALF_UP', units: { unit: 0 },
    maxManualDeltaMinor: '100', priorities: [{ ruleId: id, priority: 0 }], compatibilities: [{ leftRuleId: id, rightRuleId: id2 }] },
  estimatePublish: { validFrom: at, sourceRef: 'fixture', title: 'Fixture', currency: 'RUB', minMinor: '300', maxMinor: '500', disclaimer: 'synthetic' },
  avitoCreate: { kind: 'REVIEW', profileId: id, code: 'fixture' },
  avitoPublish: { title: 'Synthetic', sourceUrl: 'https://avito.ru/review/sample', permissionRef: 'fixture', sourceDate: '2028-02-29', excerpt: 'Synthetic text', rating: null },
};
for (const [op, body] of Object.entries(sample)) {
  assert.deepEqual(decodeP04Body(op, body), body);
  only(() => decodeP04Body(op, { ...body, expectedVersion: 1 }));
  only(() => decodeP04Body(op, Object.create(body)));
  only(() => decodeP04Body(op, Object.defineProperty({ ...body }, 'toJSON', { get: () => assert.fail('must not invoke getters') })));
}
for (const [op, patch] of [
  ['modelCreate',{ categoryId: null }], ['itemCreate',{ categoryId: null }], ['itemPublish',{ durationMinutes: 1 }],
  ['fixedClose',{ at: '2030-02-31T00:00:00.000Z' }], ['fixedClose',{ validFrom: at }],
  ['fixedPublish',{ amountMinor: 100 }], ['fixedPublish',{ amountMinor: '0' }], ['fixedPublish',{ amountMinor: '00' }],
  ['fixedPublish',{ amountMinor: '9223372036854775808' }], ['fixedPublish',{ validUntil: at }], ['fixedPublish',{ validFrom: at + '\n' }],
  ['ruleVersionPublish',{ wrapsMidnight: false }], ['ruleVersionPublish',{ fixedMinor: '23' }],
  ['ruleVersionPublish',{ categoryIds: [id, id] }], ['ruleVersionPublish',{ rateBps: 1.5 }],
  ['policyReplace',{ validFrom: at }], ['policyReplace',{ units: {} }], ['policyReplace',{ units: { unit: -0 } }],
  ['policyReplace',{ priorities: [{ ruleId: id, priority: 1 }, { ruleId: id, priority: 2 }] }],
  ['policyReplace',{ compatibilities: [{ leftRuleId: id, rightRuleId: id2 }, { leftRuleId: id2, rightRuleId: id }] }],
  ['estimatePublish',{ minMinor: '501' }], ['avitoCreate',{ kind: 'PROFILE' }],
  ['avitoPublish',{ kind: 'REVIEW' }], ['avitoPublish',{ sourceUrl: 'https://avito.ru:443/sample' }],
  ['avitoPublish',{ sourceUrl: 'https://avito.ru/%73ample' }], ['avitoPublish',{ sourceDate: '2029-02-29' }],
  ['avitoPublish',{ excerpt: '<b>no</b>' }], ['avitoPublish',{ title: ' ' }], ['avitoPublish',{ rating: 6 }],
]) { only(() => decodeP04Body(op, { ...sample[op], ...patch })); }
for (const [op, body] of [
  ['fixedPublish', { ...sample.fixedPublish, amountMinor: '0', zeroBasis: 'fixture' }],
  ['avitoPublish', { title: '🧪'.repeat(160), sourceUrl: 'https://www.avito.ru/profile/fixture', permissionRef: 'fixture', excerpt: null }],
]) { assert.deepEqual(decodeP04Body(op, body), body); }
assert.equal(fields(artifact.components.schemas.PolicyReplaceBody).validFrom, undefined);

const requests = [];
const client = createP04Client(async (request) => {
  requests.push(request);
  return request.method === 'GET' ? { status: 200, body: envelope(cityPage) }
    : { status: 200, body: envelope({ id, version: 1, revisionId: id2, revisionVersion: 1 }) };
});
assert.deepEqual(await client.request('cityList', { query: { limit: '20', cursor: 'Aa_-9' } }), { ...envelope(cityPage), status: 200 });
assert.equal(requests[0].path, '/api/v1/pricing/cities?cursor=Aa_-9&limit=20');
const input = { params: { cityId: id, itemId: id2 }, body: sample.fixedPublish, expectedVersion: 0, csrfToken: 'a'.repeat(43), idempotencyKey: id };
assert.equal((await client.request('fixedPublish', input)).status, 200);
assert.equal(requests[1].path, `/api/v1/pricing/cities/${id}/items/${id2}/price-versions`);
assert.equal(requests[1].headers['If-Match'], '"p04-v0"');
assert.equal(requests[1].headers['Idempotency-Key'], id);
assert.deepEqual(JSON.parse(requests[1].body), sample.fixedPublish);
for (const invalid of [{ expectedVersion: 2147483648 }, { expectedVersion: '0' }, { csrfToken: 'bad' }, { idempotencyKey: 'bad' }, { params: { ...input.params, extra: id } }, { params: { ...input.params, itemId: 'bad' } }]) {
  await assert.rejects(client.request('fixedPublish', { ...input, ...invalid }), TypeError);
}
assert.equal(requests.length, 2, 'invalid inputs never hit transport');
await assert.rejects(createP04Client(async () => ({ status: 503, body: {} })).request('cityList', {}), TypeError);
await assert.rejects(createP04Client(async () => ({ status: 200, body: { ...envelope(cityPage), extra: true } })).request('cityList', {}), TypeError);
console.log(`P04 contracts verified: ${Object.keys(expected).length} exact operations, ${mutationOps.length} mutations, strict client and reproducible OpenAPI/runtime/types`);
