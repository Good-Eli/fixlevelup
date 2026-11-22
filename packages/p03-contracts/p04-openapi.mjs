// Single authoring source: JSON Schema objects are shared by OpenAPI, runtime and declarations.
const exact = (pattern) => `^(?:${pattern})(?![\\s\\S])`;
const str = (minLength, maxLength, fields = {}) => ({ type: 'string', minLength, maxLength, ...fields });
const int = (minimum, maximum) => ({ type: 'integer', minimum, maximum });
const enumOf = (...values) => ({ type: 'string', enum: values });
const bool = { type: 'boolean' };
const nil = { type: 'null' };
const union = (...variants) => ({ oneOf: variants });
const nullable = (schema) => union(schema, nil);
const obj = (properties, optional = []) => ({
  type: 'object', properties, additionalProperties: false,
  required: Object.keys(properties).filter(key => !optional.includes(key)),
});
const array = (items, maxItems, extra = {}) => ({ type: 'array', items, maxItems, ...extra });
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const bodyText = (max, min = 1, plain = false) => str(min, max, {
  pattern: exact(plain ? '[^<>\\p{Cc}\\p{Cf}\\p{Cs}]*' : '[^\\p{Cc}\\p{Cf}\\p{Cs}]*'),
  'x-p04-refine': min ? 'nonblank' : undefined,
});
const MAX_VERSION = 2_147_483_647;
const version = int(1, MAX_VERSION);
const streamVersion = int(0, MAX_VERSION);
const uuidExample = '12345678-1234-4123-8123-123456789abc';
const uuid = str(36, 36, {
  format: 'uuid', examples: [uuidExample],
  pattern: exact('[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'),
});
const slug = (min, max) => str(min, max, { pattern: exact('[a-z][a-z0-9]*(?:-[a-z0-9]+)*') });
const code = slug(2, 64);
const unit = slug(1, 24);
const cursor = str(1, 512, { pattern: exact('[A-Za-z0-9_-]+'), description: 'Opaque base64url; bound to route, filters, parents and authorized target. Reauthorize every request.' });
const instant = str(24, 24, { format: 'date-time', pattern: exact('(?!0000)\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}Z'), 'x-p04-refine': 'instant', examples: ['2030-01-02T03:04:05.000Z'] });
const date = str(10, 10, { format: 'date', pattern: exact('(?!0000)\\d{4}-\\d\\d-\\d\\d'), 'x-p04-refine': 'date' });
// Canonical decimal bounds are standard JSON Schema patterns, not implicit number casts.
const boundedDigits = (max) => {
  const lower = [...max].flatMap((digit, index) => {
    const minDigit = index === 0 ? 1 : 0;
    return Number(digit) > minDigit ? [`${max.slice(0, index)}[${minDigit}-${Number(digit) - 1}][0-9]{${max.length - index - 1}}`] : [];
  });
  return `[1-9][0-9]{0,${max.length - 2}}|${[...lower, max].join('|')}`;
};
const positiveInt64 = boundedDigits('9223372036854775807');
const int32 = boundedDigits('2147483647');
const minor = str(1, 19, { pattern: exact(`0|${positiveInt64}`), description: 'Canonical decimal string, 0…9223372036854775807 inclusive; never a JSON number.', examples: ['129900'] });
const currency = str(3, 3, { pattern: exact('[A-Z]{3}'), examples: ['RUB'] });
const title = bodyText(160);
const avitoTitle = bodyText(160, 1, true);
const description = nullable(bodyText(1000, 0));
const sourceRef = bodyText(200);
const permissionRef = bodyText(200, 1, true);
const sourceUrl = str(1, 2048, {
  format: 'uri', pattern: exact('https://(?:www\\.)?avito\\.ru/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*'),
  description: 'Manual evidence only; URL format is not proof of consent or network verification.', examples: ['https://www.avito.ru/profile/example'],
});
const rating = int(1, 5);
const excerpt = bodyText(1500, 1, true);
const durationMinutes = int(1, 1440);
const itemKinds = ['WORK', 'PART', 'MATERIAL', 'TRAVEL', 'DIAGNOSTICS'];
const itemKind = enumOf(...itemKinds);
const temporalKinds = ['EVENING', 'NIGHT'];
const otherRuleKinds = ['EXPRESS', 'SURCHARGE', 'DISCOUNT'];
const ruleKind = enumOf(...temporalKinds, ...otherRuleKinds);
const avitoKind = enumOf('PROFILE', 'REVIEW');
const ruleBase = enumOf('WORKS', 'WORKS_AND_PARTS', 'ORDER_BASE');
const ruleMethod = enumOf('FIXED', 'RATE');
const rateBps = int(1, 10000);
const minute = int(0, 1439);
const categoryIds = array(uuid, 32, { uniqueItems: true });
const schedule = { validUntil: nullable(instant), sourceRef };
const baseIdentity = { id: uuid, code, version, archivedAt: nullable(instant) };
const catalogIdentity = { ...baseIdentity, currentVersionId: nullable(uuid), title: nullable(title) };
const revisionSummary = { id: uuid, version, title, publishedAt: instant };
const temporalVersion = {
  id: uuid, seriesId: uuid, cityId: uuid, cityVersionId: uuid, version,
  validFrom: instant, validUntil: nullable(instant), effectiveUntil: nullable(instant), publishedAt: instant,
};
const page = (items, pageVersion) => obj({
  ...(pageVersion ? { version: pageVersion } : {}),
  items: array(items, 50), pageInfo: obj({ nextCursor: nullable(cursor) }),
});
const pageQuery = {
  limit: str(1, 2, { pattern: exact('[1-9]|[1-4][0-9]|50'), default: '20', description: 'Canonical integer page size (1…50).' }),
  cursor,
};
const archivedQuery = { ...pageQuery, includeArchived: { ...enumOf('true', 'false'), default: 'false', description: 'Include archived identities or closed history explicitly.' } };
const filteredQuery = (kind) => ({ ...archivedQuery, kind });
const units = {
  type: 'object', propertyNames: unit, additionalProperties: int(0, 6), minProperties: 1, maxProperties: 32,
};
const policy = {
  currency, taxDisplay: bodyText(200), roundingMode: enumOf('HALF_UP', 'DOWN'), units, maxManualDeltaMinor: minor,
  priorities: array(obj({ ruleId: uuid, priority: int(0, 1_000_000) }), 64),
  compatibilities: array(obj({ leftRuleId: uuid, rightRuleId: uuid }), 128),
};
const estimate = { title, currency, minMinor: minor, maxMinor: minor, conditions: nullable(bodyText(1000, 0)), disclaimer: bodyText(500) };
const rule = {
  title, base: ruleBase, currency, minBase: nullable(minor), maxBase: nullable(minor), minDelta: nullable(minor), maxDelta: nullable(minor), categoryIds,
};
const optionalRule = ['minBase', 'maxBase', 'minDelta', 'maxDelta', 'validUntil'];
function ruleBody(period, start) {
  return union(...[[temporalKinds, true], [otherRuleKinds, false]].flatMap(([kinds, temporal]) => ['FIXED', 'RATE'].map((method) => obj({
    kind: enumOf(...kinds), ...rule, ...schedule, ...period, method: enumOf(method),
    fixedMinor: method === 'FIXED' ? minor : nil, rateBps: method === 'RATE' ? rateBps : nil,
    startMinute: temporal ? minute : nil, endMinute: temporal ? minute : nil, wrapsMidnight: temporal ? bool : nil,
  }, [...optionalRule, method === 'FIXED' ? 'rateBps' : 'fixedMinor', ...temporal ? [] : ['startMinute', 'endMinute', 'wrapsMidnight']]))).map(schema => ({
    ...schema, 'x-p04-refine': `rule-${start}`,
  })));
}
const fixedBody = (start) => union(...[true, false].map((zero) => ({
  ...obj({ amountMinor: zero ? enumOf('0') : { ...minor, pattern: exact(positiveInt64) },
    currency, zeroBasis: zero ? bodyText(200) : nil, ...schedule, [start]: instant,
  }, zero ? ['validUntil'] : ['zeroBasis', 'validUntil']),
  'x-p04-refine': `schedule-${start}`,
})));
const companyDirectory = [
  ['category', 'categories', 'CATEGORY', {}],
  ['brand', 'brands', 'BRAND', {}],
  ['model', 'models', 'MODEL', { categoryId: uuid, brandId: uuid }],
  ['fault', 'faults', 'FAULT', { categoryId: uuid }],
];

export const P04_PREFIX = '/api/v1';
export const P04BodyLimit = { Standard: 16 * 1024, Policy: 64 * 1024, Avito: 12 * 1024 };
const paths = Object.create(null);
const schemas = {
  Empty: obj({}),
  Receipt: obj({ id: uuid, version }),
  RevisionReceipt: obj({ id: uuid, version, revisionId: uuid, revisionVersion: version }),
  CloseBody: obj({ at: instant }),
  Problem: obj({ type: enumOf('about:blank'), title: str(1, 48), status: int(400, 599), code: str(1, 48), requestId: uuid }),
};
const noStore = { description: 'Never cache staff data or errors', required: true, schema: enumOf('no-store') };
const errors = {
  400: 'Invalid request', 401: 'Missing or invalid staff session', 403: 'Capability or Origin/CSRF proof missing',
  404: 'Unknown or outside the authorized target', 408: 'Request body timeout', 409: 'Conflict',
  412: 'Stale version', 413: 'Request body exceeds byte limit', 415: 'Unsupported content encoding or type',
  428: 'Missing If-Match', 500: 'Safe internal error', 503: 'Not ready or command commit outcome unknown',
};
const responseError = Object.fromEntries(Object.entries(errors).map(([status, description]) => [status, {
  description, headers: { 'Cache-Control': noStore }, content: { 'application/problem+json': { schema: ref('Problem') } },
}]));
const matchTag = (allowZero) => str(8, 17, {
  pattern: exact(`"p04-v(?:${allowZero ? '0|' : ''}${int32})"`),
  description: `Strong canonical version ${allowZero ? '0 (empty stream only) or ' : ''}1…2147483647. No wildcards or lists.`, examples: ['"p04-v1"'],
});
const header = (name, schema, required = true) => ({ in: 'header', name, schema, required });
const cap = (group, action) => group === 'avito' ? P04BodyLimit.Avito
  : group === 'policy' && ['Publish', 'Replace'].includes(action) ? P04BodyLimit.Policy : P04BodyLimit.Standard;
const profile = (scope, permissions) => ({ scope, permissions });
const catalog = profile('COMPANY', ['catalog.read', 'catalog.manage']);
const rules = profile('COMPANY', ['pricing.rules.read', 'pricing.rules.manage']);
const city = profile('CITY', ['pricing.read', 'pricing.manage']);
const avito = profile('COMPANY', ['content.externalreviews.read', 'content.externalreviews.manage']);
function add(group, action, path, auth, options) {
  const operationId = group + action;
  const mutation = options.body !== undefined;
  const method = mutation ? 'post' : 'get';
  const versioned = mutation && action !== 'Create';
  const allowZero = versioned && options.allowZero === true;
  const status = mutation && ['Create', 'Publish', 'Replace'].includes(action) ? 201 : 200;
  const name = operationId[0].toUpperCase() + operationId.slice(1);
  const data = options.data ?? ref(options.revisionReceipt ? 'RevisionReceipt' : 'Receipt');
  schemas[`${name}Data`] = data;
  if (mutation) { schemas[`${name}Body`] = options.body; }
  const query = options.query ?? {};
  const params = [...path.matchAll(/\{([a-zA-Z]+)\}/gu)].map(match => match[1]);
  const parameters = [
    ...params.map(param => ({ in: 'path', name: param, required: true, schema: uuid })),
    ...Object.entries(query).map(([name, schema]) => ({ in: 'query', name, schema, required: false })),
    header('Origin', { type: 'string', format: 'uri', description: 'Exact configured same-site staff origin (if sent on reads).' }, mutation),
    ...mutation ? [
      header('Idempotency-Key', { ...uuid, description: 'One UUID per command. Reuse only for exact, explicit replay.' }),
      ...versioned ? [header('If-Match', matchTag(allowZero))] : [],
    ] : [],
  ];
  const success = (description, tag) => ({
    description, headers: { 'Cache-Control': noStore, ...tag ? { ETag: { required: true, schema: matchTag(false) } } : {} },
    content: { 'application/json': { schema: obj({ data: ref(`${name}Data`), meta: obj({ requestId: uuid }) }) } },
  });
  const permissions = (mutation ? auth.permissions : auth.permissions.slice(0, 1)).concat(group === 'avito' && action === 'Publish' ? ['content.externalreviews.publish'] : []);
  const bodyLimit = mutation ? cap(group, action) : 0;
  const responses = { [status]: success(mutation ? 'Committed command (or exact authorized replay at 200)' : 'Scoped staff data', mutation) };
  if (status === 201) { responses[200] = success('Exact authorized replay of committed command', true); }
  const statuses = [400, 401, 403, 404, 500, 503, ...mutation ? [408, 409, 413, 415] : [], ...versioned ? [412, 428] : []];
  for (const code of statuses) { responses[code] = responseError[code]; }
  const fullPath = P04_PREFIX + path;
  const entry = (paths[fullPath] ??= {});
  if (Object.hasOwn(entry, method)) { throw new TypeError('Duplicate P04 route'); }
  entry[method] = {
    operationId, summary: `${action} ${group} (staff only)`, parameters,
    security: [mutation ? { staffSession: [], sessionCsrf: [] } : { staffSession: [] }],
    ...mutation ? { requestBody: { required: true, content: { 'application/json': { schema: ref(`${name}Body`) } } } } : {},
    responses,
    'x-p04': { bodyLimit, responseLimit: 1024 * (mutation ? 4 : options.query ? 256 : 64),
      versioned, allowZero, status, scope: auth.scope, permissions, ...mutation ? { bodyTimeoutMs: 10_000, contentEncoding: 'identity' } : {} },
  };
}
const identityRead = (group, base, auth, identity, query = archivedQuery, param = 'id') => {
  add(group, 'List', base, auth, { data: page(identity), query });
  add(group, 'Get', `${base}/{${param}}`, auth, { data: identity });
};
const historyRead = (group, actions, base, auth, summary, detail, stream = version) => {
  add(group, actions[0], base, auth, { data: page(summary, stream), query: archivedQuery });
  add(group, actions[1], `${base}/{versionId}`, auth, { data: detail });
};
const archive = (group, base, auth) => add(group, 'Archive', `${base}/archive`, auth, { body: ref('Empty') });
for (const [group, segment, kind, parents] of companyDirectory) {
  const base = `/catalog/${segment}`;
  const identity = obj({ ...catalogIdentity, kind: enumOf(kind), categoryId: 'categoryId' in parents ? uuid : nil, brandId: 'brandId' in parents ? uuid : nil });
  const revisions = { ...revisionSummary, entryId: uuid };
  identityRead(group, base, catalog, identity);
  historyRead(group, ['Versions', 'Version'], `${base}/{id}/versions`, catalog, obj(revisions), obj({ ...revisions, description }));
  add(group, 'Create', base, catalog, { body: obj({ code, ...parents }) });
  add(group, 'Publish', `${base}/{id}/versions`, catalog, { body: obj({ title, description }, ['description']), revisionReceipt: true });
  archive(group, `${base}/{id}`, catalog);
}
{
  const base = '/catalog/items';
  const identity = obj({ ...catalogIdentity, kind: itemKind, categoryId: nullable(uuid), unit });
  const revisions = { ...revisionSummary, itemId: uuid, kind: itemKind };
  const visibility = { technicianVisible: bool, publicVisible: bool };
  identityRead('item', base, catalog, identity, filteredQuery(itemKind));
  historyRead('item', ['Versions', 'Version'], `${base}/{id}/versions`, catalog, obj(revisions), obj({ ...revisions, description, durationMinutes: nullable(durationMinutes), ...visibility }));
  add('item', 'Create', base, catalog, { body: union(
    obj({ code, kind: enumOf('WORK'), unit, categoryId: uuid }),
    obj({ code, kind: enumOf(...itemKinds.filter(kind => kind !== 'WORK')), unit, categoryId: nullable(uuid) }, ['categoryId']),
  ) });
  add('item', 'Publish', `${base}/{id}/versions`, catalog, { revisionReceipt: true, body: union(
    obj({ title, description, ...visibility, kind: enumOf('WORK', 'DIAGNOSTICS'), durationMinutes }, ['description']),
    obj({ title, description, ...visibility, kind: enumOf('PART', 'MATERIAL', 'TRAVEL') }, ['description']),
  ) });
  archive('item', `${base}/{id}`, catalog);
}
{
  const base = '/catalog/fault-service-mappings';
  const pair = { categoryId: uuid, faultId: uuid, itemId: uuid };
  identityRead('mapping', base, catalog, obj({ id: uuid, version, archivedAt: nullable(instant), publishedAt: nullable(instant), ...pair }));
  add('mapping', 'Create', base, catalog, { body: obj(pair) });
  add('mapping', 'Publish', `${base}/{id}/publish`, catalog, { body: ref('Empty') });
  archive('mapping', `${base}/{id}`, catalog);
}
{
  const base = '/pricing/rules';
  identityRead('rule', base, rules, obj({ ...baseIdentity, kind: ruleKind }), filteredQuery(ruleKind));
  add('rule', 'Create', base, rules, { body: obj({ code, kind: ruleKind }) });
  archive('rule', `${base}/{id}`, rules);
}
const cities = '/pricing/cities';
const cityPath = `${cities}/{cityId}`;
const label = { id: uuid, code };
const cityLabel = { id: uuid, code: slug(2, 32), name: bodyText(200) };
add('city', 'List', cities, city, { data: page(obj(cityLabel)), query: pageQuery });
add('city', 'Categories', `${cityPath}/categories`, city, { data: page(obj({ ...label, title })), query: pageQuery });
add('city', 'Items', `${cityPath}/items`, city, { data: page(obj({ ...label, title, kind: itemKind, categoryId: nullable(uuid), unit, technicianVisible: bool, publicVisible: bool })), query: pageQuery });
add('city', 'Rules', `${cityPath}/rules`, city, { data: page(obj({ ...label, kind: ruleKind })), query: pageQuery });
const readiness = enumOf('CONFIGURED', 'MISSING');
add('pricing', 'Readiness', '/pricing/readiness', city, { data: page(obj({ ...cityLabel, fixed: readiness, policy: readiness })), query: pageQuery });
function temporal(group, base, actions, summary, detail, body, allowZero = true) {
  historyRead(group, actions, base, city, obj({ ...temporalVersion, ...summary }), obj({ ...temporalVersion, ...detail, sourceRef }), allowZero ? streamVersion : version);
  add(group, 'Publish', base, city, { body: body('validFrom'), revisionReceipt: true, allowZero });
  add(group, 'Close', `${base}/{versionId}/close`, city, { body: ref('CloseBody') });
  add(group, 'Replace', `${base}/{versionId}/replace`, city, { body: body('at'), revisionReceipt: true });
}
const fixed = { itemId: uuid, itemVersionId: uuid, amountMinor: minor, currency, zeroBasis: nullable(bodyText(200)) };
temporal('fixed', `${cityPath}/items/{itemId}/price-versions`, ['List', 'Get'], { ...fixed, sourceRef }, fixed, fixedBody);
const ruleSummary = { ruleId: uuid, kind: ruleKind, title };
temporal('ruleVersion', `${cityPath}/rules/{ruleId}/versions`, ['List', 'Get'], ruleSummary,
  { ...rule, ...ruleSummary, method: ruleMethod, fixedMinor: nullable(minor), rateBps: nullable(rateBps),
    startMinute: nullable(minute), endMinute: nullable(minute), wrapsMidnight: nullable(bool) },
  (start) => ruleBody({ [start]: instant }, start));
const withSchedule = (payload, optional = [], refine = 'schedule') => (start) => ({
  ...obj({ ...schedule, [start]: instant, ...payload }, ['validUntil', ...optional]), 'x-p04-refine': `${refine}-${start}`,
});
temporal('policy', `${cityPath}/policy-versions`, ['List', 'Get'], { currency }, policy, withSchedule(policy, [], 'policy'));
{
  const base = `${cityPath}/public-estimates`;
  identityRead('estimate', base, city, obj({ ...baseIdentity, cityId: uuid, categoryId: uuid }), archivedQuery, 'estimateId');
  add('estimate', 'Create', base, city, { body: obj({ code, categoryId: uuid }) });
  archive('estimate', `${base}/{estimateId}`, city);
  temporal('estimate', `${base}/{estimateId}/versions`, ['Versions', 'Version'],
    { title, currency, minMinor: minor, maxMinor: minor }, estimate, withSchedule(estimate, ['conditions'], 'estimate'), false);
}
{
  const base = '/content/external-reviews';
  const identity = obj({ ...catalogIdentity, kind: avitoKind, profileId: nullable(uuid) });
  const revisions = { ...revisionSummary, title: avitoTitle, kind: avitoKind, entryId: uuid };
  const fields = { sourceDate: nullable(date), excerpt: nullable(excerpt), rating: nullable(rating) };
  identityRead('avito', base, avito, identity, filteredQuery(avitoKind));
  historyRead('avito', ['Versions', 'Version'], `${base}/{id}/versions`, avito,
    obj(revisions), obj({ ...revisions, sourceUrl, permissionRef, ...fields, profileRevisionId: nullable(uuid) }));
  add('avito', 'Create', base, avito, { body: union(obj({ code, kind: enumOf('PROFILE') }), obj({ code, kind: enumOf('REVIEW'), profileId: uuid })) });
  const common = { title: avitoTitle, sourceUrl, permissionRef };
  add('avito', 'Publish', `${base}/{id}/versions`, avito, { revisionReceipt: true, body: {
    ...union(obj({ ...common, sourceDate: nil, excerpt: nil, rating: nil }, ['sourceDate', 'excerpt', 'rating']),
      obj({ ...common, sourceDate: date, excerpt, rating: nullable(rating) }, ['rating'])),
    description: 'The server verifies PROFILE versus REVIEW against the stored identity; never submit kind.',
  } });
  archive('avito', `${base}/{id}`, avito);
}

export const P04_OPENAPI = {
  openapi: '3.1.0',
  info: { title: 'FixLevelUp staff catalog management', version: '1.0.0', description: 'Closed staff HTTP API. Runtime authorization, including current role and CITY assignments, is re-evaluated for all requests and replays.' },
  paths,
  components: { schemas, securitySchemes: {
    staffSession: { type: 'apiKey', in: 'cookie', name: '__Host-fixlevelup_session' },
    sessionCsrf: { type: 'apiKey', in: 'header', name: 'X-CSRF-Token', description: 'Single 43-character base64url token bound to the staff session.',
      'x-p04-schema': str(43, 43, { pattern: exact('[A-Za-z0-9_-]{43}') }) },
  } },
};
