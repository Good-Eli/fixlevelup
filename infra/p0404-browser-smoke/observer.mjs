import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { host, isUuid, proofPort } from './isolation.mjs';

// All table names, expressions and operations are fixed by these six proof
// descriptors. The only variable input to SQL is bound and strictly typed.
const specs = {
  item: { actor: 'admin', operation: 'itemPublish', event: 'catalog.item.publish', receipt: 'p04',
    extra: ['revisionId','revisionVersion'], domain: `
      SELECT jsonb_build_object('actorStaffId',i.actor,'id',i.id,'version',i.version,'kind',v.kind,
        'revisionId',v.id,'revisionVersion',v.version) AS audit
      FROM foundation.catalog_items x JOIN foundation.catalog_item_versions v ON (v.item_id,v.id)=(x.id,x.current_version_id), input i
      WHERE (x.id,x.row_version,v.id,v.version,v.reviewed_by)=(i.id,i.version,i.revision,i.sequence,i.actor)`,
    subject: 'r.city_id IS NULL AND r.subject_id=i.id AND r.target_version_id IS NULL' },
  price: { actor: 'manager', operation: 'fixedPublish', event: 'catalog.price.publish', receipt: 'p04',
    extra: ['revisionId','revisionVersion','itemId'], domain: `
      SELECT jsonb_build_object('actorStaffId',i.actor,'id',i.id,'version',i.version,'kind','FIXED_PRICE',
        'revisionId',v.id,'revisionVersion',v.version,'cityId',s.city_id,'itemId',s.item_id) AS audit
      FROM foundation.catalog_price_series s JOIN foundation.catalog_price_versions v
        ON (v.series_id,v.city_id,v.item_id)=(s.id,s.city_id,s.item_id)
      JOIN foundation.catalog_price_periods p ON (p.price_version_id,p.series_id,p.city_id,p.item_id)=(v.id,s.id,s.city_id,s.item_id), input i
      WHERE (s.id,s.row_version,s.city_id,s.item_id,v.id,v.version,v.reviewed_by)=(i.id,i.version,i.city,i.subject,i.revision,i.sequence,i.actor)
        AND v.amount_minor=9223372036854775807::bigint AND v.currency='RUB' AND v.valid_from>v.published_at
        AND (p.valid_from,p.scheduled_until) IS NOT DISTINCT FROM (v.valid_from,v.valid_until)`,
    subject: 'r.city_id=i.city AND r.subject_id=i.subject AND r.target_version_id IS NULL' },
  district: { actor: 'admin', operation: 'districtCreate', event: 'GEOGRAPHY_CHANGED', receipt: 'geography', extra: [], domain: `
      SELECT jsonb_build_object('actorId',i.actor,'operation',i.operation,'cityId',d.city_id,'entityId',d.id,'version',i.version) AS audit
      FROM foundation.administrative_districts d, input i WHERE (d.id,d.city_id,d.row_version)=(i.id,i.city,i.version)` },
  coverage: { actor: 'admin', operation: 'areaCoverage', event: 'GEOGRAPHY_CHANGED', receipt: 'geography',
    extra: ['areaId','districtId'], domain: `
      SELECT jsonb_build_object('actorId',i.actor,'operation',i.operation,'cityId',v.city_id,'areaId',v.area_id,
        'versionId',v.id,'entityId',v.id,'version',i.version) AS audit
      FROM foundation.service_area_versions v JOIN foundation.service_area_district_coverage c
        ON (c.city_id,c.area_version_id)=(v.city_id,v.id), input i
      WHERE (v.id,v.city_id,v.area_id,c.district_id)=(i.id,i.city,i.subject,i.target) AND v.row_version>=i.version` },
  faq: { actor: 'admin', operation: 'contentPublish', event: 'content.revision.publish', receipt: 'p03',
    extra: ['revisionId','revisionVersion'], domain: `
      SELECT jsonb_build_object('actorStaffId',i.actor,'entity','CONTENT_REVISION','entityId',v.id,'blockId',b.id,
        'type',b.kind,'scope',b.scope,'cityId',b.city_id,'version',v.version,'previousVersion',i.version-1) AS audit
      FROM foundation.content_blocks b JOIN foundation.content_block_revisions v ON (v.block_id,v.id)=(b.id,b.current_revision_id), input i
      WHERE (b.id,b.row_version,v.id,v.version,v.reviewed_by)=(i.id,i.version,i.revision,i.sequence,i.actor)
        AND b.kind='FAQ' AND (b.city_id IS NULL OR b.city_id=i.city)` },
  contact: { actor: 'admin', operation: 'cityPublish', event: 'GEOGRAPHY_CHANGED', receipt: 'geography',
    extra: ['revisionId'], domain: `
      SELECT jsonb_build_object('actorId',i.actor,'operation',i.operation,'cityId',c.id,'versionId',v.id,
        'entityId',c.id,'version',i.version) AS audit
      FROM foundation.service_cities c JOIN foundation.service_city_versions v ON (v.city_id,v.id)=(c.id,c.current_version_id), input i
      WHERE (c.id,c.id,v.id,v.reviewed_by)=(i.id,i.city,i.revision,i.actor) AND c.row_version>=i.version AND v.version>1
        AND EXISTS (SELECT FROM foundation.service_city_versions prior WHERE prior.city_id=c.id AND prior.version=1
          AND (prior.public_contact,prior.office_hours,prior.address_display,prior.timezone)
            IS DISTINCT FROM (v.public_contact,v.office_hours,v.address_display,v.timezone))` },
};
const receipts = ['p04_command_receipts','p03_command_receipts','geography_command_receipts'];
const tables = ['catalog_items','catalog_item_versions','catalog_price_series','catalog_price_versions','catalog_price_periods',
  'administrative_districts','service_areas','service_area_versions','service_area_district_coverage',
  'service_cities','service_city_versions','content_blocks','content_block_revisions', ...receipts];
const inputFields = ['kind','actor','id','key','version'];
const fields = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).every(key => allowed.includes(key));
const version = value => Number.isInteger(value) && value > 0 && value <= 2147483647;

function validate(input) {
  if (!fields(input, ['writes','deniedKeys']) || !Array.isArray(input.writes) || input.writes.length > 6) { return false; }
  if (input.deniedKeys !== undefined && (!Array.isArray(input.deniedKeys) || input.deniedKeys.length > 8 || !input.deniedKeys.every(isUuid))) { return false; }
  const seen = new Set();
  for (const write of input.writes) {
    if (!write || typeof write.kind !== 'string' || !Object.hasOwn(specs, write.kind) || seen.has(write.kind)) { return false; }
    const spec = specs[write.kind];
    if (!fields(write, [...inputFields, ...spec.extra]) || write.actor !== spec.actor || !isUuid(write.id) || !isUuid(write.key)
      || !version(write.version) || !spec.extra.every(key => (key === 'revisionVersion' ? version : isUuid)(write[key]))) { return false; }
    seen.add(write.kind);
  }
  return true;
}

async function one(client, fixture, w) {
  const spec = specs[w.kind];
  const auditPayload = spec.receipt === 'geography' ? `jsonb_build_object('operation',i.operation,'entityId',i.id,'version',i.version)`
    : spec.receipt === 'p03' ? `d.audit || jsonb_build_object('operation',i.event)` : 'd.audit';
  const row = await client.query(`WITH input AS (SELECT $1::uuid actor,$2::text operation,$3::text event,$4::uuid key,
      $5::uuid id,$6::integer version,$7::uuid city,$8::uuid revision,$9::integer sequence,$10::uuid subject,$11::uuid target),
    domain AS (${spec.domain}),
    receipt AS (SELECT 1 FROM foundation.${spec.receipt}_command_receipts r, input i
      WHERE (r.actor_id,r.operation,r.key,r.entity_id,r.entity_version)=(i.actor,i.operation,i.key,i.id,i.version)
      ${spec.receipt !== 'geography' ? 'AND (r.revision_id,r.revision_version)=(i.revision,i.sequence)' : ''}
      ${spec.subject ? `AND ${spec.subject}` : ''}),
    audit AS (SELECT a.correlation_id FROM foundation.audit_logs a, domain d, input i WHERE a.operation=i.event AND a.details=d.audit),
    outbox AS (SELECT o.event_id FROM foundation.outbox_events o, domain d, input i WHERE o.event_type=i.event AND o.payload=${auditPayload})
    SELECT (SELECT count(*)::int FROM domain) AS rows,(SELECT count(*)::int FROM receipt) AS receipts,
      (SELECT count(*)::int FROM audit) AS audits,(SELECT count(*)::int FROM outbox) AS outbox,
      (SELECT count(*)::int FROM audit a JOIN outbox o ON a.correlation_id=o.event_id) AS linked`,
  [w.actor === 'admin' ? fixture.administrator.id : fixture.manager.id, spec.operation, spec.event, w.key,
    w.id, w.version, fixture.cityId, w.revisionId ?? null, w.revisionVersion ?? null, w.itemId ?? w.areaId ?? null, w.districtId ?? null]);
  const { rows, receipts, audits, outbox, linked } = row.rows[0];
  return { rows, receipts, audits, outbox, exact: rows === 1 && receipts === 1 && audits === 1 && outbox === 1 && linked === 1 };
}

export async function verify(fixture, input) {
  if (!validate(input)) { throw new Error('Invalid proof request'); }
  const client = await fixture.migrator.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const writes = {};
    for (const w of input.writes) { writes[w.kind] = await one(client, fixture, w); }
    const { rows: [counts] } = await client.query(`SELECT ${tables.map(table => `(SELECT count(*)::int FROM foundation.${table}) AS ${table}`).join(',')},
      (SELECT count(*)::int FROM foundation.audit_logs WHERE operation ~ '^(catalog[.]|pricing[.]|content[.]|GEOGRAPHY_CHANGED$)') AS audits,
      (SELECT count(*)::int FROM foundation.outbox_events WHERE event_type ~ '^(catalog[.]|pricing[.]|content[.]|GEOGRAPHY_CHANGED$)') AS outbox`);
    const { rows: [{ denied }] } = await client.query(`SELECT (${receipts.map(table =>
      `(SELECT count(*)::int FROM foundation.${table} WHERE key=ANY($1::uuid[]))`).join('+')}) AS denied`, [input.deniedKeys ?? []]);
    await client.query('COMMIT');
    return { writes, counts, deniedReceipts: denied };
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

export function observer(fixture, token, reports) {
  const bearer = Buffer.from(`Bearer ${token}`);
  let calls = 0;
  const server = createServer({ requestTimeout: 5000, headersTimeout: 5000, connectionsCheckingInterval: 500, maxHeaderSize: 2048 }, async (req, res) => {
    const actual = Buffer.from(req.headers.authorization ?? '');
    const length = Number(req.headers['content-length']);
    if (req.method !== 'POST' || req.url !== '/proof' || req.headers.host !== `${host}:${proofPort}` || req.headers.origin !== undefined
      || req.headers['sec-fetch-site'] !== undefined || req.headers['content-type'] !== 'application/json'
      || actual.length !== bearer.length || !timingSafeEqual(actual, bearer) || !Number.isInteger(length) || length < 2 || length > 8192 || ++calls > 12) {
      res.writeHead(404, { connection: 'close' }).end(); return;
    }
    try {
      let bytes = 0;
      const chunks = [];
      for await (const chunk of req) {
        if ((bytes += chunk.length) > 8192) { throw new Error('Proof body too large'); }
        chunks.push(chunk);
      }
      const result = await verify(fixture, JSON.parse(Buffer.concat(chunks).toString('utf8')));
      reports.push(result);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(result));
    } catch { res.writeHead(500).end(); }
  });
  server.maxConnections = 2;
  return server;
}
