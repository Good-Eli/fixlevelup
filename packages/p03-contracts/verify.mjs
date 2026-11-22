// Build-time consistency checks only; the public ESM entry uses no Node APIs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  P03_API_PREFIX, P03_BODY_BYTES, P03_CAPABILITIES, P03_CAPABILITY_METADATA, P03_COMMANDS,
  P03_COMPANY_FIELD_LENGTHS, P03_MAX_LIMIT, P03_MAX_VERSION, P03_OPERATIONS, P03_REFERENCE_TYPES, P03_RESPONSE_BYTES,
  P03_ROUTES, P03_TEXT_LENGTHS, decodeP03CompanyVersion, decodeP03ContentRevision, decodeP03ContentSummary,
  decodeP03Envelope, decodeP03LegalSummary, decodeP03LegalVersion, decodeP03Page, decodeP03Receipt,
  decodeP03ReferenceSummary, decodeP03TechnicianPickerItem, formatP03Etag, p03BodyLimit, p03Utf8ByteLength, parseP03Etag,
} from './dist/index.js';

const migration = readFileSync(new URL('../../prisma/migrations/20261122000400_settings_management/migration.sql', import.meta.url), 'utf8');
const catalog = migration.split('INSERT INTO foundation.permissions(code,module,description,protected,active)')[1]?.split(';')[0] ?? '';
assert.equal(P03_CAPABILITIES.length, 18);
const rows = [...catalog.matchAll(/\('([a-z.]+)'\s*,\s*'([^']+)'\)/gu)];
assert.deepEqual(rows.map(([, code]) => code).sort(), [...P03_CAPABILITIES].sort());
for (const [, code, description] of rows) {
  assert.equal(P03_CAPABILITY_METADATA[code]?.description, description);
}
const receipts = migration.split('CONSTRAINT p03_command_receipts_operation_check')[1]?.split('CONSTRAINT p03_command_receipts_request_sha256_check')[0] ?? '';
const revision = migration.split('CONSTRAINT p03_command_receipts_revision_check')[1]?.split('THEN')[0] ?? '';
const quotedNames = sql => [...sql.matchAll(/'([a-zA-Z]+)'/gu)].map(([, name]) => name).sort();
assert.equal(P03_OPERATIONS.length, 10);
assert.deepEqual(quotedNames(receipts), [...P03_OPERATIONS].sort());
assert.deepEqual(quotedNames(revision), P03_OPERATIONS.filter(op => P03_COMMANDS[op].revisionReceipt).sort());
for (const { read, manage } of Object.values(P03_REFERENCE_TYPES)) {
  assert(P03_CAPABILITIES.includes(read) && P03_CAPABILITIES.includes(manage));
}

const id = 'a1234567-1234-4321-8123-123456789012';
const paths = (template) => `${P03_API_PREFIX}${template.replace(/:\w+/gu, id)}`;
for (const [method, route, cap] of [
  ['POST', P03_ROUTES.legalPublish, P03_BODY_BYTES.legalPublish],
  ['POST', P03_ROUTES.contentPublish, P03_BODY_BYTES.contentPublish],
  ['PUT', P03_ROUTES.geographyCoverage, P03_BODY_BYTES.geographyCoverage],
]) {
  const path = paths(route);
  assert.equal(p03BodyLimit(method, path), cap);
  assert.equal(p03BodyLimit('PATCH', path), P03_BODY_BYTES.default);
  assert.equal(p03BodyLimit(method, `${path}/`), P03_BODY_BYTES.default);
  assert.equal(p03BodyLimit(method, `${path}\n`), P03_BODY_BYTES.default);
}
for (const op of P03_OPERATIONS) {
  const basic = { id, version: 1 };
  const withRevision = { ...basic, revisionId: id, revisionVersion: 1 };
  const correct = P03_COMMANDS[op].revisionReceipt ? withRevision : basic;
  assert.deepEqual(decodeP03Receipt(correct, op), correct);
  assert.equal(decodeP03Receipt({ ...correct, body: 'synthetic' }, op), null);
  assert.equal(decodeP03Receipt(P03_COMMANDS[op].revisionReceipt ? basic : withRevision, op), null);
  assert.equal(decodeP03Receipt({ ...correct, version: 0 }, op), null);
  if (P03_COMMANDS[op].revisionReceipt) {
    assert.equal(decodeP03Receipt({ ...correct, revisionVersion: 0 }, op), null);
  }
}
const technician = { id, displayName: null, version: 0 };
const technicianPage = { items: [technician], pageInfo: { hasMore: false, nextCursor: null } };
assert.deepEqual(decodeP03Page(technicianPage, decodeP03TechnicianPickerItem), technicianPage);
for (const version of [-1, 0.5, P03_MAX_VERSION + 1, null]) {
  assert.equal(decodeP03TechnicianPickerItem({ ...technician, version }), null);
}
assert.equal(parseP03Etag(formatP03Etag(2_147_483_647)), 2_147_483_647);
assert.equal(parseP03Etag('"p03-v0"'), null);
assert.equal(parseP03Etag('"p03-v0"', true), 0);
for (const invalid of ['W/"p03-v1"', '"p03-v01"', '"p03-v2147483648"', '"p03-v1"\n', '*']) {
  assert.equal(parseP03Etag(invalid), null);
}

// JSON escaping can exceed the raw UTF-8 size; assert actual serialization, not raw text length.
const longestJson = length => '\u0001'.repeat(length - 1) + '界';
const publishedAt = '2026-11-22T00:00:00.000Z';
const company = { id, version: 1, launchMode: 'SINGLE_CITY', primaryCityId: id, reviewedBy: id, publishedAt,
  settings: Object.fromEntries(Object.entries(P03_COMPANY_FIELD_LENGTHS).map(([k, max]) => [k, longestJson(max)])) };
const contentSummary = { id, blockId: id, version: 1, title: longestJson(P03_TEXT_LENGTHS.title), publishedAt };
const referenceSummary = { id, entryId: id, version: 1, label: longestJson(P03_TEXT_LENGTHS.referenceLabel), publishedAt };
const legalSummary = { id, documentId: id, sequence: 1, title: contentSummary.title, checksum: 'c'.repeat(64), publishedAt };
const legal = { ...legalSummary, purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM', reviewedBy: id,
  body: longestJson(P03_TEXT_LENGTHS.legalBody), legalBasis: longestJson(P03_TEXT_LENGTHS.legalBasis),
  sourceRef: longestJson(P03_TEXT_LENGTHS.legalSourceRef) };
const content = { ...contentSummary, body: longestJson(P03_TEXT_LENGTHS.contentBody), sourceRef: longestJson(P03_TEXT_LENGTHS.sourceRef) };
const accepted = (data, decoder, cap) => {
  const envelope = { data, meta: { requestId: id } };
  const json = JSON.stringify(envelope);
  assert(p03Utf8ByteLength(json) <= cap);
  assert.equal(p03Utf8ByteLength(json), Buffer.byteLength(json));
  assert.deepEqual(decodeP03Envelope(JSON.parse(json), decoder), envelope);
};
accepted(company, decodeP03CompanyVersion, P03_RESPONSE_BYTES.companyExact);
accepted(content, decodeP03ContentRevision, P03_RESPONSE_BYTES.contentExact);
accepted(legal, decodeP03LegalVersion, P03_RESPONSE_BYTES.legalExact);
for (const [item, decoder] of [[contentSummary, decodeP03ContentSummary], [referenceSummary, decodeP03ReferenceSummary], [legalSummary, decodeP03LegalSummary]]) {
  const pageInfo = { hasMore: false, nextCursor: null };
  accepted({ items: Array(P03_MAX_LIMIT).fill(item), pageInfo }, v => decodeP03Page(v, decoder), P03_RESPONSE_BYTES.list);
  assert.equal(decodeP03Page({ items: Array(P03_MAX_LIMIT + 1).fill(item), pageInfo }, decoder), null);
  assert.equal(decoder({ ...item, body: 'synthetic' }), null);
}
assert.equal(p03Utf8ByteLength('\uD800a世界🧪'), Buffer.byteLength('\uD800a世界🧪'));
console.log('P03 contracts verified: 18 catalog codes, 10 operations, exact caps and bounded response decoders');
