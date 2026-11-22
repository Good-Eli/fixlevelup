import { randomUUID } from 'node:crypto';
import { createConnection } from 'node:net';
import { gzipSync } from 'node:zlib';
import { expect, it } from 'vitest';
import { check, idOf as geoId, records, text, versionOf } from './geography-fixture.js';
import { integration } from './rbac-fixture.js';
import { contentInput, idOf, legalInput, managementPerTest, minimal, PRIVATE_MARKER, problem } from './settings-management-fixture.js';

/** A valid domain JSON object whose RFC 8259 trailing whitespace reaches the exact wire byte limit.
 * The fixture sends the UTF-8 bytes over real HTTP, not the JS length or advertised Content-Length. */
function atByteCount(input: object, bytes: number): Buffer {
  const body = Buffer.from(JSON.stringify(input));
  if (body.length > bytes) { throw new Error('Fixture input exceeds requested size'); }
  return Buffer.concat([body, Buffer.alloc(bytes - body.length, 0x20)]);
}

integration('P03 streaming JSON and bounded query responses on real HTTP + PostgreSQL', () => {
  const fixture = managementPerTest();

  it('accepts only exact route-local ceilings on actual chunked UTF-8 and never uses widened auth or aliases', async () => {
    const f = fixture();
    const a = f.admin;
    const legal = check(await f.post('/legal/documents', { purpose: 'MARKETING', kind: 'POLICY' }), 201);
    const legalPath = `/legal/documents/${idOf(legal)}`;
    const content = check(await f.post('/content/blocks', { scope: 'COMPANY', code: 'large-content', kind: 'SEO', allowCompanyFallback: false }), 201);
    const contentPath = `/content/blocks/${idOf(content)}`;
    const city = await f.geo.activeCity(a, 'coverage-city');
    const area = check(await f.geo.createArea(a, city.id, city.version, 'coverage-area'), 201);
    const draft = check(await f.geo.addAreaVersion(a, city.id, geoId(area), versionOf(area), 'Synthetic draft'), 201);
    const coverage = `/settings/service-cities/${city.id}/service-areas/${geoId(area)}/versions/${geoId(draft)}/district-coverage`;
    const utf8 = 'Ж界😀';
    const cases = [
      { method: 'POST', path: `${legalPath}/publish`, etag: legal.etag, bytes: 1_048_576,
        input: legalInput(utf8.repeat(45_000)), status: 201 },
      { method: 'POST', path: `${contentPath}/publish`, etag: content.etag, bytes: 131_072,
        input: contentInput(utf8.repeat(4_000)), status: 201 },
      { method: 'PUT', path: coverage, etag: draft.etag, bytes: 65_536, input: { districts: [] }, status: 200 },
    ];
    for (const sample of cases) {
      const key = randomUUID(); const options = { key, etag: sample.etag };
      problem(await f.chunked(sample.method, sample.path, atByteCount(sample.input, sample.bytes + 1), options), 413);
      const result = check(await f.chunked(sample.method, sample.path, atByteCount(sample.input, sample.bytes), options), sample.status);
      if (sample.method === 'POST') {
        minimal(result, true);
        const exactRoute = sample.path.endsWith(`${idOf(legal)}/publish`) ? `${legalPath}/versions` : `${contentPath}/revisions`;
        const exact = check(await f.read(`${exactRoute}/${text(result.data, 'revisionId')}`), 200);
        expect(exact.data['body']).toBe(sample.input['body' as keyof typeof sample.input]);
        expect(exact.bytes).toBeLessThan(sample.bytes === 1_048_576 ? 2 * 1024 * 1024 : 256 * 1024);
      }
    }
    const authInput = { login: PRIVATE_MARKER, password: PRIVATE_MARKER };
    problem(await f.chunked('POST', '/auth/login', atByteCount(authInput, 4097), { web: null }), 413);
    // Boundary reaches the existing route (without a login-specific proof it cannot succeed).
    const auth = await f.chunked('POST', '/auth/login', atByteCount(authInput, 4096), { web: null });
    expect([400, 401, 403]).toContain(auth.status); problem(auth, auth.status);
    for (const [method, path] of [['PUT', `${legalPath}/publish`], ['PATCH', `${contentPath}/publish`],
      ['POST', `${legalPath}/publish/`], ['POST', `${legalPath}/%70ublish`], ['POST', '/legal/documents/not-a-uuid/publish'], ['POST', coverage]] as const) {
      problem(await f.chunked(method, path, atByteCount({ body: PRIVATE_MARKER }, 4097)), 413);
    }
  }, 35_000);

  it('rejects malformed and compressed bodies safely and enforces an absolute 10-second streaming deadline', async () => {
    const f = fixture();
    const ref = '/settings/references/payment_method';
    const persisted = () => Promise.all(['reference_entries', 'p03_command_receipts', 'audit_logs', 'outbox_events']
      .map((table) => f.base.count(`SELECT count(*)::int n FROM foundation.${table}`)));
    const before = await persisted();
    // Invalid framing is refused by the native HTTP parser before Nest sees a request.
    const raw = await new Promise<string>((resolve, reject) => {
      const wire = createConnection({ host: '127.0.0.1', port: f.base.httpPort });
      const parts: Buffer[] = [];
      wire.once('connect', () => {
        wire.write(`POST /api/v1${ref} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: invalid\r\n\r\n{"code":"${PRIVATE_MARKER}"}`);
      });
      wire.setTimeout(2000, () => { wire.destroy(new Error('Malformed framing did not close')); });
      wire.on('data', (chunk: Buffer) => { parts.push(chunk); });
      wire.once('error', reject);
      wire.once('close', () => { resolve(Buffer.concat(parts).toString('utf8')); });
    });
    expect(raw).toMatch(/^HTTP\/1\.1 400\b/);
    expect(raw).toMatch(/\r\nConnection: close\r\n/i);
    const [, responseBody] = raw.split('\r\n\r\n');
    expect(responseBody).toBe('');
    f.assertClean(raw);
    expect(await persisted()).toEqual(before);
    problem(await f.chunked('POST', ref, Buffer.from(`{"code":"${PRIVATE_MARKER}"`)), 400);
    problem(await f.chunked('POST', ref, Buffer.from([0x7b, 0x22, 0xf5, 0x22, 0x3a, 0x30, 0x7d])), 400);
    problem(await f.chunked('POST', ref, gzipSync(JSON.stringify({ code: PRIVATE_MARKER })),
      { headers: { 'Content-Encoding': 'gzip' } }), 415);
    const started = performance.now();
    let closed: Promise<void> | undefined;
    const timed = await f.http('POST', ref, (req) => {
      closed = new Promise((resolve) => { req.once('close', resolve); });
      req.write(`{"code":"${PRIVATE_MARKER}`);
      // Dripping data cannot reset an absolute deadline. No terminating chunk.
      const timer = setInterval(() => { req.write('x'); }, 1200);
      req.once('close', () => { clearInterval(timer); });
    }, { headers: { 'Transfer-Encoding': 'chunked' } });
    problem(timed, 408);
    expect(performance.now() - started).toBeGreaterThanOrEqual(9700);
    expect(performance.now() - started).toBeLessThan(14_000);
    expect(closed).toBeDefined(); await closed;
    expect(await persisted()).toEqual(before);
    await f.assertSafeEvidence();
  }, 22_000);

  it('keeps a maximum-count legal history compact and binds keyset to the real parent without disclosing text/totals', async () => {
    const f = fixture();
    const legal = '/legal/documents';
    const first = check(await f.post(legal, { purpose: 'REQUEST_PROCESSING', kind: 'POLICY' }), 201);
    const other = check(await f.post(legal, { purpose: 'MARKETING', kind: 'POLICY' }), 201);
    const block = `${legal}/${idOf(first)}/versions`;
    // Populate only the independent test's isolated PG using 201 bounded revisions.
    // Repeated bodies are highly compressible in PG but uncompressed wire would far
    // exceed the list cap. We inspect exact keys, not just a compressed/size proxy.
    await f.base.db.query(`INSERT INTO foundation.legal_document_versions
      (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
      SELECT gen_random_uuid(),$1,'REQUEST_PROCESSING','POLICY',n,repeat(chr(1),300),payload,
        encode(sha256(convert_to(payload,'UTF8')),'hex'),$2,'fixture-source',$3
      FROM generate_series(1,201) n, LATERAL (SELECT repeat($2::text,120) AS payload) fixture`, [idOf(first), PRIVATE_MARKER, f.admin.id]);
    const page = check(await f.read(`${block}?limit=200`), 200);
    expect(page.bytes).toBeLessThanOrEqual(512 * 1024);
    expect(Object.keys(page.data).sort()).toEqual(['items', 'pageInfo', 'version']);
    expect(page.data['version']).toBe(first.data['version']);
    const items = records(page.data['items']);
    expect(items).toHaveLength(200);
    for (const row of items) {
      expect(Object.keys(row).sort()).toEqual(['checksum', 'documentId', 'id', 'publishedAt', 'sequence', 'title']);
      expect(row['documentId']).toBe(idOf(first));
    }
    const cursorInfo = page.data['pageInfo'] as Record<string, unknown>;
    expect(cursorInfo['hasMore']).toBe(true);
    const cursor = encodeURIComponent(text(cursorInfo, 'nextCursor'));
    const tail = check(await f.read(`${block}?limit=200&cursor=${cursor}`), 200);
    expect(records(tail.data['items'])).toHaveLength(1);
    expect(items.some((row) => row['id'] === records(tail.data['items'])[0]?.['id'])).toBe(false);
    expect(tail.data['pageInfo']).toEqual({ nextCursor: null, hasMore: false });
    problem(await f.read(`${legal}/${idOf(other)}/versions?cursor=${cursor}`), 400);
    problem(await f.read(`${block}?limit=1&limit=2`), 400);
    problem(await f.read(`${block}?limit=201`), 400);
    problem(await f.read(`${block}?notABoundFilter=true`), 400);
  }, 20_000);
});
