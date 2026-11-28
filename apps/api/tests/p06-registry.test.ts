import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { parseRegistryQuery } from '../src/requests/registry/filters.js';
import { readVisibleRegistry } from '../src/requests/registry/store.js';

const city = {
  cityId: '00000000-0000-4000-8000-000000000001',
  cityVersionId: '00000000-0000-4000-8000-000000000002',
  timezone: 'Europe/Moscow',
};
const parse = (query: string) => parseRegistryQuery(new URLSearchParams(query));

describe('P06 registry candidate read', () => {
  it('normalizes interval precision while retaining half-open bounds', () => {
    expect(parse('from=2026-11-17T00:00:00.123Z&to=2026-11-17T00:00:00.123001Z')).toMatchObject({
      from: '2026-11-17T00:00:00.123000Z', to: '2026-11-17T00:00:00.123001Z', limit: 30,
    });
  });

  it.each([
    'cityId=00000000-0000-4000-8000-000000000001',
    'status=NEW&status=CANCELLED',
    'status=unsupported',
    'from=2026-02-30T00:00:00.000Z',
    'from=2026-01-01T00:00:00.000Z&to=2026-01-01T00:00:00.000000Z',
    'limit=0', 'limit=101', 'limit=1e2', 'categoryId=invalid',
  ])('rejects invalid query %s', (query) => {
    expect(() => parse(query)).toThrow('INVALID_REQUEST');
  });

  it('binds filters, uses a stable tie-breaker and retains a six-digit cursor', async () => {
    const first = {
      id: 'request-1', publicNumber: '9007199254740993', createdAt: '2026-11-17T00:00:00.123456Z',
      type: 'CALLBACK', status: 'NEW', version: 1,
    };
    const second = { ...first, id: 'request-2', createdAt: '2026-11-17T00:00:00.123455Z' };
    const row = { evidenceId: null, procedureRevision: null, validUntil: null };
    const query = vi.fn().mockResolvedValueOnce({ rows: [{ ...first, ...row }, { ...second, ...row }] })
      .mockResolvedValueOnce({ rows: [{ ...second, ...row }] });
    const client = { query } as unknown as PoolClient;
    const filters = parse('status=NEW&contactMode=CHANNEL&limit=1');
    const page = await readVisibleRegistry(client, city, filters, undefined);
    expect(page.items).toEqual([first]);
    expect(page.nextCursor).toContain(`${first.createdAt}~${first.publicNumber}~`);
    expect(query).toHaveBeenNthCalledWith(1, expect.stringContaining('WHERE request.city_id = $1'),
      [city.cityId, 'NEW', 'MESSENGER', 30]);
    expect(query).toHaveBeenNthCalledWith(1,
      expect.stringContaining('ORDER BY request.created_at DESC, request.public_number DESC'), expect.any(Array));

    const next = { ...filters, cursor: page.nextCursor };
    await expect(readVisibleRegistry(client, city, next, undefined)).resolves.toMatchObject({ items: [second], nextCursor: null });
    expect(query).toHaveBeenNthCalledWith(2,
      expect.stringContaining('(request.created_at, request.public_number) < ($4::timestamptz, $5::bigint)'),
      [city.cityId, 'NEW', 'MESSENGER', first.createdAt, first.publicNumber, 30]);

    await expect(readVisibleRegistry(client, city, { ...next, status: 'CANCELLED' }, undefined)).rejects.toThrow('INVALID_REQUEST');
    await expect(readVisibleRegistry(client, { ...city, cityId: city.cityVersionId }, next, undefined)).rejects.toThrow('INVALID_REQUEST');
    await expect(readVisibleRegistry(client, city, { ...next, cursor: 'invalid' }, undefined)).rejects.toThrow('INVALID_REQUEST');
    expect(query).toHaveBeenCalledTimes(2);
  });

  it('scans past a full batch of hidden rows and derives the cursor only from visible rows', async () => {
    const createdAt = '2026-11-17T00:00:00.123456Z';
    const validUntil = new Date('2026-11-18T00:00:00.000Z');
    const candidate = { createdAt, type: 'CALLBACK', status: 'NEW', version: 1, procedureRevision: 'rev', validUntil };
    const row = (number: number) => ({ ...candidate, publicNumber: String(number), id: `request-${String(number)}`, evidenceId: `evidence-${String(number)}` });
    const query = vi.fn().mockResolvedValueOnce({ rows: Array.from({ length: 30 }, (_, index) => row(35 - index)) })
      .mockResolvedValueOnce({ rows: [5, 4, 3, 2, 1].map(row) });
    const isCurrent = vi.fn((evidence: { id: string }) => evidence.id === 'evidence-4' || evidence.id === 'evidence-2');
    const client = { query } as unknown as PoolClient;
    const page = await readVisibleRegistry(client, city, parse('limit=1'), isCurrent);
    expect(page.items).toEqual([{ createdAt, type: 'CALLBACK', status: 'NEW', version: 1, publicNumber: '4', id: 'request-4' }]);
    expect(page.nextCursor).toContain(`${createdAt}~4~`);
    expect(page.manualEvidence.map(evidence => evidence.id)).toEqual(['evidence-4', 'evidence-2']);
    expect(query).toHaveBeenCalledTimes(2);
    expect(query).toHaveBeenNthCalledWith(2, expect.any(String), [city.cityId, createdAt, '6', 30]);
  });
});
