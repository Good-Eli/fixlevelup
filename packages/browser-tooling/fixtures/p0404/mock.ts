import { expect, type Page, type Route } from '@playwright/test';
import { arrange, id, timestamp, uuid, wire, type Handler, type Hit } from '../p0305/mock.js';

// Synthetic DTOs follow p03-contracts/p04-openapi.mjs; no runtime dependency on generated output.
export const directories = {
  CATEGORY: '/catalog/categories', BRAND: '/catalog/brands', MODEL: '/catalog/models', FAULT: '/catalog/faults',
} as const;
export const itemsPath = '/catalog/items', mappingsPath = '/catalog/fault-service-mappings';
export const rulesPath = '/pricing/rules', avitoPath = '/content/external-reviews';
export const citiesPath = '/pricing/cities', cityPath = `${citiesPath}/${id.city}`;
export const policyPath = `${cityPath}/policy-versions`, estimatesPath = `${cityPath}/public-estimates`;
export const tag = (version: number) => `"p04-v${String(version)}"`;
const grants = ['catalog.read', 'catalog.manage', 'pricing.rules.read', 'pricing.rules.manage', 'pricing.read', 'pricing.manage',
  'content.externalreviews.read', 'content.externalreviews.manage', 'content.externalreviews.publish'] as const;
export const admin = grants.map(code => ({ code, scope: 'GLOBAL' as const }));
export type Fixture = Awaited<ReturnType<typeof arrange>>;
export function rig(page: Page, overrides: Parameters<typeof arrange>[1] = {}) { return arrange(page, { p04: admin, ...overrides }); }

export function listing<T>(items: readonly T[], nextCursor: string | null = null) { return { items, pageInfo: { nextCursor } }; }
export function receipt(route: Route, target: string, version: number, revisionVersion?: number, status = 201) {
  return wire(route, { id: target, version, ...(revisionVersion === undefined ? {} : { revisionId: uuid(901), revisionVersion }) }, status, tag(version));
}
export function problem(route: Route, status: 403 | 412 | 503) {
  const code = status === 403 ? 'FORBIDDEN' : status === 412 ? 'VERSION_MISMATCH' : 'COMMAND_OUTCOME_UNKNOWN';
  return route.fulfill({ status, contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'about:blank', title: code, status, code, requestId: uuid(99) }), headers: { 'cache-control': 'no-store' } });
}
export function expectCommand(hit: Hit | undefined, expected: unknown, prior?: number) {
  expect(hit?.key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect(hit?.tag).toBe(prior === undefined ? undefined : tag(prior));
  expect(hit?.syntheticCsrfMatches).toBe(true);
  expect(hit?.staffRequest).toBe(true);
  expect(hit?.sameOrigin).toBe(true);
  expect(hit?.mediaType).toBe('application/json; charset=utf-8');
  expect(hit?.url.search).toBe('');
  expect(JSON.parse(hit?.body ?? 'null') as unknown).toEqual(expected);
}

interface Identity { id: string; code: string; version: number; archivedAt: string | null }
interface Versioned extends Identity { title: string | null; currentVersionId: string | null }
function entity(n: number, code: string): Identity { return { id: uuid(n), code, version: 2, archivedAt: null }; }
function withTitle(n: number, code: string): Identity & { title: null; currentVersionId: null };
function withTitle(n: number, code: string, title: string): Identity & { title: string; currentVersionId: string };
function withTitle(n: number, code: string, title: string | null = null): Versioned {
  return { ...entity(n, code), version: title === null ? 1 : 2, title, currentVersionId: title === null ? null : uuid(n + 400) };
}
export function label(row: { code: string; title?: string | null }) { return row.title ? `${row.title} · ${row.code}` : row.code; }
export type DirectoryKind = keyof typeof directories;
interface Directory extends Versioned { kind: DirectoryKind; categoryId: string | null; brandId: string | null }
export const category = { ...withTitle(110, 'qa-device', 'Техника QA'), kind: 'CATEGORY', categoryId: null, brandId: null } satisfies Directory;
export const brand = { ...withTitle(111, 'qa-brand', 'Бренд QA'), kind: 'BRAND', categoryId: null, brandId: null } satisfies Directory;
export const model = { ...withTitle(112, 'qa-model'), kind: 'MODEL', categoryId: category.id, brandId: brand.id } satisfies Directory;
export const fault = { ...withTitle(113, 'qa-fault', 'Симптом QA'), kind: 'FAULT', categoryId: category.id, brandId: null } satisfies Directory;
export const otherCategory = { ...category, ...withTitle(115, 'qa-other', 'Другая категория') };
export const otherFault = { ...fault, ...withTitle(116, 'qa-wrong-fault'), categoryId: otherCategory.id };
export const archivedBrand = { ...brand, ...withTitle(117, 'qa-archived-brand'), version: 2, archivedAt: timestamp };
export type ItemKind = 'WORK' | 'PART' | 'MATERIAL' | 'TRAVEL' | 'DIAGNOSTICS';
interface Item extends Versioned { kind: ItemKind; categoryId: string | null; unit: string }
export const items = {
  WORK: { ...withTitle(120, 'qa-work'), kind: 'WORK', categoryId: category.id, unit: 'job' },
  PART: { ...withTitle(121, 'qa-part'), kind: 'PART', categoryId: null, unit: 'piece' },
  MATERIAL: { ...withTitle(122, 'qa-material'), kind: 'MATERIAL', categoryId: null, unit: 'meter' },
  TRAVEL: { ...withTitle(123, 'qa-travel'), kind: 'TRAVEL', categoryId: null, unit: 'trip' },
  DIAGNOSTICS: { ...withTitle(124, 'qa-diagnosis'), kind: 'DIAGNOSTICS', categoryId: null, unit: 'job' },
} satisfies Record<ItemKind, Item>;
export const otherWork = { ...items.WORK, ...withTitle(125, 'qa-wrong-work'), categoryId: otherCategory.id };
export const itemRows = Object.values(items);
export const mapping = { id: uuid(126), version: 2, archivedAt: null, publishedAt: null, categoryId: category.id, faultId: fault.id, itemId: items.WORK.id };
export type RuleKind = 'EVENING' | 'NIGHT' | 'EXPRESS' | 'SURCHARGE' | 'DISCOUNT';
export const rules = {
  EVENING: { ...entity(130, 'qa-evening'), kind: 'EVENING' }, NIGHT: { ...entity(131, 'qa-night'), kind: 'NIGHT' },
  EXPRESS: { ...entity(132, 'qa-express'), kind: 'EXPRESS' }, SURCHARGE: { ...entity(133, 'qa-surcharge'), kind: 'SURCHARGE' },
  DISCOUNT: { ...entity(134, 'qa-discount'), kind: 'DISCOUNT' },
} satisfies Record<RuleKind, Identity & { kind: RuleKind }>;
export const rulePath = (kind: RuleKind) => `${cityPath}/rules/${rules[kind].id}/versions`;
export const pricePath = (kind: ItemKind) => `${cityPath}/items/${items[kind].id}/price-versions`;
interface Avito extends Versioned { kind: 'PROFILE' | 'REVIEW'; profileId: string | null }
export const profile = { ...withTitle(140, 'qa-profile', 'Профиль QA'), kind: 'PROFILE', profileId: null } satisfies Avito;
export const review = { ...withTitle(141, 'qa-review', 'Ранее сохранённый отзыв QA'), kind: 'REVIEW', profileId: profile.id } satisfies Avito;
export const city = { id: id.city, code: 'qa-city', name: 'Свои городские цены' };
export const outsideCity = { id: uuid(150), code: 'qa-outside', name: 'Другой город' };
export const estimate = { ...entity(151, 'qa-estimate'), cityId: city.id, categoryId: category.id };
export const estimatePath = `${estimatesPath}/${estimate.id}`;
export const period = { validFrom: '2099-01-03T01:00:00.000Z', validUntil: null, sourceRef: 'synthetic-approved-source' };
export const fixed = { id: uuid(160), version: 1, cityId: city.id, cityVersionId: id.cityVersion,
  seriesId: uuid(161), validFrom: '2020-01-01T00:00:00.000Z', validUntil: null, effectiveUntil: null, publishedAt: '2020-01-01T00:00:00.000Z',
  itemId: items.PART.id, itemVersionId: uuid(162), amountMinor: '8400', currency: 'RUB', zeroBasis: null, sourceRef: 'fixture-price-review' };

export function companyReads(s: Fixture) {
  const groups = [
    [directories.CATEGORY, [category, otherCategory]], [directories.BRAND, [brand, archivedBrand]],
    [directories.MODEL, [model]], [directories.FAULT, [fault, otherFault]],
    [itemsPath, [...itemRows, otherWork]], [mappingsPath, [mapping]], [avitoPath, [profile, review]],
  ] as const;
  const handler: Handler = (route, h) => {
    if (h.method !== 'GET') { return; }
    for (const [path, rows] of groups) {
      if (h.path === path) { return wire(route, listing<{ id: string }>(rows)); }
      const found = rows.find(row => h.path === `${path}/${row.id}`);
      if (found) { return wire(route, found); }
    }
  };
  s.handlers.push(handler);
}

export function cityReads(s: Fixture, cities = [city]) {
  s.handlers.push((route, h) => {
    if (h.method !== 'GET') { return; }
    if (h.path === citiesPath) { return wire(route, listing(cities)); }
    if (h.path === '/pricing/readiness') { return wire(route, listing(cities.map(row => ({ ...row, fixed: 'CONFIGURED', policy: 'MISSING' })))); }
    if (h.path === `${cityPath}/items`) {
      return wire(route, listing(itemRows.map(({ id, code, kind, categoryId, unit }) => ({ id, code, kind, categoryId, unit,
        title: `Позиция ${kind}`, technicianVisible: false, publicVisible: false }))));
    }
    if (h.path === `${cityPath}/categories`) { return wire(route, listing([{ id: category.id, code: category.code, title: category.title }])); }
    if (h.path === `${cityPath}/rules`) { return wire(route, listing(Object.values(rules).map(({ id, code, kind }) => ({ id, code, kind })))); }
  });
}
