import { ITEM_KINDS } from '../catalog/contracts.js';
import type { CatalogClient, DirectoryKind } from '../catalog/contracts.js';
import { CatalogInternalError, MAX_VERSION, optionalUuid, refuse, uuid } from '../catalog/validation.js';
import { assertAvitoPublishForm } from './avito.js';
import type { AvitoPublishForm } from './avito.js';
import { managementPage, managementPageQuery, pageSQL, SqlValues } from './page.js';
import type { PageOrder, PageQuery, PageRow } from './page.js';

type Params = Readonly<Record<string, string>>;
type Dto = Readonly<Record<string, unknown>>;
const RULE_KINDS = ['EVENING', 'NIGHT', 'EXPRESS', 'SURCHARGE', 'DISCOUNT'] as const;
const AVITO_KINDS = ['PROFILE', 'REVIEW'] as const;

// Composed SQL only uses these module-private literals and aliases, never user data.
const utc = (value: string): string => `pg_catalog.to_char(${value} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`;
const obj = (fields: string): string => `pg_catalog.jsonb_build_object(${fields})`;

const COMMON_ID = `'id',e.id,'version',e.row_version,'archivedAt',${utc('e.archived_at')}`;
const CODED_ID = `${COMMON_ID},'code',e.code`;
const VERSIONED_ID = `${CODED_ID},'currentVersionId',e.current_version_id,'title',v.title`;
const COMMON_REVISION = `'id',v.id,'version',v.version,'title',v.title,'publishedAt',${utc('v.published_at')}`;
const CITY_LABEL = `'id',e.id,'code',e.code,'name',cv.display_name`;
const OPEN_CITY = `foundation.service_cities e
  JOIN foundation.service_city_versions cv ON (cv.city_id,cv.id)=(e.id,e.current_version_id)`;

interface Temporal {
  readonly versions: string;
  readonly periods: string;
  readonly periodId: 'version_id' | 'price_version_id';
  readonly summary: string;
  readonly detail: string;
  readonly join?: string;
}

interface Resource {
  readonly table: string;
  readonly identity?: string;
  readonly kind?: DirectoryKind;
  readonly filterKinds?: readonly string[];
  readonly city?: boolean;
  readonly subject?: 'id' | 'cityId' | 'itemId' | 'ruleId' | 'estimateId';
  readonly subjectColumn?: 'item_id' | 'rule_id';
  readonly identityJoin?: string;
  readonly revision?: { readonly table: string; readonly parent: string; readonly summary: string; readonly detail: string; readonly typed?: boolean };
  readonly temporal?: Temporal;
}

function directory(kind: DirectoryKind): Resource {
  return {
    table: 'catalog_directory_entries',
    kind,
    identity: `${VERSIONED_ID},'kind',e.kind,'categoryId',e.category_id,'brandId',e.brand_id`,
    identityJoin: `LEFT JOIN foundation.catalog_directory_versions v ON (v.entry_id,v.id)=(e.id,e.current_version_id)`,
    revision: {
      table: 'catalog_directory_versions', parent: 'entry_id',
      summary: `${COMMON_REVISION},'entryId',v.entry_id`, detail: `'description',v.description`,
    },
  };
}

const FIXED_DETAIL = `'itemId',v.item_id,'itemVersionId',v.item_version_id,'amountMinor',v.amount_minor::text,
  'currency',v.currency,'zeroBasis',v.zero_basis,'sourceRef',v.source_ref`;
const RULE_VERSION_SUMMARY = `'ruleId',v.rule_id,'kind',v.kind,'title',v.title`;
const RULE_VERSION_DETAIL = `'method',v.method,'base',v.base,'currency',v.currency,'fixedMinor',v.fixed_minor::text,
  'rateBps',v.rate_bps,'minBase',v.min_base::text,'maxBase',v.max_base::text,'minDelta',v.min_delta::text,
  'maxDelta',v.max_delta::text,'startMinute',v.start_minute,'endMinute',v.end_minute,'wrapsMidnight',v.wraps_midnight,
  'categoryIds',coalesce((SELECT jsonb_agg(s.category_id ORDER BY s.category_id)
    FROM foundation.price_rule_scopes s WHERE s.rule_version_id=v.id),'[]'::jsonb),'sourceRef',v.source_ref`;
const POLICY_DETAIL = `'taxDisplay',v.tax_display,'roundingMode',v.rounding_mode,'units',v.units,
  'maxManualDeltaMinor',v.max_manual_delta_minor::text,'sourceRef',v.source_ref,
  'priorities',coalesce((SELECT jsonb_agg(${obj(`'ruleId',r.rule_id,'priority',r.priority`)} ORDER BY r.rule_id)
    FROM foundation.price_rule_priorities r WHERE r.policy_version_id=v.id),'[]'::jsonb),
  'compatibilities',coalesce((SELECT jsonb_agg(${obj(`'leftRuleId',r.left_rule_id,'rightRuleId',r.right_rule_id`)}
    ORDER BY r.left_rule_id,r.right_rule_id) FROM foundation.price_rule_compatibilities r WHERE r.policy_version_id=v.id),'[]'::jsonb)`;

const RESOURCES = {
  category: directory('CATEGORY'), brand: directory('BRAND'), model: directory('MODEL'), fault: directory('FAULT'),
  item: {
    table: 'catalog_items', filterKinds: ITEM_KINDS,
    identity: `${VERSIONED_ID},'kind',e.kind,'categoryId',e.category_id,'unit',e.unit`,
    identityJoin: `LEFT JOIN foundation.catalog_item_versions v ON (v.item_id,v.id,v.kind)=(e.id,e.current_version_id,e.kind)`,
    revision: {
      table: 'catalog_item_versions', parent: 'item_id', typed: true,
      summary: `${COMMON_REVISION},'itemId',v.item_id,'kind',v.kind`,
      detail: `'description',v.description,'durationMinutes',v.duration_minutes,'technicianVisible',v.technician_visible,'publicVisible',v.public_visible`,
    },
  },
  mapping: {
    table: 'catalog_fault_service_mappings',
    identity: `${COMMON_ID},'categoryId',e.category_id,'faultId',e.fault_id,'itemId',e.item_id,'publishedAt',${utc('e.published_at')}`,
  },
  rule: { table: 'price_rules', filterKinds: RULE_KINDS, identity: `${CODED_ID},'kind',e.kind` },
  avito: {
    table: 'external_reviews', filterKinds: AVITO_KINDS,
    identity: `${VERSIONED_ID},'kind',e.kind,'profileId',e.profile_id`,
    identityJoin: `LEFT JOIN foundation.external_review_revisions v ON (v.entry_id,v.id,v.kind)=(e.id,e.current_version_id,e.kind)`,
    revision: {
      table: 'external_review_revisions', parent: 'entry_id', typed: true,
      summary: `${COMMON_REVISION},'entryId',v.entry_id,'kind',v.kind`,
      detail: `'sourceUrl',v.source_url,'sourceDate',v.source_date,'excerpt',v.excerpt,'rating',v.rating,'permissionRef',v.permission_ref,
        'profileRevisionId',v.profile_revision_id`,
    },
  },
  fixed: {
    table: 'catalog_price_series', city: true, subject: 'itemId', subjectColumn: 'item_id',
    temporal: { versions: 'catalog_price_versions', periods: 'catalog_price_periods', periodId: 'price_version_id',
      summary: FIXED_DETAIL, detail: '', join: ' AND v.item_id=e.item_id AND p.item_id=e.item_id' },
  },
  ruleVersion: {
    table: 'price_rule_series', city: true, subject: 'ruleId', subjectColumn: 'rule_id',
    temporal: { versions: 'price_rule_versions', periods: 'price_rule_periods', periodId: 'version_id',
      summary: RULE_VERSION_SUMMARY, detail: RULE_VERSION_DETAIL,
      join: ' AND v.rule_id=e.rule_id AND EXISTS (SELECT 1 FROM foundation.price_rules d WHERE (d.id,d.kind)=(v.rule_id,v.kind))' },
  },
  policy: {
    table: 'pricing_policy_series', city: true, subject: 'cityId',
    temporal: { versions: 'pricing_policy_versions', periods: 'pricing_policy_periods', periodId: 'version_id',
      summary: `'currency',v.currency`, detail: POLICY_DETAIL },
  },
  estimate: {
    table: 'public_price_estimate_series', city: true, subject: 'estimateId',
    identity: `${CODED_ID},'cityId',e.city_id,'categoryId',e.category_id`,
    temporal: { versions: 'public_price_estimates', periods: 'public_price_estimate_periods', periodId: 'version_id',
      summary: `'title',v.title,'currency',v.currency,'minMinor',v.min_minor::text,'maxMinor',v.max_minor::text`,
      detail: `'conditions',v.conditions,'disclaimer',v.disclaimer,'sourceRef',v.source_ref` },
  },
} as const satisfies Readonly<Record<string, Resource>>;

type ResourceName = keyof typeof RESOURCES;
const READ_ACTIONS = ['Versions', 'Version', 'List', 'Get'] as const;
const WRITE_ACTIONS = ['Create', 'Publish', 'Archive', 'Close', 'Replace'] as const;

function resourceAction<Action extends string>(operation: string, actions: readonly Action[]): {
  name: ResourceName; resource: Resource; action: Action;
} {
  const action = actions.find((value) => operation.endsWith(value));
  const name = action === undefined ? '' : operation.slice(0, -action.length);
  if (action === undefined || !Object.hasOwn(RESOURCES, name)) {
    throw new CatalogInternalError();
  }
  const resourceName = name as ResourceName;
  return { name: resourceName, resource: RESOURCES[resourceName], action };
}

function scopeKey(operation: string, params: Params, cityIds: readonly string[] | null): readonly unknown[] {
  const ids = Object.entries(params).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return [operation, ids, cityIds];
}

function scopedCities(ids: readonly string[] | null): readonly string[] | null {
  return ids === null ? null : [...new Set(ids.map((id) => uuid(id, 'cityId')))].sort();
}

function boundCity(params: Params, authorized: readonly string[] | null): string {
  const cityId = uuid(params['cityId'], 'cityId');
  if (authorized !== null && !authorized.includes(cityId)) {
    return refuse('NOT_FOUND', 'cityId');
  }
  return cityId;
}

async function requireRow(client: CatalogClient, sql: string, args: SqlValues, field: string): Promise<void> {
  const { rows } = await client.query<{ found: boolean }>(`SELECT EXISTS (${sql}) AS found`, args.args);
  const row = rows[0];
  if (row === undefined) {
    throw new CatalogInternalError();
  }
  if (!row.found) {
    refuse('NOT_FOUND', field);
  }
}

async function existingCity(client: CatalogClient, id: string, active = false): Promise<void> {
  const values = new SqlValues();
  await requireRow(client, `SELECT 1 FROM ${active ? OPEN_CITY : 'foundation.service_cities e'}
    WHERE e.id=${values.add(id)}::uuid ${active ? `AND e.lifecycle='ACTIVE'` : ''}`, values, 'cityId');
}

function identityWhere(resource: Resource, values: SqlValues, cityId?: string, id?: string): string {
  const where: string[] = [];
  if (resource.kind !== undefined) {where.push(`e.kind=${values.add(resource.kind)}::text`);}
  if (cityId !== undefined) {where.push(`e.city_id=${values.add(cityId)}::uuid`);}
  if (id !== undefined) {where.push(`e.${resource.subjectColumn ?? 'id'}=${values.add(id)}::uuid`);}
  return where.length === 0 ? 'true' : where.join(' AND ');
}

async function selectPage(client: CatalogClient, values: SqlValues, page: PageQuery, order: PageOrder,
  fields: string, from: string, where: string, id: string, key?: string) {
  const cut = pageSQL(values, page, order, id, key);
  const { rows } = await client.query<PageRow>(`SELECT ${cut.select},${obj(fields)} AS dto
    FROM ${from} WHERE ${where} AND ${cut.where} ${cut.tail}`, values.args);
  return managementPage(rows, page);
}

async function selectExact(client: CatalogClient, values: SqlValues, fields: string, from: string, where: string, field: string): Promise<Dto> {
  const { rows } = await client.query<{ dto: Dto }>(`SELECT ${obj(fields)} AS dto FROM ${from} WHERE ${where}`, values.args);
  return rows[0]?.dto ?? refuse('NOT_FOUND', field);
}

function readIdentity(client: CatalogClient, operation: string, params: Params, raw: unknown, name: ResourceName,
  resource: Resource, cityId: string | undefined, list: boolean) {
  if (resource.identity === undefined) {throw new CatalogInternalError();}
  const from = `foundation.${resource.table} e ${resource.identityJoin ?? ''}`;
  const values = new SqlValues();
  if (!list) {
    managementPageQuery(raw, {}, []);
    const field = resource.subject ?? 'id';
    const match = identityWhere(resource, values, cityId, uuid(params[field], field));
    return selectExact(client, values, resource.identity, from, match, field);
  }
  const order = name === 'mapping' ? 'id' : 'code';
  const page = managementPageQuery(raw, { order, includeArchived: true, ...(resource.filterKinds === undefined ? {} : { kinds: resource.filterKinds }) },
    scopeKey(operation, params, cityId === undefined ? null : [cityId]));
  let match = identityWhere(resource, values, cityId);
  if (!page.includeArchived) {match += ' AND e.archived_at IS NULL';}
  if (page.kind !== null) {match += ` AND e.kind::text=${values.add(page.kind)}::text`;}
  return selectPage(client, values, page, order, resource.identity, from, match, 'e.id');
}

async function currentToken(client: CatalogClient, values: SqlValues, from: string, match: string): Promise<number | null> {
  const { rows } = await client.query<{ row_version: number }>(`SELECT e.row_version FROM ${from} WHERE ${match}`, values.args);
  return rows[0]?.row_version ?? null;
}

async function readRevision(client: CatalogClient, operation: string, params: Params, raw: unknown, resource: Resource, list: boolean) {
  const revision = resource.revision;
  if (revision === undefined) {throw new CatalogInternalError();}
  const values = new SqlValues();
  const match = identityWhere(resource, values, undefined, uuid(params['id'], 'id'));
  const identity = `foundation.${resource.table} e`;
  const from = `${identity} JOIN foundation.${revision.table} v ON v.${revision.parent}=e.id${revision.typed === true ? ' AND v.kind=e.kind' : ''}`;
  if (!list) {
    managementPageQuery(raw, {}, []);
    return selectExact(client, values, `${revision.summary},${revision.detail}`, from,
      `${match} AND v.id=${values.add(uuid(params['versionId'], 'versionId'))}::uuid`, 'versionId');
  }
  const page = managementPageQuery(raw, { order: 'version', includeArchived: true }, scopeKey(operation, params, null));
  const parent = `${match}${page.includeArchived ? '' : ' AND e.archived_at IS NULL'}`;
  const version = await currentToken(client, values, identity, parent);
  if (version === null) {return refuse('NOT_FOUND', 'id');}
  return { version, ...await selectPage(client, values, page, 'version', revision.summary, from, parent, 'v.id') };
}

function temporalFrom(resource: Resource, temporal: Temporal): string {
  return `foundation.${resource.table} e
    JOIN foundation.${temporal.versions} v ON (v.series_id,v.city_id)=(e.id,e.city_id)
    JOIN foundation.${temporal.periods} p ON (p.${temporal.periodId},p.series_id,p.city_id)=(v.id,e.id,e.city_id)${temporal.join ?? ''}`;
}

function effectiveUntil(alias: string): string {
  return `coalesce(${alias}.closed_effective_until,${alias}.scheduled_until)`;
}

async function readTemporal(client: CatalogClient, operation: string, params: Params, raw: unknown,
  name: ResourceName, resource: Resource, cityId: string, list: boolean) {
  const temporal = resource.temporal;
  if (temporal === undefined) {throw new CatalogInternalError();}
  const values = new SqlValues();
  const field = resource.subject ?? 'id';
  const subject = field === 'cityId' ? undefined : uuid(params[field], field);
  const match = identityWhere(resource, values, cityId, subject);
  const from = temporalFrom(resource, temporal);
  const summary = `'id',v.id,'seriesId',v.series_id,'version',v.version,'cityId',v.city_id,'cityVersionId',v.city_version_id,
    'validFrom',${utc('v.valid_from')},'validUntil',${utc('v.valid_until')},'effectiveUntil',${utc(effectiveUntil('p'))},
    'publishedAt',${utc('v.published_at')},${temporal.summary}`;
  if (!list) {
    managementPageQuery(raw, {}, []);
    return selectExact(client, values, `${summary}${temporal.detail === '' ? '' : `,${temporal.detail}`}`, from,
      `${match} AND v.id=${values.add(uuid(params['versionId'], 'versionId'))}::uuid`, 'versionId');
  }
  const page = managementPageQuery(raw, { order: 'version', includeArchived: true }, scopeKey(operation, params, [cityId]));
  const parent = `${match}${name === 'estimate' && !page.includeArchived ? ' AND e.archived_at IS NULL' : ''}`;
  const version = await currentToken(client, values, `foundation.${resource.table} e`, parent);
  if (version === null && name === 'estimate') {return refuse('NOT_FOUND', field);}
  const visible = page.includeArchived ? parent
    : `${parent} AND p.closed_effective_until IS NULL AND (p.scheduled_until IS NULL OR p.scheduled_until>statement_timestamp())`;
  return { version: version ?? 0, ...await selectPage(client, values, page, 'version', summary, from, visible, 'v.id') };
}

const ACTIVE_CATEGORY = `cat.kind='CATEGORY' AND cat.archived_at IS NULL AND cat.current_version_id IS NOT NULL`;
const ITEM_CATEGORY = `e.category_id IS NULL OR EXISTS (SELECT 1 FROM foundation.catalog_directory_entries cat
  WHERE cat.id=e.category_id AND ${ACTIVE_CATEGORY})`;
const LABELS = {
  cityCategories: {
    fields: `'id',e.id,'code',e.code,'title',v.title`,
    from: `foundation.catalog_directory_entries e JOIN foundation.catalog_directory_versions v ON (v.entry_id,v.id)=(e.id,e.current_version_id)`,
    where: `e.kind='CATEGORY' AND e.archived_at IS NULL`,
  },
  cityItems: {
    fields: `'id',e.id,'code',e.code,'title',v.title,'kind',e.kind,'categoryId',e.category_id,'unit',e.unit,
      'technicianVisible',v.technician_visible,'publicVisible',v.public_visible`,
    from: `foundation.catalog_items e JOIN foundation.catalog_item_versions v ON (v.item_id,v.id,v.kind)=(e.id,e.current_version_id,e.kind)`,
    where: `e.archived_at IS NULL AND (${ITEM_CATEGORY})`,
  },
  cityRules: { fields: `'id',e.id,'code',e.code,'kind',e.kind`, from: 'foundation.price_rules e', where: 'e.archived_at IS NULL' },
} as const;

function effectiveNow(alias: string): string {
  return `${alias}.valid_from<=statement_timestamp()
    AND (${effectiveUntil(alias)} IS NULL OR statement_timestamp()<${effectiveUntil(alias)})`;
}

const READINESS = `'fixed',CASE WHEN EXISTS (
    SELECT 1 FROM foundation.catalog_price_periods p
    JOIN foundation.catalog_items i ON i.id=p.item_id AND i.archived_at IS NULL
    JOIN foundation.catalog_item_versions iv ON (iv.item_id,iv.id,iv.kind)=(i.id,i.current_version_id,i.kind)
    WHERE p.city_id=e.id AND ${effectiveNow('p')}
      AND (i.category_id IS NULL OR EXISTS (SELECT 1 FROM foundation.catalog_directory_entries cat
        WHERE cat.id=i.category_id AND ${ACTIVE_CATEGORY}))
  ) THEN 'CONFIGURED' ELSE 'MISSING' END,
  'policy',CASE WHEN EXISTS (SELECT 1 FROM foundation.pricing_policy_periods p
    WHERE p.city_id=e.id AND ${effectiveNow('p')}) THEN 'CONFIGURED' ELSE 'MISSING' END`;

function normalizeParams(params: Params, fields: readonly string[]): Params {
  if (Object.keys(params).length !== fields.length || fields.some((field) => !Object.hasOwn(params, field))) {
    return refuse('INVALID_INPUT', 'path');
  }
  return Object.fromEntries(fields.map((field) => [field, uuid(params[field], field)]));
}

async function discover(client: CatalogClient, operation: string, params: Params, raw: unknown, authorized: readonly string[] | null) {
  const values = new SqlValues();
  const isCityList = operation === 'cityList' || operation === 'pricingReadiness';
  const bound = normalizeParams(params, isCityList ? [] : ['cityId']);
  if (isCityList) {
    const page = managementPageQuery(raw, { order: 'code' }, scopeKey(operation, bound, authorized));
    const where = `e.lifecycle='ACTIVE'${authorized === null ? '' : ` AND e.id=ANY(${values.add(authorized)}::uuid[])`}`;
    const fields = operation === 'pricingReadiness' ? `${CITY_LABEL},${READINESS}` : CITY_LABEL;
    return selectPage(client, values, page, 'code', fields, OPEN_CITY, where, 'e.id');
  }
  if (!Object.hasOwn(LABELS, operation)) {throw new CatalogInternalError();}
  const cityId = boundCity(bound, authorized);
  const page = managementPageQuery(raw, { order: 'code' }, scopeKey(operation, bound, [cityId]));
  await existingCity(client, cityId, true);
  const { fields, from, where } = LABELS[operation as keyof typeof LABELS];
  // The route city is checked for active, authorized existence before use of these company-owned labels.
  // Rebind it in the page snapshot as well (CITY picks never fall back to another or a default city).
  const cityFilter = `EXISTS (SELECT 1 FROM foundation.service_cities c JOIN foundation.service_city_versions cv
    ON (cv.city_id,cv.id)=(c.id,c.current_version_id) WHERE c.id=${values.add(cityId)}::uuid AND c.lifecycle='ACTIVE')`;
  return selectPage(client, values, page, 'code', fields, from, `${where} AND ${cityFilter}`, 'e.id');
}

async function existingParent(client: CatalogClient, table: string, id: string, field: string, kind?: string, categoryId?: string): Promise<void> {
  const values = new SqlValues();
  let predicate = `e.id=${values.add(id)}::uuid`;
  if (kind !== undefined) {predicate += ` AND e.kind::text=${values.add(kind)}::text`;}
  if (categoryId !== undefined) {predicate += ` AND e.category_id=${values.add(categoryId)}::uuid`;}
  await requireRow(client, `SELECT 1 FROM foundation.${table} e WHERE ${predicate}`, values, field);
}

/** An empty city stream may be opened only for a currently discoverable subject.
 * A real version and its exact period in this same city also prove historical
 * visibility; a bare series, another city's history or a draft does not. The
 * caller holds the catalog fence from this check through the read or write. */
async function visibleStreamSubject(client: CatalogClient, name: 'fixed' | 'ruleVersion', cityId: string, id: string): Promise<void> {
  const resource = RESOURCES[name];
  const label = name === 'fixed' ? LABELS.cityItems : LABELS.cityRules;
  const values = new SqlValues();
  const subject = `${values.add(id)}::uuid`;
  const city = `${values.add(cityId)}::uuid`;
  await requireRow(client, `SELECT 1 FROM ${label.from} WHERE e.id=${subject} AND (${label.where})
    UNION ALL SELECT 1 FROM ${temporalFrom(resource, resource.temporal)}
    WHERE e.city_id=${city} AND e.${resource.subjectColumn}=${subject}`, values, resource.subject);
}

// Apply the same boundary to IDs carried inside a city command. Historical
// references remain readable only through data already reviewable in that city.
async function visiblePricingReferences(client: CatalogClient, cityId: string, categoryIds: readonly string[], ruleIds: readonly string[]): Promise<void> {
  if (categoryIds.length) {
    const { rows } = await client.query<{ visible: boolean }>(`SELECT NOT EXISTS (
      SELECT FROM unnest($2::uuid[]) AS requested(id)
      WHERE NOT EXISTS (SELECT FROM ${LABELS.cityCategories.from} WHERE e.id=requested.id AND (${LABELS.cityCategories.where}))
        AND NOT EXISTS (SELECT FROM foundation.public_price_estimate_series z WHERE z.city_id=$1 AND z.category_id=requested.id)
        AND NOT EXISTS (SELECT FROM ${temporalFrom(RESOURCES.ruleVersion, RESOURCES.ruleVersion.temporal)}
          JOIN foundation.price_rule_scopes rs ON rs.rule_version_id=v.id WHERE e.city_id=$1 AND rs.category_id=requested.id)
    ) AS visible`, [cityId, categoryIds]);
    if (rows[0]?.visible !== true) {refuse('NOT_FOUND', 'categoryId');}
  }
  if (ruleIds.length) {
    const { rows } = await client.query<{ visible: boolean }>(`SELECT NOT EXISTS (
      SELECT FROM unnest($2::uuid[]) AS requested(id)
      WHERE NOT EXISTS (SELECT FROM ${LABELS.cityRules.from} WHERE e.id=requested.id AND (${LABELS.cityRules.where}))
        AND NOT EXISTS (SELECT FROM ${temporalFrom(RESOURCES.ruleVersion, RESOURCES.ruleVersion.temporal)}
          WHERE e.city_id=$1 AND e.rule_id=requested.id)
        AND NOT EXISTS (SELECT FROM ${temporalFrom(RESOURCES.policy, RESOURCES.policy.temporal)} WHERE e.city_id=$1 AND (
          EXISTS (SELECT FROM foundation.price_rule_priorities q WHERE q.policy_version_id=v.id AND q.rule_id=requested.id)
          OR EXISTS (SELECT FROM foundation.price_rule_compatibilities q WHERE q.policy_version_id=v.id
            AND requested.id IN (q.left_rule_id,q.right_rule_id))))
    ) AS visible`, [cityId, ruleIds]);
    if (rows[0]?.visible !== true) {refuse('NOT_FOUND', 'ruleId');}
  }
}

function pathFields(resource: Resource, identity: boolean, version: boolean): string[] {
  const result = resource.city === true ? ['cityId'] : [];
  const subject = resource.subject ?? 'id';
  if (identity && subject !== 'cityId') {result.push(subject);}
  if (version) {result.push('versionId');}
  return result;
}

/** Caller holds the authorized RC transaction and its shared catalog fence. */
export async function readManagement(client: CatalogClient, operation: string, params: Params, rawQuery: unknown,
  authorizedCityIds: readonly string[] | null): Promise<Dto> {
  const authorized = scopedCities(authorizedCityIds);
  if (operation === 'cityList' || operation === 'pricingReadiness' || Object.hasOwn(LABELS, operation)) {
    return discover(client, operation, params, rawQuery, authorized);
  }
  const { name, resource, action } = resourceAction(operation, READ_ACTIONS);
  const temporal = resource.temporal !== undefined && (name !== 'estimate' || action === 'Versions' || action === 'Version');
  const exactVersion = temporal ? action === (name === 'estimate' ? 'Version' : 'Get') : action === 'Version';
  const isIdentityList = !temporal && action === 'List';
  const bound = normalizeParams(params, pathFields(resource, !isIdentityList, exactVersion));
  const cityId = resource.city === true ? boundCity(bound, authorized) : undefined;
  if (cityId !== undefined) {await existingCity(client, cityId);}
  if (temporal) {
    if (cityId === undefined || (name !== 'estimate' && action !== 'List' && action !== 'Get')) {throw new CatalogInternalError();}
    if (!exactVersion && (name === 'fixed' || name === 'ruleVersion')) {
      const field = RESOURCES[name].subject;
      await visibleStreamSubject(client, name, cityId, uuid(bound[field], field));
    }
    return readTemporal(client, operation, bound, rawQuery, name, resource, cityId, !exactVersion);
  }
  if (action === 'Versions' || action === 'Version') {
    return readRevision(client, operation, bound, rawQuery, resource, action === 'Versions');
  }
  return readIdentity(client, operation, bound, rawQuery, name, resource, cityId, isIdentityList);
}

interface StoredReceiptTarget {
  readonly entityId: string;
  readonly entityVersion: number;
  readonly revisionId: string | null;
  readonly revisionVersion: number | null;
}

interface ManagementTargetScope {
  readonly storedSubjectId?: string;
  readonly receipt?: StoredReceiptTarget;
  readonly categoryId?: string | null;
  readonly brandId?: string | null;
  readonly profileId?: string | null;
  readonly faultId?: string | null;
  readonly itemId?: string | null;
  readonly kind?: string;
  readonly avitoPublishForm?: AvitoPublishForm;
  readonly pricingCategoryIds?: readonly string[];
  readonly pricingRuleIds?: readonly string[];
}

async function durableKind(client: CatalogClient, table: 'external_reviews' | 'price_rules', id: string, field: string): Promise<string> {
  const { rows } = await client.query<{ kind: string }>(`SELECT e.kind FROM foundation.${table} e WHERE e.id=$1::uuid`, [id]);
  return rows[0]?.kind ?? refuse('NOT_FOUND', field);
}

async function createParents(client: CatalogClient, name: ResourceName, scope: ManagementTargetScope, cityId?: string): Promise<void> {
  const category = (name === 'model' || name === 'fault' || name === 'mapping' || name === 'estimate' || (name === 'item' && scope.kind === 'WORK'))
    ? uuid(scope.categoryId, 'categoryId') : name === 'item' ? optionalUuid(scope.categoryId, 'categoryId') : null;
  if (name === 'estimate') {
    if (cityId === undefined || category === null) {throw new CatalogInternalError();}
    await visiblePricingReferences(client, cityId, [category], []);
  } else if (category !== null) {await existingParent(client, 'catalog_directory_entries', category, 'categoryId', 'CATEGORY');}
  if (name === 'model') {
    await existingParent(client, 'catalog_directory_entries', uuid(scope.brandId, 'brandId'), 'brandId', 'BRAND');
  }
  if (name === 'mapping' && category !== null) {
    await existingParent(client, 'catalog_directory_entries', uuid(scope.faultId, 'faultId'), 'faultId', 'FAULT', category);
    await existingParent(client, 'catalog_items', uuid(scope.itemId, 'itemId'), 'itemId', 'WORK', category);
  }
  if (name === 'avito' && scope.kind === 'REVIEW') {
    await existingParent(client, 'external_reviews', uuid(scope.profileId, 'profileId'), 'profileId', 'PROFILE');
  }
}

function bindReceiptEntity(values: SqlValues, receipt: StoredReceiptTarget, revisions: boolean): string {
  const positive = (n: number): boolean => Number.isInteger(n) && n >= 1 && n <= MAX_VERSION;
  if (!positive(receipt.entityVersion)
      || (revisions ? receipt.revisionId === null || receipt.revisionVersion === null || !positive(receipt.revisionVersion)
        : receipt.revisionId !== null || receipt.revisionVersion !== null)) {
    throw new CatalogInternalError();
  }
  // The aggregate may have advanced or been archived, but cannot rewind.
  return ` AND e.id=${values.add(uuid(receipt.entityId, 'id'))}::uuid AND e.row_version>=${values.add(receipt.entityVersion)}::integer`;
}

function bindReceiptRevision(values: SqlValues, receipt: StoredReceiptTarget, alias: 'rv'): string {
  return `${alias}.id=${values.add(uuid(receipt.revisionId, 'versionId'))}::uuid
    AND ${alias}.version=${values.add(receipt.revisionVersion)}::integer`;
}

/** Called after the exclusive fence; authorization and canonical command decoding are the caller's responsibility. */
export async function assertManagementTarget(client: CatalogClient, operation: string, params: Params, scope: ManagementTargetScope = {}): Promise<void> {
  const { name, resource, action } = resourceAction(operation, WRITE_ACTIONS);
  const creating = action === 'Create';
  const versionAction = action === 'Close' || action === 'Replace';
  const bound = normalizeParams(params, pathFields(resource, !creating, versionAction));
  const cityId = resource.city === true ? uuid(bound['cityId'], 'cityId') : undefined;
  if (cityId !== undefined) {await existingCity(client, cityId);}
  const field = resource.subject ?? 'id';
  const values = new SqlValues();
  const { receipt, storedSubjectId } = scope;
  if (creating) {
    if (resource.identity === undefined || (storedSubjectId === undefined && receipt !== undefined)) {
      throw new CatalogInternalError();
    }
    if (storedSubjectId === undefined) {
      await createParents(client, name, scope, cityId);
    } else {
      const where = identityWhere(resource, values, cityId, uuid(storedSubjectId, field));
      const stored = receipt === undefined ? '' : bindReceiptEntity(values, receipt, false);
      await requireRow(client, `SELECT 1 FROM foundation.${resource.table} e WHERE ${where}${stored}`, values, field);
    }
    return;
  }
  const subject = field === 'cityId' ? undefined : uuid(bound[field], field);
  let where = identityWhere(resource, values, cityId, subject);
  if (resource.temporal !== undefined) {
    if (action !== 'Publish' && !versionAction && name !== 'estimate') {
      throw new CatalogInternalError();
    }
    if (cityId === undefined) {throw new CatalogInternalError();}
    if (action === 'Publish' && receipt === undefined && (name === 'fixed' || name === 'ruleVersion')) {
      await visibleStreamSubject(client, name, cityId, uuid(subject, field));
    }
    const temporal = resource.temporal;
    const from = versionAction ? temporalFrom(resource, temporal) : `foundation.${resource.table} e`;
    if (versionAction) {
      where += ` AND v.id=${values.add(uuid(bound['versionId'], 'versionId'))}::uuid`;
    }
    if (receipt !== undefined) {
      const publishes = action === 'Publish' || action === 'Replace';
      where += bindReceiptEntity(values, receipt, publishes);
      if (versionAction) {where += ' AND p.closed_effective_until IS NOT NULL';}
      if (publishes) {
        if (receipt.revisionVersion !== receipt.entityVersion) {throw new CatalogInternalError();}
        const revision = bindReceiptRevision(values, receipt, 'rv');
        const owned = resource.subjectColumn === undefined ? '' : ` AND rv.${resource.subjectColumn}=e.${resource.subjectColumn}`;
        const replacement = action === 'Replace' ? ' AND rv.valid_from=p.closed_effective_until AND rv.id<>v.id' : '';
        where += ` AND EXISTS (SELECT 1 FROM foundation.${temporal.versions} rv
          WHERE (rv.series_id,rv.city_id)=(e.id,e.city_id) AND ${revision}${owned}${replacement})`;
      }
    }
    if (versionAction || name === 'estimate' || receipt !== undefined) {
      await requireRow(client, `SELECT 1 FROM ${from} WHERE ${where}`, values, versionAction ? 'versionId' : field);
    }
    if (receipt === undefined && (action === 'Publish' || action === 'Replace')) {
      if (name === 'ruleVersion') {
        const kind = await durableKind(client, 'price_rules', uuid(subject, field), field);
        if (kind !== scope.kind) {refuse('INVALID_INPUT', 'kind');}
      }
      await visiblePricingReferences(client, cityId, scope.pricingCategoryIds ?? [], scope.pricingRuleIds ?? []);
    }
    return; // A valid city/source can publish its very first stream version without an existing series row.
  }
  if (versionAction || (action === 'Publish' && resource.revision === undefined && name !== 'mapping')) {
    throw new CatalogInternalError();
  }
  if (name === 'avito' && action === 'Publish' && receipt === undefined) {
    const kind = await durableKind(client, 'external_reviews', uuid(subject, 'id'), field);
    if (scope.avitoPublishForm === undefined) { throw new CatalogInternalError(); }
    assertAvitoPublishForm(kind, scope.avitoPublishForm);
    return;
  }
  if (name === 'item' && action === 'Publish' && scope.kind !== undefined) {
    where += ` AND e.kind=${values.add(scope.kind)}::text`;
  }
  if (receipt !== undefined) {
    const revision = action === 'Publish' ? resource.revision : undefined;
    where += bindReceiptEntity(values, receipt, revision !== undefined);
    if (revision !== undefined) {
      where += ` AND EXISTS (SELECT 1 FROM foundation.${revision.table} rv WHERE rv.${revision.parent}=e.id
        AND ${bindReceiptRevision(values, receipt, 'rv')}${revision.typed === true ? ' AND rv.kind=e.kind' : ''})`;
    }
  }
  await requireRow(client, `SELECT 1 FROM foundation.${resource.table} e WHERE ${where}`, values, field);
}
