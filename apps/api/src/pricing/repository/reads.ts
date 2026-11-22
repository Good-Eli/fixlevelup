import type { CatalogClient } from '../../catalog/contracts.js';
import { CatalogInternalError } from '../../catalog/validation.js';
import { normalizePricingInput, PricingError } from '../engine/index.js';
import type { PricingInput } from '../engine/index.js';
import {
  containsAt, effectiveEnd, estimateRequest, estimateResult, invalid, MAX_ESTIMATES, MAX_RULES, pricingRequest,
  queryAfterFence, SNAPSHOT_CTES, SNAPSHOT_STATUS, utc, wall,
} from './read-support.js';
import type { EffectiveEstimate, ReadEffectiveEstimatesInput, ReadPricingInput } from './read-support.js';

export type { EffectiveEstimate, PricingSelection, ReadEffectiveEstimatesInput, ReadPricingInput } from './read-support.js';

// All SQL fragments are private literals or expressions over these private aliases.
const SOURCES = `'id', v.id, 'cityId', v.city_id, 'cityVersionId', v.city_version_id,
  'validFrom', ${utc('p.valid_from')}, 'effectiveUntil', ${utc(effectiveEnd('p'))}`;

const PRICING_SQL = `WITH ${SNAPSHOT_CTES},
policy_versions AS MATERIALIZED (
  SELECT v.*, p.valid_from AS period_start, ${effectiveEnd('p')} AS period_end
  FROM city
  JOIN foundation.pricing_policy_series AS s ON s.city_id=city.city_id
  JOIN foundation.pricing_policy_periods AS p ON (p.city_id,p.series_id)=(s.city_id,s.id) AND ${containsAt('p', 'city.pricing_at')}
  JOIN foundation.pricing_policy_versions AS v ON (v.id,v.series_id,v.city_id)=(p.version_id,p.series_id,p.city_id)
  LIMIT 2
), policies AS (
  SELECT (jsonb_array_length(priorities.rows) = v.priority_count
      AND jsonb_array_length(compatibilities.rows) = v.compatibility_count) AS children_ok,
    jsonb_build_object('id',v.id,'cityId',v.city_id,'cityVersionId',v.city_version_id,'currency',v.currency,
      'taxDisplay',v.tax_display,'roundingMode',v.rounding_mode,'units',v.units,
      'maxManualDeltaMinor',v.max_manual_delta_minor::text,'priorities',priorities.rows,'compatibilities',compatibilities.rows,
      'validFrom',${utc('v.period_start')},'effectiveUntil',${utc('v.period_end')}) AS source
  FROM policy_versions v
  CROSS JOIN LATERAL (
    SELECT coalesce(jsonb_agg(jsonb_build_object('ruleId',r.rule_id,'priority',r.priority) ORDER BY r.rule_id),'[]'::jsonb) AS rows
    FROM (SELECT rule_id,priority FROM foundation.price_rule_priorities WHERE policy_version_id=v.id LIMIT 65) r
  ) priorities
  CROSS JOIN LATERAL (
    SELECT coalesce(jsonb_agg(jsonb_build_object('leftRuleId',r.left_rule_id,'rightRuleId',r.right_rule_id)
      ORDER BY r.left_rule_id,r.right_rule_id),'[]'::jsonb) AS rows
    FROM (SELECT left_rule_id,right_rule_id FROM foundation.price_rule_compatibilities WHERE policy_version_id=v.id LIMIT 129) r
  ) compatibilities
), rule_versions AS MATERIALIZED (
  SELECT v.*, p.valid_from AS period_start, ${effectiveEnd('p')} AS period_end
  FROM city
  JOIN foundation.price_rule_periods AS p ON p.city_id=city.city_id AND ${containsAt('p', 'city.pricing_at')}
  JOIN foundation.price_rule_series AS s ON (s.id,s.city_id)=(p.series_id,p.city_id)
  JOIN foundation.price_rules AS d ON d.id=s.rule_id AND d.archived_at IS NULL
  JOIN foundation.price_rule_versions AS v ON (v.id,v.series_id,v.city_id,v.rule_id,v.kind)=(p.version_id,p.series_id,p.city_id,d.id,d.kind)
  LIMIT ${String(MAX_RULES + 1)}
), rules AS (
  SELECT jsonb_array_length(scopes.rows) = v.scope_count AS children_ok,
    jsonb_build_object('id',v.id,'cityId',v.city_id,'cityVersionId',v.city_version_id,'ruleId',v.rule_id,'kind',v.kind,
      'title',v.title,'method',v.method,'base',v.base,'currency',v.currency,'fixedMinor',v.fixed_minor::text,'rateBps',v.rate_bps,
      'minBase',v.min_base::text,'maxBase',v.max_base::text,'minDelta',v.min_delta::text,'maxDelta',v.max_delta::text,
      'startMinute',v.start_minute,'endMinute',v.end_minute,'wrapsMidnight',v.wraps_midnight,'categoryIds',scopes.rows,
      'validFrom',${utc('v.period_start')},'effectiveUntil',${utc('v.period_end')}) AS source
  FROM rule_versions v
  CROSS JOIN LATERAL (
    SELECT coalesce(jsonb_agg(r.category_id ORDER BY r.category_id),'[]'::jsonb) AS rows
    FROM (SELECT category_id FROM foundation.price_rule_scopes WHERE rule_version_id=v.id LIMIT 33) r
  ) scopes
), item_versions AS MATERIALIZED (
  SELECT city.city_id,city.pricing_at,sel."lineId" AS line_id,sel.quantity,i.id,i.kind,i.category_id,i.unit,iv.id AS item_version_id,iv.title,
    CASE WHEN i.id IS NULL OR i.archived_at IS NOT NULL OR iv.id IS NULL THEN 'itemId'
      WHEN i.category_id IS NOT NULL AND (cat.id IS NULL OR cat.archived_at IS NOT NULL OR cat.current_version_id IS NULL) THEN 'categoryId'
      WHEN i.unit <> sel.unit THEN 'unit'
      WHEN ($7::text='TECHNICIAN' AND NOT iv.technician_visible) OR ($7::text='PUBLIC' AND NOT iv.public_visible) THEN 'visibility'
      ELSE NULL END AS invalid_field
  FROM city
  CROSS JOIN jsonb_to_recordset($4::jsonb) AS sel("lineId" uuid,"itemId" uuid,unit text,quantity text)
  LEFT JOIN foundation.catalog_items AS i ON i.id=sel."itemId"
  LEFT JOIN foundation.catalog_item_versions AS iv ON (iv.item_id,iv.id,iv.kind)=(i.id,i.current_version_id,i.kind)
  LEFT JOIN foundation.catalog_directory_entries AS cat ON cat.id=i.category_id AND cat.kind='CATEGORY'
), items AS (
  SELECT i.line_id, i.invalid_field, fixed.count AS price_count,
    jsonb_build_object('lineId',i.line_id,'itemId',i.id,'itemVersionId',i.item_version_id,'kind',i.kind,
      'categoryId',i.category_id,'unit',i.unit,'title',i.title,'quantity',i.quantity,'price',fixed.rows->0) AS source
  FROM item_versions i
  CROSS JOIN LATERAL (
    SELECT count(*)::int AS count,jsonb_agg(e.source) AS rows
    FROM (
      SELECT jsonb_build_object(${SOURCES},'itemId',v.item_id,'itemVersionId',v.item_version_id,
        'amountMinor',v.amount_minor::text,'currency',v.currency,'zeroBasis',v.zero_basis) AS source
      FROM foundation.catalog_price_periods AS p
      JOIN foundation.catalog_price_versions AS v
        ON (v.id,v.series_id,v.city_id,v.item_id)=(p.price_version_id,p.series_id,p.city_id,p.item_id)
      WHERE i.invalid_field IS NULL AND (p.city_id,p.item_id)=(i.city_id,i.id) AND ${containsAt('p', 'i.pricing_at')}
      LIMIT 2
    ) e
  ) fixed
), context AS (
  SELECT jsonb_build_object('calculationId',$8::uuid,'cityId',city.city_id,'cityVersionId',city.city_version_id,
    'timezone',city.timezone,'pricingAt',${utc('city.pricing_at')},'tariffAt',${utc('$5::timestamptz')},
    'localAt',${wall('$5::timestamptz AT TIME ZONE city.timezone')},
    'utcOffsetSeconds',extract(epoch FROM (($5::timestamptz AT TIME ZONE city.timezone)-($5::timestamptz AT TIME ZONE 'UTC')))::int,
    'express',$6::boolean) AS source FROM city
)
SELECT ${SNAPSHOT_STATUS} AS status,
  (SELECT source FROM context) AS context,
  (SELECT coalesce(jsonb_agg(jsonb_build_object('childrenOk',children_ok,'source',source)),'[]'::jsonb) FROM policies) AS policies,
  (SELECT coalesce(jsonb_agg(jsonb_build_object('childrenOk',children_ok,'source',source)),'[]'::jsonb) FROM rules) AS rules,
  (SELECT coalesce(jsonb_agg(jsonb_build_object('invalidField',invalid_field,'priceCount',price_count,'source',source)
      ORDER BY line_id),'[]'::jsonb) FROM items) AS items
FROM tx LEFT JOIN city ON true`;

interface ConfigRow { childrenOk: boolean; source: unknown }
interface ItemRow { invalidField: 'itemId' | 'categoryId' | 'unit' | 'visibility' | null; priceCount: number; source: unknown }
interface PricingRow {
  status: string;
  context: unknown;
  policies: ConfigRow[];
  rules: ConfigRow[];
  items: ItemRow[];
}

function ambiguous(field: string): never {
  throw new PricingError('PRICING_CONFIGURATION_AMBIGUOUS', field);
}

/** One caller-owned READ COMMITTED transaction fence; then one current-pricing snapshot. */
export async function readPricingInput(client: CatalogClient, input: ReadPricingInput): Promise<PricingInput> {
  const r = pricingRequest(input);
  // JSON is built only from copied DTO primitives, before allowing callers to run again.
  const row = await queryAfterFence<PricingRow>(client, PRICING_SQL, [
    r.cityId, r.cityVersionId, JSON.stringify(r.selections), r.tariffAt, r.express, r.visibility, r.calculationId,
  ]);
  if (row.policies.length > 1) {
    return ambiguous('policy');
  }
  if (row.rules.length > MAX_RULES) {
    return ambiguous('rules');
  }
  const policy = row.policies[0];
  if (policy === undefined) {
    throw new PricingError('PRICING_NOT_CONFIGURED', 'policy');
  }
  if (!policy.childrenOk || row.rules.some(({ childrenOk }) => !childrenOk)) {
    return invalid('priceConfiguration');
  }
  if (row.items.length !== r.selections.length) {
    throw new CatalogInternalError();
  }
  for (const item of row.items) {
    if (item.invalidField !== null) {
      return invalid(item.invalidField);
    }
    if (item.priceCount > 1) {
      return ambiguous('price');
    }
  }
  // A zero row builds a null price, intentionally distinct from malformed sources.
  return normalizePricingInput({ context: row.context, policy: policy.source,
    rules: row.rules.map(({ source }) => source), items: row.items.map(({ source }) => source),
    adjustments: r.adjustments, evidence: r.evidence });
}

const ESTIMATE_SQL = `WITH ${SNAPSHOT_CTES}, eligible_category AS MATERIALIZED (
  SELECT e.id FROM city JOIN foundation.catalog_directory_entries e ON e.id=$4 AND e.kind='CATEGORY'
  WHERE e.archived_at IS NULL AND e.current_version_id IS NOT NULL
), estimates AS MATERIALIZED (
  SELECT s.code,v.id,s.id AS series_id,jsonb_build_object(${SOURCES},'seriesId',s.id,'version',v.version,
    'categoryId',s.category_id,'code',s.code,'title',v.title,'currency',v.currency,'minMinor',v.min_minor::text,
    'maxMinor',v.max_minor::text,'conditions',v.conditions,'disclaimer',v.disclaimer,'sourceRef',v.source_ref,
    'reviewedBy',v.reviewed_by,'publishedAt',${utc('v.published_at')},'validUntil',${utc('v.valid_until')}) AS source
  FROM city CROSS JOIN eligible_category AS e
  JOIN foundation.public_price_estimate_series AS s ON s.city_id=city.city_id AND s.category_id=e.id AND s.archived_at IS NULL
  JOIN foundation.public_price_estimate_periods AS p ON (p.city_id,p.series_id)=(s.city_id,s.id) AND ${containsAt('p', 'city.pricing_at')}
  JOIN foundation.public_price_estimates AS v ON (v.id,v.series_id,v.city_id)=(p.version_id,p.series_id,p.city_id)
  LIMIT ${String(MAX_ESTIMATES + 1)}
)
SELECT ${SNAPSHOT_STATUS} AS status, ${utc('city.pricing_at')} AS pricing_at,
  EXISTS(SELECT 1 FROM eligible_category) AS category_ok,
  (SELECT coalesce(jsonb_agg(source ORDER BY code COLLATE "C",id),'[]'::jsonb) FROM estimates) AS estimates
FROM tx LEFT JOIN city ON true`;

interface EstimateRow { status: string; pricing_at: string; category_ok: boolean; estimates: unknown[] }

/** Internal reviewed ranges. They are never a fixed source or a pricing fallback. */
export async function readEffectiveEstimates(client: CatalogClient, input: ReadEffectiveEstimatesInput): Promise<readonly EffectiveEstimate[]> {
  const r = estimateRequest(input);
  const row = await queryAfterFence<EstimateRow>(client, ESTIMATE_SQL, [r.cityId, r.cityVersionId, r.categoryId]);
  if (!row.category_ok) {
    return invalid('categoryId');
  }
  if (row.estimates.length > MAX_ESTIMATES) {
    return ambiguous('estimates');
  }
  const estimates = row.estimates.map((estimate) => estimateResult(estimate, r, row.pricing_at));
  if (new Set(estimates.map(({ seriesId }) => seriesId)).size !== estimates.length
      || new Set(estimates.map(({ code }) => code)).size !== estimates.length
      || new Set(estimates.map(({ id }) => id)).size !== estimates.length) {
    return ambiguous('estimates');
  }
  return Object.freeze(estimates);
}
