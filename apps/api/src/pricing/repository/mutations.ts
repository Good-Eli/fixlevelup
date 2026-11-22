import { randomUUID } from 'node:crypto';
import type { CatalogClient, CatalogReceipt } from '../../catalog/contracts.js';
import { categoryRef, nextVersion, wrote } from '../../catalog/records.js';
import { mutate } from '../../catalog/transaction.js';
import { amountMinor, choice, currency, expectedVersion, flag, integer, optionalText, record, refuse, slug, text, uuid } from '../../catalog/validation.js';
import {
  BODY_KEYS, CLOCK, CLOSE_KEYS, SCHEDULE_KEYS, closeKey, lockCity, pricingAudit, revision, scheduleBody, scheduleKey, writeSchedule,
} from './write-support.js';
import type { CloseTarget, NewVersion, ScheduleBody, ScheduleKey } from './write-support.js';

export const RULE_KINDS = Object.freeze(['EVENING', 'NIGHT', 'EXPRESS', 'SURCHARGE', 'DISCOUNT'] as const);
export const RULE_BASES = Object.freeze(['WORKS', 'WORKS_AND_PARTS', 'ORDER_BASE'] as const);
export const ROUNDING_MODES = Object.freeze(['HALF_UP', 'DOWN'] as const);
type RuleKind = (typeof RULE_KINDS)[number];
type TemporalKind = Extract<RuleKind, 'EVENING' | 'NIGHT'>;
type RuleBase = (typeof RULE_BASES)[number];
export interface CreateRuleInput { readonly code: string; readonly kind: RuleKind }
export interface ArchiveRuleInput { readonly ruleId: string; readonly expectedVersion: number }
interface RuleKey extends ScheduleKey { readonly ruleId: string }
interface RuleDetails {
  readonly title: string;
  readonly base: RuleBase;
  readonly currency: string;
  readonly minBase?: string | null;
  readonly maxBase?: string | null;
  readonly minDelta?: string | null;
  readonly maxDelta?: string | null;
  readonly categoryIds: readonly string[];
}
export type RuleBody = RuleDetails & (
  | { readonly method: 'FIXED'; readonly fixedMinor: string; readonly rateBps?: null }
  | { readonly method: 'RATE'; readonly fixedMinor?: null; readonly rateBps: number }
) & (
  | { readonly kind: TemporalKind; readonly startMinute: number; readonly endMinute: number; readonly wrapsMidnight: boolean }
  | { readonly kind: Exclude<RuleKind, TemporalKind>; readonly startMinute?: null; readonly endMinute?: null; readonly wrapsMidnight?: null }
);
export type PublishRuleInput = RuleKey & RuleBody & ScheduleBody;
export type CloseRuleInput = RuleKey & CloseTarget;
export type ReplaceRuleInput = CloseRuleInput & RuleBody & Omit<ScheduleBody, 'validFrom'>;
export interface PolicyBody {
  readonly currency: string;
  readonly taxDisplay: string;
  readonly roundingMode: (typeof ROUNDING_MODES)[number];
  readonly units: Readonly<Record<string, number>>;
  readonly maxManualDeltaMinor: string;
  readonly priorities: readonly { readonly ruleId: string; readonly priority: number }[];
  readonly compatibilities: readonly { readonly leftRuleId: string; readonly rightRuleId: string }[];
}
export type PublishPolicyInput = ScheduleKey & PolicyBody & ScheduleBody;
export type ClosePolicyInput = ScheduleKey & CloseTarget;
export type ReplacePolicyInput = ClosePolicyInput & PolicyBody & Omit<ScheduleBody, 'validFrom'>;
export interface CreateEstimateInput { readonly cityId: string; readonly categoryId: string; readonly code: string }
interface EstimateKey extends ScheduleKey { readonly estimateId: string }
export type ArchiveEstimateInput = EstimateKey;
export interface EstimateBody {
  readonly title: string;
  readonly currency: string;
  readonly minMinor: string;
  readonly maxMinor: string;
  readonly conditions?: string | null;
  readonly disclaimer: string;
}
export type PublishEstimateInput = EstimateKey & EstimateBody & ScheduleBody;
export type CloseEstimateInput = EstimateKey & CloseTarget;
export type ReplaceEstimateInput = CloseEstimateInput & EstimateBody & Omit<ScheduleBody, 'validFrom'>;

const RULE_FIELDS = ['kind','title','method','base','currency','fixedMinor','rateBps','minBase','maxBase','minDelta','maxDelta',
  'startMinute','endMinute','wrapsMidnight','categoryIds'] as const;
const POLICY_FIELDS = ['currency','taxDisplay','roundingMode','units','maxManualDeltaMinor','priorities','compatibilities'] as const;
const ESTIMATE_FIELDS = ['title','currency','minMinor','maxMinor','conditions','disclaimer'] as const;
type ScheduleMode = 'publish' | 'replace' | 'close';

function boundedArray(value: unknown, cap: number, field: string): readonly unknown[] {
  if (!Array.isArray(value) || value.length > cap || Object.getPrototypeOf(value) !== Array.prototype) {
    return refuse('INVALID_INPUT', field);
  }
  const result: unknown[] = [];
  if (Reflect.ownKeys(value).length !== value.length + 1) {refuse('INVALID_INPUT', field);}
  for (let i = 0; i < value.length; i++) {
    const entry = Object.getOwnPropertyDescriptor(value, String(i));
    if (!entry || !('value' in entry)) {refuse('INVALID_INPUT', field);}
    result.push(entry.value);
  }
  return result;
}

function requireDistinct(values: readonly string[], field: string): void {
  if (new Set(values).size !== values.length) {refuse('INVALID_INPUT', field);}
}
function minorOrNull(value: unknown): string | null {
  return value === null || value === undefined ? null : amountMinor(value);
}
function ordered(min: string | null, max: string | null, field: string): void {
  if (min !== null && max !== null && BigInt(min) > BigInt(max)) {refuse('INVALID_INPUT', field);}
}

interface RuleRow { kind: RuleKind; row_version: number; archived: boolean }
async function existingRule(client: CatalogClient, id: string): Promise<RuleRow> {
  const { rows } = await client.query<RuleRow>(`SELECT kind,row_version,archived_at IS NOT NULL AS archived
    FROM foundation.price_rules WHERE id=$1`, [id]);
  return rows[0] ?? refuse('NOT_FOUND', 'ruleId');
}
async function checkRuleRefs(client: CatalogClient, ids: readonly string[]): Promise<void> {
  if (!ids.length) {return;}
  const { rows } = await client.query<{ id: string }>(`SELECT id FROM foundation.price_rules
    WHERE id=ANY($1::uuid[]) AND archived_at IS NULL`, [ids]);
  if (rows.length !== ids.length) {refuse('CONFLICT', 'ruleId');}
}

export async function createRule(client: CatalogClient, reviewedBy: string, input: CreateRuleInput): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['code', 'kind']);
  const code = slug(dto['code'], 2, 64, 'code'), kind = choice(dto['kind'], RULE_KINDS, 'kind');
  return mutate(client, async () => {
    const id = randomUUID();
    const { rows } = await client.query<{ row_version: number }>(`INSERT INTO foundation.price_rules(id,code,kind)
      VALUES($1,$2,$3) ON CONFLICT(code) DO NOTHING RETURNING row_version`, [id,code,kind]);
    const receipt = { id, version: (rows[0] ?? refuse('CONFLICT', 'code')).row_version };
    await pricingAudit(client, 'rule.create', actor, receipt, { ruleId: id });
    return receipt;
  });
}

export async function archiveRule(client: CatalogClient, reviewedBy: string, input: ArchiveRuleInput): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, ['ruleId','expectedVersion']);
  const id = uuid(dto['ruleId'], 'ruleId'), expected = expectedVersion(dto['expectedVersion']);
  return mutate(client, async () => {
    const row = await existingRule(client, id);
    if (row.row_version !== expected) {refuse('STALE_VERSION', 'expectedVersion');}
    if (row.archived) {refuse('ARCHIVED', 'ruleId');}
    nextVersion(expected);
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.price_rules SET archived_at=${CLOCK}
      WHERE id=$1 AND row_version=$2 RETURNING row_version`, [id,expected]);
    const receipt = { id, version: (rows[0] ?? refuse('STALE_VERSION', 'expectedVersion')).row_version };
    await pricingAudit(client, 'rule.archive', actor, receipt, { ruleId: id });
    return receipt;
  });
}

function ruleBody(dto: Record<string, unknown>) {
  const kind = choice(dto['kind'], RULE_KINDS, 'kind');
  const method = choice(dto['method'], ['FIXED','RATE'], 'method');
  const fixedMinor = minorOrNull(dto['fixedMinor']);
  const rateBps = dto['rateBps'] === undefined || dto['rateBps'] === null ? null : integer(dto['rateBps'], 1, 10_000, 'rateBps');
  if (method === 'FIXED' ? fixedMinor === null || rateBps !== null : rateBps === null || fixedMinor !== null) {
    refuse('INVALID_INPUT', 'method');
  }
  let startMinute = null, endMinute = null, wrapsMidnight = null;
  if (kind === 'EVENING' || kind === 'NIGHT') {
    startMinute = integer(dto['startMinute'], 0, 1439, 'startMinute');
    endMinute = integer(dto['endMinute'], 0, 1439, 'endMinute');
    wrapsMidnight = flag(dto['wrapsMidnight'], 'wrapsMidnight');
    if (startMinute === endMinute || wrapsMidnight !== (startMinute > endMinute)) {refuse('INVALID_INPUT', 'window');}
  } else if (['startMinute','endMinute','wrapsMidnight'].some(k => dto[k] !== undefined && dto[k] !== null)) {
    refuse('INVALID_INPUT', 'window');
  }
  const minBase = minorOrNull(dto['minBase']), maxBase = minorOrNull(dto['maxBase']);
  const minDelta = minorOrNull(dto['minDelta']), maxDelta = minorOrNull(dto['maxDelta']);
  ordered(minBase,maxBase,'baseBounds'); ordered(minDelta,maxDelta,'deltaBounds');
  const categoryIds = boundedArray(dto['categoryIds'],32,'categoryIds').map(id => uuid(id,'categoryId')).sort();
  requireDistinct(categoryIds,'categoryIds');
  return {kind,method,fixedMinor,rateBps,startMinute,endMinute,wrapsMidnight,minBase,maxBase,minDelta,maxDelta,categoryIds,
    title:text(dto['title'],160,'title'), base:choice(dto['base'],RULE_BASES,'base'), currency:currency(dto['currency'])};
}

function scheduleInput(input: unknown, mode: ScheduleMode, ownerKeys: readonly string[], fields: readonly string[]) {
  const keys = [...SCHEDULE_KEYS, ...ownerKeys, ...(mode === 'publish' ? ['validFrom'] : CLOSE_KEYS),
    ...(mode === 'close' ? [] : [...BODY_KEYS, ...fields])];
  return record(input, keys);
}

async function changeRule(client: CatalogClient, reviewedBy: string, input: unknown, mode: ScheduleMode) {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = scheduleInput(input, mode, ['ruleId'], RULE_FIELDS);
  const ruleId = uuid(dto['ruleId'], 'ruleId'), key = scheduleKey(dto, mode === 'publish');
  const end = mode === 'publish' ? null : closeKey(dto);
  if (mode === 'close') {return writeSchedule(client,actor,'rule',ruleId,key,end,null,notPublishing);}
  const schedule = scheduleBody(dto,end?.at), body = ruleBody(dto);
  return writeSchedule(client,actor,'rule',ruleId,key,end,{schedule, insert: async (v) => {
    wrote((await client.query(`INSERT INTO foundation.price_rule_versions(id,series_id,city_id,city_version_id,version,
      source_ref,reviewed_by,valid_from,valid_until,rule_id,kind,title,method,base,currency,fixed_minor,rate_bps,min_base,max_base,
      min_delta,max_delta,start_minute,end_minute,wraps_midnight,scope_count)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
    [...versionParameters(v,key,schedule,actor),ruleId,body.kind,body.title,body.method,body.base,body.currency,body.fixedMinor,
      body.rateBps,body.minBase,body.maxBase,body.minDelta,body.maxDelta,body.startMinute,body.endMinute,body.wrapsMidnight,body.categoryIds.length])).rowCount);
    if (body.categoryIds.length) {
      const { rowCount } = await client.query(`INSERT INTO foundation.price_rule_scopes(rule_version_id,category_id)
        SELECT $1,n FROM unnest($2::uuid[]) n`, [v.id,body.categoryIds]);
      if (rowCount !== body.categoryIds.length) {refuse('CONFLICT','categoryIds');}
    }
  }},async () => {
    const existing = await existingRule(client,ruleId);
    if (existing.archived) {refuse('ARCHIVED','ruleId');}
    if (existing.kind !== body.kind) {refuse('CONFLICT','kind');}
    for (const id of body.categoryIds) {await categoryRef(client,id,true);}
  });
}

function versionParameters(v:NewVersion,key:ScheduleKey,schedule:ReturnType<typeof scheduleBody>,actor:string) {
  return [v.id,v.seriesId,key.cityId,v.cityVersionId,v.version,schedule.sourceRef,actor,schedule.validFrom,schedule.validUntil] as const;
}
const notPublishing = (): Promise<void> => Promise.resolve();
export async function publishRule(client: CatalogClient, actor: string, input: PublishRuleInput) {
  return revision(await changeRule(client,actor,input,'publish'));
}
export async function replaceRule(client: CatalogClient, actor: string, input: ReplaceRuleInput) {
  return revision(await changeRule(client,actor,input,'replace'));
}
export async function closeRule(client: CatalogClient, actor: string, input: CloseRuleInput): Promise<CatalogReceipt> {
  return changeRule(client,actor,input,'close');
}

function policyBody(dto: Record<string, unknown>): PolicyBody {
  const rawUnits = dto['units'];
  if (!rawUnits || typeof rawUnits !== 'object') {refuse('INVALID_INPUT','units');}
  const ownKeys = Reflect.ownKeys(rawUnits);
  if (!ownKeys.length || ownKeys.length > 32 || ownKeys.some(k => typeof k !== 'string')) {refuse('INVALID_INPUT','units');}
  const keys = ownKeys.map(k => slug(k,1,24,'unit')).sort();
  const unitDto = record(rawUnits,keys);
  const units = Object.fromEntries(keys.map(k => [k,integer(unitDto[k],0,6,'maxScale')]));
  const priorities = boundedArray(dto['priorities'],64,'priorities').map(value => {
    const r = record(value,['ruleId','priority']);
    return {ruleId:uuid(r['ruleId'],'ruleId'),priority:integer(r['priority'],0,1_000_000,'priority')};
  });
  requireDistinct(priorities.map(p=>p.ruleId),'priorities');
  const compatibilities = boundedArray(dto['compatibilities'],128,'compatibilities').map(value => {
    const r = record(value,['leftRuleId','rightRuleId']);
    const left = uuid(r['leftRuleId'],'leftRuleId'), right = uuid(r['rightRuleId'],'rightRuleId');
    if (left === right) {refuse('INVALID_INPUT','compatibilities');}
    return left < right ? {leftRuleId:left,rightRuleId:right} : {leftRuleId:right,rightRuleId:left};
  });
  requireDistinct(compatibilities.map(p=>`${p.leftRuleId}:${p.rightRuleId}`),'compatibilities');
  return {currency:currency(dto['currency']), taxDisplay:text(dto['taxDisplay'],200,'taxDisplay'),
    roundingMode:choice(dto['roundingMode'],ROUNDING_MODES,'roundingMode'), units,
    maxManualDeltaMinor:amountMinor(dto['maxManualDeltaMinor']), priorities,compatibilities};
}

async function changePolicy(client: CatalogClient, reviewedBy: string, input: unknown, mode: ScheduleMode) {
  const actor = uuid(reviewedBy,'reviewedBy'), dto = scheduleInput(input,mode,[],POLICY_FIELDS);
  const key = scheduleKey(dto,mode==='publish'), end = mode==='publish' ? null : closeKey(dto);
  if (mode === 'close') {return writeSchedule(client,actor,'policy',null,key,end,null,notPublishing);}
  const schedule = scheduleBody(dto,end?.at), body = policyBody(dto);
  return writeSchedule(client,actor,'policy',null,key,end,{schedule,insert:async(v) => {
    wrote((await client.query(`INSERT INTO foundation.pricing_policy_versions(id,series_id,city_id,city_version_id,version,
      source_ref,reviewed_by,valid_from,valid_until,currency,tax_display,rounding_mode,units,max_manual_delta_minor,priority_count,compatibility_count)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16)`,
    [...versionParameters(v,key,schedule,actor),body.currency,body.taxDisplay,body.roundingMode,JSON.stringify(body.units),
      body.maxManualDeltaMinor,body.priorities.length,body.compatibilities.length])).rowCount);
    if (body.priorities.length) {
      const {rowCount}=await client.query(`INSERT INTO foundation.price_rule_priorities(policy_version_id,rule_id,priority)
        SELECT $1,rule_id,priority FROM unnest($2::uuid[],$3::int[]) AS u(rule_id,priority)`,
      [v.id,body.priorities.map(p=>p.ruleId),body.priorities.map(p=>p.priority)]);
      if (rowCount !== body.priorities.length) {refuse('CONFLICT','priorities');}
    }
    if (body.compatibilities.length) {
      const {rowCount}=await client.query(`INSERT INTO foundation.price_rule_compatibilities(policy_version_id,left_rule_id,right_rule_id)
        SELECT $1,left_id,right_id FROM unnest($2::uuid[],$3::uuid[]) AS u(left_id,right_id)`,
      [v.id,body.compatibilities.map(p=>p.leftRuleId),body.compatibilities.map(p=>p.rightRuleId)]);
      if (rowCount !== body.compatibilities.length) {refuse('CONFLICT','compatibilities');}
    }
  }},() => checkRuleRefs(client,[...new Set([...body.priorities.map(p=>p.ruleId),
    ...body.compatibilities.flatMap(p=>[p.leftRuleId,p.rightRuleId])])]));
}
export async function publishPolicy(client: CatalogClient, actor: string, input: PublishPolicyInput) {
  return revision(await changePolicy(client,actor,input,'publish'));
}
export async function replacePolicy(client: CatalogClient, actor: string, input: ReplacePolicyInput) {
  return revision(await changePolicy(client,actor,input,'replace'));
}
export async function closePolicy(client: CatalogClient, actor: string, input: ClosePolicyInput): Promise<CatalogReceipt> {
  return changePolicy(client,actor,input,'close');
}

export async function createEstimate(client: CatalogClient, reviewedBy: string, input: CreateEstimateInput): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy,'reviewedBy'), dto = record(input,['cityId','categoryId','code']);
  const cityId = uuid(dto['cityId'],'cityId'), categoryId = uuid(dto['categoryId'],'categoryId'), code = slug(dto['code'],2,64,'code');
  return mutate(client,async () => {
    await lockCity(client,cityId); await categoryRef(client,categoryId,true);
    const id = randomUUID();
    const {rows}=await client.query<{row_version:number}>(`INSERT INTO foundation.public_price_estimate_series(id,city_id,category_id,code)
      VALUES($1,$2,$3,$4) ON CONFLICT(city_id,category_id,code) DO NOTHING RETURNING row_version`,[id,cityId,categoryId,code]);
    const receipt = {id,version:(rows[0] ?? refuse('CONFLICT','code')).row_version};
    await pricingAudit(client,'estimate.create',actor,receipt,{cityId,estimateId:id});
    return receipt;
  });
}
export async function archiveEstimate(client: CatalogClient, reviewedBy: string, input: ArchiveEstimateInput):Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy,'reviewedBy'), dto = record(input,[...SCHEDULE_KEYS,'estimateId']);
  const key = scheduleKey(dto,false), id = uuid(dto['estimateId'],'estimateId');
  return mutate(client,async () => {
    await lockCity(client,key.cityId);
    const {rows: prior}=await client.query<{row_version:number;archived:boolean}>(`SELECT row_version,archived_at IS NOT NULL AS archived
      FROM foundation.public_price_estimate_series WHERE id=$1 AND city_id=$2`,[id,key.cityId]);
    const found = prior[0] ?? refuse('NOT_FOUND','estimateId');
    if (found.row_version!==key.expectedVersion) {refuse('STALE_VERSION','expectedVersion');}
    if (found.archived) {refuse('ARCHIVED','estimateId');}
    nextVersion(found.row_version);
    const {rows}=await client.query<{row_version:number}>(`UPDATE foundation.public_price_estimate_series SET archived_at=${CLOCK}
      WHERE id=$1 AND city_id=$2 AND row_version=$3 RETURNING row_version`,[id,key.cityId,key.expectedVersion]);
    const receipt={id,version:(rows[0] ?? refuse('STALE_VERSION','expectedVersion')).row_version};
    await pricingAudit(client,'estimate.archive',actor,receipt,{cityId:key.cityId,estimateId:id});
    return receipt;
  });
}
function estimateBody(dto:Record<string,unknown>) {
  const minMinor=amountMinor(dto['minMinor']), maxMinor=amountMinor(dto['maxMinor']);
  ordered(minMinor,maxMinor,'range');
  return { minMinor,maxMinor,title:text(dto['title'],160,'title'),currency:currency(dto['currency']),
    conditions:optionalText(dto['conditions'],1000,'conditions',0),disclaimer:text(dto['disclaimer'],500,'disclaimer') };
}
async function changeEstimate(client:CatalogClient,reviewedBy:string,input:unknown,mode:ScheduleMode) {
  const actor=uuid(reviewedBy,'reviewedBy'), dto=scheduleInput(input,mode,['estimateId'],ESTIMATE_FIELDS);
  const key=scheduleKey(dto,false), id=uuid(dto['estimateId'],'estimateId'), end=mode==='publish'?null:closeKey(dto);
  if (mode==='close') {return writeSchedule(client,actor,'estimate',id,key,end,null,notPublishing);}
  const schedule=scheduleBody(dto,end?.at), body=estimateBody(dto);
  return writeSchedule(client,actor,'estimate',id,key,end,{schedule,insert:async(v)=>{
    wrote((await client.query(`INSERT INTO foundation.public_price_estimates(id,series_id,city_id,city_version_id,version,
      source_ref,reviewed_by,valid_from,valid_until,title,currency,min_minor,max_minor,conditions,disclaimer)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    [...versionParameters(v,key,schedule,actor),body.title,body.currency,body.minMinor,body.maxMinor,body.conditions,body.disclaimer])).rowCount);
  }},async () => {
    const {rows}=await client.query<{category_id:string}>(`SELECT category_id FROM foundation.public_price_estimate_series
      WHERE id=$1 AND city_id=$2`,[id,key.cityId]);
    await categoryRef(client,(rows[0] ?? refuse('NOT_FOUND','estimateId')).category_id,true);
  });
}
export async function publishEstimate(client:CatalogClient,actor:string,input:PublishEstimateInput) {
  return revision(await changeEstimate(client,actor,input,'publish'));
}
export async function replaceEstimate(client:CatalogClient,actor:string,input:ReplaceEstimateInput) {
  return revision(await changeEstimate(client,actor,input,'replace'));
}
export async function closeEstimate(client:CatalogClient,actor:string,input:CloseEstimateInput):Promise<CatalogReceipt> {
  return changeEstimate(client,actor,input,'close');
}
