import { BadRequestException, HttpException, InternalServerErrorException } from '@nestjs/common';
import { decodeP04Body, P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import type { P04MutationOperation } from '@fixlevelup/p03-contracts/p04';
import { header } from '../auth/http.js';
import type { StaffRequest } from '../auth/http.js';
import { uuid } from '../authz/rbac-http.js';
import * as catalog from '../catalog/index.js';
import type { CatalogClient, CatalogReceipt, CatalogRevisionReceipt } from '../catalog/index.js';
import { canonicalPricingJson, parseStrictPricingJson } from '../pricing/codec/index.js';
import * as pricing from '../pricing/repository/index.js';
import { archiveAvito, createAvito, normalizeAvitoPublish, publishAvito } from './avito.js';
import type { AvitoPublishForm, CreateAvitoInput } from './avito.js';

export type Params = Readonly<Record<string, string>>;
export interface Command {
  readonly operation: P04MutationOperation;
  readonly params: Params;
  readonly key: string;
  readonly expectedVersion: number | null;
  readonly body: Readonly<Record<string, unknown>>;
}
export type Receipt = CatalogReceipt | CatalogRevisionReceipt;
const directory = Object.freeze({ category: 'CATEGORY', brand: 'BRAND', model: 'MODEL', fault: 'FAULT' } as const);
const textFields = Object.freeze(['title', 'description', 'sourceRef', 'zeroBasis', 'taxDisplay', 'conditions', 'disclaimer'] as const);
const optionalNulls: Partial<Record<P04MutationOperation, readonly string[]>> = Object.freeze({
  itemCreate: ['categoryId'], categoryPublish: ['description'], brandPublish: ['description'], modelPublish: ['description'],
  faultPublish: ['description'], itemPublish: ['description'], fixedPublish: ['validUntil', 'zeroBasis'], fixedReplace: ['validUntil', 'zeroBasis'],
  ruleVersionPublish: ['validUntil', 'fixedMinor', 'rateBps', 'minBase', 'maxBase', 'minDelta', 'maxDelta', 'startMinute', 'endMinute', 'wrapsMidnight'],
  ruleVersionReplace: ['validUntil', 'fixedMinor', 'rateBps', 'minBase', 'maxBase', 'minDelta', 'maxDelta', 'startMinute', 'endMinute', 'wrapsMidnight'],
  policyPublish: ['validUntil'], policyReplace: ['validUntil'], estimatePublish: ['validUntil', 'conditions'], estimateReplace: ['validUntil', 'conditions'],
});

function field(p: Params, key: string): string {
  const value = p[key];
  if (!value) { throw new InternalServerErrorException(); }
  return value;
}

export function commandFor(req: StaffRequest, operation: P04MutationOperation, params: Params): Command {
  const key = uuid(header(req, 'idempotency-key'));
  const rawTag = header(req, 'if-match');
  const spec = P04_ROUTES[operation];
  let expectedVersion: number | null = null;
  if (spec.versioned) {
    if (rawTag === undefined) { throw new HttpException('Precondition Required', 428); }
    const tag = /^"p04-v(0|[1-9][0-9]{0,9})"$/u.exec(rawTag);
    if (!tag || tag[0] !== rawTag) { throw new BadRequestException(); }
    expectedVersion = Number(tag[1]);
    if (expectedVersion > 2147483647 || (expectedVersion === 0 && !spec.allowZero)) { throw new BadRequestException(); }
  } else if (rawTag !== undefined) { throw new BadRequestException(); }
  let body: Record<string, unknown>;
  try {
    const decoded = decodeP04Body(operation, req.body);
    body = copyBody(operation, decoded);
    // Revalidate the exact canonical operation data, not just the pre-normalization object.
    decodeP04Body(operation, body);
  } catch (error) {
    if (error instanceof TypeError || error instanceof catalog.CatalogError) { throw new BadRequestException(); }
    throw error;
  }
  return Object.freeze({ operation, params: Object.freeze({ ...params }), key, expectedVersion, body: freezeCommandBody(body) });
}

function copyBody(operation: P04MutationOperation, input: Record<string, unknown>): Record<string, unknown> {
  if (operation === 'avitoPublish') { return { ...normalizeAvitoPublish(input) }; }
  const copy = { ...input };
  for (const name of textFields) {
    const value = copy[name];
    if (typeof value === 'string') {
      if (/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) { throw new BadRequestException(); }
      copy[name] = value.trim();
    }
  }
  for (const name of optionalNulls[operation] ?? []) {
    if (!Object.hasOwn(copy, name)) { copy[name] = null; }
  }
  if (Array.isArray(copy['categoryIds'])) { copy['categoryIds'] = [...copy['categoryIds'] as string[]].sort(); }
  if (operation === 'policyPublish' || operation === 'policyReplace') {
    const config = input as unknown as pricing.PolicyBody;
    copy['priorities'] = [...config.priorities].sort((a, b) => a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0);
    copy['compatibilities'] = config.compatibilities.map(({ leftRuleId, rightRuleId }) => leftRuleId < rightRuleId
      ? { leftRuleId, rightRuleId } : { leftRuleId: rightRuleId, rightRuleId: leftRuleId })
      .sort((a, b) => a.leftRuleId < b.leftRuleId ? -1 : a.leftRuleId > b.leftRuleId ? 1 : a.rightRuleId < b.rightRuleId ? -1 : a.rightRuleId > b.rightRuleId ? 1 : 0);
  }
  return copy;
}

function freezeData(value: unknown): void {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value)) { freezeData(child); }
    Object.freeze(value);
  }
}
function freezeCommandBody(body: Record<string, unknown>): Readonly<Record<string, unknown>> {
  const fresh = parseStrictPricingJson(canonicalPricingJson(body));
  if (typeof fresh !== 'object' || fresh === null || Array.isArray(fresh)) { throw new InternalServerErrorException(); }
  freezeData(fresh);
  return fresh;
}

export function commandScope(body: Command['body'], operation: P04MutationOperation) {
  const opts: { categoryId?: string | null; brandId?: string | null; profileId?: string | null; itemId?: string | null;
    faultId?: string | null; kind?: string; avitoPublishForm?: AvitoPublishForm;
    pricingCategoryIds?: readonly string[]; pricingRuleIds?: readonly string[] } = {};
  for (const key of ['categoryId', 'brandId', 'profileId', 'itemId', 'faultId'] as const) {
    const value = body[key];
    if (typeof value === 'string' || value === null) { opts[key] = value; }
  }
  if (typeof body['kind'] === 'string') { opts.kind = body['kind']; }
  if (operation === 'ruleVersionPublish' || operation === 'ruleVersionReplace') {
    // commandFor already validated the exact operation-specific schema.
    opts.pricingCategoryIds = (body as unknown as pricing.RuleBody).categoryIds;
  }
  if (operation === 'policyPublish' || operation === 'policyReplace') {
    const { priorities, compatibilities } = body as unknown as pricing.PolicyBody;
    opts.pricingRuleIds = [...new Set([...priorities.map(p => p.ruleId),
      ...compatibilities.flatMap(p => [p.leftRuleId, p.rightRuleId])])];
  }
  if (operation === 'avitoPublish') {
    const { sourceDate, excerpt, rating } = normalizeAvitoPublish(body);
    opts.avitoPublishForm = { sourceDate, excerpt, rating };
  }
  return opts;
}
export function subjectName(operation: P04MutationOperation): 'id' | 'itemId' | 'ruleId' | 'estimateId' | 'cityId' {
  if (operation.startsWith('fixed')) { return 'itemId'; }
  if (operation.startsWith('ruleVersion')) { return 'ruleId'; }
  if (operation.startsWith('policy')) { return 'cityId'; }
  if (operation.startsWith('estimate')) { return 'estimateId'; }
  return 'id';
}

// All assertions here are after the generated operation-specific exact decoder.
// Only server-owned fields are added; no body can supply the actor, parent or V.
export function applyCommand(client: CatalogClient, actor: string, command: Command): Promise<Receipt> {
  const { operation: op, params: p, body: b } = command;
  const expectedVersion = command.expectedVersion;
  switch (op) {
    case 'categoryCreate': case 'brandCreate': case 'modelCreate': case 'faultCreate': {
      const family = op.slice(0, -'Create'.length) as keyof typeof directory;
      return catalog.createDirectory(client, actor, { ...b, kind: directory[family] } as catalog.CreateDirectoryInput);
    }
    case 'itemCreate': return catalog.createItem(client, actor, b as unknown as catalog.CreateItemInput);
    case 'mappingCreate': return catalog.createMapping(client, actor, b as unknown as catalog.CreateMappingInput);
    case 'ruleCreate': return pricing.createRule(client, actor, b as unknown as pricing.CreateRuleInput);
    case 'estimateCreate': return pricing.createEstimate(client, actor, { ...b, cityId: field(p, 'cityId') } as unknown as pricing.CreateEstimateInput);
    case 'avitoCreate': return createAvito(client, actor, b as unknown as CreateAvitoInput);
  }
  if (expectedVersion === null) { throw new InternalServerErrorException(); }
  switch (op) {
    case 'categoryPublish': case 'brandPublish': case 'modelPublish': case 'faultPublish':
      return catalog.publishDirectory(client, actor, { ...b, id: field(p, 'id'), expectedVersion } as catalog.PublishDirectoryInput);
    case 'categoryArchive': case 'brandArchive': case 'modelArchive': case 'faultArchive':
      return catalog.archiveDirectory(client, actor, { id: field(p, 'id'), expectedVersion });
    case 'itemPublish': return catalog.publishItem(client, actor, { ...b, id: field(p, 'id'), expectedVersion } as catalog.PublishItemInput);
    case 'itemArchive': return catalog.archiveItem(client, actor, { id: field(p, 'id'), expectedVersion });
    case 'mappingPublish': return catalog.publishMapping(client, actor, { id: field(p, 'id'), expectedVersion });
    case 'mappingArchive': return catalog.archiveMapping(client, actor, { id: field(p, 'id'), expectedVersion });
    case 'ruleArchive': return pricing.archiveRule(client, actor, { ruleId: field(p, 'id'), expectedVersion });
    case 'avitoArchive': return archiveAvito(client, actor, { id: field(p, 'id'), expectedVersion });
    case 'avitoPublish': return publishAvito(client, actor, { ...normalizeAvitoPublish(b), id: field(p, 'id'), expectedVersion });
  }
  const cityId = field(p, 'cityId');
  const data = { ...b, cityId, expectedVersion };
  switch (op) {
    case 'fixedPublish': return catalog.publishFixedPrice(client, actor, { ...data, itemId: field(p, 'itemId') } as catalog.PublishFixedPriceInput);
    case 'fixedReplace': return catalog.replaceFixedPrice(client, actor, { ...data, itemId: field(p, 'itemId'), priceVersionId: field(p, 'versionId') } as catalog.ReplaceFixedPriceInput);
    case 'fixedClose': return catalog.closeFixedPrice(client, actor, { ...data, itemId: field(p, 'itemId'), priceVersionId: field(p, 'versionId') } as catalog.CloseFixedPriceInput);
    case 'ruleVersionPublish': return pricing.publishRule(client, actor, { ...data, ruleId: field(p, 'ruleId') } as pricing.PublishRuleInput);
    case 'ruleVersionReplace': return pricing.replaceRule(client, actor, { ...data, ruleId: field(p, 'ruleId'), versionId: field(p, 'versionId') } as pricing.ReplaceRuleInput);
    case 'ruleVersionClose': return pricing.closeRule(client, actor, { ...data, ruleId: field(p, 'ruleId'), versionId: field(p, 'versionId') } as pricing.CloseRuleInput);
    case 'policyPublish': return pricing.publishPolicy(client, actor, data as pricing.PublishPolicyInput);
    case 'policyReplace': return pricing.replacePolicy(client, actor, { ...data, versionId: field(p, 'versionId') } as pricing.ReplacePolicyInput);
    case 'policyClose': return pricing.closePolicy(client, actor, { ...data, versionId: field(p, 'versionId') } as pricing.ClosePolicyInput);
    case 'estimateArchive': return pricing.archiveEstimate(client, actor, { cityId, estimateId: field(p, 'estimateId'), expectedVersion });
    case 'estimatePublish': return pricing.publishEstimate(client, actor, { ...data, estimateId: field(p, 'estimateId') } as pricing.PublishEstimateInput);
    case 'estimateReplace': return pricing.replaceEstimate(client, actor, { ...data, estimateId: field(p, 'estimateId'), versionId: field(p, 'versionId') } as pricing.ReplaceEstimateInput);
    case 'estimateClose': return pricing.closeEstimate(client, actor, { ...data, estimateId: field(p, 'estimateId'), versionId: field(p, 'versionId') } as pricing.CloseEstimateInput);
  }
}
