import type {
  PricingAdjustment, PricingEvidence, PricingInput, PricingItem, PricingItemComponent, PricingItemLine,
  PricingLine, PricingResult, PricingRoundingMode, PricingRule, PricingRuleComponent, PricingRuleLine,
} from './contracts.js';
import { BIGINT_MAX, compare, fail, normalizePricingInput, pairKey, unauthorized } from './validation.js';

const ITEM_COMPONENT = {
  TRAVEL: 'travel', DIAGNOSTICS: 'diagnostics', WORK: 'works', MATERIAL: 'works', PART: 'parts',
} as const;

function checked(value: bigint): bigint {
  return value > BIGINT_MAX ? fail('OVERFLOW') : value;
}

function rounded(numerator: bigint, denominator: bigint, mode: PricingRoundingMode): bigint {
  const quotient = numerator / denominator;
  return mode === 'HALF_UP' && numerator % denominator * 2n >= denominator ? quotient + 1n : quotient;
}

interface PricedItem {
  readonly item: PricingItem;
  readonly amount: bigint;
  readonly line: PricingItemLine;
}

function priceItem(item: PricingItem, mode: PricingRoundingMode, index: number): PricedItem {
  const point = item.quantity.indexOf('.');
  const scale = point < 0 ? 0 : item.quantity.length - point - 1;
  const denominator = 10n ** BigInt(scale);
  const numerator = BigInt(item.price.amountMinor) * BigInt(item.quantity.replace('.', ''));
  const amount = checked(rounded(numerator, denominator, mode));
  const appliedMinor = amount.toString();
  const line: PricingItemLine = Object.freeze({
    source: 'ITEM', component: ITEM_COMPONENT[item.kind], ordinal: index + 1, key: `item:${item.lineId}`,
    lineId: item.lineId, itemId: item.itemId, itemVersionId: item.itemVersionId, priceVersionId: item.price.id,
    priceReviewedItemVersionId: item.price.itemVersionId, unitPriceMinor: item.price.amountMinor, zeroBasis: item.price.zeroBasis,
    rawNumerator: numerator.toString(), denominator: denominator.toString(), roundedMinor: appliedMinor, appliedMinor,
  });
  return { item, amount, line };
}

function isManual(rule: PricingRule): boolean {
  return rule.kind === 'SURCHARGE' || rule.kind === 'DISCOUNT';
}

function matchesTime(rule: PricingRule, minute: number, express: boolean): boolean {
  if (rule.kind === 'EXPRESS') { return express; }
  if (rule.startMinute === null || rule.endMinute === null) { return false; }
  return rule.wrapsMidnight ? minute >= rule.startMinute || minute < rule.endMinute
    : minute >= rule.startMinute && minute < rule.endMinute;
}

function inBase(rule: PricingRule, component: PricingItemComponent): boolean {
  return rule.base === 'ORDER_BASE' || component === 'works' || (rule.base === 'WORKS_AND_PARTS' && component === 'parts');
}

interface Applicable {
  readonly rule: PricingRule;
  readonly base: bigint;
  readonly matchingLineIds: readonly string[];
}

function applicable(rule: PricingRule, items: readonly PricedItem[]): Applicable | undefined {
  const matchingLineIds: string[] = [];
  const maxBase = rule.maxBase === null ? null : BigInt(rule.maxBase);
  let base = 0n;
  for (const { item, amount, line } of items) {
    if (inBase(rule, line.component) && (rule.categoryIds.length === 0
        || (item.categoryId !== null && rule.categoryIds.includes(item.categoryId)))) {
      base += amount;
      // All lines are nonnegative. An excluded candidate has no stored base.
      if (maxBase !== null && base > maxBase) { return undefined; }
      matchingLineIds.push(item.lineId);
    }
  }
  if (matchingLineIds.length === 0 || (rule.minBase !== null && base < BigInt(rule.minBase))) { return undefined; }
  return { rule, base: checked(base), matchingLineIds: Object.freeze(matchingLineIds) };
}

interface Ranked {
  readonly match: Applicable;
  readonly priority: number;
}

function winner(candidates: readonly Ranked[]): Applicable | undefined {
  let highest: Ranked | undefined;
  let tied = false;
  for (const candidate of candidates) {
    if (highest === undefined || candidate.priority > highest.priority) {
      highest = candidate;
      tied = false;
    } else if (candidate.priority === highest.priority) {
      tied = true;
    }
  }
  if (tied) { fail('PRICING_CONFIGURATION_AMBIGUOUS', 'priority'); }
  return highest?.match;
}

interface AppliedRule {
  readonly match: Applicable;
  readonly adjustment: PricingAdjustment | null;
  readonly evidence: PricingEvidence | null;
}

function selectRules(input: PricingInput, items: readonly PricedItem[]): AppliedRule[] {
  const { rules, context, policy, adjustments, evidence } = input;
  const minute = Number(context.localAt.slice(11, 13)) * 60 + Number(context.localAt.slice(14, 16));
  const priorities = new Map(policy.priorities.map((p) => [p.ruleId, p.priority]));
  const allows = new Set(policy.compatibilities.map((p) => pairKey(p.leftRuleId, p.rightRuleId)));
  const temporal: Ranked[] = [];
  const express: Ranked[] = [];
  const manual = new Map<string, PricingRule>();
  for (const rule of rules) {
    if (isManual(rule)) {
      manual.set(rule.ruleId, rule);
    } else if (matchesTime(rule, minute, context.express)) {
      const match = applicable(rule, items);
      if (match !== undefined) {
        const priority = priorities.get(rule.ruleId) ?? fail('PRICING_CONFIGURATION_AMBIGUOUS', 'priority');
        (rule.kind === 'EXPRESS' ? express : temporal).push({ match, priority });
      }
    }
  }

  const applied: AppliedRule[] = [];
  for (const match of [winner(temporal), winner(express)]) {
    if (match !== undefined) { applied.push({ match, adjustment: null, evidence: null }); }
  }
  if (evidence.length !== adjustments.length) { unauthorized('evidence'); }
  const records = new Map(evidence.map((v) => [v.adjustmentId, v]));
  for (const adjustment of adjustments) {
    const rule = manual.get(adjustment.ruleId) ?? unauthorized('manualRule');
    const match = applicable(rule, items) ?? unauthorized('ruleEligibility');
    applied.push({ match, adjustment, evidence: records.get(adjustment.id) ?? unauthorized('evidence') });
  }
  for (const [index, current] of applied.entries()) {
    for (const other of applied.slice(0, index)) {
      if (!allows.has(pairKey(current.match.rule.ruleId, other.match.rule.ruleId))) {
        if (current.adjustment !== null || other.adjustment !== null) { unauthorized('compatibility'); }
        fail('PRICING_CONFIGURATION_AMBIGUOUS', 'compatibility');
      }
    }
  }
  return applied.sort((a, b) => compare(a.match.rule.ruleId, b.match.rule.ruleId));
}

function authorize(input: PricingInput, rule: PricingRule, adjustment: PricingAdjustment, evidence: PricingEvidence, baseMinor: string, cappedMinor: string): void {
  const { context, policy } = input;
  const overLimit = BigInt(cappedMinor) > BigInt(policy.maxManualDeltaMinor);
  if (evidence.calculationId !== context.calculationId || evidence.adjustmentId !== adjustment.id
      || evidence.cityId !== context.cityId || evidence.policyVersionId !== policy.id || evidence.ruleVersionId !== rule.id
      || evidence.currency !== policy.currency || evidence.baseMinor !== baseMinor || evidence.appliedMinor !== cappedMinor
      || evidence.reason !== adjustment.reason || evidence.decision !== (overLimit ? 'OVER_LIMIT_APPROVED' : 'WITHIN_LIMIT')) {
    unauthorized('evidence');
  }
}

function ruleComponent(kind: PricingRule['kind']): PricingRuleComponent {
  switch (kind) {
    case 'EVENING': case 'NIGHT': return 'timeSurcharge';
    case 'EXPRESS': return 'expressSurcharge';
    case 'SURCHARGE': return 'approvedSurcharges';
    case 'DISCOUNT': return 'approvedDiscounts';
  }
}

function priceRule(input: PricingInput, applied: AppliedRule, index: number): PricingRuleLine {
  const { match: { rule, base, matchingLineIds }, adjustment, evidence } = applied;
  const denominator = rule.fixedMinor === null ? 10000n : 1n;
  // Validation ensured FIXED xor RATE; do not round an intermediate product.
  const numerator = rule.fixedMinor === null
    ? base * BigInt(rule.rateBps ?? fail('INVALID_INPUT', 'method')) : BigInt(rule.fixedMinor);
  const amount = checked(rounded(numerator, denominator, input.policy.roundingMode));
  const floor = rule.minDelta === null ? null : BigInt(rule.minDelta);
  const cap = rule.maxDelta === null ? null : BigInt(rule.maxDelta);
  const floored = floor !== null && amount < floor ? floor : amount;
  const capped = checked(cap !== null && floored > cap ? cap : floored);
  const baseMinor = base.toString();
  const cappedMinor = capped.toString();
  if (adjustment !== null) {
    authorize(input, rule, adjustment, evidence ?? unauthorized('evidence'), baseMinor, cappedMinor);
  }
  return Object.freeze({
    source: 'RULE', component: ruleComponent(rule.kind), ordinal: index + 1, key: `rule:${rule.ruleId}`,
    ruleId: rule.ruleId, ruleVersionId: rule.id, adjustmentId: adjustment?.id ?? null, evidenceId: evidence?.id ?? null,
    reason: adjustment?.reason ?? null, matchingLineIds, baseMinor, rawNumerator: numerator.toString(),
    denominator: denominator.toString(), roundedMinor: amount.toString(), cappedMinor, appliedMinor: cappedMinor,
  });
}

export function calculatePricing(value: unknown): PricingResult {
  const input = normalizePricingInput(value);
  const items = input.items.map((item, index) => priceItem(item, input.policy.roundingMode, index));
  const lines: PricingLine[] = items.map(({ line }) => line);
  const applied = selectRules(input, items);
  lines.push(...applied.map((rule, index) => priceRule(input, rule, items.length + index)));

  const amounts = {
    travel: 0n, diagnostics: 0n, works: 0n, parts: 0n, timeSurcharge: 0n, expressSurcharge: 0n,
    approvedSurcharges: 0n, approvedDiscounts: 0n,
  };
  for (const line of lines) { amounts[line.component] = checked(amounts[line.component] + BigInt(line.appliedMinor)); }
  // The signed sum is not bounded mid-formula; a discount can bring a large
  // positive subtotal back into the representable range.
  const total = amounts.travel + amounts.diagnostics + amounts.works + amounts.parts + amounts.timeSurcharge
    + amounts.expressSurcharge + amounts.approvedSurcharges - amounts.approvedDiscounts;
  if (total < 0n) { fail('NEGATIVE_TOTAL'); }
  const breakdown = Object.freeze({
    travel: amounts.travel.toString(), diagnostics: amounts.diagnostics.toString(), works: amounts.works.toString(),
    parts: amounts.parts.toString(), timeSurcharge: amounts.timeSurcharge.toString(), expressSurcharge: amounts.expressSurcharge.toString(),
    approvedSurcharges: amounts.approvedSurcharges.toString(), approvedDiscounts: amounts.approvedDiscounts.toString(),
  });
  return Object.freeze({ input, lines: Object.freeze(lines), breakdown, totalMinor: checked(total).toString() });
}
