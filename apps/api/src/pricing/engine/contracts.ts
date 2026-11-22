export type PricingErrorCode =
  | 'INVALID_INPUT' | 'PRICING_NOT_CONFIGURED' | 'PRICE_NOT_CONFIGURED'
  | 'PRICING_CONFIGURATION_AMBIGUOUS' | 'ADJUSTMENT_NOT_AUTHORIZED'
  | 'OVERFLOW' | 'NEGATIVE_TOTAL';

export class PricingError extends Error {
  constructor(readonly code: PricingErrorCode, readonly field?: string) {
    super(field === undefined ? code : `${code}: ${field}`);
    this.name = 'PricingError';
  }
}

type Instant = string;
type Minor = string;
type Id = string;
export type PricingItemKind = 'TRAVEL' | 'DIAGNOSTICS' | 'WORK' | 'MATERIAL' | 'PART';
export type PricingRuleKind = 'EVENING' | 'NIGHT' | 'EXPRESS' | 'SURCHARGE' | 'DISCOUNT';
export type PricingRuleBase = 'WORKS' | 'WORKS_AND_PARTS' | 'ORDER_BASE';
export type PricingRoundingMode = 'HALF_UP' | 'DOWN';

export interface PricingContext {
  readonly calculationId: Id;
  readonly cityId: Id;
  readonly cityVersionId: Id;
  readonly timezone: string;
  readonly pricingAt: Instant;
  readonly tariffAt: Instant;
  readonly localAt: string;
  readonly utcOffsetSeconds: number;
  readonly express: boolean;
}

interface EffectiveSource {
  readonly id: Id;
  readonly cityId: Id;
  readonly cityVersionId: Id;
  readonly validFrom: Instant;
  readonly effectiveUntil: Instant | null;
}

export interface PricingPriority {
  readonly ruleId: Id;
  readonly priority: number;
}

export interface PricingCompatibility {
  readonly leftRuleId: Id;
  readonly rightRuleId: Id;
}

export interface PricingPolicy extends EffectiveSource {
  readonly currency: string;
  readonly taxDisplay: string;
  readonly roundingMode: PricingRoundingMode;
  readonly units: Readonly<Record<string, number>>;
  readonly maxManualDeltaMinor: Minor;
  readonly priorities: readonly PricingPriority[];
  readonly compatibilities: readonly PricingCompatibility[];
}

export interface PricingFixedPrice extends EffectiveSource {
  readonly itemId: Id;
  /** The item revision reviewed with this price; not necessarily current. */
  readonly itemVersionId: Id;
  readonly amountMinor: Minor;
  readonly currency: string;
  readonly zeroBasis: string | null;
}

export interface PricingItem {
  readonly lineId: Id;
  readonly itemId: Id;
  readonly itemVersionId: Id;
  readonly kind: PricingItemKind;
  readonly categoryId: Id | null;
  readonly unit: string;
  readonly title: string;
  readonly quantity: string;
  readonly price: PricingFixedPrice;
}

export interface PricingRule extends EffectiveSource {
  readonly ruleId: Id;
  readonly kind: PricingRuleKind;
  readonly title: string;
  readonly currency: string;
  readonly method: 'FIXED' | 'RATE';
  readonly base: PricingRuleBase;
  readonly fixedMinor: Minor | null;
  readonly rateBps: number | null;
  readonly minBase: Minor | null;
  readonly maxBase: Minor | null;
  readonly minDelta: Minor | null;
  readonly maxDelta: Minor | null;
  readonly startMinute: number | null;
  readonly endMinute: number | null;
  readonly wrapsMidnight: boolean | null;
  readonly categoryIds: readonly Id[];
}

export interface PricingAdjustment {
  readonly id: Id;
  readonly ruleId: Id;
  readonly reason: string;
}

export interface PricingEvidence {
  readonly id: Id;
  readonly calculationId: Id;
  readonly adjustmentId: Id;
  readonly cityId: Id;
  readonly policyVersionId: Id;
  readonly ruleVersionId: Id;
  readonly currency: string;
  readonly baseMinor: Minor;
  readonly appliedMinor: Minor;
  readonly decision: 'WITHIN_LIMIT' | 'OVER_LIMIT_APPROVED';
  readonly actorId: Id;
  readonly reason: string;
}

/** Resolved by a trusted server boundary. Never deserialize a caller's authority into this type. */
export interface PricingInput {
  readonly context: PricingContext;
  readonly policy: PricingPolicy;
  readonly items: readonly PricingItem[];
  readonly rules: readonly PricingRule[];
  readonly adjustments: readonly PricingAdjustment[];
  readonly evidence: readonly PricingEvidence[];
}

export type PricingItemComponent = 'travel' | 'diagnostics' | 'works' | 'parts';
export type PricingRuleComponent = 'timeSurcharge' | 'expressSurcharge' | 'approvedSurcharges' | 'approvedDiscounts';
export type PricingComponent = PricingItemComponent | PricingRuleComponent;
export type PricingBreakdown = Readonly<Record<PricingComponent, Minor>>;

interface PricingLineMagnitudes {
  readonly ordinal: number;
  readonly key: string;
  readonly appliedMinor: Minor;
  readonly rawNumerator: string;
  readonly denominator: string;
  readonly roundedMinor: Minor;
}

export interface PricingItemLine extends PricingLineMagnitudes {
  readonly source: 'ITEM';
  readonly component: PricingItemComponent;
  readonly lineId: Id;
  readonly itemId: Id;
  readonly itemVersionId: Id;
  readonly priceVersionId: Id;
  readonly priceReviewedItemVersionId: Id;
  readonly unitPriceMinor: Minor;
  readonly zeroBasis: string | null;
}

export interface PricingRuleLine extends PricingLineMagnitudes {
  readonly source: 'RULE';
  readonly component: PricingRuleComponent;
  readonly ruleId: Id;
  readonly ruleVersionId: Id;
  readonly adjustmentId: Id | null;
  readonly evidenceId: Id | null;
  readonly reason: string | null;
  readonly matchingLineIds: readonly Id[];
  readonly baseMinor: Minor;
  readonly cappedMinor: Minor;
}

export type PricingLine = PricingItemLine | PricingRuleLine;

export interface PricingResult {
  readonly input: PricingInput;
  readonly lines: readonly PricingLine[];
  readonly breakdown: PricingBreakdown;
  readonly totalMinor: Minor;
}
