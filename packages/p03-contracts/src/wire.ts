import type { P03Capability, P03ReferenceDbType, P03Target } from './policy.js';
import type { P03Operation } from './routes.js';

export const P03_COMPANY_FIELD_LENGTHS = Object.freeze({
  operatorName: 200, operatorRegistrationId: 120, operatorAddress: 500,
  legalReviewRef: 200, securityPolicyRef: 200, retentionPolicyRef: 200, uploadPolicyRef: 200,
});
export type P03CompanyField = keyof typeof P03_COMPANY_FIELD_LENGTHS;
export const P03_COMPANY_FIELDS = Object.freeze(Object.keys(P03_COMPANY_FIELD_LENGTHS) as P03CompanyField[]);
export const P03_CONTENT_KINDS = Object.freeze(['FAQ', 'FACT', 'SEO'] as const);
export const P03_LEGAL_PURPOSES = Object.freeze(['REQUEST_PROCESSING', 'MARKETING'] as const);
export const P03_LEGAL_KINDS = Object.freeze(['POLICY', 'CONSENT_FORM', 'OPT_IN_NOTICE'] as const);
export const P03_CITY_STATUSES = Object.freeze(['DRAFT', 'ACTIVE', 'INACTIVE'] as const);
export const P03_TEXT_LENGTHS = Object.freeze({
  code: 64, title: 300, sourceRef: 200, referenceLabel: 200, contentBody: 20_000,
  legalBody: 200_000, legalBasis: 4_000, legalSourceRef: 500, cityName: 200, timezone: 100, staffName: 80,
});
export type P03ContentKind = (typeof P03_CONTENT_KINDS)[number];
export type P03LegalPurpose = (typeof P03_LEGAL_PURPOSES)[number];
export type P03LegalKind = (typeof P03_LEGAL_KINDS)[number];
export type P03CityStatus = (typeof P03_CITY_STATUSES)[number];

export interface P03Envelope<T> { readonly data: T; readonly meta: { readonly requestId: string } }
export interface P03Problem { readonly type: 'about:blank'; readonly title: P03ProblemCode; readonly status: number;
  readonly code: P03ProblemCode; readonly requestId: string }
export type P03ProblemCode = 'NOT_READY' | 'NOT_FOUND' | 'INTERNAL_ERROR' | 'REQUEST_REJECTED';
export interface P03PageInfo { readonly hasMore: boolean; readonly nextCursor: string | null }
export interface P03Page<T> { readonly items: readonly T[]; readonly pageInfo: P03PageInfo }
export interface P03VersionedPage<T> extends P03Page<T> { readonly version: number }
export interface P03PageQuery { readonly limit?: number; readonly cursor?: string }
export const P03_CITY_PICKER_DOMAINS = Object.freeze(['content', 'callback_interval'] as const);
export type P03CityPickerDomain = (typeof P03_CITY_PICKER_DOMAINS)[number];
export interface P03CityPickerQuery extends P03PageQuery { readonly domain: P03CityPickerDomain }
export interface P03ReferenceListQuery extends P03PageQuery { readonly cityId?: string; readonly includeArchived?: boolean }
export type P03ContentListQuery = P03PageQuery & P03Target & { readonly kind?: P03ContentKind; readonly includeArchived?: boolean };
export interface P03LegalListQuery extends P03PageQuery { readonly purpose?: P03LegalPurpose; readonly kind?: P03LegalKind }

export interface P03Receipt { readonly id: string; readonly version: number }
export interface P03RevisionReceipt extends P03Receipt { readonly revisionId: string; readonly revisionVersion: number }
export interface P03ReceiptByOperation {
  companyPublish: P03Receipt; referenceCreate: P03Receipt; referencePublish: P03RevisionReceipt;
  referenceArchive: P03Receipt; contentCreate: P03Receipt; contentPublish: P03RevisionReceipt;
  contentArchive: P03Receipt; legalCreate: P03Receipt; legalPublish: P03RevisionReceipt; bootstrapRevoke: P03Receipt;
}
export type P03CommandReceipt<O extends P03Operation = P03Operation> = P03ReceiptByOperation[O];

export type P03CompanySettingsInput = Readonly<Record<P03CompanyField, string>>;
export type P03CompanySettings = Readonly<Record<P03CompanyField, string | null>>;
export interface P03CompanySummary extends P03Receipt { readonly publishedAt: string }
export interface P03CompanyVersion extends P03CompanySummary {
  readonly launchMode: 'SINGLE_CITY' | 'MULTI_CITY'; readonly primaryCityId: string; readonly reviewedBy: string;
  readonly settings: P03CompanySettings;
}

export interface P03Interval { readonly startMinute: number; readonly endMinute: number }
export interface P03ReferenceCreateInput { readonly code: string }
export interface P03ReferencePublishInput { readonly label: string; readonly sourceRef: string;
  readonly validFrom: string; readonly validUntil: string | null; readonly cityVersionId?: string; readonly interval?: P03Interval }
export interface P03ReferenceEntry extends P03Receipt {
  readonly type: P03ReferenceDbType; readonly scope: P03Target['scope']; readonly cityId: string | null;
  readonly code: string; readonly currentVersionId: string | null; readonly archivedAt: string | null;
}
export interface P03ReferenceSummary extends P03Receipt { readonly entryId: string; readonly label: string; readonly publishedAt: string }
export interface P03ReferenceVersion extends P03ReferenceSummary { readonly type: P03ReferenceDbType;
  readonly cityId: string | null; readonly sourceRef: string; readonly validFrom: string; readonly validUntil: string | null;
  readonly provenanceCityVersionId: string | null; readonly interval: P03Interval | null }

export type P03ContentCreateInput = P03Target & {
  readonly code: string; readonly kind: P03ContentKind; readonly allowCompanyFallback: boolean };
export interface P03ContentPublishInput { readonly title: string; readonly body: string; readonly sourceRef: string }
export interface P03ContentBlock extends P03Receipt {
  readonly code: string; readonly kind: P03ContentKind; readonly scope: P03Target['scope']; readonly cityId: string | null;
  readonly allowCompanyFallback: boolean; readonly currentRevisionId: string | null; readonly archivedAt: string | null;
}
export interface P03ContentSummary extends P03Receipt { readonly blockId: string; readonly title: string; readonly publishedAt: string }
export interface P03ContentRevision extends P03ContentSummary { readonly body: string; readonly sourceRef: string }

export interface P03LegalCreateInput { readonly purpose: P03LegalPurpose; readonly kind: P03LegalKind }
export interface P03LegalPublishInput extends P03ContentPublishInput { readonly legalBasis: string }
export interface P03LegalDocument extends P03Receipt, P03LegalCreateInput { readonly currentVersionId: string | null }
export interface P03LegalSummary { readonly id: string; readonly documentId: string; readonly sequence: number;
  readonly title: string; readonly checksum: string; readonly publishedAt: string }
export interface P03LegalVersion extends P03LegalSummary, P03LegalCreateInput, P03LegalPublishInput { readonly reviewedBy: string }

export type P03EmptyInput = Readonly<Record<string, never>>;
export interface P03InputByOperation {
  companyPublish: P03CompanySettingsInput; referenceCreate: P03ReferenceCreateInput; referencePublish: P03ReferencePublishInput;
  referenceArchive: P03EmptyInput; contentCreate: P03ContentCreateInput; contentPublish: P03ContentPublishInput;
  contentArchive: P03EmptyInput; legalCreate: P03LegalCreateInput; legalPublish: P03LegalPublishInput; bootstrapRevoke: P03EmptyInput;
}

export interface P03BootstrapGrant { readonly assignmentId: string; readonly staffId: string; readonly code: P03Capability; readonly version: number }
export interface P03CityPickerItem extends P03Receipt { readonly code: string; readonly status: P03CityStatus;
  readonly currentVersionId: string | null }
export interface P03CityVersionPickerItem { readonly id: string; readonly sequence: number; readonly timezone: string; readonly published: boolean }
export interface P03TechnicianPickerItem extends P03Receipt { readonly displayName: string | null }

export const P03_READINESS_SECTION_STATES = Object.freeze({
  COMPANY_SETTINGS: Object.freeze(['CONFIGURED', 'MISSING'] as const),
  REQUEST_PROCESSING: Object.freeze(['CONFIGURED', 'MISSING'] as const),
  P04: Object.freeze(['NOT_IMPLEMENTED'] as const), P05: Object.freeze(['NOT_IMPLEMENTED'] as const),
  P09: Object.freeze(['NOT_IMPLEMENTED'] as const), PROVIDERS: Object.freeze(['NOT_ASSESSED'] as const),
  PRODUCTION: Object.freeze(['NOT_ASSESSED'] as const),
} as const);
export const P03_READINESS_MISSING = Object.freeze({
  COMPANY_SETTINGS: Object.freeze(['COMPANY_VERSION_MISSING', ...P03_COMPANY_FIELDS] as const),
  REQUEST_PROCESSING: Object.freeze(['REQUEST_PROCESSING_FORM_MISSING'] as const),
  CITY: Object.freeze(['CITY_VERSION_MISSING', 'CITY_INACTIVE'] as const),
});
export type P03ReadinessSectionKey = keyof typeof P03_READINESS_SECTION_STATES;
export type P03ReadinessSection = {
  [K in P03ReadinessSectionKey]: { readonly section: K; readonly status: (typeof P03_READINESS_SECTION_STATES)[K][number];
    readonly missing: readonly (K extends 'COMPANY_SETTINGS' | 'REQUEST_PROCESSING' ? (typeof P03_READINESS_MISSING)[K][number] : never)[] }
}[P03ReadinessSectionKey];
export interface P03ReadinessCity { readonly id: string; readonly name: string | null;
  readonly status: 'CONFIGURED' | 'MISSING'; readonly missing: readonly (typeof P03_READINESS_MISSING.CITY)[number][] }
export interface P03Readiness extends P03Page<P03ReadinessCity> { readonly sections: readonly P03ReadinessSection[] }
