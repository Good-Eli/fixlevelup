import type { PoolClient } from 'pg';

export type CatalogClient = Pick<PoolClient, 'query'>;
export const DIRECTORY_KINDS = Object.freeze(['CATEGORY', 'BRAND', 'MODEL', 'FAULT'] as const);
export type DirectoryKind = (typeof DIRECTORY_KINDS)[number];
export const ITEM_KINDS = Object.freeze(['WORK', 'PART', 'MATERIAL', 'TRAVEL', 'DIAGNOSTICS'] as const);
export type ItemKind = (typeof ITEM_KINDS)[number];
export const PRICE_VISIBILITIES = Object.freeze(['TECHNICIAN', 'PUBLIC'] as const);
export type PriceVisibility = (typeof PRICE_VISIBILITIES)[number];

export interface CatalogReceipt {
  readonly id: string;
  readonly version: number;
}

export interface CatalogRevisionReceipt extends CatalogReceipt {
  readonly revisionId: string;
  readonly revisionVersion: number;
}

export type CreateDirectoryInput = { readonly code: string } & (
  | { readonly kind: 'CATEGORY' | 'BRAND'; readonly categoryId?: never; readonly brandId?: never }
  | { readonly kind: 'MODEL'; readonly categoryId: string; readonly brandId: string }
  | { readonly kind: 'FAULT'; readonly categoryId: string; readonly brandId?: never }
);

export interface CatalogCasInput {
  readonly id: string;
  readonly expectedVersion: number;
}

export interface PublishDirectoryInput extends CatalogCasInput {
  readonly title: string;
  readonly description?: string | null;
}

export type CreateItemInput = { readonly code: string; readonly unit: string } & (
  | { readonly kind: 'WORK'; readonly categoryId: string }
  | { readonly kind: Exclude<ItemKind, 'WORK'>; readonly categoryId?: string | null }
);

export type PublishItemInput = PublishDirectoryInput & {
  readonly technicianVisible: boolean;
  readonly publicVisible: boolean;
} & (
  | { readonly kind: 'WORK' | 'DIAGNOSTICS'; readonly durationMinutes: number }
  | { readonly kind: 'PART' | 'MATERIAL' | 'TRAVEL'; readonly durationMinutes?: never }
);

export interface CreateMappingInput {
  readonly categoryId: string;
  readonly faultId: string;
  readonly itemId: string;
}

interface PriceSeriesInput {
  readonly cityId: string;
  readonly itemId: string;
  readonly expectedVersion: number;
}

interface PriceBody {
  readonly amountMinor: string;
  readonly currency: string;
  readonly zeroBasis?: string | null;
  readonly sourceRef: string;
  readonly validUntil?: string | null;
}

export interface PublishFixedPriceInput extends PriceSeriesInput, PriceBody {
  readonly validFrom: string;
}

export interface CloseFixedPriceInput extends PriceSeriesInput {
  readonly priceVersionId: string;
  readonly at: string;
}

export interface ReplaceFixedPriceInput extends CloseFixedPriceInput, PriceBody {}

/** For trusted server city context only; never pass a city accepted from the browser. */
export interface ReadFixedPriceInput {
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly itemId: string;
  readonly visibility?: PriceVisibility;
}

export interface ReadFixedPriceRevisionInput {
  readonly cityId: string;
  readonly itemId: string;
  readonly priceVersionId: string;
}

export interface ReadCatalogRevisionInput {
  readonly type: 'directory' | 'item';
  readonly id: string;
  readonly revisionId: string;
}

interface RevisionMetadata {
  readonly revisionId: string;
  readonly version: number;
  readonly title: string;
  readonly description: string | null;
  readonly reviewedBy: string;
  readonly publishedAt: string;
}

export interface DirectoryRevision extends RevisionMetadata {
  readonly type: 'directory';
  readonly id: string;
  readonly kind: DirectoryKind;
  readonly code: string;
  readonly categoryId: string | null;
  readonly brandId: string | null;
}

export interface ItemRevision extends RevisionMetadata {
  readonly type: 'item';
  readonly id: string;
  readonly kind: ItemKind;
  readonly code: string;
  readonly categoryId: string | null;
  readonly unit: string;
  readonly durationMinutes: number | null;
  readonly technicianVisible: boolean;
  readonly publicVisible: boolean;
}

export interface FixedPriceRevision {
  readonly seriesId: string;
  readonly priceVersionId: string;
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly itemId: string;
  /** The item revision reviewed with this price, not the current item pointer. */
  readonly itemVersionId: string;
  readonly version: number;
  readonly amountMinor: string;
  readonly currency: string;
  readonly zeroBasis: string | null;
  readonly sourceRef: string;
  readonly reviewedBy: string;
  readonly publishedAt: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
}

export interface FixedPrice {
  readonly pricingAt: string;
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly itemId: string;
  /** The current eligible item metadata revision. */
  readonly itemVersionId: string;
  readonly unit: string;
  readonly title: string;
  readonly description: string | null;
  readonly durationMinutes: number | null;
  readonly technicianVisible: boolean;
  readonly publicVisible: boolean;
  readonly price: FixedPriceRevision & { readonly closedEffectiveUntil: string | null };
}
