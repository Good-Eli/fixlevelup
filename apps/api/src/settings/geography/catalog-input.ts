/**
 * Pure request validation for the P03-02 geography catalog commands.
 *
 * Nothing here touches a database, a session or an authorization decision: it
 * narrows an untrusted HTTP payload into the small typed inputs the commands
 * accept and enforces the per-field type/size/quantity limits that the schema
 * cannot express. Database CHECK/trigger rules stay authoritative - the IANA
 * catalog membership of a timezone and the office-hours CHECK are re-verified by
 * migration `20261121000100_city_foundation` when the row is inserted, and the
 * draft/publish/pointer guards of `20261121000200_service_areas` remain the only
 * authority on revision state.
 *
 * Every failure is a bare `BadRequestException`: the message deliberately does
 * not echo the submitted value, so a validation error cannot become a log or
 * response leak of contact data or free text.
 */
import { BadRequestException, HttpException } from '@nestjs/common';

/** Seven ISO weekdays, Monday first; each slot is `[startMinute, endMinute)`. */
export type OfficeHours = readonly (readonly (readonly [number, number])[])[];

export interface CityCreateInput {
  readonly code: string;
}
export interface CityVersionInput {
  readonly displayName: string;
  readonly addressDisplay: string | null;
  readonly timezone: string;
  readonly publicContact: string;
  readonly officeHours: OfficeHours;
}
export interface CityActivateInput {
  /** Only set when the caller explicitly replaces the currently ACTIVE city. */
  readonly replaceActiveCityId: string | null;
  readonly replaceActiveCityVersion: number | null;
}
export interface CityDeactivateInput {
  /** Explicitly allows deactivating the primary city and suspending intake. */
  readonly suspendIntake: boolean;
}
/** Bounded list read: the schema stores unbounded rows, the API does not return them. */
export interface ListQuery {
  readonly limit: number;
  readonly includeArchived: boolean;
}
export interface DistrictCreateInput {
  readonly code: string;
  readonly name: string;
}
export interface DistrictUpdateInput {
  readonly name: string;
}
export interface AreaCreateInput {
  readonly code: string;
}
export interface AreaVersionInput {
  readonly name: string;
  readonly coverageDescription: string | null;
  readonly addressCriteria: string | null;
}
/** Partial draft edit: an absent key keeps the stored value, `null` clears it. */
export interface AreaVersionPatch {
  readonly name?: string;
  readonly coverageDescription?: string | null;
  readonly addressCriteria?: string | null;
}
export interface CoverageEntryInput {
  readonly districtId: string;
  readonly relation: 'FULL' | 'PARTIAL';
  readonly description: string | null;
}

/** Mirrors the migration CHECK patterns so a malformed value is a 400, not a 409. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const TIMEZONE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)+$/;

/** Quantity limits. The schema stores unbounded text and unlimited coverage rows. */
export const MAX_INTERVALS_PER_DAY = 12;
export const MAX_COVERAGE_ENTRIES = 200;
export const MAX_LIST_ROWS = 200;
export const DEFAULT_LIST_ROWS = 50;
export const MAX_DISPLAY_NAME = 200;
export const MAX_ADDRESS_DISPLAY = 500;
export const MAX_PUBLIC_CONTACT = 320;
export const MAX_COVERAGE_DESCRIPTION = 2000;
export const MAX_ADDRESS_CRITERIA = 2000;
export const MAX_DISTRICT_NAME = 200;
export const MAX_COVERAGE_ENTRY_DESCRIPTION = 500;

function invalid(): never {
  throw new BadRequestException();
}

function bodyObject(body: unknown): Record<string, unknown> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    invalid();
  }
  return body as Record<string, unknown>;
}

function rejectUnknown(value: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      invalid();
    }
  }
}

function requiredText(value: unknown, max: number): string {
  if (typeof value !== 'string') {
    invalid();
  }
  const text = value.trim();
  if (text.length === 0 || text.length > max) {
    invalid();
  }
  return text;
}

function optionalText(value: unknown, max: number): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  return requiredText(value, max);
}

/** Path/body identifier: a canonical UUID, lowercased. Foreign ids are a 404 in the command. */
export function routeId(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) {
    invalid();
  }
  return value.toLowerCase();
}

/** A command body that carries no data at all; unknown keys are refused, not ignored. */
export function emptyBody(body: unknown): void {
  if (body === undefined || body === null) {
    return;
  }
  const value = bodyObject(body);
  if (Object.keys(value).length !== 0) {
    invalid();
  }
}

/** `If-Match` is mandatory for every mutation of an existing aggregate (428 otherwise). */
export function expectedVersion(expected: number | null): number {
  if (expected === null) {
    throw new HttpException('Precondition Required', 428);
  }
  if (!Number.isSafeInteger(expected) || expected < 1) {
    invalid();
  }
  return expected;
}

/** Publishing moves the parent area's pointer as well as freezing the draft. Both must still match. */
export function publicationAreaVersion(body: unknown): number {
  const value = bodyObject(body);
  rejectUnknown(value, ['expectedAreaVersion']);
  const version = value['expectedAreaVersion'];
  if (version === undefined) { throw new HttpException('Precondition Required', 428); }
  if (typeof version !== 'number') { invalid(); }
  return expectedVersion(version);
}

/** Creation of a brand new aggregate has no prior revision; an `If-Match` there is a mistake. */
export function noExpected(expected: number | null): void {
  if (expected !== null) {
    invalid();
  }
}

function code(value: unknown): string {
  if (typeof value !== 'string' || value.length < 2 || value.length > 32 || !CODE.test(value)) {
    invalid();
  }
  return value;
}

/**
 * Shape of an IANA area/id name. Catalog membership is deliberately NOT checked
 * here: migration 010 owns that rule, and the reviewed name is stored verbatim so
 * a later tzdata update cannot reinterpret the immutable snapshot.
 */
function timezone(value: unknown): string {
  if (typeof value !== 'string' || value.length > 64) {
    invalid();
  }
  if (value !== 'UTC' && (!TIMEZONE.test(value) || /^(posix|right|SystemV)\//.test(value))) {
    invalid();
  }
  return value;
}

function officeHours(value: unknown): OfficeHours {
  if (!Array.isArray(value) || value.length !== 7) {
    invalid();
  }
  const days: (readonly (readonly [number, number])[])[] = [];
  for (const day of value as unknown[]) {
    if (!Array.isArray(day) || day.length > MAX_INTERVALS_PER_DAY) {
      invalid();
    }
    const slots: (readonly [number, number])[] = [];
    let previousEnd = 0;
    for (const slot of day as unknown[]) {
      if (!Array.isArray(slot) || slot.length !== 2) {
        invalid();
      }
      const pair: unknown[] = slot;
      const start: unknown = pair[0];
      const end: unknown = pair[1];
      if (typeof start !== 'number' || typeof end !== 'number' || !Number.isInteger(start) || !Number.isInteger(end)) {
        invalid();
      }
      // Sorted, non-overlapping, within one day; an empty day is an explicitly closed day.
      if (start < 0 || start >= end || end > 1440 || start < previousEnd) {
        invalid();
      }
      slots.push([start, end]);
      previousEnd = end;
    }
    days.push(slots);
  }
  return days;
}

export function cityCreateInput(body: unknown): CityCreateInput {
  const value = bodyObject(body);
  rejectUnknown(value, ['code']);
  return { code: code(value['code']) };
}

export function cityVersionInput(body: unknown): CityVersionInput {
  const value = bodyObject(body);
  rejectUnknown(value, ['displayName', 'addressDisplay', 'timezone', 'publicContact', 'officeHours']);
  return {
    displayName: requiredText(value['displayName'], MAX_DISPLAY_NAME),
    addressDisplay: optionalText(value['addressDisplay'], MAX_ADDRESS_DISPLAY),
    timezone: timezone(value['timezone']),
    publicContact: requiredText(value['publicContact'], MAX_PUBLIC_CONTACT),
    officeHours: officeHours(value['officeHours']),
  };
}

export function cityActivateInput(body: unknown): CityActivateInput {
  if (body === undefined || body === null) {
    return { replaceActiveCityId: null, replaceActiveCityVersion: null };
  }
  const value = bodyObject(body);
  rejectUnknown(value, ['replaceActiveCityId', 'replaceActiveCityVersion']);
  if (!Object.hasOwn(value, 'replaceActiveCityId') && !Object.hasOwn(value, 'replaceActiveCityVersion')) {
    return { replaceActiveCityId: null, replaceActiveCityVersion: null };
  }
  const replaceActiveCityId = routeId(value['replaceActiveCityId']);
  const replaceActiveCityVersion = value['replaceActiveCityVersion'];
  if (typeof replaceActiveCityVersion !== 'number' || !Number.isSafeInteger(replaceActiveCityVersion) || replaceActiveCityVersion < 1) {
    invalid();
  }
  return { replaceActiveCityId, replaceActiveCityVersion };
}

export function cityDeactivateInput(body: unknown): CityDeactivateInput {
  if (body === undefined || body === null) {
    return { suspendIntake: false };
  }
  const value = bodyObject(body);
  rejectUnknown(value, ['suspendIntake']);
  const suspend = value['suspendIntake'];
  if (suspend !== undefined && typeof suspend !== 'boolean') {
    invalid();
  }
  return { suspendIntake: suspend === true };
}

export function listQuery(body: unknown): ListQuery {
  if (body === undefined || body === null) {
    return { limit: DEFAULT_LIST_ROWS, includeArchived: true };
  }
  const value = bodyObject(body);
  rejectUnknown(value, ['limit', 'includeArchived']);
  // An explicit null is a type error, not "absent": only a missing key takes the default.
  const limit: unknown = Object.hasOwn(value, 'limit') ? value['limit'] : DEFAULT_LIST_ROWS;
  if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_LIST_ROWS) {
    invalid();
  }
  const includeArchived: unknown = Object.hasOwn(value, 'includeArchived') ? value['includeArchived'] : true;
  if (typeof includeArchived !== 'boolean') {
    invalid();
  }
  return { limit, includeArchived };
}

export function districtCreateInput(body: unknown): DistrictCreateInput {
  const value = bodyObject(body);
  rejectUnknown(value, ['code', 'name']);
  return { code: code(value['code']), name: requiredText(value['name'], MAX_DISTRICT_NAME) };
}

export function districtUpdateInput(body: unknown): DistrictUpdateInput {
  const value = bodyObject(body);
  rejectUnknown(value, ['name']);
  return { name: requiredText(value['name'], MAX_DISTRICT_NAME) };
}

export function areaCreateInput(body: unknown): AreaCreateInput {
  const value = bodyObject(body);
  rejectUnknown(value, ['code']);
  return { code: code(value['code']) };
}

export function areaVersionInput(body: unknown): AreaVersionInput {
  const value = bodyObject(body);
  rejectUnknown(value, ['name', 'coverageDescription', 'addressCriteria']);
  return {
    name: requiredText(value['name'], MAX_DISPLAY_NAME),
    coverageDescription: optionalText(value['coverageDescription'], MAX_COVERAGE_DESCRIPTION),
    addressCriteria: optionalText(value['addressCriteria'], MAX_ADDRESS_CRITERIA),
  };
}

export function areaVersionPatchInput(body: unknown): AreaVersionPatch {
  const value = bodyObject(body);
  rejectUnknown(value, ['name', 'coverageDescription', 'addressCriteria']);
  const patch: { name?: string; coverageDescription?: string | null; addressCriteria?: string | null } = {};
  let fields = 0;
  if (Object.hasOwn(value, 'name')) {
    patch.name = requiredText(value['name'], MAX_DISPLAY_NAME);
    fields += 1;
  }
  if (Object.hasOwn(value, 'coverageDescription')) {
    patch.coverageDescription = optionalText(value['coverageDescription'], MAX_COVERAGE_DESCRIPTION);
    fields += 1;
  }
  if (Object.hasOwn(value, 'addressCriteria')) {
    patch.addressCriteria = optionalText(value['addressCriteria'], MAX_ADDRESS_CRITERIA);
    fields += 1;
  }
  if (fields === 0) {
    invalid();
  }
  return patch;
}

/**
 * Full replacement of the district mapping of one DRAFT area revision.
 * `districts` is mandatory so an empty body can never silently wipe coverage;
 * duplicate district ids are refused here instead of surfacing as 23505.
 */
export function coverageInput(body: unknown): readonly CoverageEntryInput[] {
  const value = bodyObject(body);
  rejectUnknown(value, ['districts']);
  const raw: unknown = value['districts'];
  if (!Array.isArray(raw) || raw.length > MAX_COVERAGE_ENTRIES) {
    invalid();
  }
  const seen = new Set<string>();
  const entries: CoverageEntryInput[] = [];
  for (const item of raw as unknown[]) {
    const entry = bodyObject(item);
    rejectUnknown(entry, ['districtId', 'relation', 'description']);
    const districtId = routeId(entry['districtId']);
    if (seen.has(districtId)) {
      invalid();
    }
    seen.add(districtId);
    const relation = entry['relation'];
    if (relation !== 'FULL' && relation !== 'PARTIAL') {
      invalid();
    }
    entries.push({ districtId, relation, description: optionalText(entry['description'], MAX_COVERAGE_ENTRY_DESCRIPTION) });
  }
  return entries;
}
