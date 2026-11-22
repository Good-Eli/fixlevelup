import { BadRequestException, HttpException } from '@nestjs/common';
import {
  P03_COMMANDS, P03_COMPANY_FIELDS, P03_CONTENT_KINDS, P03_LEGAL_KINDS, P03_LEGAL_PURPOSES,
  P03_REFERENCE_TYPES, isP03Capability, parseP03Etag,
} from '@fixlevelup/p03-contracts';
import type {
  P03Capability, P03CompanySettingsInput, P03ContentCreateInput, P03ContentPublishInput,
  P03LegalCreateInput, P03LegalPublishInput, P03Operation, P03ReferenceType, P03Target,
} from '@fixlevelup/p03-contracts';
import { header } from '../../auth/http.js';
import type { StaffRequest } from '../../auth/http.js';
import { uuid } from '../../authz/rbac-http.js';
import {
  companySettingsPublishInput, contentBlockCreateInput, contentRevisionInput, referenceEntryCreateInput, referenceVersionInput,
} from '../configuration/configuration-input.js';
import type { ReferenceVersionInput } from '../configuration/index.js';
import { documentVersionInput } from '../legal/legal-input.js';

export const COMPANY = Object.freeze({ scope: 'COMPANY' } as const);
const PLACEHOLDER = '00000000-0000-4000-8000-000000000000'; // Validation only; never a persisted staff ID.
export type ReferenceDescriptor = (typeof P03_REFERENCE_TYPES)[P03ReferenceType];

export function invalid(): never { throw new BadRequestException(); }
export function oneOf<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) { invalid(); }
  return value as T;
}

// The Unicode flag makes a valid surrogate pair one scalar, not two surrogate code points.
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;
function bodyFields(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) { invalid(); }
  const row = value as Record<string, unknown>;
  if (Object.keys(row).length !== fields.length || fields.some(key => !Object.hasOwn(row, key))) { invalid(); }
  // node-postgres cannot preserve NUL or unpaired UTF-16 surrogates as PostgreSQL UTF-8 text.
  if (Object.values(row).some(v => typeof v === 'string' && (v.includes('\0') || LONE_SURROGATE.test(v)))) { invalid(); }
  return row;
}

export interface Preconditions { readonly key: string; readonly expectedVersion: number | null }
export function preconditions(op: P03Operation, req: StaffRequest): Preconditions {
  const key = uuid(header(req, 'idempotency-key'));
  const tag = header(req, 'if-match');
  if (!P03_COMMANDS[op].versioned) {
    if (tag !== undefined) { invalid(); }
    return { key, expectedVersion: null };
  }
  if (tag === undefined) { throw new HttpException('Precondition Required', 428); }
  const expectedVersion = parseP03Etag(tag);
  if (expectedVersion === null) { invalid(); }
  return { key, expectedVersion };
}

export type P03Command =
  | { readonly op: 'companyPublish'; readonly body: P03CompanySettingsInput }
  | { readonly op: 'referenceCreate'; readonly ref: ReferenceDescriptor; readonly target: P03Target; readonly body: { readonly code: string } }
  | { readonly op: 'referencePublish'; readonly ref: ReferenceDescriptor; readonly target: P03Target; readonly id: string; readonly body: Omit<ReferenceVersionInput, 'type' | 'entryId' | 'expectedVersion'> }
  | { readonly op: 'referenceArchive'; readonly ref: ReferenceDescriptor; readonly target: P03Target; readonly id: string; readonly body: Record<string, never> }
  | { readonly op: 'contentCreate'; readonly target: P03Target; readonly body: P03ContentCreateInput }
  | { readonly op: 'contentPublish'; readonly id: string; readonly body: P03ContentPublishInput }
  | { readonly op: 'contentArchive'; readonly id: string; readonly body: Record<string, never> }
  | { readonly op: 'legalCreate'; readonly body: P03LegalCreateInput }
  | { readonly op: 'legalPublish'; readonly id: string; readonly body: P03LegalPublishInput }
  | { readonly op: 'bootstrapRevoke'; readonly staffId: string; readonly code: P03Capability; readonly body: Record<string, never> };

export function referenceScope(ref: ReferenceDescriptor, query: Query): P03Target {
  if (ref.scope === 'CITY') { return { scope: 'CITY', cityId: uuid(query.take('cityId')) }; }
  return COMPANY;
}
export function explicitTarget(scope: unknown, cityId: unknown): P03Target {
  if (scope === 'CITY') { return { scope, cityId: uuid(cityId) }; }
  if (scope === 'COMPANY' && cityId === undefined) { return COMPANY; }
  return invalid();
}
export function referenceType(value: unknown): ReferenceDescriptor {
  if (typeof value !== 'string' || !Object.hasOwn(P03_REFERENCE_TYPES, value)) { invalid(); }
  return P03_REFERENCE_TYPES[value as P03ReferenceType];
}

/** Use the same normalization as the internal ports, before acquiring a connection. */
export function parseCommand(op: P03Operation, params: Readonly<Record<string, string>>, query: Query, value: unknown): P03Command {
  switch (op) {
    case 'companyPublish': {
      const { settings } = companySettingsPublishInput({ settings: bodyFields(value, P03_COMPANY_FIELDS), expectedLastVersion: 0 });
      return { op, body: settings };
    }
    case 'referenceCreate': {
      const ref = referenceType(params['type']);
      const target = referenceScope(ref, query);
      const { code } = referenceEntryCreateInput({ ...bodyFields(value, ['code']), type: ref.dbType, cityId: target.cityId });
      return { op, ref, target, body: { code } };
    }
    case 'referencePublish': {
      const ref = referenceType(params['type']);
      const target = referenceScope(ref, query);
      const id = uuid(params['id']);
      const fields = ['label', 'sourceRef', 'validFrom', 'validUntil'];
      if (target.scope === 'CITY') { fields.push('cityVersionId', 'interval'); }
      const body = bodyFields(value, fields);
      if (target.scope === 'CITY') { bodyFields(body['interval'], ['startMinute', 'endMinute']); }
      const { label, sourceRef, validFrom, validUntil, cityVersionId, interval } = referenceVersionInput({
        ...body, ...(target.scope === 'CITY' ? { cityVersionId: uuid(body['cityVersionId']) } : {}),
        type: ref.dbType, entryId: id, expectedVersion: 1,
      });
      return { op, ref, target, id, body: { label, sourceRef, validFrom, validUntil, cityVersionId, interval } };
    }
    case 'referenceArchive': {
      const ref = referenceType(params['type']);
      bodyFields(value, []);
      return { op, ref, target: referenceScope(ref, query), id: uuid(params['id']), body: {} };
    }
    case 'contentCreate': {
      if (!value || typeof value !== 'object' || !('scope' in value)) { invalid(); }
      const fields = ['scope', 'kind', 'code', 'allowCompanyFallback'];
      if (value.scope === 'CITY') { fields.push('cityId'); }
      const body = bodyFields(value, fields);
      const target = explicitTarget(body['scope'], body['cityId']);
      if (typeof body['allowCompanyFallback'] !== 'boolean') { invalid(); }
      const { code, kind, allowCompanyFallback } = contentBlockCreateInput({
        ...body, ...target, kind: oneOf(body['kind'], P03_CONTENT_KINDS),
      });
      return { op, target, body: { ...target, code, kind, allowCompanyFallback } };
    }
    case 'contentPublish': {
      const id = uuid(params['id']);
      const { title, body, sourceRef } = contentRevisionInput({
        ...bodyFields(value, ['title', 'body', 'sourceRef']), blockId: id, expectedVersion: 1,
      });
      return { op, id, body: { title, body, sourceRef } };
    }
    case 'contentArchive':
      bodyFields(value, []);
      return { op, id: uuid(params['id']), body: {} };
    case 'legalCreate': {
      const body = bodyFields(value, ['purpose', 'kind']);
      return { op, body: { purpose: oneOf(body['purpose'], P03_LEGAL_PURPOSES), kind: oneOf(body['kind'], P03_LEGAL_KINDS) } };
    }
    case 'legalPublish': {
      const id = uuid(params['id']);
      const { title, body, sourceRef, legalBasis } = documentVersionInput({
        ...bodyFields(value, ['title', 'body', 'sourceRef', 'legalBasis']), documentId: id, expectedVersion: 1, reviewedBy: PLACEHOLDER,
      });
      return { op, id, body: { title, body, sourceRef, legalBasis } };
    }
    case 'bootstrapRevoke': {
      bodyFields(value, []);
      const code = params['code'];
      if (!isP03Capability(code)) { invalid(); }
      return { op, staffId: uuid(params['staffId']), code, body: {} };
    }
  }
}

/** Consumed keys are removed; unknown and duplicate keys fail before any SQL. */
export class Query {
  private readonly values = new Map<string, string>();
  constructor(url: string | undefined) {
    const i = url?.indexOf('?') ?? -1;
    if (i === -1) { return; }
    for (const [k, v] of new URLSearchParams(url?.slice(i + 1))) {
      if (this.values.has(k)) { invalid(); }
      this.values.set(k, v);
    }
  }
  take(key: string): string | undefined {
    const value = this.values.get(key);
    this.values.delete(key);
    return value;
  }
  flag(key: string): boolean {
    const value = this.take(key);
    return value === undefined ? false : oneOf(value, ['true', 'false']) === 'true';
  }
  optional<T extends string>(key: string, choices: readonly T[]): T | null {
    const value = this.take(key);
    return value === undefined ? null : oneOf(value, choices);
  }
  finish(): void { if (this.values.size) { invalid(); } }
}
