/**
 * Pure validation of the P03-03 configuration inputs.
 *
 * These tests need no database: they prove that the typed boundary refuses
 * unexpected keys, arbitrary settings/secret keys, contact or timezone duplicates,
 * scope/type contradictions, malformed callback windows, a foreign or missing
 * intake city version, reserved content codes and an implicit content fallback.
 */
import { describe, expect, it } from 'vitest';
import { ConfigurationError } from '../src/settings/configuration/configuration-errors.js';
import {
  COMPANY_SETTINGS_FIELDS, companySettingsPublishInput, contentBlockCreateInput, contentListInput,
  contentResolutionInput, contentRevisionInput, contentSnapshotInput, referenceArchiveInput,
  referenceEntryCreateInput, referenceListInput, referenceResolutionInput, referenceSnapshotInput,
  referenceVersionInput, REFERENCE_TYPE_SCOPE, RESERVED_CONTENT_CODES,
} from '../src/settings/configuration/configuration-input.js';

const ID = '11111111-1111-4111-8111-111111111111';
const CITY = '22222222-2222-4222-8222-222222222222';
const VERSION = '33333333-3333-4333-8333-333333333333';

const completeSettings = {
  operatorName: 'Synthetic Operator LLC',
  operatorRegistrationId: 'SYNTH-1',
  operatorAddress: 'Synthetic street 1',
  legalReviewRef: 'review://synthetic-legal/1',
  securityPolicyRef: 'policy://synthetic-security/1',
  retentionPolicyRef: 'policy://synthetic-retention/1',
  uploadPolicyRef: 'policy://synthetic-upload/1',
};

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof ConfigurationError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a typed refusal');
}

describe('company settings input', () => {
  it('accepts exactly the seven policy fields and freezes the result', () => {
    const parsed = companySettingsPublishInput({ settings: completeSettings, expectedLastVersion: 3 });
    expect(Object.keys(parsed.settings)).toEqual([...COMPANY_SETTINGS_FIELDS]);
    expect(parsed.expectedLastVersion).toBe(3);
    expect(Object.isFrozen(parsed.settings)).toBe(true);
  });

  it('refuses an incomplete revision', () => {
    for (const field of COMPANY_SETTINGS_FIELDS) {
      // Omit the field by filtering entries instead of mutating with a dynamic key.
      const settings = Object.fromEntries(
        Object.entries(completeSettings).filter(([key]) => key !== field),
      );
      expect(codeOf(() => companySettingsPublishInput({ settings, expectedLastVersion: 0 }))).toBe('INVALID_INPUT');
      expect(codeOf(() => companySettingsPublishInput({
        settings: { ...completeSettings, [field]: '   ' }, expectedLastVersion: 0,
      }))).toBe('INVALID_INPUT');
    }
  });

  it('refuses arbitrary, secret and duplicate-value keys', () => {
    for (const key of ['apiKey', 'secret', 'password', 'retentionDays', 'operator', 'timezone', 'publicContact']) {
      expect(codeOf(() => companySettingsPublishInput({
        settings: { ...completeSettings, [key]: 'x' }, expectedLastVersion: 0,
      }))).toBe('INVALID_INPUT');
    }
    expect(codeOf(() => companySettingsPublishInput({
      settings: completeSettings, expectedLastVersion: 0, extra: true,
    }))).toBe('INVALID_INPUT');
  });

  it('refuses a negative, fractional or missing expected version', () => {
    for (const expectedLastVersion of [-1, 1.5, '1', null, undefined]) {
      expect(codeOf(() => companySettingsPublishInput({ settings: completeSettings, expectedLastVersion })))
        .toBe('INVALID_INPUT');
    }
  });
});

describe('reference catalogue input', () => {
  it('derives the scope from the type and refuses a contradictory city', () => {
    expect(REFERENCE_TYPE_SCOPE.CALLBACK_INTERVAL).toBe('CITY');
    expect(REFERENCE_TYPE_SCOPE.PAYMENT_METHOD).toBe('COMPANY');
    expect(referenceEntryCreateInput({ type: 'CALLBACK_INTERVAL', cityId: CITY, code: 'day-window' }))
      .toEqual({ type: 'CALLBACK_INTERVAL', cityId: CITY, code: 'day-window' });
    // A city interval without a city, or a company type with a city, is refused.
    expect(codeOf(() => referenceEntryCreateInput({ type: 'CALLBACK_INTERVAL', code: 'day-window' })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => referenceEntryCreateInput({ type: 'PAYMENT_METHOD', cityId: CITY, code: 'card' })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => referenceEntryCreateInput({ type: 'UNKNOWN_TYPE', code: 'card' }))).toBe('INVALID_INPUT');
  });

  it('requires an interval only for CALLBACK_INTERVAL and bounds it to the local day', () => {
    const base = {
      type: 'CALLBACK_INTERVAL', entryId: ID, expectedVersion: 1, label: 'Day window',
      sourceRef: 'review://synthetic/1', validFrom: '2026-01-01T00:00:00Z', cityVersionId: VERSION,
    };
    expect(referenceVersionInput({ ...base, interval: { startMinute: 540, endMinute: 1080 } }).interval)
      .toEqual({ startMinute: 540, endMinute: 1080 });
    for (const interval of [
      { startMinute: 540, endMinute: 540 },
      { startMinute: 600, endMinute: 540 },
      { startMinute: 0, endMinute: 1441 },
      { startMinute: -1, endMinute: 60 },
      { startMinute: 0 },
      undefined,
    ]) {
      expect(codeOf(() => referenceVersionInput({ ...base, interval }))).toBe('INVALID_INPUT');
    }
    // A company type must not carry an interval, a city version or a city window.
    expect(codeOf(() => referenceVersionInput({
      ...base, type: 'PAYMENT_METHOD', cityVersionId: null, interval: { startMinute: 0, endMinute: 60 },
    }))).toBe('INVALID_INPUT');
    expect(codeOf(() => referenceVersionInput({
      ...base, type: 'PAYMENT_METHOD', cityVersionId: VERSION, interval: null,
    }))).toBe('INVALID_INPUT');
  });

  it('refuses an inverted validity period, a missing source and a foreign key shape', () => {
    const base = {
      type: 'PAYMENT_METHOD', entryId: ID, expectedVersion: 1, label: 'Card',
      sourceRef: 'review://synthetic/1', validFrom: '2026-02-01T00:00:00Z', cityVersionId: null, interval: null,
    };
    expect(codeOf(() => referenceVersionInput({ ...base, validUntil: '2026-02-01T00:00:00Z' })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => referenceVersionInput({ ...base, validUntil: '2026-01-01T00:00:00Z' })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => referenceVersionInput({ ...base, sourceRef: '  ' }))).toBe('INVALID_INPUT');
    expect(codeOf(() => referenceVersionInput({ ...base, entryId: 'not-a-uuid' }))).toBe('INVALID_INPUT');
    // A timestamp without an explicit offset would be an implicit timezone guess.
    expect(codeOf(() => referenceVersionInput({ ...base, validFrom: '2026-02-01T00:00:00' })))
      .toBe('INVALID_INPUT');
  });

  it('requires a trusted intake city version for a city-scoped use and forbids one for company types', () => {
    expect(referenceResolutionInput({ type: 'CALLBACK_INTERVAL', entryId: ID, intakeCityVersionId: VERSION }))
      .toMatchObject({ intakeCityVersionId: VERSION, at: null });
    expect(codeOf(() => referenceResolutionInput({ type: 'CALLBACK_INTERVAL', entryId: ID })))
      .toBe('INVALID_INPUT');
    expect(referenceResolutionInput({ type: 'PAYMENT_METHOD', entryId: ID }).intakeCityVersionId).toBeNull();
    expect(codeOf(() => referenceResolutionInput({ type: 'CALLBACK_INTERVAL', entryId: ID, intakeCityVersionId: VERSION, at: 'tomorrow' })))
      .toBe('INVALID_INPUT');
  });

  it('bounds list/snapshot/archive inputs and refuses an unknown key', () => {
    expect(referenceListInput({ type: 'CALLBACK_INTERVAL', cityId: CITY })).toMatchObject({
      includeArchived: false, limit: 50,
    });
    expect(codeOf(() => referenceListInput({ type: 'CALLBACK_INTERVAL' }))).toBe('INVALID_INPUT');
    expect(codeOf(() => referenceListInput({ type: 'CALLBACK_INTERVAL', cityId: CITY, limit: 0 })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => referenceListInput({ type: 'CALLBACK_INTERVAL', cityId: CITY, limit: 201 })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => referenceListInput({ type: 'PAYMENT_METHOD', cityId: CITY }))).toBe('INVALID_INPUT');
    expect(referenceSnapshotInput({ type: 'PAYMENT_METHOD', entryId: ID })).toEqual({
      type: 'PAYMENT_METHOD', entryId: ID, version: null,
    });
    expect(referenceArchiveInput({ entryId: ID, expectedVersion: 2 })).toEqual({ entryId: ID, expectedVersion: 2 });
    expect(codeOf(() => referenceArchiveInput({ entryId: ID }))).toBe('INVALID_INPUT');
  });
});

describe('content input', () => {
  it('binds scope to city presence and keeps the fallback flag on the company row', () => {
    expect(contentBlockCreateInput({ code: 'faq-installation', kind: 'FAQ', scope: 'COMPANY' }))
      .toMatchObject({ scope: 'COMPANY', cityId: null, allowCompanyFallback: false });
    expect(contentBlockCreateInput({
      code: 'faq-installation', kind: 'FAQ', scope: 'CITY', cityId: CITY,
    })).toMatchObject({ scope: 'CITY', cityId: CITY });
    expect(codeOf(() => contentBlockCreateInput({ code: 'faq', kind: 'FAQ', scope: 'CITY' })))
      .toBe('INVALID_INPUT');
    expect(codeOf(() => contentBlockCreateInput({ code: 'faq', kind: 'FAQ', scope: 'COMPANY', cityId: CITY })))
      .toBe('INVALID_INPUT');
    // Only the company row may grant a fallback; a city row cannot self-authorize one.
    expect(codeOf(() => contentBlockCreateInput({
      code: 'faq', kind: 'FAQ', scope: 'CITY', cityId: CITY, allowCompanyFallback: true,
    }))).toBe('INVALID_INPUT');
    expect(codeOf(() => contentBlockCreateInput({ code: 'faq', kind: 'REVIEW', scope: 'COMPANY' })))
      .toBe('INVALID_INPUT');
  });

  it('refuses a reserved policy/contact/timezone code', () => {
    for (const code of RESERVED_CONTENT_CODES) {
      expect(codeOf(() => contentBlockCreateInput({ code, kind: 'FACT', scope: 'COMPANY' })))
        .toBe('RESERVED_CODE');
    }
  });

  it('requires reviewed title/body/source and a bounded list', () => {
    const base = { blockId: ID, expectedVersion: 1, title: 'Title', body: 'Body', sourceRef: 'review://synthetic/1' };
    expect(contentRevisionInput(base)).toMatchObject({ title: 'Title', body: 'Body' });
    for (const field of ['title', 'body', 'sourceRef'] as const) {
      expect(codeOf(() => contentRevisionInput({ ...base, [field]: '  ' }))).toBe('INVALID_INPUT');
    }
    expect(codeOf(() => contentRevisionInput({ ...base, extra: 1 }))).toBe('INVALID_INPUT');
    expect(contentListInput({ scope: 'CITY', cityId: CITY })).toMatchObject({ limit: 50, kind: null });
    expect(codeOf(() => contentListInput({ scope: 'CITY' }))).toBe('INVALID_INPUT');
    expect(contentSnapshotInput({ blockId: ID })).toEqual({ blockId: ID, version: null });
    expect(contentResolutionInput({ code: 'faq', cityId: CITY })).toEqual({ code: 'faq', cityId: CITY });
    expect(codeOf(() => contentResolutionInput({ code: 'faq' }))).toBe('INVALID_INPUT');
  });
});
