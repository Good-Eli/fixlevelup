/**
 * P03-03 configuration ports: company settings, typed reference catalogue and
 * content blocks.
 *
 * Every export is a plain function over the caller's `PoolClient`. There is no
 * NestJS provider, controller, DI token, HTTP route, capability check or session
 * dependency here: authentication and capability policy stay an external
 * mandatory port (P03-05/P05), and the caller owns the transaction.
 *
 * ## Caller-transaction contract (mandatory)
 *
 * ```ts
 * const client = await pool.connect();
 * try {
 *   await client.query('BEGIN');
 *   await publishCompanySettings(client, trustedActorStaffId, input);
 *   await client.query('COMMIT');
 * } catch (error) {
 *   await client.query('ROLLBACK');
 *   throw error;
 * } finally {
 *   client.release();
 * }
 * ```
 *
 * A write is only atomic with its audit/outbox rows if the caller commits them
 * together. `publishCompanySettings` verifies this by taking the shared company
 * advisory lock and re-reading it on the same backend: outside an explicit
 * transaction the transaction-scoped lock is already gone, so the call is refused
 * with `TRANSACTION_REQUIRED` instead of running non-atomically.
 *
 * ## Lock order
 *
 * Any caller that also touches geography must take locks in this order:
 * authorization/admin invariant locks, then the company settings lock
 * (`acquireCompanySettingsLock`), then city/row locks. The settings publisher
 * follows it: company lock first, and it never takes a `FOR UPDATE` city lock (its
 * city reference is only the FK check on insert). A publisher that locked a city
 * first would invert geography's city -> company order and could deadlock.
 *
 * ## Scope boundaries
 *
 * - company settings: legal identity and security/retention/upload *policy refs*
 *   only. A ref is reviewed provenance, never an executable policy, secret or
 *   default value. City timezone/contact/hours are read from `service_city_versions`
 *   only, never copied here.
 * - references: `CALLBACK_INTERVAL` is CITY-scoped with a reviewed local window;
 *   the timezone at use comes from the caller's trusted intake city version, while
 *   the stored city version is creation provenance only. Other types are
 *   COMPANY-scoped and have no interval or city.
 * - content: COMPANY/CITY blocks with immutable revisions and explicit fallback
 *   provenance. Content never overrides legal/retention/security/upload policy and
 *   never carries a second copy of contacts/hours/timezone.
 *
 * No write is idempotent by key: these ports are compare-and-swap only. An HTTP
 * retry/receipt policy belongs to the trusted command layer of P03-05.
 */
export {
  COMPANY_SETTINGS_LOCK_HELD_SQL, COMPANY_SETTINGS_LOCK_KEY, COMPANY_SETTINGS_LOCK_SQL,
  acquireCompanySettingsLock,
} from './company-lock.js';
export { CONFIGURATION_AUDIT_OPERATIONS, writeConfigurationAudit } from './configuration-audit.js';
export type {
  AuditScalar, ConfigurationAuditContext, ConfigurationAuditDetails, ConfigurationAuditOperation,
} from './configuration-audit.js';
export { ConfigurationError } from './configuration-errors.js';
export type { ConfigurationErrorCode } from './configuration-errors.js';
export type { ConfigurationClient } from './configuration-port.js';
export {
  CONFIGURATION_TX_PROBE_SQL, CONFIGURATION_TX_SET_SQL, CONFIGURATION_TX_SETTING, assertCallerTransaction,
} from './configuration-tx.js';

export {
  COMPANY_SETTINGS_COLUMNS, COMPANY_SETTINGS_FIELDS, CONTENT_KINDS, DEFAULT_LIST_ROWS,
  MAX_LIST_ROWS, MINUTES_PER_DAY, REFERENCE_TYPES, REFERENCE_TYPE_SCOPE, RESERVED_CONTENT_CODES,
} from './configuration-input.js';
export type {
  CallbackInterval, CompanySettings, CompanySettingsField, CompanySettingsPublishInput, ContentArchiveInput,
  ContentBlockCreateInput, ContentKind, ContentListInput, ContentResolutionInput, ContentRevisionInput,
  ContentScope, ContentSnapshotInput, ReferenceArchiveInput, ReferenceEntryCreateInput, ReferenceListInput,
  ReferenceResolutionInput, ReferenceScope, ReferenceSnapshotInput, ReferenceType, ReferenceVersionInput,
} from './configuration-input.js';

export {
  CONSENT_DOCUMENT_KIND, DEFAULT_REQUIRED_CONSENT_PURPOSES, KNOWN_CONSENT_PURPOSES, listCompanySettingsHistory,
  publishCompanySettings, readCompanySettings, readCompanySettingsReadiness, readCompanySettingsVersion,
  requireCompleteSettings,
} from './company-settings.js';
export type {
  CompanySettingsHistory, CompanySettingsPublishReceipt, CompanySettingsReadiness, CompanySettingsView,
  ConsentDocumentStatus, StoredCompanySettings,
} from './company-settings.js';

export {
  archiveReferenceEntry, createReferenceEntry, listReferenceEntries, publishReferenceVersion,
  readReferenceSnapshot, resolveReferenceForUse,
} from './references.js';
export type {
  ReferenceEntryReceipt, ReferenceEntryView, ReferenceList, ReferenceResolution, ReferenceSnapshot,
  ReferenceVersionReceipt, ReferenceVersionView,
} from './references.js';

export {
  archiveContentBlock, createContentBlock, listContentBlocks, publishContentRevision, readContentSnapshot,
  resolveEffectiveContent,
} from './content.js';
export type {
  ContentBlockReceipt, ContentBlockView, ContentList, ContentProvenance, ContentRevisionReceipt,
  ContentRevisionView, ContentSnapshot, EffectiveContent,
} from './content.js';
