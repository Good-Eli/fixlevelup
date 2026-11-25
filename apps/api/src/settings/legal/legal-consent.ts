/**
 * Append-only consent evidence: GIVEN and REVOKED, purpose by purpose.
 *
 * ## What this port refuses to do
 *
 * - It never treats a browser UUID as authority. Every operation proves the
 *   pre-submit anchor first (raw token against the stored digest, or a branded
 *   trusted-server proof), and the anchor must be live on the database clock.
 * - It never coerces acceptance. `accepted` must be exactly `true`; `"true"`, `1`
 *   and every other truthy value are refused by the input parser before any SQL.
 * - It never accepts stale text silently. A GIVEN always names the document's
 *   *current* CONSENT_FORM revision; if the text changed, the caller must obtain a
 *   new acceptance of the new revision instead of reusing the old one. Only a
 *   POLICY or OPT_IN_NOTICE document is refused as "not a consent form".
 * - It never resurrects a revoked consent. A replay of an old GIVEN whose exact
 *   event was later superseded by a REVOKED event returns `CONSENT_REVOKED`; it
 *   does not recreate the acceptance.
 * - It never stores PII or a raw token. Evidence columns are ids, the purpose, the
 *   action, the immutable document's legal basis and a caller-supplied opaque
 *   `evidence_ref` (a UUID), plus database-clock `occurred_at`.
 *
 * ## Lock order
 *
 * Every write and every consumption takes the anchor row `FOR UPDATE` first and
 * the document row second, in that order and never the reverse. The document lock
 * is a single-table statement that locks exactly one `legal_documents` row; the
 * current revision and `legal_basis` are read in a *separate* statement issued
 * only after that lock, so a concurrent publish that committed during the lock
 * wait is observed instead of being hidden by a pre-wait snapshot. Migration 013's
 * `consent_records_guard` re-takes the same two locks in the same order, so the
 * ordering holds even for a caller that bypasses these ports.
 *
 * ## Idempotency
 *
 * `unique(session_id,evidence_ref)` makes one caller retry one event. A replay is
 * accepted only when the stored event has the same action/purpose/document/version
 * and the anchor is still live; it then re-checks the current document and the
 * revoke state. Anything else is a mismatch, not a second event. The unique index
 * is also the concurrency primitive: two simultaneous retries race on it, the
 * loser re-reads the winner's row and applies exactly the same replay checks.
 * P05-02 binds its mandatory `Idempotency-Key` to this `evidence_ref`, so the
 * protocol-level key and the legal evidence identity are the same value.
 */
import { randomUUID } from 'node:crypto';
import { LegalPortError } from './legal-contract.js';
import type {
  ConsentReceipt, CurrentConsent, CurrentConsentReason, LegalPurpose, LegalSqlClient, SessionProof,
} from './legal-contract.js';
import { CONSENT_FORM_KIND, CONSENT_SOURCE } from './legal-contract.js';
import { writeLegalAudit } from './legal-audit.js';
import { guard } from './legal-errors.js';
import { consentGivenInput, consentRevokeInput, currentConsentInput, purposeValue } from './legal-input.js';
import { assertAnchorLiveAfterLock, requireAnchorProof, requireLiveAnchor } from './legal-sessions.js';
import type { RequestSessionRow } from './legal-sessions.js';

interface ConsentRow {
  id: string;
  session_id: string;
  document_id: string;
  document_version_id: string;
  purpose: string;
  action: string;
  legal_basis: string;
  source: string;
  evidence_ref: string;
  occurred_at: Date;
  supersedes_id: string | null;
}

interface ConsentFormDocument {
  id: string;
  purpose: string;
  kind: string;
  row_version: number;
  current_version_id: string | null;
  legal_basis: string | null;
}

const CONSENT_COLUMNS = 'id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref,occurred_at,supersedes_id';

function receipt(row: ConsentRow, replayed: boolean): ConsentReceipt {
  return {
    evidenceId: row.id,
    sessionId: row.session_id,
    documentId: row.document_id,
    documentVersionId: row.document_version_id,
    purpose: row.purpose as LegalPurpose,
    action: row.action === 'REVOKED' ? 'REVOKED' : 'GIVEN',
    occurredAt: row.occurred_at.toISOString(),
    replayed,
  };
}

/**
 * Locks exactly one `legal_documents` row: step 2 of the mandated lock order.
 *
 * The statement is deliberately single-table and returns no revision data. A
 * joined projection (`current_version_id`, the version's `legal_basis`) inside the
 * locking statement would be evaluated from a snapshot taken *before* the lock
 * wait, so a concurrent publish that committed meanwhile could be missed and an
 * acceptance of superseded text recorded as current. `FOR UPDATE` on the unique
 * primary-key / `(purpose,kind)` predicate locks one row and nothing else.
 */
async function lockConsentDocument(
  client: LegalSqlClient, purpose: LegalPurpose, documentId: string | null,
): Promise<string> {
  const result = documentId === null
    ? await guard(() => client.query<{ id: string }>(
      `SELECT id FROM foundation.legal_documents
       WHERE purpose=$1 AND kind=$2
       FOR UPDATE`,
      [purposeValue(purpose), CONSENT_FORM_KIND],
    ))
    : await guard(() => client.query<{ id: string }>(
      `SELECT id FROM foundation.legal_documents
       WHERE id=$1 AND purpose=$2
       FOR UPDATE`,
      [documentId, purposeValue(purpose)],
    ));
  const row = result.rows[0];
  if (!row) {
    throw new LegalPortError('NOT_FOUND');
  }
  return row.id;
}

/**
 * Reads the *locked* document's current revision and legal basis.
 *
 * This must be a separate statement issued after `lockConsentDocument` in the
 * same transaction: only then is the pointer guaranteed not to move under a
 * concurrent publish, and only then does `legal_basis` describe the exact revision
 * the event is about to name. The kind and publication checks live here as well,
 * so an explicitly named POLICY is still a precise `KIND_NOT_CONSENT_FORM`
 * refusal instead of a silent lookup miss.
 */
async function readCurrentConsentForm(
  client: LegalSqlClient, documentId: string,
): Promise<{ documentId: string; currentVersionId: string; legalBasis: string }> {
  const result = await guard(() => client.query<ConsentFormDocument>(
    `SELECT d.id,d.purpose,d.kind,d.row_version,d.current_version_id,v.legal_basis
     FROM foundation.legal_documents d
     LEFT JOIN foundation.legal_document_versions v ON v.id=d.current_version_id AND v.document_id=d.id
     WHERE d.id=$1`,
    [documentId],
  ));
  const row = result.rows[0];
  if (!row) {
    throw new LegalPortError('NOT_FOUND');
  }
  if (row.kind !== CONSENT_FORM_KIND) {
    throw new LegalPortError('KIND_NOT_CONSENT_FORM');
  }
  if (row.current_version_id === null || row.legal_basis === null) {
    throw new LegalPortError('DOCUMENT_NOT_PUBLISHED');
  }
  return { documentId: row.id, currentVersionId: row.current_version_id, legalBasis: row.legal_basis };
}

/**
 * Locks the purpose's CONSENT_FORM document (step 2 of the lock order) and returns
 * the current immutable revision that a GIVEN must name: lock first, then read in
 * a separate statement. The kind predicate is part of the locking statement when
 * the caller does not name a document, so a purpose that has both a POLICY and a
 * CONSENT_FORM cannot resolve to whichever row the planner returned first.
 */
async function lockConsentForm(
  client: LegalSqlClient, purpose: LegalPurpose, documentId: string | null,
): Promise<{ documentId: string; currentVersionId: string; legalBasis: string }> {
  const lockedId = await lockConsentDocument(client, purpose, documentId);
  return await readCurrentConsentForm(client, lockedId);
}

/** A later REVOKED event that names this exact GIVEN event, if any. */
async function revokeOf(client: LegalSqlClient, givenId: string): Promise<ConsentRow | null> {
  const result = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records
     WHERE supersedes_id=$1 AND action='REVOKED' LIMIT 1`,
    [givenId],
  ));
  return result.rows[0] ?? null;
}

async function byEvidenceRef(
  client: LegalSqlClient, sessionId: string, evidenceRef: string,
): Promise<ConsentRow | null> {
  const result = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records
     WHERE session_id=$1 AND evidence_ref=$2`,
    [sessionId, evidenceRef],
  ));
  return result.rows[0] ?? null;
}

/**
 * Shared replay verification for a GIVEN event. Used when an event with the same
 * `(session_id,evidence_ref)` already exists.
 *
 * It re-validates everything the original acceptance depended on, because the
 * world may have moved: the document may have been republished (stale text), the
 * acceptance may have been revoked, or the anchor may have expired. The exact
 * revision named by *this* request is compared as well, so a replay cannot be
 * used to smuggle a different revision past the same evidence key.
 */
async function replayGiven(
  client: LegalSqlClient, anchor: RequestSessionRow, existing: ConsentRow,
  form: { documentId: string; currentVersionId: string }, purpose: LegalPurpose, requestedVersionId: string,
): Promise<ConsentReceipt> {
  if (existing.action !== 'GIVEN' || existing.purpose !== purpose || existing.document_id !== form.documentId) {
    throw new LegalPortError('REPLAY_MISMATCH');
  }
  // Same evidence key, different accepted revision: not the same event.
  if (existing.document_version_id !== requestedVersionId) {
    throw new LegalPortError('REPLAY_MISMATCH');
  }
  // A newer revision means the text this event accepted is no longer current.
  if (existing.document_version_id !== form.currentVersionId) {
    throw new LegalPortError('DOCUMENT_NOT_CURRENT');
  }
  // A replay must never report a withdrawn consent as granted.
  if ((await revokeOf(client, existing.id)) !== null) {
    throw new LegalPortError('CONSENT_REVOKED');
  }
  // Evidence reads can wait on relation locks even though the anchor is locked.
  await assertAnchorLiveAfterLock(client, anchor);
  return receipt(existing, true);
}

/**
 * Records one GIVEN event for the exact CONSENT_FORM revision the caller says was
 * accepted.
 *
 * The request names `documentVersionId`; it must be the document's current
 * revision. That comparison is what makes "stale text is refused, never silently
 * accepted" true: the port will not upgrade an acceptance of an older text to a
 * newer one by substituting the current pointer.
 *
 * Returns `replayed: true` for an idempotent retry of the exact same event.
 *
 * A second *active* GIVEN for the same session/purpose/document **and the same
 * version** is refused by the database guard as `CONSENT_ALREADY_ACTIVE`. That
 * duplicate scope is per version on purpose: after a text update a person can
 * accept the new current version without first withdrawing the older acceptance,
 * because the older GIVEN is history for a superseded text rather than an active
 * consent for the current one. Withdrawing an older acceptance stays possible at
 * any time through `recordConsentRevoked`.
 */
export async function recordConsentGiven(client: LegalSqlClient, input: unknown): Promise<ConsentReceipt> {
  const parsed = consentGivenInput(input);
  // Lock order: anchor first, then exactly one document row, then (separately)
  // the current revision and legal basis of that locked document.
  const anchor = await requireLiveAnchor(client, parsed.session);
  const form = await lockConsentForm(client, parsed.purpose, parsed.documentId);
  // The document lock may have waited past the anchor's expiry; re-check the
  // database clock now that both locks are held.
  await assertAnchorLiveAfterLock(client, anchor);

  const existing = await byEvidenceRef(client, anchor.id, parsed.evidenceRef);
  if (existing !== null) {
    return replayGiven(client, anchor, existing, form, parsed.purpose, parsed.documentVersionId);
  }
  // The accepted revision must be the current one. Checked before the insert so the
  // refusal is precise; the database guard re-checks it as the final authority.
  if (parsed.documentVersionId !== form.currentVersionId) {
    throw new LegalPortError('DOCUMENT_NOT_CURRENT');
  }
  // The evidence read above is a plain SELECT, but it can still wait on a
  // relation lock; the decision point is here, so the database clock is sampled
  // once more before the event is written.
  await assertAnchorLiveAfterLock(client, anchor);

  const inserted = await guard(() => client.query<ConsentRow>(
    `INSERT INTO foundation.consent_records
       (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref)
     VALUES ($1,$2,$3,$4,$5,'GIVEN',$6,$7,$8)
     RETURNING ${CONSENT_COLUMNS}`,
    [randomUUID(), anchor.id, form.documentId, form.currentVersionId, parsed.purpose, form.legalBasis,
      CONSENT_SOURCE, parsed.evidenceRef],
  ));
  const row = inserted.rows[0];
  if (!row) {
    throw new LegalPortError('CONFLICT');
  }
  await writeLegalAudit(client, 'CONSENT_GIVEN', {
    sessionId: anchor.id,
    documentId: form.documentId,
    versionId: form.currentVersionId,
    purpose: parsed.purpose,
    action: 'GIVEN',
    source: CONSENT_SOURCE,
    evidenceId: row.id,
  });
  return receipt(row, false);
}

/**
 * Records one REVOKED event that supersedes exactly one GIVEN event.
 *
 * The superseded GIVEN must belong to the same anchor, purpose, document and
 * document version. Revoking an *old accepted* revision after the text changed is
 * deliberately allowed (with a live anchor): withdrawing a consent must not
 * require consenting to new text first. The event affects only the named GIVEN;
 * other events of the same purpose stay as they are, and a later new GIVEN for the
 * same purpose is a new event that this revoke does not touch.
 */
export async function recordConsentRevoked(client: LegalSqlClient, input: unknown): Promise<ConsentReceipt> {
  const parsed = consentRevokeInput(input);
  const anchor = await requireLiveAnchor(client, parsed.session);
  // Early refusal on the clock sampled with the anchor lock. This is *not* the
  // authoritative check: a revoke also locks the document below, and that wait can
  // cross the expiry, so the live-anchor proof is repeated after that lock too.
  await assertAnchorLiveAfterLock(client, anchor);

  const existing = await byEvidenceRef(client, anchor.id, parsed.evidenceRef);
  if (existing !== null) {
    if (existing.action !== 'REVOKED' || existing.purpose !== parsed.purpose
      || existing.supersedes_id !== parsed.supersedesEvidenceId) {
      throw new LegalPortError('REPLAY_MISMATCH');
    }
    await assertAnchorLiveAfterLock(client, anchor);
    return receipt(existing, true);
  }

  const target = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records
     WHERE id=$1 AND session_id=$2 AND purpose=$3 AND action='GIVEN'`,
    [parsed.supersedesEvidenceId, anchor.id, parsed.purpose],
  ));
  const given = target.rows[0];
  if (!given) {
    // Wrong session/purpose, or the id is not a GIVEN event: the same refusal, so a
    // caller cannot probe another anchor's evidence.
    throw new LegalPortError('NOT_FOUND');
  }
  // Lock order: anchor already held; lock the document this GIVEN names. The
  // document's *current* revision is irrelevant here, which is what allows a
  // withdrawal of an accepted older revision after a text update.
  await guard(() => client.query(
    'SELECT id FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [given.document_id],
  ));
  // This document lock can wait arbitrarily long (a concurrent publish or another
  // consent of the same document holds it), so the anchor may have expired while we
  // were blocked. Re-check the database clock *after* both locks are held, exactly
  // as the GIVEN path does, so a REVOKED event is never written for an anchor that
  // was already dead at the moment of the write. A refusal here leaves the
  // transaction clean: no event, audit or outbox row has been inserted yet.
  await assertAnchorLiveAfterLock(client, anchor);
  if ((await revokeOf(client, given.id)) !== null) {
    throw new LegalPortError('CONSENT_REVOKED');
  }

  let row: ConsentRow;
  try {
    const inserted = await guard(() => client.query<ConsentRow>(
      `INSERT INTO foundation.consent_records
         (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref,supersedes_id)
       VALUES ($1,$2,$3,$4,$5,'REVOKED',$6,$7,$8,$9)
       RETURNING ${CONSENT_COLUMNS}`,
      [randomUUID(), anchor.id, given.document_id, given.document_version_id, given.purpose, given.legal_basis,
        CONSENT_SOURCE, parsed.evidenceRef, given.id],
    ));
    const insertedRow = inserted.rows[0];
    if (!insertedRow) {
      throw new LegalPortError('CONFLICT');
    }
    row = insertedRow;
  } catch (error) {
    // The anchor row is locked FOR UPDATE for the whole call, so a concurrent
    // duplicate of this exact request cannot be in flight: any 23505 here is the
    // one-revoke-per-GIVEN unique index, not a replay race.
    if (error instanceof LegalPortError && error.code === 'ALREADY_EXISTS') {
      throw new LegalPortError('CONSENT_REVOKED');
    }
    throw error;
  }
  await writeLegalAudit(client, 'CONSENT_REVOKED', {
    sessionId: anchor.id,
    documentId: given.document_id,
    versionId: given.document_version_id,
    purpose: given.purpose,
    action: 'REVOKED',
    source: CONSENT_SOURCE,
    evidenceId: row.id,
    supersedesId: given.id,
  });
  return receipt(row, false);
}

/**
 * Evaluates whether this anchor currently holds a valid consent for one purpose.
 *
 * A refusal is returned as a typed value (intake must render "expired", "revoked",
 * "text changed", ...), never as an exception. The checks are:
 *
 * 1. live anchor on the database clock (expiry and revocation);
 * 2. a published current CONSENT_FORM for exactly this purpose — a purpose that
 *    only has a POLICY/OPT_IN_NOTICE, or a document with no published revision, is
 *    `DOCUMENT_NOT_PUBLISHED`, not a "wrong proof" error;
 * 3. the GIVEN event of *that exact current version*. Selection is by version id,
 *    never by timestamp ordering: migration 013 allows at most one active GIVEN
 *    per (session, purpose, document, version), so the row for the current version
 *    is unique and the answer cannot depend on event order. A still-unrevoked GIVEN
 *    of an older text is history: it yields `DOCUMENT_NOT_CURRENT`.
 *
 * Purposes are independent: a granted REQUEST_PROCESSING says nothing about
 * MARKETING, and an absent optional purpose is simply `NOT_GIVEN`.
 */
export async function currentPurposeConsent(client: LegalSqlClient, input: unknown): Promise<CurrentConsent> {
  const parsed = currentConsentInput(input);
  let anchor;
  try {
    anchor = await requireLiveAnchor(client, parsed.session);
  } catch (error) {
    if (error instanceof LegalPortError && (error.code === 'SESSION_EXPIRED' || error.code === 'SESSION_REVOKED')) {
      return refusal(error.code === 'SESSION_EXPIRED' ? 'SESSION_EXPIRED' : 'SESSION_REVOKED');
    }
    throw error;
  }
  let form;
  try {
    form = await lockConsentForm(client, parsed.purpose, null);
    // The document lock can wait; a decision must reflect the clock at decision time.
    await assertAnchorLiveAfterLock(client, anchor);
  } catch (error) {
    if (error instanceof LegalPortError
      && (error.code === 'NOT_FOUND' || error.code === 'DOCUMENT_NOT_PUBLISHED' || error.code === 'KIND_NOT_CONSENT_FORM')) {
      return refusal('DOCUMENT_NOT_PUBLISHED');
    }
    if (error instanceof LegalPortError && error.code === 'SESSION_EXPIRED') {
      return refusal('SESSION_EXPIRED');
    }
    if (error instanceof LegalPortError && error.code === 'SESSION_REVOKED') {
      return refusal('SESSION_REVOKED');
    }
    throw error;
  }

  // The active GIVEN of the current version: a GIVEN that no REVOKED event has
  // superseded. A GIVEN → REVOKED → GIVEN sequence on the *same* version is legal
  // (the person withdrew and later accepted the same text again), so selecting the
  // newest row would report a withdrawn event as the answer. Filtering on the
  // absence of a revoke makes the answer independent of event order and time.
  const current = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records c
     WHERE c.session_id=$1 AND c.purpose=$2 AND c.document_id=$3
       AND c.document_version_id=$4 AND c.action='GIVEN'
       AND NOT EXISTS (SELECT 1 FROM foundation.consent_records r WHERE r.supersedes_id=c.id)`,
    [anchor.id, parsed.purpose, form.documentId, form.currentVersionId],
  ));
  const given = current.rows[0];
  if (given) {
    // The evidence SELECT may have waited past expiry after the document check.
    try {
      await assertAnchorLiveAfterLock(client, anchor);
    } catch (error) {
      if (error instanceof LegalPortError && (error.code === 'SESSION_EXPIRED' || error.code === 'SESSION_REVOKED')) {
        return refusal(error.code);
      }
      throw error;
    }
    return answer(form, given, 'GRANTED', true);
  }

  // No active GIVEN for the current text. Prefer the most specific refusal for the
  // *current* version (an explicit withdrawal of it) over "an older text was
  // accepted", so a v1 GIVEN followed by a v2 GIVEN+REVOKED reports REVOKED.
  const withdrawn = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records
     WHERE session_id=$1 AND purpose=$2 AND document_id=$3 AND action='GIVEN'
       AND document_version_id=$4
     ORDER BY occurred_at DESC, id DESC LIMIT 1`,
    [anchor.id, parsed.purpose, form.documentId, form.currentVersionId],
  ));
  const revokedGiven = withdrawn.rows[0];
  if (revokedGiven) {
    return answer(form, revokedGiven, 'REVOKED', false);
  }
  // An accepted older revision: the text changed and the current one was not accepted.
  const older = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records
     WHERE session_id=$1 AND purpose=$2 AND document_id=$3 AND action='GIVEN'
       AND document_version_id<>$4
     ORDER BY occurred_at DESC, id DESC LIMIT 1`,
    [anchor.id, parsed.purpose, form.documentId, form.currentVersionId],
  ));
  const previous = older.rows[0];
  if (previous) {
    return answer(form, previous, 'DOCUMENT_NOT_CURRENT', false);
  }
  return refusal('NOT_GIVEN');
}

function answer(
  form: { documentId: string }, event: ConsentRow, reason: CurrentConsentReason, granted: boolean,
): CurrentConsent {
  return {
    granted,
    reason,
    documentId: form.documentId,
    documentVersionId: event.document_version_id,
    evidenceId: event.id,
    occurredAt: event.occurred_at.toISOString(),
  };
}

function refusal(reason: CurrentConsentReason): CurrentConsent {
  return {
    granted: false, reason, documentId: null, documentVersionId: null, evidenceId: null, occurredAt: null,
  };
}

/**
 * Bounded read of the anchor's own evidence, for a caller that must display or
 * export exactly what this session accepted. No PII, no raw token, no legal text.
 *
 * Ownership is proved by the raw token, but the anchor is *not* required to be
 * live: reading what was accepted after the intake window closed (or after a
 * withdrawal) is legitimate, while every write still refuses a dead anchor.
 */
export async function listSessionConsent(client: LegalSqlClient, proof: SessionProof): Promise<readonly ConsentReceipt[]> {
  const anchor = await requireAnchorProof(client, proof);
  const result = await guard(() => client.query<ConsentRow>(
    `SELECT ${CONSENT_COLUMNS} FROM foundation.consent_records
     WHERE session_id=$1 ORDER BY occurred_at, id LIMIT 200`,
    [anchor.id],
  ));
  return result.rows.map((row) => receipt(row, false));
}
