/**
 * Content-block port against a real isolated PostgreSQL instance.
 *
 * Proves the explicit fallback rule (city first; company only with its own
 * permission), the provenance of an effective value, immutable revisions that
 * survive archive, the CAS on the block token, and that content never carries a
 * second copy of contacts/hours/timezone or overrides a company policy code.
 */
import { afterAll, beforeAll, expect, it } from 'vitest';
import {
  archiveContentBlock, createContentBlock, listContentBlocks, publishContentRevision, readContentSnapshot,
  resolveEffectiveContent,
} from '../src/settings/configuration/index.js';
import { ConfigurationError } from '../src/settings/configuration/configuration-errors.js';
import {
  configurationIntegration, createConfigurationFixture, createSyntheticCity, installFailingAuditTrigger,
  removeFailingAuditTrigger,
} from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';

const codeOf = async (promise: Promise<unknown>): Promise<string> => {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ConfigurationError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a typed refusal');
};

configurationIntegration('content blocks against isolated PostgreSQL', () => {
  let fixture: ConfigurationFixture;
  let city: SyntheticCity;
  let otherCity: SyntheticCity;

  beforeAll(async () => {
    fixture = await createConfigurationFixture();
    city = await createSyntheticCity(fixture);
    otherCity = await createSyntheticCity(fixture);
  }, 60_000);

  afterAll(async () => { await fixture.close(); }, 30_000);

  const createCompanyBlock = (code: string, allowCompanyFallback = false) =>
    fixture.inTransaction((client) => createContentBlock(client, fixture.reviewer, {
      code, kind: 'FAQ', scope: 'COMPANY', allowCompanyFallback,
    }));

  const createCityBlock = (target: SyntheticCity, code: string) =>
    fixture.inTransaction((client) => createContentBlock(client, fixture.reviewer, {
      code, kind: 'FAQ', scope: 'CITY', cityId: target.id,
    }));

  const publish = (blockId: string, expectedVersion: number, title: string, body = 'Reviewed synthetic body') =>
    fixture.inTransaction((client) => publishContentRevision(client, fixture.reviewer, {
      blockId, expectedVersion, title, body, sourceRef: 'review://synthetic/content/1',
    }));

  it('publishes immutable revisions and moves the current pointer with CAS', async () => {
    const block = await createCompanyBlock('company-faq');
    expect(block.version).toBe(1);

    const first = await publish(block.id, 1, 'Installation FAQ');
    expect(first).toMatchObject({ blockId: block.id, version: 1, blockVersion: 2 });

    // A stale token cannot append a second revision over an unseen state.
    expect(await codeOf(publish(block.id, 1, 'Stale title'))).toBe('STALE_VERSION');

    const second = await publish(block.id, 2, 'Installation FAQ v2');
    expect(second).toMatchObject({ version: 2, blockVersion: 3 });

    const current = await fixture.inTransaction((client) => readContentSnapshot(client, { blockId: block.id }));
    expect(current.revision).toMatchObject({ id: second.id, version: 2, title: 'Installation FAQ v2' });
    expect(current.block).toMatchObject({ code: 'company-faq', scope: 'COMPANY', cityId: null, version: 3 });

    // The first revision is unchanged and still readable by its version number.
    const historical = await fixture.inTransaction((client) => readContentSnapshot(client, {
      blockId: block.id, version: 1,
    }));
    expect(historical.revision).toMatchObject({ title: 'Installation FAQ', version: 1 });

    // No staff identity or contact value leaks through the projection.
    expect(JSON.stringify(current)).not.toContain(fixture.reviewer);

    // A duplicate company code is refused by the partial unique index.
    expect(await codeOf(createCompanyBlock('company-faq'))).toBe('CONFLICT');
  }, 60_000);

  it('resolves city content first and reports its provenance', async () => {
    const companyBlock = await createCompanyBlock('scope-faq', true);
    await publish(companyBlock.id, 1, 'Company FAQ');

    // With no city block, the company value is used because the company row allows it.
    const fallback = await fixture.inTransaction((client) => resolveEffectiveContent(client, {
      code: 'scope-faq', cityId: city.id,
    }));
    expect(fallback.title).toBe('Company FAQ');
    expect(fallback.provenance).toMatchObject({
      scope: 'COMPANY', cityId: null, blockId: companyBlock.id, fallback: true,
      sourceRef: 'review://synthetic/content/1',
    });

    // A city block with the same code wins.
    const cityBlock = await createCityBlock(city, 'scope-faq');
    const cityRevision = await publish(cityBlock.id, 1, 'City FAQ');
    const resolved = await fixture.inTransaction((client) => resolveEffectiveContent(client, {
      code: 'scope-faq', cityId: city.id,
    }));
    expect(resolved.title).toBe('City FAQ');
    expect(resolved.provenance).toMatchObject({
      scope: 'CITY', cityId: city.id, blockId: cityBlock.id, revisionId: cityRevision.id, fallback: false,
    });

    // Another city without its own block still falls back to the company value.
    const other = await fixture.inTransaction((client) => resolveEffectiveContent(client, {
      code: 'scope-faq', cityId: otherCity.id,
    }));
    expect(other.provenance).toMatchObject({ scope: 'COMPANY', fallback: true });
  }, 60_000);

  it('never falls back implicitly and never inherits an archived city block', async () => {
    // A company block that does not grant the fallback is not substituted.
    const strict = await createCompanyBlock('strict-faq', false);
    await publish(strict.id, 1, 'Company only');
    expect(await codeOf(fixture.inTransaction((client) => resolveEffectiveContent(client, {
      code: 'strict-faq', cityId: city.id,
    })))).toBe('NOT_FOUND');

    // An archived city block is a withdrawal: it is not used, and it does not block
    // the permitted company fallback either.
    const company = await createCompanyBlock('withdraw-faq', true);
    await publish(company.id, 1, 'Company withdraw FAQ');
    const cityBlock = await createCityBlock(city, 'withdraw-faq');
    await publish(cityBlock.id, 1, 'City withdraw FAQ');
    await fixture.inTransaction((client) => archiveContentBlock(client, fixture.reviewer, {
      blockId: cityBlock.id, expectedVersion: 2,
    }));
    const resolved = await fixture.inTransaction((client) => resolveEffectiveContent(client, {
      code: 'withdraw-faq', cityId: city.id,
    }));
    expect(resolved.provenance).toMatchObject({ scope: 'COMPANY', fallback: true });

    // An unknown code is not found; there is no default or empty content.
    expect(await codeOf(fixture.inTransaction((client) => resolveEffectiveContent(client, {
      code: 'missing-faq', cityId: city.id,
    })))).toBe('NOT_FOUND');
  }, 60_000);

  it('keeps the historical revision after archive and refuses new use', async () => {
    const block = await createCityBlock(city, 'archive-faq');
    const published = await publish(block.id, 1, 'Archive FAQ');
    const archived = await fixture.inTransaction((client) => archiveContentBlock(client, fixture.reviewer, {
      blockId: block.id, expectedVersion: 2,
    }));
    expect(archived.version).toBe(3);

    // The reviewed revision is unchanged and still readable.
    const historical = await fixture.inTransaction((client) => readContentSnapshot(client, {
      blockId: block.id, version: published.version,
    }));
    expect(historical.revision.title).toBe('Archive FAQ');
    expect(historical.block.archivedAt).not.toBeNull();

    // No new revision, no re-archive and no un-archive.
    expect(await codeOf(publish(block.id, 3, 'Archived publish'))).toBe('ARCHIVED');
    expect(await codeOf(fixture.inTransaction((client) => archiveContentBlock(client, fixture.reviewer, {
      blockId: block.id, expectedVersion: 3,
    })))).toBe('ARCHIVED');

    // The archived block is excluded from the default list but listed on request.
    const listed = await fixture.inTransaction((client) => listContentBlocks(client, { scope: 'CITY', cityId: city.id }));
    expect(listed.items.map((item) => item.id)).not.toContain(block.id);
    const withArchived = await fixture.inTransaction((client) => listContentBlocks(client, {
      scope: 'CITY', cityId: city.id, includeArchived: true,
    }));
    expect(withArchived.items.map((item) => item.id)).toContain(block.id);
  }, 60_000);

  it('refuses a policy/contact/timezone code and a cross-scope body shape', async () => {
    for (const code of ['public-contact', 'office-hours', 'timezone', 'retention-policy-ref']) {
      expect(await codeOf(createCompanyBlock(code))).toBe('RESERVED_CODE');
    }
    // A city row cannot self-authorize a fallback.
    expect(await codeOf(fixture.inTransaction((client) => createContentBlock(client, fixture.reviewer, {
      code: 'city-fallback', kind: 'FAQ', scope: 'CITY', cityId: city.id, allowCompanyFallback: true,
    })))).toBe('INVALID_INPUT');
    // A company row cannot carry a city.
    expect(await codeOf(fixture.inTransaction((client) => createContentBlock(client, fixture.reviewer, {
      code: 'company-city', kind: 'FAQ', scope: 'COMPANY', cityId: city.id,
    })))).toBe('INVALID_INPUT');
    // A block cannot be created for a city that does not exist.
    expect(await codeOf(fixture.inTransaction((client) => createContentBlock(client, fixture.reviewer, {
      code: 'ghost-city', kind: 'FAQ', scope: 'CITY', cityId: '44444444-4444-4444-8444-444444444444',
    })))).toBe('NOT_FOUND');
  }, 60_000);

  it('requires an explicit caller transaction and keeps revisions append-only', async () => {
    const client = await fixture.runtime.connect();
    try {
      expect(await codeOf(createContentBlock(client, fixture.reviewer, {
        code: 'autocommit-faq', kind: 'FAQ', scope: 'COMPANY',
      }))).toBe('TRANSACTION_REQUIRED');
      const revision = await fixture.migrator.query<{ id: string }>(
        'SELECT id FROM foundation.content_block_revisions LIMIT 1');
      const revisionId = revision.rows[0]?.id;
      expect(revisionId).toBeDefined();
      // A reviewed revision is immutable and a block is archived, never deleted.
      await expect(client.query('UPDATE foundation.content_block_revisions SET body=$2 WHERE id=$1',
        [revisionId, 'rewritten'])).rejects.toMatchObject({ code: '42501' });
      await expect(client.query('DELETE FROM foundation.content_blocks')).rejects.toMatchObject({ code: '42501' });
    } finally {
      client.release();
    }
  }, 30_000);

  it('rolls the publish back when the audit write fails', async () => {
    const block = await createCompanyBlock('rollback-faq');
    await installFailingAuditTrigger(fixture);
    try {
      await expect(publish(block.id, 1, 'Rolled back FAQ')).rejects.toBeDefined();
    } finally {
      await removeFailingAuditTrigger(fixture);
    }
    const revisions = await fixture.migrator.query(
      'SELECT 1 FROM foundation.content_block_revisions WHERE block_id=$1', [block.id]);
    expect(revisions.rows).toHaveLength(0);
    const blockRow = await fixture.migrator.query<{ row_version: number; current_revision_id: string | null }>(
      'SELECT row_version,current_revision_id FROM foundation.content_blocks WHERE id=$1', [block.id]);
    expect(blockRow.rows[0]).toEqual({ row_version: 1, current_revision_id: null });
    const outbox = await fixture.migrator.query(
      `SELECT 1 FROM foundation.outbox_events WHERE event_type='content.revision.publish' AND payload->>'blockId'=$1`,
      [block.id]);
    expect(outbox.rows).toHaveLength(0);
    // The block is still usable afterwards.
    expect((await publish(block.id, 1, 'Rolled back FAQ')).version).toBe(1);
  }, 60_000);
});
