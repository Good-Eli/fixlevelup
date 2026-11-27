import { readFile } from 'node:fs/promises';
import type { ContactSearchIndex } from '../src/requests/search/index.js';
import type { RbacFixture } from './rbac-fixture.js';

function assertSyntheticSearch(lab: RbacFixture) {
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || process.env['FIXLEVELUP_P06_SEARCH_PROOF'] !== '1'
    || !/^fixlevelup_configuration_test_[0-9a-f]{24}$/.test(lab.database)) {
    throw new Error('P06 search fixture requires its isolated database');
  }
}

export async function installSearchFixture(lab: RbacFixture) {
  assertSyntheticSearch(lab);
  await lab.db.query(await readFile(new URL('../../../infra/p06-lab/search-v1.sql',import.meta.url),'utf8'));
}

export async function rebuildSearchFixture(lab: RbacFixture, index: ContactSearchIndex,
  config: Parameters<ContactSearchIndex['rebuild']>[1], issuer: Parameters<ContactSearchIndex['rebuild']>[2]) {
  assertSyntheticSearch(lab);
  const client = await lab.db.connect();
  try {
    await client.query('BEGIN');
    await index.rebuild(client,config,issuer);
    await client.query('COMMIT');
  } finally {
    try { await client.query('ROLLBACK'); } finally { client.release(); }
  }
}
