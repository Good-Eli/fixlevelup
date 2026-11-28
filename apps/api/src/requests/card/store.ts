import type { PoolClient } from 'pg';
import type { P05ChannelProvider, P05CoverageOutcome, P05Urgency } from '@fixlevelup/p03-contracts/p05';
import { REGISTRY } from '../workflow/registry.js';
import type { DispatchBranch } from '../workflow/registry.js';
import type { RequestRow } from '../intake/store.js';
import { deny } from '../intake/errors.js';

const unavailable = Object.freeze({ appointments:'not_ready', quotes:'not_ready', reports:'not_ready', payments:'not_ready', messages:'not_ready',
  attachments:'not_ready', comments:'not_ready', contactDetails:'not_ready' } as const);

export async function readCard(client: PoolClient, row: RequestRow) {
  const { rows: [facts] } = await client.query<{
    createdAt: string; branch: DispatchBranch | null; provider: P05ChannelProvider | null;
    source: string | null; category: string | null; district: string | null;
    urgency: P05Urgency | null; coverage: P05CoverageOutcome | null;
  }>(`
    SELECT to_char(q.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt",
      preference.contact_mode AS branch, choice.provider, preference.urgency,
      source.label AS source, category.title AS category, district.name AS district, assessment.outcome AS coverage
    FROM foundation.requests q
    LEFT JOIN foundation.request_preference_revisions preference
      ON preference.request_id=q.id AND preference.id=q.current_preference_revision_id
    LEFT JOIN foundation.request_channel_choices choice ON choice.request_id=q.id
    LEFT JOIN foundation.request_intake_provenance provenance ON provenance.request_id=q.id
    LEFT JOIN foundation.reference_entry_versions source
      ON source.entry_id=provenance.source_entry_id AND source.id=provenance.source_version_id
    LEFT JOIN foundation.request_appliance_revisions appliance
      ON appliance.request_id=q.id AND appliance.id=q.current_appliance_revision_id
    LEFT JOIN foundation.catalog_directory_versions category
      ON category.entry_id=appliance.category_id AND category.id=appliance.category_version_id
    LEFT JOIN foundation.request_address_revisions address
      ON address.request_id=q.id AND address.id=q.current_address_revision_id
    LEFT JOIN foundation.administrative_districts district
      ON district.id=address.district_id AND district.city_id=q.city_id
    LEFT JOIN foundation.request_coverage_assessments assessment
      ON assessment.request_id=q.id AND assessment.id=q.current_assessment_id
    WHERE q.id=$1 AND q.row_version=$2`, [row.id,row.row_version]);
  if (!facts) { return deny('NOT_READY'); }
  return {
    id:row.id, publicNumber:row.public_number, type:row.type, status:row.status, version:row.row_version,
    createdAt:facts.createdAt, branch:facts.branch, contactMode:facts.branch === 'MESSENGER' ? 'CHANNEL' as const : facts.branch,
    provider:facts.branch === 'MESSENGER' ? facts.provider : null,
    facts:{source:facts.source,category:facts.category,district:facts.district,urgency:facts.urgency,coverage:facts.coverage},
    unavailable,
  };
}

interface TimelineEvent {
  readonly version: number;
  readonly command: string;
  readonly actorKind: string;
  readonly createdAt: string;
}

const timelineCommands = new Set<string>(REGISTRY.filter(spec => spec.decision === 'EXECUTABLE').map(spec => spec.command));

/** Last 100 committed P05 events, newest first by immutable resulting version. */
export async function readTimeline(client: PoolClient, row: RequestRow) {
  const { rows } = await client.query<TimelineEvent>(`SELECT resulting_version AS version,command,actor_type AS "actorKind",
      to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"
    FROM foundation.request_events WHERE request_id=$1 AND resulting_version <= $2
    ORDER BY resulting_version DESC LIMIT 100`, [row.id,row.row_version]);
  if (rows.some(event => !timelineCommands.has(event.command) || (event.actorKind !== 'F' && event.actorKind !== 'STAFF'))) {
    return deny('NOT_READY');
  }
  return { items:rows };
}
