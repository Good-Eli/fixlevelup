import type { Metadata } from 'next';
import { readSnapshotQuery } from '../dashboard/metrics';
import Registry from './registry';
import SnapshotRegistry from './snapshot';
import '../access/style.css';
import './style.css';

export const metadata: Metadata = { title: 'Реестр заявок · FixLevelUp' };

type SearchParams = Record<string, string | string[] | undefined>;

function normalizeSearchParams(value: unknown): SearchParams | 'invalid' {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) { return 'invalid'; }
  const normalized: SearchParams = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === 'string') {
      normalized[key] = raw;
    } else if (Array.isArray(raw)) {
      const strings = raw.filter((item): item is string => typeof item === 'string');
      if (strings.length !== raw.length) { return 'invalid'; }
      normalized[key] = strings;
    } else if (raw !== undefined) {
      return 'invalid';
    }
  }
  return normalized;
}

export default async function RequestsPage({ searchParams }: PageProps<'/crm/requests'>) {
  // Next's generated PageProps type is not consistently preserved by ESLint's
  // typed parser; normalize the awaited value from unknown before passing it
  // into the strict query decoder rather than relying on an unchecked cast.
  const resolved: unknown = await searchParams;
  const params = normalizeSearchParams(resolved);
  const query = params === 'invalid' ? 'invalid' : readSnapshotQuery(params);
  return query === null ? <Registry/> : <SnapshotRegistry query={query}/>;
}
