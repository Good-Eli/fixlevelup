import type { Metadata } from 'next';
import { readSnapshotQuery } from '../dashboard/metrics';
import Registry from './registry';
import SnapshotRegistry from './snapshot';
import '../access/style.css';
import './style.css';

export const metadata: Metadata = { title: 'Реестр заявок · FixLevelUp' };

export default async function RequestsPage({ searchParams }: PageProps<'/crm/requests'>) {
  const query = readSnapshotQuery(await searchParams);
  return query === null ? <Registry/> : <SnapshotRegistry query={query}/>;
}
