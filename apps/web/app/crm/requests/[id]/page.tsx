import type { Metadata } from 'next';
import RequestCard from './request-card';
import '../../access/style.css';
import '../style.css';

export const metadata: Metadata = { title: 'Карточка заявки · FixLevelUp' };

export default async function RequestPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <RequestCard key={id} id={id}/>;
}
