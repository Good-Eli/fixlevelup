import type { Metadata } from 'next';
import Registry from './registry';
import '../access/style.css';
import './style.css';

export const metadata: Metadata = { title: 'Реестр заявок · FixLevelUp' };

export default function RequestsPage() {
  return <Registry/>;
}
