import type { Metadata } from 'next';
import Dashboard from './dashboard';
import '../access/style.css';
import './style.css';

export const metadata: Metadata = { title: 'Дашборд CRM · FixLevelUp' };

export default function DashboardPage() {
  return <Dashboard/>;
}
