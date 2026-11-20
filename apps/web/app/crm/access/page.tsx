import type { Metadata } from 'next';
import Desk from './desk';
import './style.css';

export const metadata: Metadata = { title: 'Сотрудники и доступ · FixLevelUp' };
export default function AccessPage() { return <Desk/>; }
