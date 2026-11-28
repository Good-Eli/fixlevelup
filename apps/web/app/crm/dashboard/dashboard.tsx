'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { DashboardError, readDashboard } from './client';
import { readyKeys, readyMetrics, unavailableMetrics } from './metrics';

type Data = Awaited<ReturnType<typeof readDashboard>>;
type View = { data: Data } | { error: string } | null;
const countFormat = new Intl.NumberFormat('ru');

export default function Dashboard() {
  const [view, setView] = useState<View>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const request = new AbortController();
    void readDashboard(request.signal).then(data => {
      if (!request.signal.aborted) { setView({ data }); }
    }).catch((error: unknown) => {
      if (!request.signal.aborted) {
        setView({ error: error instanceof DashboardError ? error.message : 'Не удалось загрузить данные дашборда.' });
      }
    });
    return () => { request.abort(); };
  }, [attempt]);

  const data = view && 'data' in view ? view.data : null;
  return <main className="desk crm-dashboard">
    <header><h1>Дашборд CRM</h1></header>
    <nav aria-label="Навигация CRM"><Link href="/crm/requests" prefetch={false}>Реестр заявок</Link></nav>
    {view === null && <p role="status">Загрузка дашборда…</p>}
    {view && 'error' in view && <div><p role="alert">{view.error}</p>
      <button type="button" onClick={() => { setView(null); setAttempt(value => value + 1); }}>Повторить загрузку</button>
    </div>}
    {data && <>
      <p className="crm-snapshot-meta">Данные на <time dateTime={data.asOf}>{data.localAsOf}</time> ({data.timezone})
        <span>Правила {data.definitionsVersion}</span>
      </p>
      <section aria-labelledby="dashboard-requests">
        <h2 id="dashboard-requests">Показатели по заявкам</h2>
        <ul className="crm-metric-grid">
          {readyKeys.map(key => <li key={key}>
            <Link className="crm-metric" href={data.metrics[key].href} prefetch={false}
              aria-labelledby={`metric-${key}`} aria-describedby={`count-${key}`}>
              <span id={`metric-${key}`}>{readyMetrics[key].label}</span>
              <strong id={`count-${key}`}>{countFormat.format(data.metrics[key].count)}</strong>
            </Link>
          </li>)}
        </ul>
      </section>
      <section aria-labelledby="dashboard-unavailable">
        <h2 id="dashboard-unavailable">Другие показатели</h2>
        <ul className="crm-metric-grid">
          {Object.entries(unavailableMetrics).map(([key, label]) => <li key={key} className="crm-metric crm-metric-unavailable">
            <span>{label}</span><small>Пока недоступно</small>
          </li>)}
        </ul>
      </section>
    </>}
  </main>;
}
