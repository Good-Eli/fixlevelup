'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { DashboardError, readSnapshot } from '../dashboard/client';
import { readyMetrics } from '../dashboard/metrics';
import type { SnapshotQuery } from '../dashboard/metrics';
import RequestTable from './table';

type Page = Awaited<ReturnType<typeof readSnapshot>>;
type View = { page: Page } | { error: string } | null;

function SnapshotRows({ query }: { query: SnapshotQuery }) {
  const [view, setView] = useState<View>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const request = new AbortController();
    void readSnapshot(query, request.signal).then(page => {
      if (!request.signal.aborted) { setView({ page }); }
    }).catch((error: unknown) => {
      if (!request.signal.aborted) {
        setView({ error: error instanceof DashboardError ? error.message : 'Не удалось загрузить данные дашборда.' });
      }
    });
    return () => { request.abort(); };
  }, [query, attempt]);

  const page = view && 'page' in view ? view.page : null;
  const link = page?.snapshot.metrics[query.metric].href;
  return <section aria-labelledby="snapshot-metric" aria-busy={view === null}>
    <h2 id="snapshot-metric">{readyMetrics[query.metric].label}</h2>
    {view === null && <p role="status">Загрузка заявок…</p>}
    {view && 'error' in view && <div><p role="alert">{view.error}</p>
      <button type="button" onClick={() => { setView(null); setAttempt(value => value + 1); }}>Повторить загрузку</button>
    </div>}
    {page && link && <>
      {page.refreshed && <p role="status" className="notice">Снимок обновлён. Показана первая страница актуального списка.</p>}
      <p>Данные на <time dateTime={page.snapshot.asOf}>{page.snapshot.localAsOf}</time> ({page.snapshot.timezone})</p>
      <p>Заявок в снимке: {page.snapshot.metrics[query.metric].count}.</p>
      {page.items.length === 0 && <p role="status">На этой странице заявок нет.</p>}
      {page.items.length > 0 && <RequestTable items={page.items}/>}
      {(page.nextOffset !== null || page.offset > 0) && <nav aria-label="Страницы снимка">
        {page.offset > 0 && <Link href={link} prefetch={false}>Первая страница</Link>}
        {page.nextOffset !== null && <Link href={`${link}&offset=${String(page.nextOffset)}`} prefetch={false}>Следующая страница</Link>}
      </nav>}
    </>}
  </section>;
}

export default function SnapshotRegistry({ query }: { query: SnapshotQuery | 'invalid' }) {
  return <main className="desk">
    <header><h1>Реестр заявок</h1></header>
    <nav aria-label="Навигация CRM">
      <Link href="/crm/dashboard" prefetch={false}>Дашборд CRM</Link>
      <Link href="/crm/requests" prefetch={false}>Весь реестр</Link>
    </nav>
    {query === 'invalid' ? <p role="alert">Ссылка на список заявок недействительна.</p>
      : <SnapshotRows key={`${query.snapshot}:${query.metric}:${String(query.offset)}`} query={query}/>}
  </main>;
}
