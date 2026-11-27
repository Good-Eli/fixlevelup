'use client';

import { useEffect, useState } from 'react';
import type { SubmitEvent } from 'react';
import Link from 'next/link';
import { P05_STATUSES } from '@fixlevelup/p03-contracts/p05';
import { readRegistry, readRegistryOptions, RegistryError } from './client';
import { date, requestTypes, statuses } from './format';
type Page = Awaited<ReturnType<typeof readRegistry>>;
type View = { page: Page } | { error: string } | null;
type Options = Awaited<ReturnType<typeof readRegistryOptions>>;
const directories = [
  { group: 'categories', name: 'categoryId', label: 'Тип техники' },
  { group: 'districts', name: 'districtId', label: 'Район' },
  { group: 'sources', name: 'sourceId', label: 'Источник' },
] as const;

export default function Registry() {
  const [filters, setFilters] = useState(new URLSearchParams());
  const [query, setQuery] = useState(filters);
  const [view, setView] = useState<View>(null);
  const [options, setOptions] = useState<Options | 'unavailable' | null>(null);
  const [optionsAttempt, setOptionsAttempt] = useState(0);

  useEffect(() => {
    const request = new AbortController();
    void readRegistryOptions(request.signal).then(result => {
      if (!request.signal.aborted) { setOptions(result); }
    }).catch(() => {
      if (!request.signal.aborted) { setOptions('unavailable'); }
    });
    return () => { request.abort(); };
  }, [optionsAttempt]);

  useEffect(() => {
    const request = new AbortController();
    void readRegistry(query, request.signal).then(page => {
      if (!request.signal.aborted) { setView({ page }); }
    }).catch((error: unknown) => {
      if (!request.signal.aborted) { setView({ error: error instanceof RegistryError ? error.message : 'Реестр временно недоступен.' }); }
    });
    return () => { request.abort(); };
  }, [query]);

  function open(params: URLSearchParams) {
    setView(null);
    setQuery(params);
  }

  function apply(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const params = new URLSearchParams();
    for (const [key, value] of new FormData(event.currentTarget)) {
      if (typeof value !== 'string' || !value) { continue; }
      params.set(key, key === 'from' || key === 'to' ? new Date(`${value}Z`).toISOString() : value);
    }
    setFilters(params);
    open(params);
  }

  const page = view && 'page' in view ? view.page : null;
  const nextCursor = page?.nextCursor;
  return <main className="desk">
    <header><h1>Реестр заявок</h1></header>
    <form className="panel" aria-label="Фильтры заявок" onSubmit={apply} onReset={() => {
      const empty = new URLSearchParams();
      setFilters(empty);
      open(empty);
    }}>
      <div className="actions">
        <label>Создана с (UTC)<input type="datetime-local" name="from"/></label>
        <label>Создана до (UTC)<input type="datetime-local" name="to"/></label>
      </div>
      <div className="actions">
        <label>Статус<select name="status"><option value="">Все</option>
          {P05_STATUSES.map(status => <option key={status} value={status}>{statuses[status]}</option>)}
        </select></label>
        <label>Срочность<select name="urgency"><option value="">Любая</option>
          <option value="FLEXIBLE">Гибкая</option><option value="WITHIN_DAY">В течение дня</option><option value="URGENT">Срочно</option>
        </select></label>
        <label>Способ связи<select name="contactMode"><option value="">Любой</option>
          <option value="PHONE">Телефон</option><option value="CHANNEL">Мессенджер</option>
        </select></label>
        <label>Мессенджер<select name="provider"><option value="">Любой</option>
          <option value="TG">Telegram</option><option value="VK">ВКонтакте</option><option value="MAX">MAX</option>
        </select></label>
      </div>
      <div className="actions">
        {directories.map(({ group, name, label }) => <label key={group}>{label}
          <select name={name} disabled={options === null || options === 'unavailable'}><option value="">Все</option>
            {options && options !== 'unavailable' && options[group].map(choice =>
              <option key={choice.id} value={choice.id}>{choice.name}</option>)}
          </select>
        </label>)}
      </div>
      {options === 'unavailable' && <div className="actions"><span>Справочники временно недоступны.</span>
        <button type="button" onClick={() => { setOptions(null); setOptionsAttempt(attempt => attempt + 1); }}>Повторить загрузку</button>
      </div>}
      {options && options !== 'unavailable' && <p>Фильтры по мастеру, оплате и проблемам пока недоступны.</p>}
      <div className="actions"><button type="submit">Применить</button><button type="reset">Сбросить</button></div>
    </form>
    <section aria-label="Заявки" aria-busy={view === null}>
      {view === null && <p role="status">Загрузка заявок…</p>}
      {view && 'error' in view && <div role="alert"><p>{view.error}</p>
        <button onClick={() => { open(new URLSearchParams(filters)); }}>Повторить с первой страницы</button></div>}
      {page?.items.length === 0 && <p role="status">Заявок по выбранным фильтрам нет.</p>}
      {page && page.items.length > 0 && <div className="registry-table"><table>
        <thead><tr><th scope="col">Номер</th><th scope="col">Создана (UTC)</th><th scope="col">Тип</th><th scope="col">Статус</th></tr></thead>
        <tbody>{page.items.map(row => <tr key={row.id}><td><Link href={`/crm/requests/${row.id}`}>{row.publicNumber}</Link></td>
          <td><time dateTime={row.createdAt}>{date.format(new Date(row.createdAt))}</time></td>
          <td>{requestTypes[row.type]}</td><td>{statuses[row.status]}</td></tr>)}</tbody>
      </table></div>}
      {nextCursor && <button onClick={() => {
        const next = new URLSearchParams(filters);
        next.set('cursor', nextCursor);
        open(next);
      }}>Следующая страница</button>}
      {query.has('cursor') && page && <button onClick={() => { open(new URLSearchParams(filters)); }}>Первая страница</button>}
    </section>
  </main>;
}
