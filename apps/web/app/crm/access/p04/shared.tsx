import { createContext, useContext, useRef, useState, type ReactNode, type SubmitEvent } from 'react';
import { flushSync } from 'react-dom';
import { p04Scopes, type Access, type P04Capability, type P04Scope } from '../api';
import { FormError, jsonBytes } from '../p0305-client';

export function hasP04(access: Access, code: P04Capability, scope?: P04Scope | 'COMPANY'): boolean {
  const grants = access.p04Permissions?.filter(g => g.code === code) ?? [];
  const grant = grants[0];
  return grants.length === 1 && grant !== undefined && p04Scopes(access.role, code).includes(grant.scope)
    && (scope === undefined || grant.scope === (scope === 'COMPANY' ? 'GLOBAL' : scope));
}

export type Draft = Readonly<{ key: string; fields: readonly (readonly [string, string])[] }>;
export const P04DraftContext = createContext<{
  readonly retained: Draft | null;
  readonly stage: (draft: Draft | null) => void;
  readonly discard: () => void;
}>({ retained: null, stage: () => undefined, discard: () => undefined });

function snapshot(key: string, body: FormData): Draft {
  const fields: [string, string][] = [];
  for (const [name, entry] of body) {
    if (typeof entry !== 'string') { throw new FormError('Файлы не поддерживаются в этой форме.'); }
    fields.push([name, entry]);
  }
  if (jsonBytes(JSON.stringify(fields)) > 96 * 1024) { throw new FormError('Превышен допустимый размер формы.'); }
  return { key, fields };
}
function restoreFields(form: HTMLFormElement, data: FormData): ReadonlyMap<string, readonly FormDataEntryValue[]> {
  const updates: (() => void)[] = [];
  const represented = new Set<string>();
  const choices = new Map<string, readonly FormDataEntryValue[]>();
  for (const control of form.elements) {
    if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement)
      || !control.name || control.matches(':disabled')) { continue; }
    const values = data.getAll(control.name);
    if (control instanceof HTMLSelectElement) {
      const options = Array.from(control.options);
      const available = options.filter(option => !option.matches(':disabled'));
      if ((!control.multiple && values.length > 1) || values.some(value => !available.some(option => option.value === value))) {
        throw new FormError('Вариант из черновика недоступен. Загрузите исходные варианты или явно уберите черновик.');
      }
      const first = values[0];
      choices.set(control.name, values);
      updates.push(() => {
        if (control.multiple) {
          for (const option of options) { option.selected = available.includes(option) && values.includes(option.value); }
        } else { control.value = typeof first === 'string' ? first : ''; }
      });
    } else if (control instanceof HTMLInputElement && ['checkbox','radio'].includes(control.type)) {
      updates.push(() => { control.checked = values.includes(control.value); });
    } else if (!(control instanceof HTMLInputElement && ['hidden','file','password','submit'].includes(control.type))) {
      const field = values[0];
      if (typeof field === 'string') { updates.push(() => { control.value = field; }); }
    } else { continue; }
    represented.add(control.name);
  }
  if ([...data.keys()].some(name => !represented.has(name))) { throw new FormError('Поле черновика недоступно. Загрузите исходные варианты или явно уберите черновик.'); }
  // Validate the complete selection before applying any fields. In particular,
  // a lost category must not silently broaden a pricing rule to all categories.
  for (const update of updates) { update(); }
  return choices;
}

type P04FormProps = {
  title: string; draftKey: string; children?: ReactNode; submit: string; action: (form: FormData) => void;
  prompt?: string; restore?: (form: FormData) => void;
};
export function P04Form(props: P04FormProps) {
  // Parent controls can live outside the form. Drop mounted input values as
  // well as restoration affordances when any part of the target changes.
  return <DraftForm key={props.draftKey} {...props}/>;
}
function DraftForm({ title, draftKey, children, submit, action, prompt, restore }: P04FormProps) {
  const context = useContext(P04DraftContext);
  const form = useRef<HTMLFormElement>(null);
  const [error, setError] = useState('');
  const [restored, setRestored] = useState<ReadonlyMap<string, readonly FormDataEntryValue[]> | null>(null);
  const draft = context.retained?.key === draftKey ? context.retained : null;
  function onSubmit(e: SubmitEvent<HTMLFormElement>) {
    e.preventDefault(); setError('');
    try {
      if (draft) { throw new FormError('Сначала восстановите или явно уберите сохранённый черновик.'); }
      const data = new FormData(e.currentTarget);
      if (restored && [...restored].some(([name, values]) => {
        const live = data.getAll(name);
        return live.length !== values.length || values.some(value => !live.includes(value));
      })) { throw new FormError('Исходный набор вариантов изменился. Восстановите его или явно уберите черновик и заполните форму заново.'); }
      if (prompt && !window.confirm(prompt)) { return; }
      context.stage(snapshot(draftKey, data));
      try { action(data); } finally { context.stage(null); }
    } catch (e) { setError(e instanceof FormError ? e.message : 'Проверьте заполнение полей.'); }
  }
  function restoreDraft() {
    const element = form.current;
    if (!draft || !element) { return; }
    setError('');
    try {
      const data = new FormData();
      for (const [key, field] of draft.fields) { data.append(key, field); }
      if (restore) { flushSync(() => { restore(data); }); }
      if (form.current !== element) { throw new FormError('Форма изменилась. Загрузите исходные варианты заново.'); }
      setRestored(restoreFields(element, data));
      context.discard();
    } catch (e) { setError(e instanceof FormError ? e.message : 'Не удалось восстановить черновик.'); }
  }
  function discard() {
    if (!window.confirm('Убрать черновик и заново заполнить форму? Ничего не будет отправлено.')) { return; }
    form.current?.reset();
    context.discard(); setRestored(null); setError('');
  }
  return <form ref={form} onSubmit={onSubmit}>
    <fieldset className="p03-fields"><legend>{title}</legend>
      {error && <p role="alert" className="notice">{error}</p>}
      {(draft || restored) && <div className="actions">{draft && <button type="button" onClick={restoreDraft}>Восстановить черновик</button>}
        <button type="button" onClick={discard}>Убрать черновик</button></div>}
      {restored && <p role="status">Сверьте черновик с актуальной версией. Исходный набор вариантов сохранён; отправки не было.</p>}
      {children}<button disabled={draft !== null}>{submit}</button>
    </fieldset>
  </form>;
}

type Page = { readonly items: readonly { readonly id: string }[];
  readonly pageInfo: { readonly nextCursor: string | null }; readonly version?: number };
export function P04Pages<P extends Page>({ title, load, loaded, render }: {
  title: string; load: (cursor: string | null, done: (page: P) => void) => void;
  loaded?: (page: P, append: boolean) => void; render?: (row: P['items'][number]) => ReactNode;
}) {
  const [pages, setPages] = useState<readonly P[]>([]);
  const [error, setError] = useState('');
  const cursor = pages.at(-1)?.pageInfo.nextCursor ?? null;
  function next(append: boolean) {
    setError('');
    if (!append) { setPages([]); }
    load(append ? cursor : null, page => {
      const prior = append ? pages : [];
      const seen = new Set(prior.flatMap(p => p.items.map(row => row.id)));
      const nextCursor = page.pageInfo.nextCursor;
      if ((append && page.version !== prior[0]?.version)
        || (nextCursor !== null && prior.some(p => p.pageInfo.nextCursor === nextCursor))
        || page.items.some(row => seen.has(row.id))) {
        setPages([]); setError('Список изменился. Загрузите его с начала перед редактированием.'); return;
      }
      setPages([...prior, page]); loaded?.(page, append);
    });
  }
  const listing = render ? pages.flatMap(p => p.items.map(render)).filter(node => node !== null && node !== undefined) : [];
  return <div className="p03-pages">
    <button type="button" onClick={() => { next(false); }}>{pages.length ? 'Обновить: ' + title : title}</button>
    {error && <p role="alert">{error}</p>}
    {pages.length > 0 && !pages.some(p => p.items.length) && <p>Нет доступных записей.</p>}
    {listing.length > 0 && <ul>{listing}</ul>}
    {cursor !== null && <button type="button" aria-label={`Загрузить ещё: ${title}`} onClick={() => { next(true); }}>Загрузить ещё</button>}
  </div>;
}
