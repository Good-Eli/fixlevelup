import { useState, type SubmitEvent, type ReactNode } from 'react';
import { P03_DEFAULT_LIMIT, type P03Page } from '@fixlevelup/p03-contracts';
import { FormError, p03Read, query, type CommandSpec, type Decoder } from './p0305-client';

export type Read = <T>(load: (signal: AbortSignal) => Promise<T>, show: (value: T) => void) => void;
export type WriteCommand = (spec: CommandSpec, body: object) => void;
export type IO = { read: Read; write: WriteCommand };
export const path = (template: string, values: Record<string, string | number> = {}) => template.replace(/^\//, '').replace(/:(\w+)/g, (_, key: string) => {
  const value = values[key];
  if (value === undefined || !/^[a-z0-9_.-]+$/i.test(String(value))) { throw new Error('Invalid route parameter'); }
  return String(value);
});
export function detail<T>(read: Read, route: string, decoder: Decoder<T>, show: (value: T) => void, cap?: number) {
  read(signal => p03Read(signal, route, decoder, cap), show);
}
export function Pages<P extends P03Page<unknown>>({ read, route, decoder, render, loaded, title = 'Загрузить список' }: {
  read: Read; route: string; decoder: Decoder<P>; render: (item: P['items'][number]) => ReactNode; loaded?: (page: P, append: boolean) => void; title?: string;
}) {
  const [pages, setPages] = useState<P[]>([]);
  const cursor = pages.at(-1)?.pageInfo.nextCursor ?? null;
  function next(append: boolean) {
    const [pathname = '', raw] = route.split('?');
    const options = Object.fromEntries(new URLSearchParams(raw));
    read(async signal => {
      const result = await p03Read(signal, query(pathname, { ...options, limit: P03_DEFAULT_LIMIT, cursor: append ? cursor ?? undefined : undefined }), decoder);
      if (append && (result.pageInfo.nextCursor === cursor || ('version' in result && pages[0] && 'version' in pages[0] && result.version !== pages[0].version))) {
        throw new FormError('Список изменился. Загрузите его заново перед редактированием.');
      }
      return result;
    }, p => { setPages(append ? [...pages, p] : [p]); loaded?.(p, append); });
  }
  return <div className="p03-pages"><button onClick={() => { next(false); }}>{pages.length ? 'Обновить список' : title}</button>
    {pages.length > 0 && (pages.some(p => p.items.length) ? <ul>{pages.flatMap(p => p.items.map(render))}</ul> : <p>Нет доступных записей.</p>)}
    {cursor && <button onClick={() => { next(true); }}>Загрузить ещё</button>}</div>;
}
export function Form({ title, children, submit, action, prompt }: {
  title: string; children?: ReactNode; submit: string; action: (form: FormData) => void; prompt?: string;
}) {
  const [error, setError] = useState('');
  function onSubmit(e: SubmitEvent<HTMLFormElement>) {
    e.preventDefault(); setError('');
    try { if (!prompt || window.confirm(prompt)) { action(new FormData(e.currentTarget)); } }
    catch (e) { setError(e instanceof FormError ? e.message : 'Проверьте заполнение полей.'); }
  }
  return <form onSubmit={onSubmit}><fieldset className="p03-fields"><legend>{title}</legend>
    {error && <p role="alert" className="notice">{error}</p>}{children}<button>{submit}</button></fieldset></form>;
}
export function Text({ name, label, max, value, required = true, area = false, pattern }: {
  name: string; label: string; max: number; value?: string | undefined | null; required?: boolean; area?: boolean; pattern?: string;
}) {
  return <label>{label}{area ? <textarea aria-label={label} name={name} defaultValue={value ?? ''} maxLength={max} required={required} rows={5}/>
    : <input name={name} defaultValue={value ?? ''} maxLength={max} required={required} {...(pattern ? { pattern } : {})}/>}</label>;
}
export function Select({ name, label, values, value }: { name: string; label: string; values: readonly string[]; value?: string }) {
  return <label>{label}<select name={name} defaultValue={value ?? values[0]} required>{values.map(v => <option key={v}>{v}</option>)}</select></label>;
}
export function value(form: FormData, key: string, max = Infinity, trim = true) {
  const raw = form.get(key);
  if (typeof raw !== 'string' || !raw.trim() || raw.length > max) { throw new FormError('Заполните обязательные поля и соблюдайте ограничения длины.'); }
  return trim ? raw.trim() : raw;
}
export function optional(form: FormData, key: string) {
  const raw = form.get(key); return typeof raw === 'string' ? raw.trim() || null : null;
}
export function choice<const T extends string>(form: FormData, key: string, accepted: readonly T[]): T {
  const selected = accepted.find(v => v === form.get(key));
  if (!selected) { throw new FormError('Выберите доступное значение.'); }
  return selected;
}
export function integer(form: FormData, key: string, min: number, max: number) {
  const raw = value(form, key); const n = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(n) || n < min || n > max) { throw new FormError('Проверьте числовое значение и указанные границы.'); }
  return n;
}
export function instant(form: FormData, key: string, required: true): string;
export function instant(form: FormData, key: string, required?: false): string | null;
export function instant(form: FormData, key: string, required = false) {
  const raw = optional(form, key);
  if (!raw && !required) { return null; }
  const match = raw?.match(/^(\d{4})-(\d\d)-(\d\d)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(Z|[+-](?:0\d|1[0-4]):[0-5]\d)$/);
  const year = Number(match?.[1]); const month = Number(match?.[2]); const day = Number(match?.[3]);
  if (!raw || !match || year < 1000 || month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate() || !Number.isFinite(Date.parse(raw)) || /^[+-]14:(?!00)/.test(match[4] ?? '')) {
    throw new FormError('Укажите действительные дату и время ISO 8601 с зоной: ГГГГ-ММ-ДДTчч:мм:ссZ или +чч:мм.');
  }
  return raw;
}
export function Confirm({ children, prompt, action, disabled }: { children: ReactNode; prompt: string; action: () => void; disabled?: boolean }) {
  return <button className="danger" disabled={disabled} onClick={() => { if (window.confirm(prompt)) { action(); } }}>{children}</button>;
}
export function Plain({ children }: { children: string }) { return <pre className="p03-plain">{children}</pre>; }
