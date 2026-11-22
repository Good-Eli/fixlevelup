import { useRef, useState, type ReactNode } from 'react';
import { type P04Data } from '@fixlevelup/p03-contracts/p04';
import { uuidPattern, type Access } from '../api';
import { Confirm, Form, Text, value } from '../management-ui';
import { FormError } from '../p0305-client';
import { type P04IO } from './client';
import { CloseForm, EstimateCreateForm, EstimateForm, FixedForm, PolicyForm, RuleForm } from './city-forms';
import { body, closeAt, isClosable, ITEM_KINDS, periodStatus, sameRevision, type TemporalRevision } from './city-wires';
import { hasP04, P04Pages } from './shared';

type Page<T> = { readonly items: readonly T[]; readonly pageInfo: { readonly nextCursor: string | null } };
type City = P04Data<'cityList'>['items'][number];
type Scope = { io: P04IO; cityId: string; manage: boolean };
type Load<P> = (cursor: string | null, done: (data: P) => void) => void;
const pageQuery = (cursor: string | null) => ({ limit: '20', ...(cursor ? { cursor } : {}) });
const historyQuery = (cursor: string | null) => ({ ...pageQuery(cursor), includeArchived: 'true' as const });
const itemLabel: Record<(typeof ITEM_KINDS)[number], string> = {
  WORK: 'Работы', PART: 'Запчасти', MATERIAL: 'Материалы', TRAVEL: 'Выезды', DIAGNOSTICS: 'Диагностика',
};
const now = () => new Date().toISOString();
const none = (content: string | null) => content ?? 'Не задано';

function Picker<T extends { readonly id: string }>({ title, label, items, selected, set, text }: {
  title: string; label: string; items: readonly T[]; selected: T | undefined; set: (entry: T | undefined) => void; text: (entry: T) => string;
}) {
  return <label>{label}<select aria-label={label} value={selected?.id ?? ''} disabled={!items.length} onChange={e => {
    const id = e.currentTarget.value;
    set(items.find(entry => entry.id === id));
  }}><option value="">{title}</option>{items.map(entry => <option key={entry.id} value={entry.id}>{text(entry)}</option>)}</select></label>;
}

function useLabels<T extends { readonly id: string }>(source: Load<Page<T>>) {
  const [items, setItems] = useState<readonly T[]>([]);
  const [selected, setSelected] = useState<T>();
  const [current, setCurrent] = useState(false);
  return { items, selected, setSelected, current, load: (cursor: string | null, done: (p: Page<T>) => void) => {
    setCurrent(false); setSelected(undefined);
    if (cursor === null) { setItems([]); }
    source(cursor, done);
  }, loaded: (page: Page<T>, append: boolean) => {
    setItems(old => append ? [...old, ...page.items] : page.items);
    setCurrent(true);
  } };
}

function CategoryPages({ io, cityId, children }: Pick<Scope, 'io' | 'cityId'> & {
  children: (items: readonly P04Data<'cityCategories'>['items'][number][], current: boolean) => ReactNode;
}) {
  const categories = useLabels<P04Data<'cityCategories'>['items'][number]>((cursor, done) => { io.read('cityCategories', { params: { cityId }, query: pageQuery(cursor) }, done); });
  return <><P04Pages title="Загрузить категории города" load={categories.load} loaded={categories.loaded} render={() => null}/>
    {children(categories.items, categories.current)}</>;
}
function RulePages({ io, cityId, children }: Pick<Scope, 'io' | 'cityId'> & {
  children: (items: readonly P04Data<'cityRules'>['items'][number][], current: boolean) => ReactNode;
}) {
  const rules = useLabels<P04Data<'cityRules'>['items'][number]>((cursor, done) => { io.read('cityRules', { params: { cityId }, query: pageQuery(cursor) }, done); });
  return <><P04Pages title="Загрузить правила города" load={rules.load} loaded={rules.loaded} render={() => null}/>
    {children(rules.items, rules.current)}</>;
}

interface StreamActions<D> {
  readonly expectedVersion: number;
  readonly receiptSeriesId: string | null;
  readonly closable: D | undefined;
  readonly effect: (action: () => void, versionId?: string) => void;
}
function Period({ row }: { row: TemporalRevision }) {
  return <dl>
    <dt>Состояние периода</dt><dd>{periodStatus(row, now())}</dd>
    <dt>Начало действия (UTC)</dt><dd>{row.validFrom}</dd>
    <dt>Запланированный конец (UTC)</dt><dd>{none(row.validUntil)}</dd>
    <dt>Фактический конец (UTC)</dt><dd>{none(row.effectiveUntil)}</dd>
    <dt>Опубликована (UTC)</dt><dd>{row.publishedAt}</dd>
    <dt>Версия города</dt><dd>{row.cityVersionId}</dd>
  </dl>;
}
function Stream<S extends TemporalRevision, D extends S>({ cityId, knownSeriesId, load, get, summary, detail, actions }: {
  cityId: string; knownSeriesId?: string; load: Load<Page<S> & { readonly version: number }>; get: (id: string, done: (value: D) => void) => void;
  summary: (row: S) => string; detail: (row: D) => ReactNode; actions: (state: StreamActions<D>) => ReactNode;
}) {
  const [rows, setRows] = useState<readonly S[]>([]);
  const [chosen, choose] = useState<S>();
  const [exact, setExact] = useState<D>();
  const [version, setVersion] = useState<number>();
  const [error, setError] = useState('');
  const request = useRef(0);
  const aggregate = useRef<{ expected: number; serial: number } | null>(null);
  const verified = useRef<D | null>(null);
  const series = useRef<{ expected: number; rows: readonly S[] } | null>(null);
  function clear() {
    request.current++;
    aggregate.current = null;
    verified.current = null;
    setVersion(undefined); choose(undefined); setExact(undefined); setError('');
  }
  function readExact(row: S) {
    verified.current = null;
    setExact(undefined); setError('');
    const previous = aggregate.current;
    const serial = ++request.current;
    if (previous !== null) { aggregate.current = { expected: previous.expected, serial }; }
    get(row.id, result => {
      if (request.current !== serial) { return; }
      if (result.cityId !== cityId || !sameRevision(row, result) || summary(row) !== summary(result)) {
        clear(); setError('Точная версия изменилась. Загрузите историю заново.'); return;
      }
      verified.current = result;
      setExact(result);
    });
  }
  function readPage(cursor: string | null, done: (data: Page<S> & { readonly version: number }) => void) {
    clear();
    if (cursor === null) { setRows([]); series.current = null; }
    const serial = request.current;
    load(cursor, data => { if (request.current === serial) { done(data); } });
  }
  return <>
    <P04Pages title="Загрузить историю версий" load={readPage} loaded={(data, append) => {
      const prev = append ? series.current : null;
      const all = [...prev?.rows ?? [], ...data.items];
      const seriesIds = new Set(all.map(row => row.seriesId));
      const duplicateVersion = new Set(all.map(row => row.version)).size !== all.length;
      if ((append && (prev === null || prev.expected !== data.version)) || seriesIds.size > 1 || duplicateVersion
          || (knownSeriesId !== undefined && all.some(row => row.seriesId !== knownSeriesId))
          || (knownSeriesId === undefined && (data.version === 0) !== (all.length === 0))
          || all.some(row => row.cityId !== cityId || row.version > data.version)) {
        clear(); series.current = null; setRows([]); setError('История изменилась. Загрузите первый лист заново.'); return;
      }
      series.current = { expected: data.version, rows: all };
      aggregate.current = { expected: data.version, serial: request.current };
      setRows(all); setVersion(data.version);
    }} render={() => null}/>
    {error && <p role="alert">{error}</p>}
    {version !== undefined && <p>Версия набора: {version}. {!rows.length && 'Опубликованных версий нет.'}</p>}
    <Picker title="Выберите точную версию" label="Версия" items={version === undefined ? [] : rows} selected={chosen} text={row => `v${String(row.version)} · ${summary(row)} · ${row.validFrom} · ${periodStatus(row, now())}`}
      set={row => {
        choose(row); verified.current = null; setExact(undefined); setError('');
        if (row === undefined) {
          const serial = ++request.current;
          if (aggregate.current !== null) { aggregate.current = { expected: aggregate.current.expected, serial }; }
          return;
        }
        readExact(row);
      }}/>
    {chosen && !exact && <button onClick={() => { readExact(chosen); }}>Загрузить точную версию</button>}
    {exact && <div><h5>Точная версия v{exact.version}</h5><Period row={exact}/>{detail(exact)}</div>}
    {version !== undefined && actions({ expectedVersion: version, receiptSeriesId: knownSeriesId ?? rows[0]?.seriesId ?? null,
      closable: exact && isClosable(exact, now()) ? exact : undefined,
      effect: (send, versionId) => {
        if (aggregate.current?.expected !== version || aggregate.current.serial !== request.current
            || (versionId !== undefined && (verified.current?.id !== versionId || verified.current.seriesId !== (knownSeriesId ?? rows[0]?.seriesId)))) {
          throw new FormError('Загрузите текущую историю перед изменением.');
        }
        send(); clear();
      },
    })}
  </>;
}

function HistoricalSubject({ label, children }: { label: string; children: (id: string) => ReactNode }) {
  const [id, setId] = useState<string>();
  return <details><summary>История по известному идентификатору (только чтение)</summary>
    <p>История проверяется сервером только для выбранного города. Этот поиск не открывает формы изменения.</p>
    <Form title="Исторический идентификатор" submit="Выбрать для просмотра" action={form => {
      const raw = value(form, 'historicalId', 36, false);
      if (!new RegExp(`^${uuidPattern}$`).test(raw)) { throw new FormError('Укажите известный UUID.'); }
      setId(raw.toLowerCase());
    }}><Text name="historicalId" label={label} max={36} pattern={uuidPattern}/></Form>
    {id && <div key={id}>{children(id)}</div>}
  </details>;
}

function Fixed({ io, cityId, manage }: Scope) {
  const items = useLabels<P04Data<'cityItems'>['items'][number]>((cursor, done) => { io.read('cityItems', { params: { cityId }, query: pageQuery(cursor) }, done); });
  const [kind, setKind] = useState<(typeof ITEM_KINDS)[number] | ''>('');
  return <>
    <P04Pages title="Загрузить позиции города" load={items.load} loaded={items.loaded} render={() => null}/>
    <label>Вид позиции<select aria-label="Вид позиции" value={kind} onChange={e => {
      const next = e.currentTarget.value;
      setKind(ITEM_KINDS.find(entry => entry === next) ?? ''); items.setSelected(undefined);
    }}><option value="">Все виды</option>{ITEM_KINDS.map(kind => <option key={kind} value={kind}>{itemLabel[kind]} ({kind})</option>)}</select></label>
    <Picker label="Позиция" title="Выберите позицию" items={items.current ? items.items.filter(row => !kind || row.kind === kind) : []}
      selected={items.current ? items.selected : undefined} set={items.setSelected} text={row => `${row.title} · ${row.code} · ${row.kind}`}/>
    {items.current && items.selected && <FixedStream key={items.selected.id} {...{ io, cityId, manage }} itemId={items.selected.id}/>}
    {(!items.current || !items.selected) && <HistoricalSubject label="UUID позиции">{id => <FixedStream {...{ io, cityId }} manage={false} itemId={id}/>}</HistoricalSubject>}
  </>;
}
function FixedStream({ io, cityId, manage, itemId }: Scope & { itemId: string }) {
  const params = { cityId, itemId };
  const key = `${cityId}:${itemId}`;
  return <Stream<P04Data<'fixedList'>['items'][number], P04Data<'fixedGet'>> cityId={cityId} load={(cursor, done) => { io.read('fixedList', { params, query: historyQuery(cursor) }, done); }}
    get={(versionId, done) => { io.read('fixedGet', { params: { ...params, versionId } }, done); }}
    summary={row => `${row.amountMinor} ${row.currency}`}
    detail={row => <p>{row.amountMinor} {row.currency} · Обоснование нуля: {none(row.zeroBasis)} · Источник: {row.sourceRef}</p>}
    actions={({ expectedVersion, receiptSeriesId, closable, effect }) => manage && <>
      <FixedForm draftKey={`fixedPublish:${key}`} action={({ at, ...dates }, prices) => {
        const payload = body('fixedPublish', { ...dates, ...prices, validFrom: at });
        effect(() => { io.write('fixedPublish', { params, expectedVersion, receiptSeriesId, body: payload }); });
      }}/>
      {closable && <div key={closable.id}>
        <CloseForm noun="цену" draftKey={`fixedClose:${key}:${closable.id}`} action={at => {
          const payload = { at: closeAt(closable, at, now()) };
          effect(() => { io.write('fixedClose', { params: { ...params, versionId: closable.id }, expectedVersion, receiptSeriesId: closable.seriesId, body: payload }); }, closable.id);
        }}/>
        <FixedForm replace draftKey={`fixedReplace:${key}:${closable.id}`} action={({ at, ...dates }, prices) => {
          const payload = body('fixedReplace', { ...dates, ...prices, at: closeAt(closable, at, now()) });
          effect(() => { io.write('fixedReplace', { params: { ...params, versionId: closable.id }, expectedVersion, receiptSeriesId: closable.seriesId, body: payload }); }, closable.id);
        }}/>
      </div>}
    </>}/>;
}

function Estimates({ io, cityId, manage }: Scope) {
  type Estimate = P04Data<'estimateGet'>;
  const params = { cityId };
  const estimates = useLabels<Estimate>((cursor, done) => { io.read('estimateList', { params, query: historyQuery(cursor) }, data => {
    if (data.items.some(row => row.cityId !== cityId)) { throw new FormError('Список не относится к выбранному городу.'); }
    done(data);
  }); });
  return <>
    <p>Оценочные диапазоны не являются фиксированными ценами.</p>
    {manage && <CategoryPages {...{ io, cityId }}>{(categories, current) => current && categories.length > 0 &&
      <EstimateCreateForm draftKey={`estimateCreate:${cityId}`} categories={categories} action={fields => {
        io.write('estimateCreate', { params, body: body('estimateCreate', fields) }); estimates.setSelected(undefined);
      }}/>}</CategoryPages>}
    <P04Pages title="Загрузить оценочные диапазоны" load={estimates.load} loaded={estimates.loaded} render={() => null}/>
    <Picker label="Диапазон" title="Выберите диапазон" items={estimates.current ? estimates.items : []} selected={estimates.current ? estimates.selected : undefined}
      set={estimates.setSelected} text={row => `${row.code}${row.archivedAt ? ' · Архив' : ''}`}/>
    {estimates.current && estimates.selected && <EstimateStream key={estimates.selected.id} {...{ io, cityId, manage }} selected={estimates.selected}/>}
  </>;
}
function EstimateStream({ io, cityId, manage, selected }: Scope & { selected: P04Data<'estimateGet'> }) {
  const [identity, setIdentity] = useState<P04Data<'estimateGet'>>();
  const [mismatch, setMismatch] = useState(false);
  const params = { cityId, estimateId: selected.id };
  const key = `${cityId}:${selected.id}`;
  return <>
    <button onClick={() => {
      setIdentity(undefined); setMismatch(false);
      io.read('estimateGet', { params }, detail => {
        if (detail.id !== selected.id || detail.cityId !== cityId || detail.version !== selected.version || detail.archivedAt !== selected.archivedAt
            || detail.code !== selected.code || detail.categoryId !== selected.categoryId) { setMismatch(true); return; }
        setIdentity(detail);
      });
    }}>Загрузить точный диапазон</button>
    {mismatch && <p role="alert">Диапазон изменился. Обновите список диапазонов.</p>}
    {identity && <>
      <p>Код: {identity.code} · Версия: {identity.version} {identity.archivedAt && `· Архив: ${identity.archivedAt}`}</p>
      <Stream<P04Data<'estimateVersions'>['items'][number], P04Data<'estimateVersion'>> cityId={cityId} knownSeriesId={identity.id}
        load={(cursor, done) => { io.read('estimateVersions', { params, query: historyQuery(cursor) }, done); }}
        get={(versionId, done) => { io.read('estimateVersion', { params: { ...params, versionId } }, done); }}
        summary={row => `${row.title}: ${row.minMinor}–${row.maxMinor} ${row.currency}`}
        detail={row => <><p>{row.title}: {row.minMinor}–{row.maxMinor} {row.currency}</p><p>Условия: {none(row.conditions)} · Предупреждение: {row.disclaimer} · Источник: {row.sourceRef}</p></>}
        actions={({ expectedVersion, closable, effect }) => {
          if (!manage || identity.archivedAt) { return null; }
          if (expectedVersion !== identity.version) { return <p role="alert">Версия диапазона изменилась. Обновите список диапазонов.</p>; }
          return <>
            <EstimateForm draftKey={`estimatePublish:${key}`} action={({ at, ...dates }, fields) => {
              const payload = body('estimatePublish', { ...dates, ...fields, validFrom: at });
              effect(() => { io.write('estimatePublish', { params, expectedVersion, body: payload }); });
            }}/>
            {closable && <div key={closable.id}>
              <CloseForm noun="диапазон" draftKey={`estimateClose:${key}:${closable.id}`} action={at => {
                const payload = { at: closeAt(closable, at, now()) };
                effect(() => { io.write('estimateClose', { params: { ...params, versionId: closable.id }, expectedVersion, body: payload }); }, closable.id);
              }}/>
              <EstimateForm replace draftKey={`estimateReplace:${key}:${closable.id}`} action={({ at, ...dates }, fields) => {
                const payload = body('estimateReplace', { ...dates, ...fields, at: closeAt(closable, at, now()) });
                effect(() => { io.write('estimateReplace', { params: { ...params, versionId: closable.id }, expectedVersion, body: payload }); }, closable.id);
              }}/>
            </div>}
            <Confirm prompt="Отправить этот диапазон в архив?" action={() => {
              effect(() => { io.write('estimateArchive', { params, expectedVersion, body: {} }); });
            }}>Архивировать диапазон</Confirm>
          </>;
        }}/>
    </>}
  </>;
}

function Rules({ io, cityId, manage }: Scope) {
  const rules = useLabels<P04Data<'cityRules'>['items'][number]>((cursor, done) => { io.read('cityRules', { params: { cityId }, query: pageQuery(cursor) }, done); });
  return <>
    <P04Pages title="Загрузить правила города" load={rules.load} loaded={rules.loaded} render={() => null}/>
    <Picker label="Правило" title="Выберите правило" items={rules.current ? rules.items : []} selected={rules.current ? rules.selected : undefined}
      set={rules.setSelected} text={row => `${row.code} · ${row.kind}`}/>
    {rules.current && rules.selected && <RuleStream key={rules.selected.id} {...{ io, cityId, manage }} ruleId={rules.selected.id} kind={rules.selected.kind}/>}
    {(!rules.current || !rules.selected) && <HistoricalSubject label="UUID правила">{id => <RuleStream {...{ io, cityId }} manage={false} ruleId={id}/>}</HistoricalSubject>}
  </>;
}
function RuleStream({ io, cityId, manage, ruleId, kind }: Scope & { ruleId: string; kind?: P04Data<'cityRules'>['items'][number]['kind'] }) {
  const params = { cityId, ruleId };
  const key = `${cityId}:${ruleId}`;
  return <CategoryPages {...{ io, cityId }}>{(categories, current) =>
    <Stream<P04Data<'ruleVersionList'>['items'][number], P04Data<'ruleVersionGet'>> cityId={cityId} load={(cursor, done) => { io.read('ruleVersionList', { params, query: historyQuery(cursor) }, done); }}
      get={(versionId, done) => { io.read('ruleVersionGet', { params: { ...params, versionId } }, done); }}
      summary={row => `${row.title} · ${row.kind}`}
      detail={row => <>
        <p>{row.title} · {row.kind} · {row.base} · {row.currency}</p>
        <p>Метод: {row.method === 'FIXED' ? `${none(row.fixedMinor)} мин. ед.` : `${row.rateBps === null ? 'Не задано' : String(row.rateBps)} б.п.`}; база: {none(row.minBase)} — {none(row.maxBase)}; дельта: {none(row.minDelta)} — {none(row.maxDelta)}.</p>
        {row.startMinute !== null && row.endMinute !== null && <p>Местное окно: {minuteLabel(row.startMinute)} — {minuteLabel(row.endMinute)}{row.wrapsMidnight && ' (через полночь)'}.</p>}
        <p>Категории: {row.categoryIds.length ? row.categoryIds.map(id => categories.find(row => row.id === id)?.title ?? 'Метка недоступна').join(', ') : 'Без ограничения'} · Источник: {row.sourceRef}</p>
      </>}
      actions={({ expectedVersion, receiptSeriesId, closable, effect }) => manage && kind && <>
        {current && <RuleForm draftKey={`ruleVersionPublish:${key}`} kind={kind} categories={categories} action={({ at, ...dates }, fields) => {
          const payload = body('ruleVersionPublish', { ...dates, ...fields, validFrom: at });
          effect(() => { io.write('ruleVersionPublish', { params, expectedVersion, receiptSeriesId, body: payload }); });
        }}/>}
        {closable && closable.kind === kind && <div key={closable.id}>
          <CloseForm noun="правило" draftKey={`ruleVersionClose:${key}:${closable.id}`} action={at => {
            const payload = { at: closeAt(closable, at, now()) };
            effect(() => { io.write('ruleVersionClose', { params: { ...params, versionId: closable.id }, expectedVersion, receiptSeriesId: closable.seriesId, body: payload }); }, closable.id);
          }}/>
          {current && <RuleForm replace draftKey={`ruleVersionReplace:${key}:${closable.id}`} kind={kind} categories={categories} action={({ at, ...dates }, fields) => {
            const payload = body('ruleVersionReplace', { ...dates, ...fields, at: closeAt(closable, at, now()) });
            effect(() => { io.write('ruleVersionReplace', { params: { ...params, versionId: closable.id }, expectedVersion, receiptSeriesId: closable.seriesId, body: payload }); }, closable.id);
          }}/>}
        </div>}
      </>}/>}</CategoryPages>;
}
function minuteLabel(n: number) { return `${String(Math.floor(n / 60)).padStart(2, '0')}:${String(n % 60).padStart(2, '0')}`; }

function Policy({ io, cityId, manage }: Scope) {
  const params = { cityId };
  return <RulePages {...{ io, cityId }}>{(rules, current) => {
    const ruleName = (id: string) => rules.find(row => row.id === id)?.code ?? 'Метка недоступна';
    return <Stream<P04Data<'policyList'>['items'][number], P04Data<'policyGet'>> cityId={cityId} load={(cursor, done) => { io.read('policyList', { params, query: historyQuery(cursor) }, done); }}
      get={(versionId, done) => { io.read('policyGet', { params: { ...params, versionId } }, done); }}
      summary={row => row.currency}
      detail={row => <>
        <p>{row.currency} · {row.taxDisplay} · {row.roundingMode} · Максимальная ручная дельта: {row.maxManualDeltaMinor} · Источник: {row.sourceRef}</p>
        <p>Шкалы: {Object.entries(row.units).map(([unit, scale]) => `${unit}: ${String(scale)}`).join(', ')}</p>
        <p>Приоритеты: {row.priorities.length ? row.priorities.map(rule => `${ruleName(rule.ruleId)}: ${String(rule.priority)}`).join(', ') : 'Нет'}</p>
        <p>Совместимости: {row.compatibilities.length ? row.compatibilities.map(pair => `${ruleName(pair.leftRuleId)} ↔ ${ruleName(pair.rightRuleId)}`).join(', ') : 'Нет'}</p>
      </>}
      actions={({ expectedVersion, receiptSeriesId, closable, effect }) => manage && <>
        {current && <PolicyForm draftKey={`policyPublish:${cityId}`} rules={rules} action={({ at, ...dates }, fields) => {
          const payload = body('policyPublish', { ...dates, ...fields, validFrom: at });
          effect(() => { io.write('policyPublish', { params, expectedVersion, receiptSeriesId, body: payload }); });
        }}/>}
        {closable && <div key={closable.id}>
          <CloseForm noun="политику" draftKey={`policyClose:${cityId}:${closable.id}`} action={at => {
            const payload = { at: closeAt(closable, at, now()) };
            effect(() => { io.write('policyClose', { params: { ...params, versionId: closable.id }, expectedVersion, receiptSeriesId: closable.seriesId, body: payload }); }, closable.id);
          }}/>
          {current && <PolicyForm replace draftKey={`policyReplace:${cityId}:${closable.id}`} rules={rules} action={({ at, ...dates }, fields) => {
            const payload = body('policyReplace', { ...dates, ...fields, at: closeAt(closable, at, now()) });
            effect(() => { io.write('policyReplace', { params: { ...params, versionId: closable.id }, expectedVersion, receiptSeriesId: closable.seriesId, body: payload }); }, closable.id);
          }}/>}
        </div>}
      </>}/>;
  }}</RulePages>;
}

function Readiness({ io, city }: { io: P04IO; city: City }) {
  const readiness = useLabels<P04Data<'pricingReadiness'>['items'][number]>((cursor, done) => { io.read('pricingReadiness', { query: pageQuery(cursor) }, done); });
  const record = readiness.current ? readiness.items.find(row => row.id === city.id) : undefined;
  const status = (flag: 'CONFIGURED' | 'MISSING') => flag === 'CONFIGURED' ? 'Настроено' : 'Не настроено (нет действующей версии)';
  return <>
    <P04Pages title="Загрузить готовность цен" load={readiness.load} loaded={readiness.loaded} render={() => null}/>
    {record ? <dl><dt>Фиксированные цены</dt><dd>{status(record.fixed)}</dd><dt>Ценовая политика</dt><dd>{status(record.policy)}</dd></dl>
      : <p>Готовность выбранного города не загружена.</p>}
    <p>Отсутствие цены не означает нулевую цену.</p>
  </>;
}

function CitySections({ io, city, manage }: { io: P04IO; city: City; manage: boolean }) {
  const sections = { 'Готовность цен': Readiness, 'Фиксированные цены': Fixed, 'Оценочные диапазоны': Estimates,
    'Тарифные правила': Rules, 'Ценовая политика': Policy };
  const [tab, setTab] = useState<keyof typeof sections>();
  const Panel = tab ? sections[tab] : null;
  return <>
    <h3>{city.name} · {city.code}</h3>
    <nav aria-label="Разделы городских цен">{Object.keys(sections).map(label => <button key={label} type="button" aria-pressed={tab === label}
      onClick={() => { if (Object.hasOwn(sections, label)) { setTab(label as keyof typeof sections); } }}>{label}</button>)}</nav>
    {tab && Panel && <section aria-label={tab}><h4>{tab}</h4><Panel io={io} city={city} cityId={city.id} manage={manage}/></section>}
  </>;
}

export function CityWorkspace({ access, io }: { access: Access; io: P04IO }) {
  const cities = useLabels<City>((cursor, done) => { io.read('cityList', { query: pageQuery(cursor) }, done); });
  const read = hasP04(access, 'pricing.read');
  const manage = read && cities.selected !== undefined && (hasP04(access, 'pricing.manage', 'GLOBAL')
    || (hasP04(access, 'pricing.manage', 'CITY') && (hasP04(access, 'pricing.read', 'CITY')
      || access.p04PricingWriteCityIds?.includes(cities.selected.id) === true)));
  if (!read) { return null; }
  return <section aria-label="Городские цены и тарифы">
    <h2>Городские цены и тарифы</h2>
    <P04Pages title="Загрузить города" load={cities.load} loaded={cities.loaded} render={() => null}/>
    <Picker label="Город" title="Выберите город" items={cities.current ? cities.items : []} selected={cities.current ? cities.selected : undefined}
      set={cities.setSelected} text={city => `${city.name} · ${city.code}`}/>
    {!manage && hasP04(access, 'pricing.manage') && <p>Для выбранной области нет подтверждённого права изменения города.</p>}
    {cities.current && (cities.selected ? <CitySections key={cities.selected.id} io={io} city={cities.selected} manage={manage}/>
      : <p>Выберите город. Город не подставляется автоматически.</p>)}
  </section>;
}
