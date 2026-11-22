import { useState } from 'react';
import {
  decodeP03BootstrapGrant, decodeP03CityPickerItem, decodeP03CityVersionPickerItem, decodeP03CompanySummary, decodeP03CompanyVersion,
  decodeP03ContentBlock, decodeP03ContentRevision, decodeP03ContentSummary, decodeP03LegalDocument, decodeP03LegalSummary, decodeP03LegalVersion,
  decodeP03Page, decodeP03Readiness, decodeP03Receipt, decodeP03ReferenceEntry, decodeP03ReferenceSummary, decodeP03ReferenceVersion, decodeP03VersionedPage,
  P03_COMMANDS, P03_COMPANY_FIELDS, P03_COMPANY_FIELD_LENGTHS, P03_CONTENT_KINDS, P03_LEGAL_KINDS, P03_LEGAL_PURPOSES,
  P03_REFERENCE_TYPES, P03_REFERENCE_URL_TYPES, P03_RESPONSE_BYTES, P03_ROUTES, P03_TEXT_LENGTHS,
  type P03CityPickerDomain, type P03CompanyField, type P03CompanyVersion, type P03ContentBlock, type P03ContentRevision,
  type P03InputByOperation, type P03LegalDocument, type P03LegalVersion, type P03Operation, type P03Readiness, type P03ReferenceEntry,
  type P03ReferenceType, type P03ReferenceVersion, type P03Target, type P03Page,
} from '@fixlevelup/p03-contracts';
import type { Access } from './api';
import { admin, has, hasGeo, hasP03, protects, type Snapshot } from './workspace';
import { Confirm, Form, Pages, Plain, Select, Text, choice, detail, instant, integer, path, value, type IO, type Read, type WriteCommand } from './management-ui';
import { FormError, query, type Decoder } from './p0305-client';
import { Geography } from './geography';

const R = P03_ROUTES;
const lengths = P03_TEXT_LENGTHS;
const refNames: Record<P03ReferenceType, string> = { callback_interval:'Интервалы обратного звонка', payment_method:'Способы оплаты', cancel_reason:'Причины отмены', decline_reason:'Причины отказа', request_source:'Источники заявки' };
export const companyNames: Record<P03CompanyField, string> = { operatorName:'Название оператора', operatorRegistrationId:'Регистрационный идентификатор оператора', operatorAddress:'Адрес оператора', legalReviewRef:'Источник юридической проверки', securityPolicyRef:'Источник политики безопасности', retentionPolicyRef:'Источник политики хранения', uploadPolicyRef:'Источник политики загрузки' };
const companyPage = (v: unknown) => decodeP03VersionedPage(v, decodeP03CompanySummary, true);
const bootstrapPage = (v: unknown) => decodeP03Page(v, decodeP03BootstrapGrant);
const cities = (v: unknown) => decodeP03Page(v, decodeP03CityPickerItem);
const cityVersions = (v: unknown) => decodeP03VersionedPage(v, decodeP03CityVersionPickerItem);
const blockRevisions = (v: unknown) => decodeP03VersionedPage(v, decodeP03ContentSummary);
const refVersions = (v: unknown) => decodeP03VersionedPage(v, decodeP03ReferenceSummary);
const documents = (v: unknown) => decodeP03Page(v, decodeP03LegalDocument);
const legalVersions = (v: unknown) => decodeP03VersionedPage(v, decodeP03LegalSummary);

export function managementCommand<O extends P03Operation>(write: WriteCommand, op: O, payload: P03InputByOperation[O], parameters: Record<string, string> = {}, version?: number, parametersQuery: Record<string, string | undefined> = {}) {
  const meta = P03_COMMANDS[op];
  if (meta.versioned !== (version !== undefined)) { throw new FormError('Нужна актуальная версия записи.'); }
  write({ path: query(path(meta.route, parameters), parametersQuery), read: v => decodeP03Receipt(v, op), version,
    limit: op === 'legalPublish' ? 'legal' : op === 'contentPublish' ? 'content' : 'standard' }, payload);
}
export function p03Tabs(a: Access) {
  return [
    ...(hasGeo(a, 'geography.read') ? [{ id: 'geography', label: 'Города и зоны' } as const] : []),
    ...(hasP03(a,'settings.fullread') || P03_REFERENCE_URL_TYPES.some(type => hasP03(a, P03_REFERENCE_TYPES[type].read)) ? [{ id: 'settings', label: 'Настройки и справочники' } as const] : []),
    ...(hasP03(a,'content.read') ? [{ id: 'content', label: 'Контент' } as const] : []),
    ...(hasP03(a,'legal.read') ? [{ id: 'legal', label: 'Документы' } as const] : []),
    ...(hasP03(a,'settings.readiness.read','GLOBAL') ? [{ id: 'readiness', label: 'Готовность' } as const] : []),
    ...(protects(a,'roles.permissions.manage') && a.p03Permissions?.some(g => g.scope === 'GLOBAL' && hasP03(a,g.code,'GLOBAL')) ? [{ id: 'bootstrap', label: 'Личные права' } as const] : []),
  ];
}
export type P03Section = ReturnType<typeof p03Tabs>[number]['id'];
export function P03Desk({ data, section, read, write }: IO & { data: Snapshot; section: P03Section }) {
  const a = data.access;
  switch (section) {
    case 'geography': return <Geography data={data} read={read} write={write}/>;
    case 'settings': return <Settings access={a} read={read} write={write}/>;
    case 'content': return <Content access={a} read={read} write={write}/>;
    case 'legal': return <Legal access={a} read={read} write={write}/>;
    case 'readiness': return <Readiness read={read}/>;
    case 'bootstrap': return <Bootstrap access={a} read={read} write={write}/>;
  }
}
function Settings({ access, read, write }: IO & { access: Access }) {
  const available = P03_REFERENCE_URL_TYPES.filter(type => hasP03(access, P03_REFERENCE_TYPES[type].read));
  const company = hasP03(access,'settings.fullread','GLOBAL');
  const [active, setActive] = useState<'company' | P03ReferenceType | undefined>(company ? 'company' : available[0]);
  return <section><h2>Настройки и справочники</h2><nav aria-label="Настройки и типы справочников">
    {company && <button aria-pressed={active === 'company'} onClick={() => { setActive('company'); }}>Настройки компании</button>}
    {available.map(type => <button key={type} aria-pressed={active === type} onClick={() => { setActive(type); }}>{refNames[type]}</button>)}
  </nav>{active === 'company' ? <Company manage={hasP03(access,'settings.manage','GLOBAL')} read={read} write={write}/>
    : active && <References key={active} type={active} access={access} read={read} write={write}/>}</section>;
}
function Company({ read, write, manage }: IO & { manage: boolean }) {
  const [current, setCurrent] = useState<number | null>(null);
  const [exact, setExact] = useState<P03CompanyVersion | null>(null);
  const [edit, setEdit] = useState(false);
  return <article className="panel"><h3>Настройки компании</h3><p>Основной город, часовой пояс и активация настраиваются в разделе «Города и зоны».</p>
    <Pages read={read} route={path(R.companyList)} decoder={companyPage} title="Загрузить настройки" loaded={(p, append) => {
      if (!append) { setCurrent(p.version); setExact(null); setEdit(false); }
    }} render={v => <li key={v.id}><button onClick={() => { detail(read, path(R.companyExact,{version:v.version}), decodeP03CompanyVersion, revision => { setExact(revision); setEdit(false); }, P03_RESPONSE_BYTES.companyExact); }}>Версия {v.version}</button> · {v.publishedAt}</li>}/>
    {current === 0 && <p>Первая версия появится при активации города. Настройки ещё отсутствуют.</p>}
    {exact && <section key={exact.id}><h4>Версия {exact.version}{exact.version === current ? ' · текущая' : ' · история'}</h4>
      <p>Опубликована: {exact.publishedAt} · Проверил: {exact.reviewedBy}</p><dl>{P03_COMPANY_FIELDS.map(k => <div key={k}><dt>{companyNames[k]}</dt><dd>{exact.settings[k] ?? 'Не задано'}</dd></div>)}</dl>
      {manage && exact.version === current && <><button onClick={() => { setEdit(!edit); }}>{edit ? 'Закрыть редактор' : 'Редактировать настройки'}</button>
        {edit && <Form title="Новая версия настроек" submit="Опубликовать настройки" prompt="Опубликовать полную новую версию настроек компании?" action={f => {
          const settings = Object.fromEntries(P03_COMPANY_FIELDS.map(k => [k, value(f,k,P03_COMPANY_FIELD_LENGTHS[k])])) as P03InputByOperation['companyPublish'];
          managementCommand(write,'companyPublish',settings,{},exact.version);
        }}>{P03_COMPANY_FIELDS.map(k => <Text key={k} name={k} label={companyNames[k]} max={P03_COMPANY_FIELD_LENGTHS[k]} value={exact.settings[k]}/>)}</Form>}</>}
    </section>}
  </article>;
}
function CityPicker({ domain, read, choose, selected }: { domain: P03CityPickerDomain; read: Read; choose: (id: string) => void; selected: string | null }) {
  return <fieldset><legend>Город</legend><Pages read={read} route={query(path(R.cityPicker),{domain})} decoder={cities} title="Загрузить города" render={city => <li key={city.id}>
    <button aria-pressed={selected === city.id} onClick={() => { choose(city.id); }}>{city.code}</button> · {city.status}</li>}/></fieldset>;
}
function References({ type, access, read, write }: IO & { type: P03ReferenceType; access: Access }) {
  const [city, setCity] = useState<string|null>(null);
  return <article className="panel"><h3>{refNames[type]}</h3>{type === 'callback_interval' && <CityPicker domain="callback_interval" read={read} choose={setCity} selected={city}/>}
    {(city || type !== 'callback_interval') && <ReferenceScope key={city ?? 'COMPANY'} type={type} city={city} manage={hasP03(access, P03_REFERENCE_TYPES[type].manage)} read={read} write={write}/>}</article>;
}
function ReferenceScope({ type, city, manage, read, write }: IO & { type: P03ReferenceType; city: string|null; manage: boolean }) {
  const [selected, setSelected] = useState<P03ReferenceEntry|null>(null);
  const scope = { cityId: city ?? undefined };
  const config = P03_REFERENCE_TYPES[type];
  const scopedEntry: Decoder<P03ReferenceEntry> = v => { const row = decodeP03ReferenceEntry(v); return row?.type === config.dbType && row.cityId === city ? row : null; };
  const scopedPage: Decoder<P03Page<P03ReferenceEntry>> = v => decodeP03Page(v,scopedEntry);
  return <><Pages read={read} route={query(path(R.referenceList,{type}),{...scope,includeArchived:true})} decoder={scopedPage} loaded={(_p, append) => { if (!append) { setSelected(null); } }}
    render={item => <li key={item.id}><button onClick={() => { detail(read,query(path(R.referenceGet,{type,id:item.id}),scope),scopedEntry,setSelected); }}>{item.code}</button>{item.archivedAt && ' · архив'}</li>}/>
    {manage && <Form title="Новая запись справочника" submit="Создать запись" action={f => { managementCommand(write,'referenceCreate',{code:value(f,'code',lengths.code)},{type},undefined,scope); }}>
      <Text name="code" label="Код записи" max={lengths.code} pattern={'[A-Za-z][A-Za-z0-9_.\\-]{0,63}'}/>
    </Form>}
    {selected && <ReferenceCard key={`${selected.id}:${String(selected.version)}`} type={type} item={selected} manage={manage} read={read} write={write}/>}</>;
}
function ReferenceCard({ type, item, manage, read, write }: IO & { type: P03ReferenceType; item: P03ReferenceEntry; manage: boolean }) {
  const [exact, setExact] = useState<P03ReferenceVersion|null>(null);
  const [cityVersion, setCityVersion] = useState<{id:string; timezone:string} | null>(null);
  const params = { type,id:item.id }; const scope = { cityId:item.cityId ?? undefined };
  const city = item.cityId;
  return <section className="panel"><h4>{item.code} · версия записи {item.version}{item.archivedAt && ' · архив'}</h4>
    <Pages title="История справочника" read={read} route={query(path(R.referenceVersions,params),scope)} decoder={refVersions} render={v => <li key={v.id}>
      <button onClick={() => { detail(read,query(path(R.referenceExact,{...params,versionId:v.id}),scope),decodeP03ReferenceVersion, setExact,P03_RESPONSE_BYTES.referenceExact); }}>{v.label} · версия {v.version}</button>{v.id === item.currentVersionId && ' · текущая'}</li>}/>
    {exact && <section><h5>{exact.label} · версия {exact.version}</h5><dl><dt>Источник</dt><dd>{exact.sourceRef}</dd><dt>Начало действия</dt><dd>{exact.validFrom}</dd><dt>Окончание</dt><dd>{exact.validUntil ?? 'Без ограничения'}</dd>
      {exact.interval && <><dt>Интервал</dt><dd>{exact.interval.startMinute} – {exact.interval.endMinute} мин. от начала местных суток (версия города: {exact.provenanceCityVersionId})</dd></>}</dl></section>}
    {manage && !item.archivedAt && <>{city && <fieldset><legend>Версия города и часовой пояс</legend><Pages read={read} route={query(path(R.cityVersionPicker,{cityId:city}),{domain:'callback_interval'})}
      decoder={cityVersions} title="Загрузить версии города" render={v => <li key={v.id}><button aria-pressed={v.id === cityVersion?.id} onClick={() => { setCityVersion(v); }}>{v.sequence} · {v.timezone}</button>{v.published ? ' · опубликована' : ''}</li>}/></fieldset>}
      {(!city || cityVersion) && <Form title="Новая версия справочника" submit="Опубликовать новую версию" prompt="Опубликовать неизменяемую версию записи?" action={f => {
        const validFrom = instant(f,'validFrom',true); const validUntil = instant(f,'validUntil');
        if (validUntil && Date.parse(validFrom) >= Date.parse(validUntil)) { throw new FormError('Конец действия должен быть позже начала.'); }
        let interval: {startMinute:number;endMinute:number} | undefined;
        if (cityVersion) {
          interval = { startMinute:integer(f,'startMinute',0,1439),endMinute:integer(f,'endMinute',1,1440) };
          if (interval.startMinute >= interval.endMinute) { throw new FormError('Конец интервала должен быть позже начала.'); }
        }
        managementCommand(write,'referencePublish',{label:value(f,'label',lengths.referenceLabel),sourceRef:value(f,'sourceRef',lengths.sourceRef),validFrom,validUntil,
          ...(cityVersion && interval ? {cityVersionId:cityVersion.id, interval} : {})},params,item.version,scope);
      }}><Text name="label" label="Название записи" max={lengths.referenceLabel}/><Text name="sourceRef" label="Источник" max={lengths.sourceRef}/>
        <Text name="validFrom" label="Начало действия (ISO 8601 с зоной)" max={29}/><Text name="validUntil" label="Окончание действия (ISO 8601 с зоной)" max={29} required={false}/>
        {cityVersion && <><p>Часовой пояс: {cityVersion.timezone}. Время задаётся в минутах от начала суток.</p><label>Начало интервала<input name="startMinute" type="number" min="0" max="1439" required/></label>
          <label>Конец интервала<input name="endMinute" type="number" min="1" max="1440" required/></label></>}
      </Form>}
      <Confirm prompt="Архивировать запись? Опубликованные версии останутся доступны в истории." action={() => { managementCommand(write,'referenceArchive',{},params,item.version,scope); }}>Архивировать запись</Confirm>
    </>}
  </section>;
}
function Content({ access, read, write }: IO & { access: Access }) {
  const company = hasP03(access,'content.read','GLOBAL');
  const [scope, setScope] = useState<P03Target['scope']>(company ? 'COMPANY' : 'CITY');
  const [city, setCity] = useState<string|null>(null);
  const target: P03Target | null = scope === 'COMPANY' && company ? {scope} : city ? {scope:'CITY',cityId:city} : null;
  function change(next: P03Target['scope']) { setScope(next); setCity(null); }
  return <section><h2>Контент</h2>{company && <nav aria-label="Область контента"><button aria-pressed={scope === 'COMPANY'} onClick={() => { change('COMPANY'); }}>Компания</button>
    <button aria-pressed={scope === 'CITY'} onClick={() => { change('CITY'); }}>Город</button></nav>}
    {scope === 'CITY' && <CityPicker domain="content" read={read} choose={setCity} selected={city}/>}
    {target && <ContentScope key={target.cityId ?? target.scope} target={target} manage={hasP03(access,'content.manage', target.scope === 'COMPANY' ? 'GLOBAL' : undefined)}
      publish={hasP03(access,'content.publish', target.scope === 'COMPANY' ? 'GLOBAL' : undefined)} read={read} write={write}/>}
  </section>;
}
function ContentScope({ target, manage, publish, read, write }: IO & { target: P03Target; manage:boolean; publish:boolean }) {
  const [selected,setSelected] = useState<P03ContentBlock|null>(null);
  const scopedBlock: Decoder<P03ContentBlock> = v => {
    const block = decodeP03ContentBlock(v); return block?.scope === target.scope && block.cityId === (target.cityId ?? null) ? block : null;
  };
  return <article className="panel"><h3>Блоки контента · {target.scope === 'COMPANY' ? 'компания' : 'выбранный город'}</h3>
    <Pages read={read} route={query(path(R.contentList), {...target,includeArchived:true})} decoder={(v): P03Page<P03ContentBlock> | null => decodeP03Page(v,scopedBlock)} loaded={(_p, appendix) => { if (!appendix) { setSelected(null); } }}
      render={block => <li key={block.id}><button onClick={() => { detail(read,path(R.contentGet,{id:block.id}),scopedBlock,setSelected); }}>{block.kind} · {block.code}</button>{block.archivedAt && ' · архив'}</li>}/>
    {manage && <Form title="Новый блок контента" submit="Создать блок" action={f => {
      managementCommand(write,'contentCreate',{...target,kind:choice(f,'kind',P03_CONTENT_KINDS),code:value(f,'code',lengths.code),allowCompanyFallback:target.scope === 'COMPANY' && f.has('fallback')});
    }}><Select name="kind" label="Тип контента" values={P03_CONTENT_KINDS}/><Text name="code" label="Код блока" max={lengths.code} pattern={'[A-Za-z][A-Za-z0-9_.\\-]{0,63}'}/>
      {target.scope === 'COMPANY' && <label className="permission"><input type="checkbox" name="fallback"/>Разрешить подстановку версии компании для использования в городе (не даёт права просмотра)</label>}
    </Form>}
    {selected && <ContentCard key={`${selected.id}:${String(selected.version)}`} item={selected} manage={manage} publish={publish} read={read} write={write}/>}
  </article>;
}
function PublicationFields({ legal = false }: { legal?:boolean }) {
  return <><p>Несохранённый текст остаётся только на этой странице. Сервер получит его после явной публикации.</p><Text name="title" label="Заголовок" max={lengths.title}/>
    <Text name="body" label={legal ? 'Текст документа' : 'Текст публикации'} max={legal ? lengths.legalBody : lengths.contentBody} area/>
    {legal && <Text name="legalBasis" label="Правовое основание" max={lengths.legalBasis} area/>}
    <Text name="sourceRef" label="Источник" max={legal ? lengths.legalSourceRef : lengths.sourceRef}/>
    <small>Обычный текст: до {legal ? lengths.legalBody : lengths.contentBody} символов; весь JSON до {legal ? '1 МиБ' : '128 КиБ'} (UTF-8).</small></>;
}
function publication(f: FormData, legal: boolean) {
  return { title:value(f,'title',lengths.title), body:value(f,'body',legal ? lengths.legalBody : lengths.contentBody,false),
    sourceRef:value(f,'sourceRef',legal ? lengths.legalSourceRef : lengths.sourceRef) };
}
function ContentCard({ item, manage, publish, read, write }: IO & { item:P03ContentBlock; manage:boolean; publish:boolean }) {
  const [exact, setExact] = useState<P03ContentRevision|null>(null);
  const params = {id:item.id};
  return <section className="panel"><h4>{item.code} · {item.kind}{item.archivedAt && ' · архив'}</h4>
    <Pages title="История публикаций" read={read} route={path(R.contentRevisions,params)} decoder={blockRevisions} render={v => <li key={v.id}>
      <button onClick={() => { detail(read,path(R.contentExact,{...params,revisionId:v.id}),decodeP03ContentRevision,setExact,P03_RESPONSE_BYTES.contentExact); }}>{v.title} · версия {v.version}</button>{v.id === item.currentRevisionId && ' · текущая'}</li>}/>
    {exact && <section><h5>{exact.title} · версия {exact.version}</h5><p>Опубликовано: {exact.publishedAt} · Источник: {exact.sourceRef}</p><Plain>{exact.body}</Plain></section>}
    {manage && !item.archivedAt && <>{publish && <Form title="Локальный черновик контента" submit="Опубликовать новую версию" prompt="Опубликовать новую неизменяемую версию контента?" action={f => {
      managementCommand(write,'contentPublish',publication(f,false),params,item.version);
    }}><PublicationFields/></Form>}
      <Confirm prompt="Архивировать блок контента? История версий останется доступна." action={() => { managementCommand(write,'contentArchive',{},params,item.version); }}>Архивировать блок</Confirm></>}
  </section>;
}
function Legal({ access, read, write }: IO & { access: Access }) {
  const manage = hasP03(access,'legal.manage','GLOBAL');
  const [purpose,setPurpose] = useState<(typeof P03_LEGAL_PURPOSES)[number]>('REQUEST_PROCESSING');
  const [selected,setSelected] = useState<P03LegalDocument|null>(null);
  return <section><h2>Документы</h2><p>Документы разделены по назначению. Здесь нет действий от имени клиента и юридического одобрения.</p>
    <nav aria-label="Назначение документов">{P03_LEGAL_PURPOSES.map(p => <button key={p} aria-pressed={purpose === p} onClick={() => { setPurpose(p); setSelected(null); }}>{p}</button>)}</nav>
    <Pages key={`list-${purpose}`} read={read} route={query(path(R.legalList),{purpose})} decoder={documents} loaded={(_p, append) => { if (!append) { setSelected(null); } }}
      render={item => <li key={item.id}><button onClick={() => { detail(read,path(R.legalGet,{id:item.id}),decodeP03LegalDocument,setSelected); }}>{item.kind}</button>{!item.currentVersionId && ' · ещё не опубликован'}</li>}/>
    {manage && <Form key={`create-${purpose}`} title={`Новый документ · ${purpose}`} submit="Создать документ" action={f => { managementCommand(write,'legalCreate',{purpose,kind:choice(f,'kind',P03_LEGAL_KINDS)}); }}>
      <Select name="kind" label="Вид документа" values={P03_LEGAL_KINDS}/></Form>}
    {selected && <LegalCard key={`${selected.id}:${String(selected.version)}`} item={selected} manage={manage} read={read} write={write}/>}
  </section>;
}
function LegalCard({ item, read, write, manage }: IO & { item:P03LegalDocument; manage:boolean }) {
  const [exact,setExact] = useState<P03LegalVersion|null>(null); const params = {id:item.id};
  return <article className="panel"><h3>{item.purpose} · {item.kind}</h3>
    <Pages title="История документа" read={read} route={path(R.legalVersions,params)} decoder={legalVersions} render={v => <li key={v.id}>
      <button onClick={() => { detail(read,path(R.legalExact,{...params,versionId:v.id}),decodeP03LegalVersion,setExact,P03_RESPONSE_BYTES.legalExact); }}>{v.title} · версия {v.sequence}</button>{v.id === item.currentVersionId && ' · текущая'} · {v.publishedAt}</li>}/>
    {exact && <section><h4>{exact.title} · версия {exact.sequence}</h4><dl><dt>Контрольная сумма SHA-256</dt><dd>{exact.checksum}</dd><dt>Источник</dt><dd>{exact.sourceRef}</dd><dt>Правовое основание</dt><dd>{exact.legalBasis}</dd><dt>Проверил</dt><dd>{exact.reviewedBy}</dd></dl><Plain>{exact.body}</Plain></section>}
    {manage && <Form title="Локальный черновик документа" submit="Опубликовать новую версию" prompt="Опубликовать неизменяемую версию документа для выбранного назначения? Это не юридическое одобрение." action={f => {
      managementCommand(write,'legalPublish',{...publication(f,true),legalBasis:value(f,'legalBasis',lengths.legalBasis)},params,item.version);
    }}><PublicationFields legal/></Form>}
  </article>;
}
function Readiness({ read }: { read:Read }) {
  const [sections,setSections] = useState<P03Readiness['sections']>([]);
  return <section><h2>Готовность</h2><p>Проверка наличия конфигурации, а не подтверждение готовности к запуску.</p>
    {!!sections.length && <ul>{sections.map(s => <li key={s.section}>{s.section}: {s.status}{s.missing.length > 0 && ` · ${s.missing.join(', ')}`}</li>)}</ul>}
    <Pages read={read} route={path(R.readiness)} decoder={decodeP03Readiness} title="Проверить готовность" loaded={result => { setSections(result.sections); }}
      render={city => <li key={city.id}>{city.name ?? city.id}: {city.status}{city.missing.length > 0 && ` · ${city.missing.join(', ')}`}</li>}/>
  </section>;
}
function Bootstrap({ access, read, write }: IO & { access: Access }) {
  return <section><h2>Личные права первоначального администратора</h2><p>Доступны только ваши действующие личные источники. Отзыв необратим и не отменяет сознательно выданные права ролей.</p>
    <Pages read={read} route={path(R.bootstrapList)} decoder={bootstrapPage} title="Загрузить личные права" render={grant => grant.staffId === access.staffId && hasP03(access,grant.code,'GLOBAL') ? <li key={grant.code}>
      <strong>{grant.code}</strong> · GLOBAL · версия {grant.version}{' '}
      {admin(access) && has(access,'roles.permissions.manage') && <Confirm prompt={`Необратимо отозвать личный источник ${grant.code} (GLOBAL)? Права ролей останутся без изменений.`}
        action={() => { managementCommand(write,'bootstrapRevoke',{},{staffId:grant.staffId,code:grant.code},grant.version); }}>Отозвать личное право {grant.code}</Confirm>}
    </li> : null}/>
  </section>;
}
