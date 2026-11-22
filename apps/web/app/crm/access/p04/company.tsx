import { useState, type ReactNode } from 'react';
import type { P04Data } from '@fixlevelup/p03-contracts/p04';
import type { Access } from '../api';
import { Confirm, value } from '../management-ui';
import { FormError } from '../p0305-client';
import type { P04IO } from './client';
import { hasP04, P04Form, P04Pages } from './shared';
import {
  AvitoFields, AvitoSnapshot, Code, ItemFields, ItemSnapshot, TitleDescription, Unit,
  avitoLabels, avitoPublication, checkedBody, itemLabels, itemPublication, ruleLabels, titleDescription,
  type AvitoKind, type ItemKind,
} from './company-fields';

const directory = {
  category: { tab: 'Категории', load: 'Загрузить категории', form: 'Новая категория', submit: 'Создать категорию' },
  brand: { tab: 'Бренды', load: 'Загрузить бренды', form: 'Новый бренд', submit: 'Создать бренд' },
  model: { tab: 'Модели', load: 'Загрузить модели', form: 'Новая модель', submit: 'Создать модель' },
  fault: { tab: 'Неисправности', load: 'Загрузить неисправности', form: 'Новая неисправность', submit: 'Создать неисправность' },
} as const;
type Directory = keyof typeof directory;
type CatalogTab = Directory | ItemKind | 'mapping';
const catalogTabs = { category: directory.category.tab, brand: directory.brand.tab, model: directory.model.tab,
  fault: directory.fault.tab, mapping: 'Связи неисправностей', ...itemLabels };
type RuleKind = P04Data<'ruleGet'>['kind'];
type Category = P04Data<'categoryGet'>;
type Brand = P04Data<'brandGet'>;

type Page<Row extends { id:string }> = { readonly items:readonly Row[]; readonly pageInfo:{ readonly nextCursor:string|null } };
type Load<P> = (cursor:string|null, done:(data:P) => void) => void;
const query = (cursor:string|null, includeArchived = false) => ({
  limit:'20', includeArchived:includeArchived ? 'true' as const : 'false' as const, ...(cursor === null ? {} : { cursor }),
});
const codedLabel = (row:{ title?:string|null;code:string }) => row.title ? `${row.title} · ${row.code}` : row.code;
const status = (row:{ archivedAt:string|null }) => row.archivedAt === null ? '' : ' · архив';
const isActive = (row:{ archivedAt:string|null }) => row.archivedAt === null;

function Tabs<K extends string>({ labels, chosen, choose, title }: {
  labels: Readonly<Record<K,string>>; chosen: K; choose: (value:K) => void; title: string;
}) {
  return <nav aria-label={title}>{(Object.keys(labels) as K[]).map(kind => <button key={kind} aria-pressed={chosen === kind} onClick={() => { choose(kind); }}>{labels[kind]}</button>)}</nav>;
}
function ChoiceList<R extends { id:string; code:string; archivedAt:string|null; title?:string|null }>({ label, load, selected, select, accept }: {
  label:string; load:Load<Page<R>>; selected:R|null; select:(row:R|null)=>void; accept?:(row:R)=>boolean;
}) {
  return <fieldset className="p03-fields"><legend>{label}</legend>
    <p>{selected ? `Выбрано: ${codedLabel(selected)}` : 'Ничего не выбрано.'}</p>
    {selected && <button type="button" onClick={() => { select(null); }}>Снять выбор: {label}</button>}
    <P04Pages<Page<R>> title={`Загрузить варианты: ${label}`} load={(cursor,done) => {
      load(cursor,data => { done({ ...data, items:data.items.filter(row => isActive(row) && (accept?.(row) ?? true)) }); });
    }} loaded={(_,append) => { if (!append) { select(null); } }} render={row => <li key={row.id}>
      <button type="button" aria-pressed={selected?.id === row.id} onClick={() => { select(row); }}>Выбрать: {codedLabel(row)}</button></li>}/>
  </fieldset>;
}
function CategoryChoice({ io, selected, select }: { io:P04IO;selected:Category|null;select:(row:Category|null)=>void }) {
  return <ChoiceList<Category> label="Категория" selected={selected} select={select}
    load={(cursor,done) => { io.read('categoryList',{ query:query(cursor) },done); }}/>;
}
function selectedId(row:{ id:string }|null) {
  if (row === null) { throw new FormError('Выберите доступную запись из списка.'); }
  return row.id;
}

function Entries<Row extends { id:string; archivedAt:string|null }, D extends Row>({ title, load, get, label, card }: {
  title:string; load:(cursor:string|null, archived:boolean, done:(data:Page<Row>)=>void)=>void;
  get:(id:string, done:(data:D)=>void)=>void; label:(row:Row)=>string;
  card:(data:D, reload:()=>void)=>ReactNode;
}) {
  const [archived,setArchived] = useState(false);
  const [selected,setSelected] = useState<D|null>(null);
  const [generation,advance] = useState(0);
  function open(id:string) {
    setSelected(null);
    get(id, data => { if (data.id === id) { setSelected(data); advance(n => n + 1); } });
  }
  return <><label><input type="checkbox" checked={archived} onChange={e => { setSelected(null); setArchived(e.target.checked); }}/>Показывать архив</label>
    <P04Pages<Page<Row>> key={String(archived)} title={title} load={(cursor,done) => { load(cursor,archived,done); }}
      loaded={(_,append) => { if (!append) { setSelected(null); } }} render={row => <li key={row.id}>
        <button onClick={() => { open(row.id); }}>{label(row)}</button>{status(row)}</li>}/>
    {selected && <article className="panel" key={generation}>
      <h4>{label(selected)}{status(selected)}</h4>
      <button onClick={() => { open(selected.id); }}>Перечитать карточку</button>
      {card(selected, () => { open(selected.id); })}
    </article>}
  </>;
}
function Archive({ action }: { action:()=>void }) {
  return <Confirm prompt="Архивировать запись? Опубликованные версии сохранятся в истории." action={action}>Архивировать</Confirm>;
}
function Reference({ io, op, id, label }: { io:P04IO;op:'categoryGet'|'brandGet'|'faultGet'|'itemGet'|'avitoGet';id:string;label:string }) {
  const [name,setName] = useState<string|null>(null);
  return <><dt>{label}</dt><dd>{name ?? id} <button type="button" onClick={() => {
    io.read(op,{ params:{ id } },row => { if (row.id === id) { setName(`${codedLabel(row)}${status(row)}`); } });
  }}>Загрузить название: {label}</button></dd></>;
}

type RevisionSummary = { id:string; version:number; title:string; publishedAt:string };
function companyRevisionProof(current:RevisionSummary|null) {
  return current === null ? null : { id:current.id,version:current.version };
}
type RevisionPage = Page<RevisionSummary> & { readonly version:number };
type RevisionedIdentity = { id:string; version:number; archivedAt:string|null; currentVersionId:string|null };
function Revisions<R extends RevisionSummary>({ entry, load, get, snapshot, publish, archive, reload }: {
  entry:RevisionedIdentity; load:Load<RevisionPage>; get:(versionId:string, done:(revision:R)=>void)=>void;
  snapshot:(revision:R)=>ReactNode; publish?:((current:R|null)=>ReactNode)|undefined; archive?:(()=>void)|undefined; reload:()=>void;
}) {
  const [current,setCurrent] = useState<R|null>(null);
  const [history,setHistory] = useState<R|null>(null);
  const [stale,setStale] = useState(false);
  const currentId = entry.currentVersionId;
  // An active identity starts at V1 and advances only when a new revision is published.
  const revisionMismatch = isActive(entry) && (currentId === null ? entry.version !== 1
    : current !== null && (current.id !== currentId || entry.version !== current.version + 1));
  const refreshRequired = stale || revisionMismatch;
  const saveAllowed = isActive(entry) && !refreshRequired;
  return <><p>Версия карточки: {entry.version}</p>
    {currentId === null ? <p>Опубликованных версий пока нет.</p> : <>
      <button onClick={() => { get(currentId,setCurrent); }}>Загрузить текущую версию</button>
      {current && <section><h5>Текущая версия · {current.version} · {current.title}</h5><p>Опубликована: {current.publishedAt}</p>{snapshot(current)}</section>}
    </>}
    <P04Pages<RevisionPage> title="История версий" load={(cursor,done) => {
      load(cursor,page => {
        if (page.version !== entry.version) { setStale(true); }
        setHistory(null);
        done(page);
      });
    }} render={row => <li key={row.id}><button onClick={() => { setHistory(null); get(row.id,setHistory); }}>
      {`Версия ${String(row.version)} · ${row.title}`}</button>{row.id === currentId && ' · текущая по карточке'}</li>}/>
    {history && <section><h5>Историческая версия · {history.version} · {history.title}</h5><p>Опубликована: {history.publishedAt}</p>{snapshot(history)}</section>}
    {refreshRequired && <p role="status">Карточка изменилась. Перечитайте её перед записью. <button onClick={reload}>Получить актуальную карточку</button></p>}
    {saveAllowed && publish && (currentId === null ? publish(null) : current?.id === currentId
      ? publish(current) : <p>Загрузите текущую версию перед публикацией новой.</p>)}
    {saveAllowed && archive && <Archive action={archive}/>}
  </>;
}

export function CompanyWorkspace({ access, io, area }: { access:Access;io:P04IO;area:'catalog'|'rules'|'avito' }) {
  if (area === 'catalog' && hasP04(access,'catalog.read','COMPANY')) {
    return <Catalog io={io} manage={hasP04(access,'catalog.manage','COMPANY')}/>;
  }
  if (area === 'rules' && hasP04(access,'pricing.rules.read','COMPANY')) {
    return <Rules io={io} manage={hasP04(access,'pricing.rules.manage','COMPANY')}/>;
  }
  if (area === 'avito' && hasP04(access,'content.externalreviews.read','COMPANY')) {
    const manage = hasP04(access,'content.externalreviews.manage','COMPANY');
    return <Avito io={io} manage={manage} publish={manage && hasP04(access,'content.externalreviews.publish','COMPANY')}/>;
  }
  return <p>Нет доступа к этому разделу компании.</p>;
}
type CompanyIO = { io:P04IO; manage:boolean };
function Catalog({ io, manage }: CompanyIO) {
  const [tab,setTab] = useState<CatalogTab>('category');
  return <section><h2>Каталог компании</h2><Tabs labels={catalogTabs} chosen={tab} choose={setTab} title="Разделы каталога"/>
    {tab === 'mapping' ? <Mappings io={io} manage={manage}/> :
      tab === 'category' || tab === 'brand' || tab === 'model' || tab === 'fault' ? <DirectoryPanel key={tab} group={tab} io={io} manage={manage}/> :
      <Items key={tab} kind={tab} io={io} manage={manage}/>}
  </section>;
}
type DirectoryRow = P04Data<`${Directory}Get`>;
type DirectoryRevision = P04Data<`${Directory}Version`>;
function DirectoryPanel({ io, manage, group }: CompanyIO & { group:Directory }) {
  const [category,setCategory] = useState<Category|null>(null);
  const [brand,setBrand] = useState<Brand|null>(null);
  const labels = directory[group];
  const needsCategory = group === 'model' || group === 'fault';
  const needsBrand = group === 'model';
  const createDraftKey = group === 'model' ? category && brand && `modelCreate:${category.id}:${brand.id}`
    : group === 'fault' ? category && `faultCreate:${category.id}` : `${group}Create`;
  return <section><h3>{labels.tab}</h3>
    <Entries<DirectoryRow,DirectoryRow> title={labels.load} label={codedLabel}
      load={(cursor,archived,done) => { io.read(`${group}List`,{ query:query(cursor,archived) },done); }}
      get={(id,done) => { io.read(`${group}Get`,{ params:{ id } },done); }}
      card={(entry,reload) => <>{(entry.categoryId || entry.brandId) && <dl>
        {entry.categoryId && <Reference io={io} op="categoryGet" id={entry.categoryId} label="Категория"/>}
        {entry.brandId && <Reference io={io} op="brandGet" id={entry.brandId} label="Бренд"/>}</dl>}
        <Revisions<DirectoryRevision> entry={entry} reload={reload}
          load={(cursor,done) => { io.read(`${group}Versions`,{ params:{ id:entry.id },query:query(cursor,true) },done); }}
          get={(versionId,done) => { io.read(`${group}Version`,{ params:{ id:entry.id,versionId } },r => {
            if (r.entryId === entry.id && r.id === versionId) { done(r); }
          }); }}
          snapshot={r => <p>{r.description ?? 'Описание не указано.'}</p>}
          publish={manage ? current => <P04Form title="Новая неизменяемая версия" submit="Опубликовать версию" draftKey={`${group}Publish:${entry.id}`}
            action={f => { const op = `${group}Publish` as const;
              io.write(op,{ params:{ id:entry.id },expectedVersion:entry.version,receiptCompanyRevision:companyRevisionProof(current),body:checkedBody(op,titleDescription(f)) }); }}>
            <TitleDescription revision={current}/></P04Form> : undefined}
          archive={manage ? () => { io.write(`${group}Archive`,{ params:{ id:entry.id },expectedVersion:entry.version,body:{} }); } : undefined}/></>}/>
    {manage && <section>{needsCategory && <CategoryChoice io={io} selected={category} select={setCategory}/>}
      {needsBrand && <ChoiceList<Brand> label="Бренд" selected={brand} select={setBrand} load={(cursor,done) => {
        io.read('brandList',{ query:query(cursor) },done);
      }}/>}
      {createDraftKey !== null && <P04Form title={labels.form} submit={labels.submit} draftKey={createDraftKey} action={f => {
        const code = value(f,'code',64);
        if (group === 'model') {
          io.write('modelCreate',{ body:checkedBody('modelCreate',{ code,categoryId:selectedId(category),brandId:selectedId(brand) }) });
        } else if (group === 'fault') {
          io.write('faultCreate',{ body:checkedBody('faultCreate',{ code,categoryId:selectedId(category) }) });
        } else {
          const op = `${group}Create` as const;
          io.write(op,{ body:checkedBody(op,{ code }) });
        }
      }}><Code/></P04Form>}
    </section>}
  </section>;
}

type Item = P04Data<'itemGet'>;
const itemLoadLabels: Readonly<Record<ItemKind,string>> = {
  WORK:'Загрузить работы', PART:'Загрузить запчасти', MATERIAL:'Загрузить материалы', TRAVEL:'Загрузить выезды', DIAGNOSTICS:'Загрузить диагностику',
};
function Items({ io, manage, kind }: CompanyIO & { kind:ItemKind }) {
  const [category,setCategory] = useState<Category|null>(null);
  const categoryId = category?.id ?? null;
  // No category is a separate immutable parent state, not a draft-key wildcard.
  return <section><h3>{itemLabels[kind]}</h3>
    <Entries<Item,Item> title={itemLoadLabels[kind]} label={codedLabel}
      load={(cursor,archived,done) => { io.read('itemList',{ query:{ ...query(cursor,archived),kind } },page => {
        done({ ...page, items:page.items.filter(row => row.kind === kind) });
      }); }}
      get={(id,done) => { io.read('itemGet',{ params:{ id } },row => { if (row.kind === kind) { done(row); } }); }}
      card={(entry,reload) => <><dl><dt>Тип позиции</dt><dd>{itemLabels[entry.kind]}</dd><dt>Единица измерения</dt><dd>{entry.unit}</dd>
        {entry.categoryId ? <Reference io={io} op="categoryGet" id={entry.categoryId} label="Категория"/> : <><dt>Категория</dt><dd>Без категории</dd></>}</dl>
        <Revisions<P04Data<'itemVersion'>> entry={entry} reload={reload}
          load={(cursor,done) => { io.read('itemVersions',{ params:{ id:entry.id },query:query(cursor,true) },done); }}
          get={(versionId,done) => { io.read('itemVersion',{ params:{ id:entry.id,versionId } },r => {
            if (r.itemId === entry.id && r.kind === kind && r.id === versionId) { done(r); }
          }); }} snapshot={r => <ItemSnapshot revision={r}/>}
          publish={manage ? current => <P04Form title="Новая неизменяемая версия" submit="Опубликовать версию" draftKey={`itemPublish:${entry.id}`}
            action={f => { io.write('itemPublish',{ params:{ id:entry.id },expectedVersion:entry.version,receiptCompanyRevision:companyRevisionProof(current),body:itemPublication(kind,f) }); }}>
            <ItemFields kind={kind} revision={current}/></P04Form> : undefined}
          archive={manage ? () => { io.write('itemArchive',{ params:{ id:entry.id },expectedVersion:entry.version,body:{} }); } : undefined}/></>}/>
    {manage && <section><p>{kind === 'WORK' ? 'Выберите обязательную категорию работы.' : 'Категория необязательна.'} Категория и единица измерения не меняются после создания.</p>
      <CategoryChoice io={io} selected={category} select={setCategory}/>
      {(kind !== 'WORK' || category) && <P04Form title={`Новая позиция · ${itemLabels[kind]}`} submit="Создать позицию" draftKey={`itemCreate:${kind}:${categoryId ?? 'no-category'}`}
        action={f => {
          const base = { code:value(f,'code',64),unit:value(f,'unit',24) };
          io.write('itemCreate',{ body:checkedBody('itemCreate',kind === 'WORK'
            ? { ...base,kind,categoryId:selectedId(category) } : { ...base,kind,categoryId }) });
        }}><Code/><Unit/></P04Form>}
    </section>}
  </section>;
}

type Fault = P04Data<'faultGet'>;
type Mapping = P04Data<'mappingGet'>;
function Mappings({ io, manage }: CompanyIO) {
  const [category,setCategory] = useState<Category|null>(null);
  const [fault,setFault] = useState<Fault|null>(null);
  const [work,setWork] = useState<Item|null>(null);
  const matchesWork = (row:Item) => row.kind === 'WORK' && row.categoryId === category?.id;
  const matchesFault = (row:Fault) => row.categoryId === category?.id;
  return <section><h3>Связи неисправностей</h3><p>Неисправность и работа (WORK) должны относиться к одной категории.</p>
    <Entries<Mapping,Mapping> title="Загрузить связи" label={row => `${row.faultId} → ${row.itemId}`}
      load={(cursor,archived,done) => { io.read('mappingList',{ query:query(cursor,archived) },done); }}
      get={(id,done) => { io.read('mappingGet',{ params:{ id } },done); }}
      card={entry => <><dl><Reference io={io} op="categoryGet" id={entry.categoryId} label="Категория"/>
        <Reference io={io} op="faultGet" id={entry.faultId} label="Неисправность"/>
        <Reference io={io} op="itemGet" id={entry.itemId} label="Работа (WORK)"/><dt>Версия карточки</dt><dd>{entry.version}</dd>
        <dt>Опубликована</dt><dd>{entry.publishedAt ?? 'Нет'}</dd></dl>
        {manage && isActive(entry) && <>{entry.publishedAt === null && <Confirm prompt="Опубликовать связь неисправности с работой?" action={() => {
          io.write('mappingPublish',{ params:{ id:entry.id },expectedVersion:entry.version,body:{} });
        }}>Опубликовать связь</Confirm>}
        <Archive action={() => { io.write('mappingArchive',{ params:{ id:entry.id },expectedVersion:entry.version,body:{} }); }}/></>}
      </>}/>
    {manage && <section><CategoryChoice io={io} selected={category} select={row => { setCategory(row); setFault(null); setWork(null); }}/>
      {category && <section key={category.id}>
        <ChoiceList<Fault> label="Неисправность" selected={fault} select={setFault} accept={matchesFault}
          load={(cursor,done) => { io.read('faultList',{ query:query(cursor) },done); }}/>
        <ChoiceList<Item> label="Работа (WORK)" selected={work} select={setWork} accept={matchesWork}
          load={(cursor,done) => { io.read('itemList',{ query:{ ...query(cursor),kind:'WORK' } },done); }}/>
        {fault && work && <P04Form title="Новая связь" submit="Создать связь" draftKey={`mappingCreate:${category.id}:${fault.id}:${work.id}`} action={() => {
          if (!matchesFault(fault) || !matchesWork(work)) { throw new FormError('Выберите работу и неисправность той же категории.'); }
          io.write('mappingCreate',{ body:checkedBody('mappingCreate',{ categoryId:category.id,faultId:fault.id,itemId:work.id }) });
        }}/>}</section>}
    </section>}
  </section>;
}

function Rules({ io, manage }: CompanyIO) {
  const [kind,setKind] = useState<RuleKind>('EVENING');
  type Rule = P04Data<'ruleGet'>;
  return <section><h2>Определения правил компании</h2><p>Здесь задаются типы правил; денежные параметры и периоды настраиваются отдельно для города.</p>
    <Tabs labels={ruleLabels} chosen={kind} choose={setKind} title="Виды правил"/>
    <section key={kind}><h3>{ruleLabels[kind]}</h3>
      <Entries<Rule,Rule> title="Загрузить определения" label={codedLabel}
        load={(cursor,archived,done) => { io.read('ruleList',{ query:{ ...query(cursor,archived),kind } },page => {
          done({ ...page,items:page.items.filter(row => row.kind === kind) });
        }); }} get={(id,done) => { io.read('ruleGet',{ params:{ id } },row => { if (row.kind === kind) { done(row); } }); }}
        card={entry => <><p>{ruleLabels[entry.kind]} · версия карточки {entry.version}</p>
          {manage && isActive(entry) && <Archive action={() => {
            io.write('ruleArchive',{ params:{ id:entry.id },expectedVersion:entry.version,body:{} });
          }}/>}</>}/>
      {manage && <P04Form title={`Новое определение · ${ruleLabels[kind]}`} submit="Создать определение" draftKey={`ruleCreate:${kind}`}
        action={f => { io.write('ruleCreate',{ body:checkedBody('ruleCreate',{ code:value(f,'code',64),kind }) }); }}><Code/></P04Form>}
    </section>
  </section>;
}

type AvitoRow = P04Data<'avitoGet'>;
function Avito({ io, manage, publish }: CompanyIO & { publish:boolean }) {
  const [kind,setKind] = useState<AvitoKind>('PROFILE');
  return <section><h2>Ручные источники Авито</h2>
    <p>Только для внутреннего использования в CRM. Не загружает данные из Авито и не публикует их на сайте.</p>
    <Tabs labels={avitoLabels} chosen={kind} choose={setKind} title="Тип записи Авито"/>
    <AvitoPanel key={kind} kind={kind} io={io} manage={manage} publish={publish}/>
  </section>;
}
function AvitoPanel({ io, manage, publish, kind }: CompanyIO & { publish:boolean;kind:AvitoKind }) {
  const [profile,setProfile] = useState<AvitoRow|null>(null);
  const createDraftKey = kind === 'PROFILE' ? 'avitoCreate:PROFILE' : profile && `avitoCreate:REVIEW:${profile.id}`;
  return <section><h3>{avitoLabels[kind]}</h3>
    <Entries<AvitoRow,AvitoRow> title={kind === 'PROFILE' ? 'Загрузить профили' : 'Загрузить отзывы'} label={codedLabel}
      load={(cursor,archived,done) => { io.read('avitoList',{ query:{ ...query(cursor,archived),kind } },page => {
        done({ ...page,items:page.items.filter(row => row.kind === kind) });
      }); }} get={(id,done) => { io.read('avitoGet',{ params:{ id } },row => { if (row.kind === kind) { done(row); } }); }}
      card={(entry,reload) => <>{entry.profileId && <dl><Reference io={io} op="avitoGet" id={entry.profileId} label="Профиль Авито"/></dl>}
        <Revisions<P04Data<'avitoVersion'>> entry={entry} reload={reload}
          load={(cursor,done) => { io.read('avitoVersions',{ params:{ id:entry.id },query:query(cursor,true) },done); }}
          get={(versionId,done) => { io.read('avitoVersion',{ params:{ id:entry.id,versionId } },r => {
            if (r.entryId === entry.id && r.kind === kind && r.id === versionId) { done(r); }
          }); }} snapshot={r => <AvitoSnapshot revision={r}/>}
          publish={publish ? current => <P04Form title="Новая внутренняя версия" submit="Опубликовать версию" draftKey={`avitoPublish:${entry.id}`}
            prompt="Сохранить неизменяемую версию только для внутреннего использования в CRM?"
            action={f => { io.write('avitoPublish',{ params:{ id:entry.id },expectedVersion:entry.version,receiptCompanyRevision:companyRevisionProof(current),body:avitoPublication(kind,f) }); }}>
            <AvitoFields kind={kind} revision={current}/></P04Form> : undefined}
          archive={manage ? () => { io.write('avitoArchive',{ params:{ id:entry.id },expectedVersion:entry.version,body:{} }); } : undefined}/></>}/>
    {manage && <section>{kind === 'REVIEW' && <ChoiceList<AvitoRow> label="Профиль Авито" selected={profile} select={setProfile}
      accept={row => row.kind === 'PROFILE'} load={(cursor,done) => {
        io.read('avitoList',{ query:{ ...query(cursor),kind:'PROFILE' } },done);
      }}/>}
      {createDraftKey !== null && <P04Form title={kind === 'PROFILE' ? 'Новый профиль Авито' : 'Новый отзыв Авито'}
        submit={kind === 'PROFILE' ? 'Создать профиль' : 'Создать отзыв'} draftKey={createDraftKey} action={f => {
          const code = value(f,'code',64);
          io.write('avitoCreate',{ body:checkedBody('avitoCreate',kind === 'PROFILE' ? { kind,code } : { kind,code,profileId:selectedId(profile) }) });
        }}><Code/></P04Form>}
    </section>}
  </section>;
}
