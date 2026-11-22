import { useState } from 'react';
import { decodeP03Page, decodeP03TechnicianPickerItem, P03_ROUTES, type P03TechnicianPickerItem } from '@fixlevelup/p03-contracts';
import { admin, hasGeo, protects, type Snapshot } from './workspace';
import { Confirm, Form, Pages, Text, choice, detail, instant, optional, path, value, type IO, type WriteCommand } from './management-ui';
import { FormError, p03Read, query, type Method } from './p0305-client';
import { decodeOfficeHours, geoAdmins, geoArea, geoAreas, geoAreaVersion, geoAreaVersions, geoCities, geoCity, geoCityVersions, geoCoverage,
  geoDistrict, geoDistricts, geoReceipt, geoTechAreas, geoTechCities, type City, type CityVersion, type Mapping, type OfficeHours } from './geography-wire';

const base = 'settings/service-cities';
const weekdays = ['Понедельник','Вторник','Среда','Четверг','Пятница','Суббота','Воскресенье'];
const codePattern = '[a-z][a-z0-9]*(?:-[a-z0-9]+)*';
function command(write: WriteCommand, path: string, body: object, version?: number, method: Method = 'POST', coverage = false) {
  write({ path, read:geoReceipt, family:'geo', version, method, limit:coverage ? 'coverage' : 'standard' }, body);
}
function staffCommand(write: WriteCommand, path: string, body: object, version: number) {
  write({ path, read:geoReceipt, family:'geo', version, allowZeroVersion:true }, body);
}
function Code() { return <label>Код<input name="code" required minLength={2} maxLength={32} pattern={codePattern}/></label>; }
function Hours({ hours }: { hours?: OfficeHours | undefined }) {
  return <fieldset><legend>Часы работы · местное время</legend><p>Необязательно: до 12 интервалов на день. Формат: 09:00–12:00, 13:00–18:00 (разделитель времени «-» или «–»). Пустой день — закрыто.</p>
    {weekdays.map((label,i) => <Text key={label} name={`hours${String(i)}`} label={label} max={200} required={false}
      value={hours?.[i]?.map(([start,end]) => `${clock(start)}–${clock(end)}`).join(', ')}/>)}</fieldset>;
}
function clock(minutes: number) { return `${String(Math.floor(minutes / 60)).padStart(2,'0')}:${String(minutes % 60).padStart(2,'0')}`; }
export function hoursFromForm(form: FormData) {
  const days = weekdays.map((_, i) => {
    const raw = optional(form,`hours${String(i)}`);
    return raw ? raw.split(',').map(pair => {
      const m = /^\s*(\d\d):(\d\d)\s*[-–]\s*(\d\d):(\d\d)\s*$/.exec(pair);
      if (!m || Number(m[2]) > 59 || Number(m[4]) > 59) { throw new FormError('Проверьте формат часов работы.'); }
      return [Number(m[1]) * 60 + Number(m[2]), Number(m[3]) * 60 + Number(m[4])];
    }) : [];
  });
  try { return decodeOfficeHours(days); } catch { throw new FormError('Часы работы должны быть отсортированы, не пересекаться и укладываться в одни сутки.'); }
}
export function Geography({ data, read, write }: IO & { data: Snapshot }) {
  const a = data.access;
  const [selected,setSelected] = useState<City|null>(null);
  const [replacement,setReplacement] = useState<{id:string;version:number;code:string}|null>(null);
  const manager = hasGeo(a,'geography.manage');
  const cityWrite = admin(a) && manager;
  const cityCreate = admin(a) && hasGeo(a,'geography.manage','GLOBAL');
  const publish = admin(a) && hasGeo(a,'geography.publish');
  const changeLifecycle = admin(a) && hasGeo(a,'geography.publish','GLOBAL');
  return <section><h2>Города и зоны</h2><Pages read={read} route={base} decoder={geoCities} title="Загрузить города" loaded={(_p,append) => { if (!append) { setSelected(null); setReplacement(null); } }}
    render={item => <li key={item.id}><button onClick={() => { detail(read,`${base}/${item.id}`,geoCity,setSelected); }}>{item.code}</button> · {item.lifecycle}
      {changeLifecycle && item.lifecycle === 'ACTIVE' && <>{' '}<button aria-pressed={replacement?.id === item.id} onClick={() => { setReplacement(replacement?.id === item.id ? null : item); }}>Выбрать для замены: {item.code}</button></>}</li>}/>
    {cityCreate && <Form title="Новый город" submit="Создать черновик города" action={f => { command(write,base,{code:value(f,'code',32)}); }}><Code/></Form>}
    {selected && <CityCard key={`${selected.id}:${String(selected.version)}`} data={data} city={selected} cityWrite={cityWrite} manage={manager} publish={publish} replacement={replacement?.id === selected.id ? null : replacement} read={read} write={write}
      reload={() => { detail(read,`${base}/${selected.id}`,geoCity,setSelected); }}/>}
  </section>;
}
function CitySnapshot({ revision }: { revision:CityVersion }) {
  return <dl><dt>Версия города</dt><dd>{revision.sequence} · {revision.displayName}</dd><dt>Адрес</dt><dd>{revision.addressDisplay ?? 'Не задан'}</dd><dt>Часовой пояс</dt><dd>{revision.timezone}</dd>
    <dt>Контакт</dt><dd>{revision.publicContact}</dd><dt>Часы работы</dt><dd>{revision.officeHours.map((slots,i) => <div key={weekdays[i]}>{weekdays[i]}: {slots.map(([start,end]) => `${clock(start)}–${clock(end)}`).join(', ') || 'Закрыто'}</div>)}</dd></dl>;
}
function CityCard({ data, city, cityWrite, manage, publish, replacement, read, write, reload }: IO & { data:Snapshot; city:City; cityWrite:boolean; manage:boolean; publish:boolean; replacement:{id:string;version:number;code:string}|null; reload:() => void }) {
  const cityPath = `${base}/${city.id}`;
  const [snapshot,setSnapshot] = useState<CityVersion|null>(city.currentVersion);
  const [historyChanged,setHistoryChanged] = useState(false);
  const cityVersion = city.version;
  const [section,setSection] = useState<'city'|'districts'|'areas'|'technicians'|'administrators'>('city');
  const a = data.access;
  const staffAreas = hasGeo(a,'staff.geography.read');
  const administrators = admin(a) && hasGeo(a,'geography.manage','GLOBAL') && protects(a,'staff.role.assign');
  return <article className="panel"><h3>{city.code} · {city.lifecycle}</h3><nav aria-label="Управление городом">
    <button aria-pressed={section === 'city'} onClick={() => { setSection('city'); }}>Версии города</button>
    <button aria-pressed={section === 'districts'} onClick={() => { setSection('districts'); }}>Районы</button>
    <button aria-pressed={section === 'areas'} onClick={() => { setSection('areas'); }}>Зоны обслуживания</button>
    {staffAreas && <button aria-pressed={section === 'technicians'} onClick={() => { setSection('technicians'); }}>Допуски мастеров</button>}
    {administrators && <button aria-pressed={section === 'administrators'} onClick={() => { setSection('administrators'); }}>Административные назначения</button>}
  </nav>
  {section === 'city' && <><Pages read={read} route={`${cityPath}/versions`} decoder={geoCityVersions} title="История города" loaded={p => { if (p.version !== cityVersion) { setHistoryChanged(true); } }}
    render={v => <li key={v.id}><button onClick={() => { setSnapshot(v); }}>Версия города {v.sequence}</button> · {v.timezone}{v.id === city.currentVersionId && ' · текущая'}</li>}/>
    {historyChanged && <p role="status">История города изменилась. Перечитайте карточку и проверьте текущие значения перед записью. <button onClick={reload}>Перечитать карточку города</button></p>}
    {snapshot && <><CitySnapshot revision={snapshot}/>{publish && snapshot.id !== city.currentVersionId && <Confirm disabled={historyChanged} prompt="Сделать эту версию текущей?" action={() => { command(write,`${cityPath}/versions/${snapshot.id}/publish`,{},cityVersion); }}>Опубликовать версию города</Confirm>}</>}
    {cityWrite && <fieldset disabled={historyChanged} className="workspace"><Form title="Новая версия города" submit="Создать версию города" action={f => { command(write,`${cityPath}/versions`,{
      displayName:value(f,'displayName',200),addressDisplay:optional(f,'addressDisplay'),timezone:value(f,'timezone',64),publicContact:value(f,'publicContact',320),officeHours:hoursFromForm(f),
    },cityVersion); }}><Text name="displayName" label="Название города" value={city.currentVersion?.displayName} max={200}/><Text name="timezone" label="Часовой пояс IANA" value={city.currentVersion?.timezone} max={64}/>
    <Text name="addressDisplay" label="Адрес" value={city.currentVersion?.addressDisplay} max={500} required={false}/><Text name="publicContact" label="Публичный контакт" value={city.currentVersion?.publicContact} max={320}/><Hours hours={city.currentVersion?.officeHours}/></Form></fieldset>}
    {publish && hasGeo(a,'geography.publish','GLOBAL') && city.currentVersionId && <fieldset className="workspace actions" disabled={historyChanged}>
      {city.lifecycle !== 'ACTIVE' ? <Confirm prompt={replacement ? `Активировать ${city.code} и деактивировать ${replacement.code}?` : 'Активировать этот город как основной? Другой активный город не заменится без явного выбора.'}
        action={() => { command(write,`${cityPath}/activate`, replacement ? {replaceActiveCityId:replacement.id,replaceActiveCityVersion:replacement.version} : {},cityVersion); }}>{replacement ? `Активировать вместо ${replacement.code}` : 'Активировать город'}</Confirm>
      : <><Confirm prompt="Установить этот город основным?" action={() => { command(write,`${cityPath}/primary`,{},cityVersion); }}>Сделать основным</Confirm>
        <Confirm prompt="Деактивировать город? При отключении основного города приём заявок приостановится." action={() => { command(write,`${cityPath}/deactivate`,{suspendIntake:true},cityVersion); }}>Деактивировать город</Confirm></>}
    </fieldset>}
  </>}
  {section === 'districts' && <Districts city={city} cityPath={cityPath} manage={manage} read={read} write={write}/>}
  {section === 'areas' && <Areas city={city} cityPath={cityPath} manage={manage} publish={publish} read={read} write={write}/>}
  {section === 'technicians' && staffAreas && <Technicians city={city} cityPath={cityPath} manage={hasGeo(a,'staff.geography.manage')} read={read} write={write}/>}
  {section === 'administrators' && administrators && <Administrators data={data} city={city} cityPath={cityPath} read={read} write={write}/>}
  </article>;
}
type District = NonNullable<ReturnType<typeof geoDistrict>>;
function Districts({ city, cityPath, manage, read, write }: IO & { city:City;cityPath:string;manage:boolean }) {
  const route = `${cityPath}/administrative-districts`;
  const [selected,setSelected] = useState<District|null>(null);
  const [version,setVersion] = useState(city.version);
  return <section><h4>Районы</h4><Pages read={read} route={route} decoder={geoDistricts} title="Загрузить районы" loaded={(p,append) => { if (!append) { setVersion(p.version); setSelected(null); } }}
    render={v => <li key={v.id}><button onClick={() => { detail(read,`${route}/${v.id}`,geoDistrict,setSelected); }}>{v.name}</button> · {v.code}{v.archivedAt && ' · архив'}</li>}/>
    {manage && <Form title="Новый район" submit="Создать район" action={f => { command(write,route,{code:value(f,'code',32),name:value(f,'name',200)},version); }}><Code/><Text name="name" label="Название района" max={200}/></Form>}
    {selected && <section key={selected.id}><h5>{selected.name}{selected.archivedAt && ' · архив'}</h5>{manage && !selected.archivedAt && <>
      <Form title="Редактирование района" submit="Сохранить район" action={f => { command(write,`${route}/${selected.id}`,{name:value(f,'name',200)},selected.version,'PATCH'); }}>
        <Text name="name" label="Название района" value={selected.name} max={200}/></Form>
      <Confirm prompt="Архивировать район?" action={() => { command(write,`${route}/${selected.id}/archive`,{},selected.version); }}>Архивировать район</Confirm></>}
    </section>}
  </section>;
}
type Area = NonNullable<ReturnType<typeof geoArea>>;
type AreaVersion = NonNullable<ReturnType<typeof geoAreaVersion>>;
function Areas({ city,cityPath,manage,publish,read,write }: IO & { city:City;cityPath:string;manage:boolean;publish:boolean }) {
  const route = `${cityPath}/service-areas`;
  const [selected,setSelected] = useState<Area|null>(null);
  const [version,setVersion] = useState(city.version);
  return <section><h4>Зоны обслуживания</h4><Pages read={read} route={route} decoder={geoAreas} title="Загрузить зоны" loaded={(p,append) => { if (!append) { setVersion(p.version); setSelected(null); } }}
    render={v => <li key={v.id}><button onClick={() => { detail(read,`${route}/${v.id}`,geoArea,setSelected); }}>{v.code}</button>{v.archivedAt && ' · архив'}</li>}/>
    {manage && <Form title="Новая зона" submit="Создать зону" action={f => { command(write,route,{code:value(f,'code',32)},version); }}><Code/></Form>}
    {selected && <AreaCard key={selected.id} area={selected} route={`${route}/${selected.id}`} cityPath={cityPath} manage={manage && !selected.archivedAt} publish={publish && !selected.archivedAt} read={read} write={write}/>}
  </section>;
}
function AreaFields({ revision }: { revision?:AreaVersion }) {
  return <><Text name="name" label="Название зоны" value={revision?.name} max={200}/><Text name="coverageDescription" label="Описание покрытия" value={revision?.coverageDescription} max={2000} area required={false}/>
    <Text name="addressCriteria" label="Критерии адреса" value={revision?.addressCriteria} max={2000} area required={false}/></>;
}
const areaValues = (f: FormData) => ({name:value(f,'name',200),coverageDescription:optional(f,'coverageDescription'),addressCriteria:optional(f,'addressCriteria')});
function AreaCard({ area, route, cityPath, manage, publish, read, write }: IO & {area:Area;route:string;cityPath:string;manage:boolean;publish:boolean}) {
  const versions = `${route}/versions`;
  const [selected,setSelected] = useState<AreaVersion|null>(null);
  const [areaVersion,setAreaVersion] = useState(area.version);
  return <section className="panel"><h5>{area.code}{area.archivedAt && ' · архив'}</h5>
    <Pages read={read} route={versions} decoder={geoAreaVersions} title="История зоны" loaded={(p,append) => { if (!append) { setAreaVersion(p.version); setSelected(null); } }}
      render={v => <li key={v.id}><button onClick={() => { detail(read,`${versions}/${v.id}`,geoAreaVersion,setSelected); }}>{v.name} · версия {v.sequence}</button> · {v.publishedAt ? 'опубликована' : 'черновик'}</li>}/>
    {manage && <Form title="Новый черновик зоны" submit="Создать черновик зоны" action={f => { command(write,versions,areaValues(f),areaVersion); }}><AreaFields/></Form>}
    {selected && <AreaRevision key={`${selected.id}:${String(selected.version)}:${String(areaVersion)}`} revision={selected} route={`${versions}/${selected.id}`} parentRoute={route} cityPath={cityPath} manage={manage && !selected.publishedAt} publish={publish && !selected.publishedAt} areaVersion={areaVersion} read={read} write={write}/>}
    {manage && <Confirm prompt="Архивировать зону?" action={() => { command(write,`${route}/archive`,{},areaVersion); }}>Архивировать зону</Confirm>}
  </section>;
}
type FullCoverage = NonNullable<ReturnType<typeof geoCoverage>>;
export function reviewedPublication(revision: {id:string;version:number}, coverage: Pick<FullCoverage,'areaVersionId'|'version'> | null, parentVersion: number) {
  return coverage?.areaVersionId === revision.id && coverage.version === revision.version
    ? { version:revision.version, expectedAreaVersion:parentVersion } : null;
}
function AreaRevision({ revision: initial,route,parentRoute,cityPath,manage,publish,areaVersion,read,write }: IO & {revision:AreaVersion;route:string;parentRoute:string;cityPath:string;manage:boolean;publish:boolean;areaVersion:number}) {
  const coveragePath = `${route}/district-coverage`;
  const [review,setReview] = useState({revision:initial,parentVersion:areaVersion,archived:false});
  const [coverage,setCoverage] = useState<FullCoverage|null>(null);
  const { revision } = review;
  const editable = !review.archived && !revision.publishedAt;
  const publication = reviewedPublication(revision,coverage,review.parentVersion);
  const readCoverage = (raw:unknown) => { const decoded = geoCoverage(raw); return decoded?.areaVersionId === initial.id ? decoded : null; };
  function reread() {
    read(async signal => {
      const parent = await p03Read(signal,parentRoute,geoArea);
      const fresh = await p03Read(signal,route,geoAreaVersion);
      const complete = await p03Read(signal,coveragePath,readCoverage);
      const checkedParent = await p03Read(signal,parentRoute,geoArea);
      if (fresh.id !== initial.id || fresh.areaId !== parent.id || parent.id !== checkedParent.id || parent.version !== checkedParent.version || !reviewedPublication(fresh,complete,parent.version)) {
        throw new FormError('Черновик или зона меняются. Перечитайте их ещё раз перед записью.');
      }
      return {revision:fresh,coverage:complete,parentVersion:parent.version,archived:parent.archivedAt !== null};
    }, next => { setReview(next); setCoverage(next.coverage); });
  }
  return <section className="panel"><h5>{revision.name} · {revision.publishedAt ? 'опубликована' : 'черновик'}</h5><p>{revision.coverageDescription ?? 'Описание не задано'}</p><p>{revision.addressCriteria ?? 'Критерии не заданы'}</p>
    {manage && editable && <Form key={revision.version} title="Редактирование черновика зоны" submit="Сохранить черновик зоны" action={f => { command(write,route,areaValues(f),revision.version,'PATCH'); }}><AreaFields revision={revision}/></Form>}
    <button onClick={() => { detail(read,coveragePath,readCoverage,setCoverage); }}>Загрузить полное покрытие</button>
    {coverage && !publication && <p role="status">Версии черновика и покрытия различаются. Перечитайте их перед публикацией.</p>}
    {(manage || publish) && <button onClick={reread}>Перечитать черновик и покрытие</button>}
    {coverage && <Coverage key={coverage.version} coverage={coverage.items} cityPath={cityPath} manage={manage && editable} read={read}
      save={districts => { command(write,coveragePath,{districts},coverage.version,'PUT',true); }}/>}
    {publish && editable && <Confirm disabled={!publication} prompt="Опубликовать зону? Черновик и его покрытие станут неизменяемыми." action={() => {
      if (publication) { command(write,`${route}/publish`,{expectedAreaVersion:publication.expectedAreaVersion},publication.version); }
    }}>Опубликовать зону</Confirm>}
  </section>;
}
export function changeMapping(existing: readonly Mapping[], id: string, next: Mapping | null): Mapping[] {
  if (next?.districtId === id) { return existing.some(row => row.districtId === id) ? existing.map(row => row.districtId === id ? next : row) : [...existing,next]; }
  if (next === null) { return existing.filter(row => row.districtId !== id); }
  throw new FormError('Выберите доступный район.');
}
function Coverage({ coverage,cityPath,manage,read,save }: {coverage:readonly Mapping[];cityPath:string;manage:boolean;read:IO['read'];save:(rows:Mapping[])=>void}) {
  const [rows,setRows] = useState<Mapping[]>([...coverage]);
  const [districts,setDistricts] = useState<Map<string,District>>(new Map());
  const [pick,setPick] = useState<District|null>(null);
  return <section><h5>Полное покрытие районов ({rows.length} / 200)</h5>
    <ul>{rows.map(row => { const district = districts.get(row.districtId); return <li key={row.districtId}>{district?.name ?? row.districtId} · {row.relation}{row.description && ` · ${row.description}`}{district?.archivedAt && ' · архив'}
      {manage && <button type="button" onClick={() => { setRows(changeMapping(rows,row.districtId,null)); }}>Убрать из покрытия: {district?.name ?? row.districtId}</button>}</li>; })}</ul>
    {manage && <><p>Показан полный набор. Загрузка страниц списка районов не удаляет уже включённые районы. Лимит полной замены — 64 КиБ JSON (UTF-8).</p>
      <Pages read={read} route={query(`${cityPath}/administrative-districts`,{includeArchived:true})} decoder={geoDistricts} title="Загрузить районы для покрытия"
        loaded={(p,append) => { if (!append) { setPick(null); } setDistricts(new Map([...(append ? districts : new Map<string,District>()),...p.items.map(d => [d.id,d] as const)])); }}
        render={d => <li key={d.id}><button disabled={!!d.archivedAt} aria-pressed={d.id === pick?.id} onClick={() => { setPick(d); }}>{d.name}</button>{d.archivedAt && ' · архив'}</li>}/>
      {pick && <Form key={pick.id} title={`Покрытие: ${pick.name}`} submit="Применить к полному набору" action={f => {
        const next = changeMapping(rows,pick.id,{districtId:pick.id,relation:choice(f,'relation',['FULL','PARTIAL']),description:optional(f,'description')});
        if (next.length > 200) { throw new FormError('Допустимо не более 200 районов в покрытии.'); } setRows(next); setPick(null);
      }}><label>Охват<select name="relation" defaultValue={rows.find(row => row.districtId === pick.id)?.relation ?? 'FULL'}><option>FULL</option><option>PARTIAL</option></select></label>
        <Text name="description" label="Описание покрытия района" value={rows.find(row => row.districtId === pick.id)?.description} max={500} required={false}/></Form>}
      <Confirm disabled={JSON.stringify(rows) === JSON.stringify(coverage)} prompt="Заменить полный набор покрытия? Включая районы, недоступные на открытой странице списка." action={() => { save(rows); }}>Сохранить полное покрытие</Confirm>
    </>}
  </section>;
}
const technicians = (v: unknown) => decodeP03Page(v,decodeP03TechnicianPickerItem);
function Technicians({ city,cityPath,manage,read,write }: IO & {city:City;cityPath:string;manage:boolean}) {
  const [selected,setSelected] = useState<P03TechnicianPickerItem|null>(null);
  return <section><h4>Допуски мастеров</h4><Pages read={read} route={path(P03_ROUTES.technicianPicker,{cityId:city.id})} decoder={technicians} title="Загрузить мастеров города"
    loaded={(_p,append) => { if (!append) { setSelected(null); } }} render={v => <li key={v.id}><button onClick={() => { setSelected(v); }}>{v.displayName ?? v.id}</button></li>}/>
    {selected && <Technician key={selected.id} person={selected} city={city} cityPath={cityPath} manage={manage} read={read} write={write}/>}
  </section>;
}
function Technician({ person,city,cityPath,manage,read,write }: IO & {person:P03TechnicianPickerItem;city:City;cityPath:string;manage:boolean}) {
  const root = `${cityPath}/technicians/${person.id}`;
  const membership = `${root}/city-memberships`; const grants = `${root}/service-area-grants`;
  const [version,setVersion] = useState(person.version);
  const [area,setArea] = useState<Area|null>(null);
  function interval(f:FormData) {
    const validFrom = instant(f,'validFrom',true); const validTo = instant(f,'validTo');
    if (validTo && Date.parse(validFrom) >= Date.parse(validTo)) { throw new FormError('Конец допуска должен быть позже начала.'); }
    return {validFrom,validTo};
  }
  const revoke = (route:string, id:string) => <Confirm prompt="Отозвать допуск? История сохранится." action={() => { staffCommand(write,`${route}/${id}/revoke`,{},version); }}>Отозвать допуск</Confirm>;
  return <article className="panel"><h5>Мастер: {person.displayName ?? person.id}</h5>
    <Pages read={read} route={membership} decoder={geoTechCities} title="История допуска в город" loaded={(p,append) => { if (!append) { setVersion(p.version); } }}
      render={m => <li key={m.id}>{m.validFrom} – {m.validTo ?? 'без окончания'}{m.revokedAt ? ' · отозван' : m.active ? ' · действующий' : ' · не действует сейчас'}{manage && !m.revokedAt && revoke(membership,m.id)}</li>}/>
    <Pages read={read} route={grants} decoder={geoTechAreas} title="История допуска в зоны" loaded={(p,append) => { if (!append) { setVersion(p.version); } }}
      render={m => <li key={m.id}>{m.areaId} · {m.validFrom} – {m.validTo ?? 'без окончания'}{m.revokedAt ? ' · отозван' : m.active ? ' · действующий' : ' · не действует сейчас'}{manage && !m.revokedAt && revoke(grants,m.id)}</li>}/>
    {manage && city.lifecycle === 'ACTIVE' && <><Form title="Допуск мастера в город" submit="Выдать допуск в город" prompt="Выдать допуск в этот город на указанный период?" action={f => { staffCommand(write,membership,interval(f),version); }}><IntervalFields/></Form>
      <Pages read={read} route={query(`${cityPath}/service-areas`,{includeArchived:false})} decoder={geoAreas} title="Загрузить зоны для допуска" render={v => <li key={v.id}>
        <button disabled={!v.currentVersionId} aria-pressed={v.id === area?.id} onClick={() => { setArea(v); }}>{v.code}</button></li>}/>
      {area && <Form key={area.id} title={`Допуск в зону: ${area.code}`} submit="Выдать допуск в зону" prompt="Выдать допуск в зону на указанный период?" action={f => {
        staffCommand(write,grants,{...interval(f),areaId:area.id},version);
      }}><IntervalFields/></Form>}
    </>}
  </article>;
}
function IntervalFields() { return <><Text name="validFrom" label="Начало допуска (ISO 8601 с зоной)" max={29}/><Text name="validTo" label="Конец допуска (ISO 8601 с зоной)" max={29} required={false}/></>; }
function Administrators({ data,city,cityPath,read,write }: IO & {data:Snapshot;city:City;cityPath:string}) {
  const eligible = data.people.filter(p => p.id !== data.access.staffId && p.role !== 'TECHNICIAN');
  const [person,setPerson] = useState<typeof eligible[number]|null>(null);
  return <section><h4>Административные назначения</h4><p>Территория не выдаёт новых возможностей роли. Для расширения области CITY сервер проверит каждое право.</p>
    {eligible.length ? <label>Сотрудник с веб-доступом<select value={person?.id ?? ''} onChange={e => { setPerson(eligible.find(p => p.id === e.currentTarget.value) ?? null); }}>
      <option value="">Выберите сотрудника</option>{eligible.map(p => <option key={p.id} value={p.id}>{p.displayName ?? p.id}</option>)}</select></label> : <p>Нет доступных целей в текущем списке сотрудников.</p>}
    {person && <AdminTarget key={person.id} person={person} city={city} route={`${cityPath}/administrators/${person.id}/assignments`} read={read} write={write}/>}
  </section>;
}
function AdminTarget({ person,city,route,read,write }: IO & {person:Snapshot['people'][number];city:City;route:string}) {
  const [version,setVersion] = useState<number|null>(null);
  const [assigned,setAssigned] = useState(false);
  return <><Pages read={read} route={route} decoder={geoAdmins} title="Загрузить назначения" loaded={(p,append) => {
    if (!append) { setVersion(p.version); setAssigned(false); } if (p.items.some(g => g.active)) { setAssigned(true); }
  }} render={m => <li key={m.id}>{m.grantedAt} · {m.active ? 'действует' : 'отозвано'}
    {m.active && <Confirm prompt="Отозвать административное назначение?" action={() => { if (version !== null) { staffCommand(write,`${route}/${m.id}/revoke`,{},version); } }}>Отозвать назначение</Confirm>}</li>}/>
    {version !== null && !assigned && city.lifecycle === 'ACTIVE' && person.employmentState === 'ACTIVE' && <Confirm prompt="Назначить сотруднику этот административный город? Это расширяет территорию уже имеющихся прав CITY." action={() => { staffCommand(write,route,{},version); }}>Назначить административный город</Confirm>}</>;
}
