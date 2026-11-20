import { useState } from 'react';
import { uuidPattern, type Person } from './api';
import { admin, canTarget, delegable, fields, has, protects, roleLabel, type Snapshot, type Write } from './workspace';

type Subject = { id: string; label: string; version: number; self: boolean; displayName: string; roleId?: string };
function Actions({ data, target, write }: { data: Snapshot; target: Subject; write: Write }) {
  const a = data.access; const path = target.self ? 'self' : target.id;
  const available = data.roles.filter(r => delegable(a,r) && r.id !== target.roleId);
  return <div className="actions-stack">
    {has(a, target.self ? 'staff.self.update' : 'staff.update') && <form onSubmit={e => {
      e.preventDefault(); const value = fields(e.currentTarget, 'name'); write(c => c.rename(path, target.version, value), 'Имя сотрудника обновлено.');
    }}><label>Новое отображаемое имя<input name="name" defaultValue={target.displayName} required maxLength={80}/></label><button>Сохранить имя</button></form>}
    {!target.self && protects(a, 'staff.role.assign') && <form onSubmit={e => {
      e.preventDefault(); const roleId = fields(e.currentTarget, 'roleId'); const choice = available.find(r => r.id === roleId);
      if (has(a,'roles.read') && !choice) { return; }
      const label = choice ? roleLabel(choice) : `UUID ${roleId} (просмотр роли недоступен)`;
      if (window.confirm(`Сменить роль на «${label}»? Затронут 1 сотрудник: ${target.label}. Прежние сессии будут отозваны. Назначение не создаёт новый способ входа; для ADMIN нужны существующие CRM-учётные данные.`)) {
        write(c => c.assign(path, target.version, roleId), 'Основная роль сотрудника изменена.');
      }
    }}><label>Новая роль{has(a, 'roles.read') ? <select name="roleId" defaultValue="" required><option value="" disabled>Выберите роль</option>
      {available.map(r => <option key={r.id} value={r.id}>{roleLabel(r)}</option>)}</select> : <input name="roleId" placeholder="Известный UUID роли" pattern={uuidPattern} required/>}</label><button>Сменить роль</button></form>}
    {has(a, target.self ? 'staff.self.deactivate' : 'staff.deactivate') && <button className="danger" onClick={() => {
      if (window.confirm(`Деактивировать ${target.label}? Затронут 1 сотрудник. Доступ к CRM и Mini App будет отозван. Последнего администратора деактивировать нельзя.`)) {
        write(c => c.deactivate(path, target.version), 'Сотрудник деактивирован.');
      }
    }}>Деактивировать{target.self ? ' свой профиль' : ' сотрудника'}</button>}
  </div>;
}
function Card({ data, person, write }: { data: Snapshot; person: Person; write: Write }) {
  const self = person.id === data.access.staffId;
  const label = person.displayName ?? person.id;
  return <article className="panel"><h3>{self ? 'Мой профиль' : 'Карточка сотрудника'}: {label}</h3>
    <dl><dt>Идентификатор</dt><dd>{person.id}</dd><dt>Основная роль</dt><dd>{person.roleName} · {person.role}</dd>
    <dt>Состояние</dt><dd>{person.employmentState === 'ACTIVE' ? 'Активен' : 'Неактивен'}</dd><dt>Версия</dt><dd>{person.version}</dd></dl>
    {(self || canTarget(data.access, person)) && person.employmentState === 'ACTIVE' && <Actions data={data} write={write} target={{self, label, id:person.id, version:person.version, displayName:person.displayName ?? '', roleId:person.roleId}}/>}
  </article>;
}
function KnownTarget({ data, self, write }: { data: Snapshot; self: boolean; write: Write }) {
  const [target, setTarget] = useState<Subject | null>(null);
  return <section className="panel"><h3>{self ? 'Мой профиль без права просмотра' : 'Адресное действие без списка'}</h3>
    <p>Нужна известная версия карточки. Данные не запрашиваются; допустимость операции проверит сервер.</p>
    {!target ? <form onSubmit={e => {
      e.preventDefault(); const id = self ? data.access.staffId : fields(e.currentTarget, 'id').toLowerCase();
      if (!self && id === data.access.staffId) { (e.currentTarget.elements.namedItem('id') as HTMLInputElement).setCustomValidity('Используйте действие своего профиля.'); e.currentTarget.reportValidity(); return; }
      const version = Number(fields(e.currentTarget, 'version')); setTarget({id, self, label:self ? 'свой профиль' : id, version, displayName:''});
    }}>{!self && <label>UUID сотрудника<input name="id" required pattern={uuidPattern} onInput={e => { e.currentTarget.setCustomValidity(''); }}/></label>}
    <label>Известная версия<input name="version" type="number" min="0" step="1" max={Number.MAX_SAFE_INTEGER} required/></label><button>Выбрать цель</button></form>
    : <><p>{target.label} · версия {target.version}</p><Actions data={data} target={target} write={write}/><button onClick={() => { setTarget(null); }}>Отменить выбор</button></>}
  </section>;
}
export function People({ data, selected, open, write }: { data: Snapshot; selected: Person | null; open: (id: string) => void; write: Write }) {
  const a = data.access;
  const initial = (['TECHNICIAN','MANAGER'] as const).filter(code =>
    (code === 'TECHNICIAN' || protects(a,'staff.role.assign')) && (!has(a,'roles.read') || data.roles.some(r => r.code === code && r.type === 'SYSTEM' && delegable(a,r))));
  return <section><h2>Сотрудники</h2>
    {data.self && <details><summary>Мой профиль</summary><Card data={data} person={data.self} write={write}/></details>}
    {!data.self && (has(a,'staff.self.update') || has(a,'staff.self.deactivate')) && <KnownTarget self data={data} write={write}/>}
    {has(a,'staff.create') && <form className="panel" onSubmit={e => {
      e.preventDefault(); const role = fields(e.currentTarget, 'role'); const name = fields(e.currentTarget,'name');
      if (role === 'TECHNICIAN' || role === 'MANAGER') { write(c => c.createPerson(role, name), 'Профиль сотрудника создан.', true); }
    }}><h3>Новый сотрудник</h3><label>Имя (необязательно)<input name="name" maxLength={80}/></label>
    <label>Начальная роль<select name="role" required>{initial.map(code => <option key={code} value={code}>{code === 'TECHNICIAN' ? 'Мастер' : 'Менеджер'} · {code} · системная</option>)}</select></label>
    <small>{initial.length ? 'Создаётся профиль, а не учётные данные для входа.' : 'Нет доступной начальной роли с передаваемыми правами.'}</small><button disabled={!initial.length}>Создать сотрудника</button></form>}
    {!admin(a) && <p>Действия над другими сотрудниками ограничены системной ролью «Мастер».</p>}
    {has(a, 'staff.read') ? <section className="panel"><h3>Доступные сотрудники ({data.people.length})</h3>
      {!data.people.length && <p>Нет доступных сотрудников.</p>}<ul>{data.people.map(p => <li key={p.id}><button onClick={() => { open(p.id); }}>{p.displayName ?? p.id}</button> · {p.roleName} · {p.employmentState === 'ACTIVE' ? 'активен' : 'неактивен'}</li>)}</ul></section>
      : <><p>Для текущей роли список сотрудников закрыт.</p>{(has(a,'staff.update') || has(a,'staff.deactivate') || protects(a,'staff.role.assign')) && <KnownTarget data={data} self={false} write={write}/>}</>}
    {selected && <Card key={`${selected.id}:${String(selected.version)}`} data={data} person={selected} write={write}/>}
  </section>;
}
