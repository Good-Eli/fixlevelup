import { useState } from 'react';
import { isP03Capability } from '@fixlevelup/p03-contracts';
import type { Grant, Person, Role } from './api';
import { allowedScopes, canEditGrant, fields, has, hasP03, p03ReplacementAllowed, protects, roleLabel, type Snapshot, type Write } from './workspace';

type Props = { data: Snapshot; selected: Role | null; members: Person[] | null; open: (id: string) => void; openMembers: (id: string) => void; write: Write };
function RoleFields({ role }: { role?: Role }) {
  return <><label>Название<input name="name" defaultValue={role?.name} required maxLength={80}/></label>
    <label>Описание<textarea name="description" defaultValue={role?.description ?? ''} maxLength={500}/></label></>;
}
function RoleCard({ data, role, members, openMembers, write }: Omit<Props,'selected'|'open'> & {role:Role}) {
  const a = data.access; const active = role.status === 'ACTIVE';
  const [chosen, choose] = useState(() => new Map<string, Grant['scope']>(role.permissions.map(p => [p.code, p.scope])));
  const original = new Map(role.permissions.map(p => [p.code, p.scope]));
  const dirty = chosen.size !== original.size || [...chosen].some(([k, v]) => original.get(k) !== v);
  const known = [...original.keys()].every(k => data.catalog.some(p => k === p.code));
  const modules = [...new Set(data.catalog.map(p => p.module))];
  const grants = data.catalog.flatMap(p => { const scope = chosen.get(p.code); return scope === undefined ? [] : [{ code: p.code, scope }]; });
  const changedP03 = grants.filter(g => isP03Capability(g.code) && original.get(g.code) !== g.scope);
  const scopeDetails = changedP03.map(g => `${g.code} · ${g.scope}`).join(', ');
  const roleWide = `${scopeDetails}. Права получат все нынешние и будущие сотрудники этой роли, а не выбранный сотрудник. CITY действует в назначенных каждому городах; GLOBAL — без географической границы. Отзыв личного права основателя не снимет эти права роли.`;
  const impact = role.assignedCount === null ? 'Количество назначенных сотрудников скрыто правами доступа' : `Назначено сотрудников: ${String(role.assignedCount)}; активных: ${String(role.activeAssignedCount)} (в видимой области на момент загрузки)`;
  return <article className="panel"><h3>{role.name}</h3><p>{role.description || 'Без описания'}</p><dl>
    <dt>Код</dt><dd>{role.code}</dd><dt>Тип и статус</dt><dd>{role.type === 'SYSTEM' ? 'Системная' : 'Пользовательская'} · {active ? 'активна' : 'архивирована'}</dd>
    <dt>Версия</dt><dd>{role.version}</dd><dt>Последнее изменение</dt><dd>{role.updatedAt}{role.updatedBy && ` · ${role.updatedBy}`}</dd></dl><p>{impact}.</p>
    {active && role.type === 'CUSTOM' && protects(a,'roles.update') && <form onSubmit={e => {
      e.preventDefault(); const name = fields(e.currentTarget,'name'); const description = fields(e.currentTarget,'description');
      write(c => c.editRole(role,name,description), 'Описание роли обновлено.');
    }}><RoleFields role={role}/><button>Сохранить сведения</button></form>}
    <h4>Возможности по модулям</h4><p>SELF — только свой профиль; CITY — только назначенные сотруднику города; GLOBAL — без географической границы. Географические права выдаются отдельно: у неадминистративной роли допустим только CITY, а публикация и GLOBAL — только у системной роли «Администратор». Действия независимы: выбор не добавляет другие права. Новое право можно выдать только при наличии его у вас. Для операций с сотрудниками у неадминистраторов цель — только системная роль «Мастер».</p>
    {role.id === a.role.id && role.type === 'SYSTEM' && <p className="notice">Снятое у собственной роли ADMIN обычное право нельзя восстановить самовыдачей через этот редактор.</p>}
    {modules.map(module => <fieldset key={module}><legend>{module}</legend>{data.catalog.filter(p => p.module === module).map(p => {
      const scopes = allowedScopes(role, p);
      const current = chosen.get(p.code);
      return <label className="permission" key={p.code}>
        <input type="checkbox" checked={current !== undefined} disabled={!known || !canEditGrant(a,role,p,p.protected)} onChange={e => {
          const selected = e.currentTarget.checked; choose(prev => { const next = new Map(prev); if (selected) { next.set(p.code, scopes[0] ?? p.scope); } else { next.delete(p.code); } return next; });
        }}/><span>{p.description}<small>{p.code} · {current ?? (scopes.length > 1 ? scopes.join('/') : p.scope)}{p.protected ? ' · защищённая возможность' : ''}</small></span>
        {current !== undefined && scopes.length > 1 && <select aria-label={`Область ${p.code}`} value={current} disabled={!canEditGrant(a,role,p,p.protected) || (isP03Capability(p.code) && !hasP03(a, p.code, 'GLOBAL'))} onChange={e => {
          const value = e.currentTarget.value as Grant['scope']; choose(prev => { const next = new Map(prev); next.set(p.code, value); return next; });
        }}>{scopes.map(s => <option key={s} value={s}>{s}</option>)}</select>}
      </label>;
    })}</fieldset>)}
    {changedP03.length > 0 && <p className="notice">{roleWide}</p>}
    {active && protects(a,'roles.permissions.manage') && <button disabled={!dirty || !known || !p03ReplacementAllowed(a, role, grants)} onClick={() => {
      const effect = changedP03.length ? ` ${roleWide}` : '';
      if (window.confirm(`Изменить права роли «${role.name}»? ${impact}. Новые права применятся немедленно.${effect}`)) { write(c => c.permissions(role,grants), 'Возможности роли обновлены.'); }
    }}>Сохранить возможности</button>}
    {has(a,'staff.read') && <section><h4>Назначенные сотрудники</h4><button onClick={() => { openMembers(role.id); }}>Показать сотрудников роли</button>
      {members && (members.length ? <ul>{members.map(p => <li key={p.id}>{p.displayName ?? p.id} · {p.employmentState}</li>)}</ul> : <p>В доступной области сотрудников нет.</p>)}</section>}
    {active && role.type === 'CUSTOM' && protects(a,'roles.archive') && <><p>Нельзя архивировать роль, пока она назначена активным сотрудникам.</p>
      <button className="danger" disabled={role.activeAssignedCount !== null && role.activeAssignedCount > 0} onClick={() => {
        if (window.confirm(`Архивировать «${role.name}»? ${impact}. Роль нельзя будет назначать сотрудникам.`)) { write(c => c.archive(role), 'Роль архивирована.'); }
      }}>Архивировать роль</button></>}
  </article>;
}
export function Roles({ data, selected, members, open, openMembers, write }: Props) {
  const a = data.access; return <section><h2>Роли и возможности</h2>
    {protects(a,'roles.create') && <form className="panel" onSubmit={e => { e.preventDefault(); const name = fields(e.currentTarget,'name');
      const description = fields(e.currentTarget,'description'); write(c => c.createRole(name,description), 'Пользовательская роль создана без разрешений.', true);
    }}><h3>Новая пользовательская роль</h3><RoleFields/><button>Создать роль</button></form>}
    {!has(a, 'roles.read') ? <p>Для текущей роли каталог и карточки ролей закрыты.</p> : <section className="panel"><h3>Каталог ролей ({data.roles.length})</h3>
      <ul>{data.roles.map(r => <li key={r.id}><button onClick={() => { open(r.id); }}>{roleLabel(r)}</button> · {r.status === 'ACTIVE' ? 'активна' : 'архивирована'}</li>)}</ul></section>}
    {selected && <RoleCard key={`${selected.id}:${String(selected.version)}`} role={selected} data={data} members={members} openMembers={openMembers} write={write}/>}
  </section>;
}
