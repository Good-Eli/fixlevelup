'use client';
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage, type Client, type Person, type Role } from './api';
import { load, type Snapshot, type Write } from './workspace';
import { People } from './people';
import { Roles } from './roles';

type Screen = 'checking'|'login'|'closed'|'ready';
export default function Desk() {
  const [screen, setScreen] = useState<Screen>('checking');
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [section, setSection] = useState<'people'|'roles'>('people');
  const [person, setPerson] = useState<Person | null>(null);
  const [role, setRole] = useState<Role | null>(null);
  const [members, setMembers] = useState<Person[] | null>(null);
  const [revision, bump] = useState(0);
  // One in-flight operation for the entire desk, including detail reads and logout.
  // Abort on unmount; a late completion must never reinstate an old session or card.
  const pending = useRef<AbortController | null>(null);
  const session = useRef<{ staffId: string; csrf: string } | null>(null);
  function clear() { setSnapshot(null); setPerson(null); setRole(null); setMembers(null); }
  async function refresh(signal: AbortSignal, expectedActor?: string) {
    const identity = await api(signal).me();
    signal.throwIfAborted();
    if (expectedActor && identity.staffId !== expectedActor) { throw new Error('Session changed'); }
    session.current = identity;
    const data = await load(api(signal, identity.csrf), identity.staffId);
    signal.throwIfAborted(); clear(); setSnapshot(data); setScreen('ready'); bump(n => n + 1);
  }
  function run(action: (signal: AbortSignal) => Promise<void>, mode: 'login'|'check'|'operation' = 'operation') {
    if (pending.current) { return; }
    const controller = new AbortController(); const signal = controller.signal;
    pending.current = controller; setBusy(true); setNote('');
    void (async () => {
      try { await action(signal); }
      catch (e) {
        if (signal.aborted) { return; }
        const expired = e instanceof ApiError && e.status === 401;
        if (expired) {
          clear(); session.current = null; setScreen('login');
          setNote(mode === 'login' ? 'Вход не выполнен. Проверьте логин и пароль.' : mode === 'check' ? '' : errorMessage(e));
        } else if (mode === 'login' && !session.current) { setScreen('login'); setNote(errorMessage(e)); }
        else {
          clear(); setScreen('closed'); setNote(errorMessage(e));
          // Re-evaluate rights and versions after rejection. Never retry a mutation.
          if (mode === 'operation' && e instanceof ApiError && [403,404,409,412,428].includes(e.status)) {
            try { await refresh(signal); }
            catch (again) { if (pending.current === controller && again instanceof ApiError && again.status === 401) { session.current = null; setScreen('login'); } }
          }
        }
      } finally { if (pending.current === controller) { pending.current = null; setBusy(false); } }
    })();
  }
  useEffect(() => {
    run(refresh, 'check');
    return () => { pending.current?.abort(); pending.current = null; session.current = null; };
  }, []);
  function client(signal: AbortSignal) { return api(signal, session.current?.csrf); }
  const write: Write = (call, success, showReceipt) => { run(async signal => {
    const actor = session.current?.staffId;
    if (!actor) { throw new Error('Missing actor'); }
    const receipt = await call(client(signal)); signal.throwIfAborted(); clear(); setScreen('checking');
    try {
      await refresh(signal, actor); signal.throwIfAborted();
      setNote(showReceipt ? `${success} ID: ${receipt.id}. Версия: ${String(receipt.version)}.` : success);
    } catch {
      signal.throwIfAborted();
      clear(); session.current = null; setScreen('login');
      setNote('Сервер подтвердил операцию, но рабочая сессия больше не подтверждена. Идентификатор результата скрыт; не отправляйте операцию повторно.');
    }
  }); };
  function readCard<T>(call: (c: Client) => Promise<T>, show: (v: T) => void) {
    run(async signal => { const value = await call(client(signal)); signal.throwIfAborted(); show(value); });
  }
  return <main className="desk">
    <header><p className="eyebrow">FixLevelUp · закрытая CRM</p><h1>Сотрудники и доступ</h1></header>
    {note && <p className="notice" role="status">{note}</p>}
    {busy && <p role="status">Загрузка…</p>}
    {screen === 'login' && <form className="panel" onSubmit={e => {
      e.preventDefault(); const form = e.currentTarget; const values = new FormData(form);
      const login = values.get('login'); const password = values.get('password'); form.reset();
      if (typeof login !== 'string' || typeof password !== 'string') { return; }
      run(async signal => { const result = await api(signal).login(login, password); signal.throwIfAborted(); session.current = result; await refresh(signal); }, 'login');
    }}><h2>Вход для сотрудников</h2><label>Логин<input name="login" autoComplete="username" required maxLength={1024}/></label>
      <label>Пароль<input type="password" name="password" autoComplete="current-password" required maxLength={1024}/></label>
      <button disabled={busy}>Войти</button></form>}
    {screen === 'closed' && <h2>Рабочая область закрыта</h2>}
    {(screen === 'ready' || screen === 'closed') && <div className="actions"><button disabled={busy} onClick={() => { clear(); setScreen('checking'); run(refresh, 'check'); }}>Обновить доступ</button>
      {session.current && <button disabled={busy} onClick={() => { run(async signal => { await client(signal).logout(); signal.throwIfAborted(); clear(); session.current = null; setScreen('login'); setNote('Вы вышли из CRM.'); }); }}>Выйти</button>}</div>}
    {screen === 'ready' && snapshot && <fieldset disabled={busy} className="workspace" key={revision}>
      <p>Текущая роль: <strong>{snapshot.access.role.code}</strong></p>
      <nav aria-label="Разделы управления"><button aria-pressed={section === 'people'} onClick={() => { setSection('people'); setNote(''); }}>Сотрудники</button>
        <button aria-pressed={section === 'roles'} onClick={() => { setSection('roles'); setNote(''); }}>Роли и возможности</button></nav>
      {section === 'people' ? <People data={snapshot} selected={person} open={id => { readCard(c => c.person(id), setPerson); }} write={write}/>
        : <Roles data={snapshot} selected={role} members={members} write={write} open={id => { readCard(c => c.role(id), r => { setMembers(null); setRole(r); }); }}
            openMembers={id => { readCard(c => c.members(id), setMembers); }}/>} </fieldset>}
  </main>;
}
