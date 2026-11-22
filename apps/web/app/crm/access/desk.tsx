'use client';
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage, type Client, type Identity, type Person, type Role } from './api';
import { load, type Snapshot, type Write } from './workspace';
import { People } from './people';
import { Roles } from './roles';
import { P03Desk, p03Tabs, type P03Section } from './management';
import { FormError, SessionChanged, guardedRead, isUncertain, prepareCommand, proveSession, sendCommand, type CommandSpec, type PreparedCommand } from './p0305-client';

type Screen = 'checking'|'login'|'closed'|'ready'|'uncertain';
const confirmationMissing = 'Сервер подтвердил операцию, но рабочая сессия больше не подтверждена. Идентификатор результата скрыт; не отправляйте операцию повторно. Войдите снова или обновите страницу.';
const outcomeUnknown = 'Результат операции не подтверждён. Не создавайте новую команду. Можно явно проверить или повторить тот же запрос.';
export default function Desk() {
  const [screen, setScreen] = useState<Screen>('checking');
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [section, setSection] = useState<'people'|'roles'|P03Section>('people');
  const [person, setPerson] = useState<Person | null>(null);
  const [role, setRole] = useState<Role | null>(null);
  const [members, setMembers] = useState<Person[] | null>(null);
  const [revision, bump] = useState(0);
  const pending = useRef<AbortController | null>(null);
  const uncertain = useRef<PreparedCommand | null>(null);
  const session = useRef<Identity | null>(null);
  function clear() { setSnapshot(null); setPerson(null); setRole(null); setMembers(null); }
  function forget() { clear(); session.current = null; uncertain.current = null; }
  async function refresh(signal: AbortSignal, expected?: Identity) {
    const identity = expected ? await proveSession(signal, expected) : await api(signal).me();
    signal.throwIfAborted();
    session.current = identity;
    const data = await load(api(signal, identity.csrf), identity.staffId);
    if (expected) { await proveSession(signal, identity); }
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
        if (e instanceof FormError) { setNote(e.message); return; }
        const expired = e instanceof ApiError && e.status === 401;
        if (expired || e instanceof SessionChanged) {
          forget(); setScreen('login');
          setNote(e instanceof SessionChanged ? 'Рабочая сессия изменилась. Войдите снова.' : mode === 'login' ? 'Вход не выполнен. Проверьте логин и пароль.' : mode === 'check' ? '' : errorMessage(e));
        } else if (mode === 'login' && !session.current) { setScreen('login'); setNote(errorMessage(e)); }
        else {
          const expected = session.current;
          uncertain.current = null; clear(); setScreen('closed'); setNote(errorMessage(e));
          // Re-evaluate rights and versions after rejection. Never retry a mutation.
          if (mode === 'operation' && expected && e instanceof ApiError && [403,404,409,412,428].includes(e.status)) {
            try { await refresh(signal, expected); }
            catch (again) {
              if (pending.current !== controller) { return; }
              if (again instanceof SessionChanged || (again instanceof ApiError && again.status === 401)) { forget(); setScreen('login'); }
            }
          }
        }
      } finally { if (pending.current === controller) { pending.current = null; setBusy(false); } }
    })();
  }
  useEffect(() => {
    run(refresh, 'check');
    return () => { pending.current?.abort(); pending.current = null; session.current = null; uncertain.current = null; };
  }, []);
  function client(signal: AbortSignal) { return api(signal, session.current?.csrf); }
  const write: Write = (call, success, showReceipt) => { run(async signal => {
    const actor = session.current;
    if (!actor) { throw new SessionChanged(); }
    const receipt = await call(client(signal)); signal.throwIfAborted(); clear(); setScreen('checking');
    try {
      await refresh(signal, actor); signal.throwIfAborted();
      setNote(showReceipt ? `${success} ID: ${receipt.id}. Версия: ${String(receipt.version)}.` : success);
    } catch {
      signal.throwIfAborted(); forget(); setScreen('login'); setNote(confirmationMissing);
    }
  }); };
  function readCard<T>(call: (c: Client) => Promise<T>, show: (v: T) => void) {
    run(async signal => { const value = await call(client(signal)); signal.throwIfAborted(); show(value); });
  }
  function readP03<T>(call: (signal: AbortSignal) => Promise<T>, show: (v: T) => void) {
    run(async signal => {
      const actor = session.current;
      if (!actor) { throw new SessionChanged(); }
      const value = await guardedRead(signal, actor, call);
      signal.throwIfAborted(); show(value);
    });
  }
  async function execute(signal: AbortSignal, command: PreparedCommand, retry: boolean) {
    let current: Identity;
    try { current = await proveSession(signal, command.actor); }
    catch (e) {
      signal.throwIfAborted();
      if (retry && isUncertain(e) && !(e instanceof SessionChanged)) { setNote(outcomeUnknown); return; }
      throw e;
    }
    try { await sendCommand(signal, current, command); }
    catch (e) {
      signal.throwIfAborted();
      if (isUncertain(e) && !(e instanceof SessionChanged)) {
        uncertain.current = command; clear(); setScreen('uncertain'); setNote(outcomeUnknown); return;
      }
      uncertain.current = null;
      throw e;
    }
    signal.throwIfAborted(); uncertain.current = null; clear(); setScreen('checking');
    try { await refresh(signal, current); setNote('Операция подтверждена сервером. Доступ обновлён; загрузите актуальную карточку.'); }
    catch { signal.throwIfAborted(); forget(); setScreen('login'); setNote(confirmationMissing); }
  }
  function writeP03(spec: CommandSpec, body: object) {
    if (uncertain.current) { return; }
    run(async signal => {
      if (!session.current) { throw new SessionChanged(); }
      await execute(signal, prepareCommand(spec, body, session.current), false);
    });
  }
  function logout() {
    const identity = session.current;
    pending.current?.abort(); pending.current = null; forget(); setScreen('checking');
    run(async signal => {
      if (identity) { await api(signal, identity.csrf).logout(); }
      signal.throwIfAborted(); setScreen('login'); setNote('Вы вышли из CRM.');
    });
  }
  const sections = snapshot ? p03Tabs(snapshot.access) : [];
  const visibleSection = section === 'people' || section === 'roles' || sections.some(tab => tab.id === section) ? section : 'people';
  return <main className="desk">
    <header><p className="eyebrow">FixLevelUp · закрытая CRM</p><h1>Сотрудники и доступ</h1></header>
    {note && <p className="notice" role="status">{note}</p>}
    {busy && <p role="status">Загрузка…</p>}
    {screen === 'login' && <form className="panel" onSubmit={e => {
      e.preventDefault(); const form = e.currentTarget; const values = new FormData(form);
      const login = values.get('login'); const password = values.get('password'); form.reset();
      if (typeof login !== 'string' || typeof password !== 'string') { return; }
      run(async signal => { const result = await api(signal).login(login, password); signal.throwIfAborted(); session.current = result; await refresh(signal, result); }, 'login');
    }}><h2>Вход для сотрудников</h2><label>Логин<input name="login" autoComplete="username" required maxLength={1024}/></label>
      <label>Пароль<input type="password" name="password" autoComplete="current-password" required maxLength={1024}/></label>
      <button disabled={busy}>Войти</button></form>}
    {screen === 'closed' && <h2>Рабочая область закрыта</h2>}
    {(screen === 'ready' || screen === 'closed' || screen === 'uncertain') && <div className="actions">
      {screen === 'uncertain' ? <button disabled={busy} onClick={() => { const command = uncertain.current; if (command) { run(signal => execute(signal, command, true)); } }}>Проверить / повторить</button>
        : <button disabled={busy} onClick={() => { clear(); setScreen('checking'); run(refresh, 'check'); }}>Обновить доступ</button>}
      {session.current && <button onClick={logout}>Выйти</button>}</div>}
    {screen === 'ready' && snapshot && <fieldset disabled={busy} className="workspace" key={revision}>
      <p>Текущая роль: <strong>{snapshot.access.role.code}</strong></p>
      <nav aria-label="Разделы управления"><button aria-pressed={visibleSection === 'people'} onClick={() => { setSection('people'); setNote(''); }}>Сотрудники</button>
        <button aria-pressed={visibleSection === 'roles'} onClick={() => { setSection('roles'); setNote(''); }}>Роли и возможности</button>
        {sections.map(tab => <button key={tab.id} aria-pressed={visibleSection === tab.id} onClick={() => { setSection(tab.id); setNote(''); }}>{tab.label}</button>)}
      </nav>
      {visibleSection === 'people' ? <People data={snapshot} selected={person} open={id => { readCard(c => c.person(id), setPerson); }} write={write}/>
        : visibleSection === 'roles' ? <Roles data={snapshot} selected={role} members={members} write={write} open={id => { readCard(c => c.role(id), r => { setMembers(null); setRole(r); }); }}
          openMembers={id => { readCard(c => c.members(id), setMembers); }}/>
          : <P03Desk key={visibleSection} data={snapshot} section={visibleSection} read={readP03} write={writeP03}/>} </fieldset>}
  </main>;
}
