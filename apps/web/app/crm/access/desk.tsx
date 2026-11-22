'use client';
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage, type Access, type Client, type Identity, type Person, type Role } from './api';
import { load, type Snapshot, type Write } from './workspace';
import { People } from './people';
import { Roles } from './roles';
import { P03Desk, p03Tabs, type P03Section } from './management';
import { FormError, SessionChanged, guardedRead, isUncertain, prepareCommand, proveSession, sameSession, sendCommand, type CommandSpec, type PreparedCommand } from './p0305-client';
import { prepareP04Command, readP04, sendPreparedP04, type P04IO, type PreparedP04 } from './p04/client';
import { P04DraftContext, type Draft } from './p04/shared';
import { P04Desk, p04Tabs, type P04Section } from './p04/workspace';

type Screen = 'checking'|'login'|'closed'|'ready'|'uncertain';
type Pending = { readonly slice: 'P03'; readonly command: PreparedCommand }
  | { readonly slice: 'P04'; readonly command: PreparedP04; readonly access: string; readonly draft: Draft | null };

function catalogAccess(access: Access): string {
  const grants = access.p04Permissions?.map(g => `${g.code}:${g.scope}`).sort() ?? [];
  return JSON.stringify([access.staffId, access.role.id, access.role.type, access.role.code,
    grants, [...access.p04PricingWriteCityIds ?? []].sort()]);
}
function catalogMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) { return 'Конфликт состояния. Операция не выполнена. Сверьте действующие версии и периоды.'; }
    if (error.status === 413) { return 'Сервер отклонил слишком большой запрос.'; }
  }
  return errorMessage(error);
}
const confirmationMissing = 'Сервер подтвердил операцию, но рабочая сессия больше не подтверждена. Идентификатор результата скрыт; не отправляйте операцию повторно. Войдите снова или обновите страницу.';
const outcomeUnknown = 'Результат операции не подтверждён. Не создавайте новую команду. Можно явно проверить или повторить тот же запрос.';
const retryClosed = 'Повтор не подтверждён. Исходная операция могла выполниться. Не создавайте новую команду вместо неё; сначала сверьте доступную историю.';
class CatalogAccessChanged extends Error {}
class CatalogRetryClosed extends Error {}
export default function Desk() {
  const [screen, setScreen] = useState<Screen>('checking');
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [section, setSection] = useState<'people'|'roles'|P03Section|P04Section>('people');
  const [draft, setDraft] = useState<Draft | null>(null);
  const [person, setPerson] = useState<Person | null>(null);
  const [role, setRole] = useState<Role | null>(null);
  const [members, setMembers] = useState<Person[] | null>(null);
  const [revision, bump] = useState(0);
  const pending = useRef<AbortController | null>(null);
  const uncertain = useRef<Pending | null>(null);
  const session = useRef<Identity | null>(null);
  const submitted = useRef<Draft | null>(null);
  function clear() { setSnapshot(null); setPerson(null); setRole(null); setMembers(null); }
  function forget() { clear(); session.current = null; uncertain.current = null; submitted.current = null; setDraft(null); }
  async function refresh(signal: AbortSignal, expected?: Identity) {
    const identity = expected ? await proveSession(signal, expected) : await api(signal).me();
    signal.throwIfAborted();
    if (session.current && !sameSession(session.current, identity)) { setDraft(null); }
    session.current = identity;
    const data = await load(api(signal, identity.csrf), identity.staffId);
    if (expected) { await proveSession(signal, identity); }
    signal.throwIfAborted(); clear(); setSnapshot(data); setScreen('ready'); bump(n => n + 1);
  }
  function run(action: (signal: AbortSignal) => Promise<void>, mode: 'login'|'check'|'operation'|'catalog' = 'operation') {
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
          uncertain.current = null; clear(); setScreen('closed');
          setNote(e instanceof CatalogRetryClosed ? retryClosed : e instanceof CatalogAccessChanged
            ? 'Доступ к каталогу изменился. Загрузите актуальные данные.' : mode === 'catalog' ? catalogMessage(e) : errorMessage(e));
          // Re-evaluate rights and versions after rejection. Never retry a mutation.
          const known = e instanceof ApiError && (mode === 'catalog' ? [400,403,404,408,409,412,413,415,428].includes(e.status)
            : mode === 'operation' && [403,404,409,412,428].includes(e.status));
          if (expected && (known || e instanceof CatalogAccessChanged || e instanceof CatalogRetryClosed)) {
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
  async function proveCatalog(signal: AbortSignal, actor: Identity, expected: string): Promise<Identity> {
    const lifetime = AbortSignal.any([signal, AbortSignal.timeout(14_000)]);
    const view = await api(lifetime).access();
    if (view.staffId !== actor.staffId) { throw new SessionChanged(); }
    const current = await proveSession(lifetime, actor);
    if (catalogAccess(view) !== expected) { throw new CatalogAccessChanged(); }
    return current;
  }
  async function execute(signal: AbortSignal, entry: Pending, retry: boolean) {
    let current: Identity;
    const { command } = entry;
    try {
      current = entry.slice === 'P04' ? await proveCatalog(signal, entry.command.actor, entry.access)
        : await proveSession(signal, command.actor);
    } catch (e) {
      signal.throwIfAborted();
      if (e instanceof CatalogAccessChanged) {
        if (retry) { throw new CatalogRetryClosed(); }
        if (entry.slice === 'P04') { setDraft(entry.draft); }
        throw e;
      }
      if (retry && isUncertain(e) && !(e instanceof SessionChanged)) { setNote(outcomeUnknown); return; }
      throw e;
    }
    try {
      if (entry.slice === 'P04') { await sendPreparedP04(signal, current, entry.command); }
      else { await sendCommand(signal, current, entry.command); }
    } catch (e) {
      signal.throwIfAborted();
      if (isUncertain(e) && !(e instanceof SessionChanged)) {
        uncertain.current = entry; clear(); setScreen('uncertain'); setNote(outcomeUnknown); return;
      }
      uncertain.current = null;
      if (entry.slice === 'P04' && e instanceof ApiError && e.status !== 401) {
        if (retry) { throw new CatalogRetryClosed(); }
        setDraft(entry.draft);
      }
      throw e;
    }
    signal.throwIfAborted(); uncertain.current = null;
    if (entry.slice === 'P04') { setDraft(null); }
    clear(); setScreen('checking');
    try { await refresh(signal, current); setNote('Операция подтверждена сервером. Доступ обновлён; загрузите актуальную карточку.'); }
    catch { signal.throwIfAborted(); forget(); setScreen('login'); setNote(confirmationMissing); }
  }
  function writeP03(spec: CommandSpec, body: object) {
    if (uncertain.current) { return; }
    run(async signal => {
      if (!session.current) { throw new SessionChanged(); }
      await execute(signal, { slice: 'P03', command: prepareCommand(spec, body, session.current) }, false);
    });
  }
  const p04: P04IO = {
    read(op, input, show) {
      if (!snapshot || uncertain.current) { return; }
      const access = catalogAccess(snapshot.access);
      run(async signal => {
        const actor = session.current;
        if (!actor) { throw new SessionChanged(); }
        await proveCatalog(signal, actor, access);
        const result = await readP04(signal, op, input);
        await proveCatalog(signal, actor, access);
        signal.throwIfAborted(); show(result);
      }, 'catalog');
    },
    write(op, input) {
      if (!snapshot || uncertain.current) { return; }
      const access = catalogAccess(snapshot.access);
      const saved = submitted.current;
      run(async signal => {
        if (!session.current) { throw new SessionChanged(); }
        const command = await prepareP04Command(op, input, session.current);
        signal.throwIfAborted();
        await execute(signal, { slice: 'P04', command, access, draft: saved }, false);
      }, 'catalog');
    },
  };
  function logout() {
    const identity = session.current;
    pending.current?.abort(); pending.current = null; forget(); setScreen('checking');
    run(async signal => {
      if (identity) { await api(signal, identity.csrf).logout(); }
      signal.throwIfAborted(); setScreen('login'); setNote('Вы вышли из CRM.');
    });
  }
  const settings = snapshot ? p03Tabs(snapshot.access) : [];
  const catalog = snapshot ? p04Tabs(snapshot.access) : [];
  const sections = [...settings, ...catalog];
  const catalogSection = catalog.find(tab => tab.id === section);
  const settingsSection = settings.find(tab => tab.id === section);
  const visibleSection = catalogSection?.id ?? settingsSection?.id ?? (section === 'roles' ? 'roles' : 'people');
  function openSection(next: typeof section) { setSection(next); setNote(''); }
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
      {screen === 'uncertain' ? <button disabled={busy} onClick={() => {
        const entry = uncertain.current;
        if (entry) { run(signal => execute(signal, entry, true), entry.slice === 'P04' ? 'catalog' : 'operation'); }
      }}>Проверить / повторить</button>
        : <button disabled={busy} onClick={() => {
          const actor = session.current ?? undefined;
          clear(); setScreen('checking'); run(signal => refresh(signal, actor), 'check');
        }}>Обновить доступ</button>}
      {session.current && <button onClick={logout}>Выйти</button>}</div>}
    {screen === 'ready' && snapshot && <fieldset disabled={busy} className="workspace" key={revision}>
      <p>Текущая роль: <strong>{snapshot.access.role.code}</strong></p>
      <nav aria-label="Разделы управления"><button aria-pressed={visibleSection === 'people'} onClick={() => { openSection('people'); }}>Сотрудники</button>
        <button aria-pressed={visibleSection === 'roles'} onClick={() => { openSection('roles'); }}>Роли и возможности</button>
        {sections.map(tab => <button key={tab.id} aria-pressed={visibleSection === tab.id} onClick={() => { openSection(tab.id); }}>{tab.label}</button>)}
      </nav>
      {catalogSection ? <P04DraftContext.Provider value={{ retained: draft, stage: next => { submitted.current = next; }, discard: () => { setDraft(null); } }}>
        <P04Desk key={catalogSection.id} access={snapshot.access} section={catalogSection.id} io={p04} openP03={openSection}/>
      </P04DraftContext.Provider> : settingsSection ? <P03Desk key={settingsSection.id} data={snapshot} section={settingsSection.id} read={readP03} write={writeP03}/>
        : visibleSection === 'roles' ? <Roles data={snapshot} selected={role} members={members} write={write} open={id => { readCard(c => c.role(id), r => { setMembers(null); setRole(r); }); }}
          openMembers={id => { readCard(c => c.members(id), setMembers); }}/>
          : <People data={snapshot} selected={person} open={id => { readCard(c => c.person(id), setPerson); }} write={write}/>}</fieldset>}
  </main>;
}
