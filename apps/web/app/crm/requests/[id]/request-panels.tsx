'use client';

import { useEffect, useRef, useState } from 'react';
import type { SubmitEvent } from 'react';
import { addRequestComment, readRequestComments, readRequestContactDetails, RequestPanelHttpError } from '../client';
import type { CommentProof } from '../client';
import { date } from '../format';

type Comments = Awaited<ReturnType<typeof readRequestComments>>;
type Contacts = Awaited<ReturnType<typeof readRequestContactDetails>>;
type Feedback = { role: 'status' | 'alert'; message: string };
type PanelView<T> = { data: T } | { error: string };
type CommentIntent = CommentProof & { text: string; key: string };

export type CommentDraft = { csrf: string; text: string };

function panelError(error: unknown, unavailable: string, fallback: string) {
  if (error instanceof RequestPanelHttpError) {
    if (error.status === 401) { return 'Войдите в CRM, чтобы открыть данные заявки.'; }
    if (error.status === 403 || error.status === 404 || error.status === 503) { return unavailable; }
  }
  return fallback;
}

export function RequestComments({ id, proof, draft, refreshCard }: {
  id: string; proof: CommentProof | null; draft: CommentDraft | null;
  refreshCard: (draft: CommentDraft) => void;
}) {
  const [view, setView] = useState<PanelView<Comments> | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [text, setText] = useState(() => draft && proof?.csrf === draft.csrf ? draft.text : '');
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [sending, setSending] = useState(false);
  const [stale, setStale] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const pending = useRef<CommentIntent | null>(null);
  const writeRequest = useRef<AbortController | null>(null);

  useEffect(() => {
    const active = new AbortController();
    void readRequestComments(id, active.signal).then(data => {
      if (!active.signal.aborted) { setView({ data }); }
    }).catch((error: unknown) => {
      if (!active.signal.aborted) {
        setView({ error: panelError(error, 'Внутренние комментарии сейчас недоступны.', 'Не удалось загрузить комментарии.') });
      }
    });
    return () => { active.abort(); };
  }, [id, attempt]);

  useEffect(() => () => { writeRequest.current?.abort(); }, []);

  function refreshComments() {
    setView(null);
    setAttempt(value => value + 1);
  }

  async function submit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!proof || writeRequest.current || stale || blocked) { return; }
    const submittedText = text.replaceAll('\r\n', '\n').normalize('NFC').trim();
    const characters = Array.from(submittedText);
    if (!submittedText || !submittedText.isWellFormed() || characters.length > 2000) {
      setFeedback({ role: 'alert', message: 'Введите от 1 до 2000 символов.' });
      return;
    }
    if (characters.some(character => {
      const code = character.charCodeAt(0);
      return (code < 32 && code !== 9 && code !== 10) || code === 127;
    })) {
      setFeedback({ role: 'alert', message: 'Удалите из комментария недопустимые управляющие символы.' });
      return;
    }

    const active = new AbortController();
    writeRequest.current = active;
    setSending(true);
    setFeedback(null);
    try {
      const previous = pending.current;
      const key = previous?.text === submittedText && previous.etag === proof.etag && previous.csrf === proof.csrf
        ? previous.key : crypto.randomUUID();
      pending.current = { ...proof, text: submittedText, key };
      await addRequestComment(id, proof, key, submittedText, active.signal);
      if (active.signal.aborted) { return; }
      pending.current = null;
      setText('');
      setFeedback({ role: 'status', message: 'Комментарий добавлен.' });
      refreshComments();
    } catch (error: unknown) {
      if (active.signal.aborted) { return; }
      const status = error instanceof RequestPanelHttpError ? error.status : null;
      if (status === null || status === 408 || status === 429 || status >= 500) {
        setFeedback({ role: 'alert', message: 'Не удалось подтвердить добавление комментария. Повторите отправку с тем же текстом.' });
        return;
      }
      pending.current = null;
      if (status === 412 || status === 428) {
        setStale(true);
        setFeedback({ role: 'alert', message: 'Заявка изменилась. Обновите карточку перед отправкой комментария.' });
      } else if (status === 401 || status === 403 || status === 404) {
        setBlocked(true);
        setText('');
        setView({ error: panelError(error, 'Внутренние комментарии сейчас недоступны.', 'Не удалось загрузить комментарии.') });
      } else {
        setFeedback({ role: 'alert', message: status === 400 || status === 422
          ? 'Проверьте текст комментария и повторите отправку.' : 'Не удалось добавить комментарий.' });
      }
    } finally {
      writeRequest.current = null;
      if (!active.signal.aborted) { setSending(false); }
    }
  }

  const comments = view && 'data' in view ? view.data : null;
  return <section className="panel" aria-labelledby="request-comments">
    <h2 id="request-comments">Внутренние комментарии</h2>
    {view === null && <p role="status">Загрузка комментариев…</p>}
    {view && 'error' in view && <div role="alert"><p>{view.error}</p>
      {!blocked && <button type="button" onClick={refreshComments}>Повторить загрузку комментариев</button>}
    </div>}
    {comments?.length === 0 && <p>Комментариев пока нет.</p>}
    {comments && comments.length > 0 && <ul className="request-comments">
      {comments.map(comment => <li key={comment.id}>
        <small><time dateTime={comment.createdAt}>{date.format(new Date(comment.createdAt))}</time> UTC · Версия {comment.version}</small>
        <p>{comment.text}</p>
      </li>)}
    </ul>}
    {comments && proof && !blocked && <form onSubmit={event => { void submit(event); }}>
      <label>Текст комментария
        <textarea rows={4} value={text} required disabled={sending} onChange={event => { setText(event.target.value); }}/>
      </label>
      <button type="submit" disabled={sending || stale}>{sending ? 'Добавляем комментарий…' : 'Добавить комментарий'}</button>
      {stale && <button type="button" onClick={() => { refreshCard({ csrf: proof.csrf, text }); }}>Обновить карточку</button>}
    </form>}
    {feedback && <p role={feedback.role}>{feedback.message}</p>}
  </section>;
}

export function RequestContactDetails({ id }: { id: string }) {
  const [view, setView] = useState<PanelView<Contacts> | null>(null);
  const [loading, setLoading] = useState(false);
  const readRequest = useRef<AbortController | null>(null);

  useEffect(() => () => { readRequest.current?.abort(); }, []);

  async function showContacts() {
    if (readRequest.current) { return; }
    const active = new AbortController();
    readRequest.current = active;
    setView(null);
    setLoading(true);
    try {
      const data = await readRequestContactDetails(id, active.signal);
      if (!active.signal.aborted) { setView({ data }); }
    } catch (error: unknown) {
      if (!active.signal.aborted) {
        setView({ error: panelError(error, 'Контактные данные сейчас недоступны.', 'Не удалось загрузить контактные данные.') });
      }
    } finally {
      readRequest.current = null;
      if (!active.signal.aborted) { setLoading(false); }
    }
  }

  const contacts = view && 'data' in view ? view.data : null;
  return <section className="panel" aria-labelledby="request-contact-details">
    <h2 id="request-contact-details">Контактные данные</h2>
    <button type="button" aria-expanded={contacts !== null} aria-controls="request-contact-values" disabled={loading}
      onClick={() => { if (contacts) { setView(null); } else { void showContacts(); } }}>
      {contacts ? 'Скрыть контактные данные' : 'Показать контактные данные'}
    </button>
    {loading && <p role="status">Загрузка контактных данных…</p>}
    {view && 'error' in view && <p role="alert">{view.error}</p>}
    <div id="request-contact-values" hidden={!contacts}>
      {contacts && <dl>
        <dt>Имя</dt><dd>{contacts.name}</dd>
        <dt>Телефон</dt><dd>{contacts.phone ?? 'Звонок недоступен'}</dd>
      </dl>}
    </div>
  </section>;
}
