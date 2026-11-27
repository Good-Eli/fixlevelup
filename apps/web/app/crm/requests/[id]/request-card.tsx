'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { P05WireError } from '@fixlevelup/p03-contracts/p05';
import { readRequestCard, readRequestEvents, RequestCardError, startRequestReview, unavailableSections } from '../client';
import { date, requestTypes, statuses } from '../format';
import { RequestComments, RequestContactDetails } from './request-panels';
import type { CommentDraft } from './request-panels';

type Card = Awaited<ReturnType<typeof readRequestCard>>;
type Events = Awaited<ReturnType<typeof readRequestEvents>>;
type View<T> = { data: T } | { error: string } | null;
type ReviewIntent = { id: string; etag: string; csrf: string; key: string };
type ReviewFeedback = { role: 'status' | 'alert'; message: string };

const contactModes = { PHONE: 'Телефон', CHANNEL: 'Мессенджер' };
const providers = { TG: 'Telegram', VK: 'ВКонтакте', MAX: 'MAX' };
const urgency = { FLEXIBLE: 'Гибкий срок', WITHIN_DAY: 'В течение дня', URGENT: 'Срочно' };
const coverage = { IN_ZONE: 'В зоне обслуживания', OUTSIDE: 'Вне зоны обслуживания', REVIEW: 'Требуется проверка', EXCEPTION: 'Исключение согласовано' };

function Timeline({ id }: { id: string }) {
  const [view, setView] = useState<View<Events>>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const request = new AbortController();
    void readRequestEvents(id, request.signal).then(data => {
      if (!request.signal.aborted) { setView({ data }); }
    }).catch((error: unknown) => {
      if (!request.signal.aborted) {
        setView({ error: error instanceof RequestCardError ? error.message : 'Не удалось загрузить историю заявки.' });
      }
    });
    return () => { request.abort(); };
  }, [id, attempt]);

  const events = view && 'data' in view ? view.data : null;
  return <section className="panel" aria-labelledby="request-timeline" aria-busy={view === null}>
    <h2 id="request-timeline">Последние события заявки</h2>
    {view === null && <p role="status">Загрузка истории…</p>}
    {view && 'error' in view && <div role="alert"><p>{view.error}</p>
      <button type="button" onClick={() => { setView(null); setAttempt(value => value + 1); }}>Повторить загрузку истории</button>
    </div>}
    {events?.length === 0 && <p>Событий пока нет.</p>}
    {events && events.length > 0 && <div className="registry-table"><table>
      <thead><tr><th scope="col">Версия</th><th scope="col">Дата (UTC)</th><th scope="col">Событие</th><th scope="col">Инициатор</th></tr></thead>
      <tbody>{events.map(event => <tr key={event.version}>
        <td>{event.version}</td><td><time dateTime={event.createdAt}>{date.format(new Date(event.createdAt))}</time></td>
        <td>{event.label}</td><td>{event.actorKind === 'F' ? 'Клиент' : 'Сотрудник'}</td>
      </tr>)}</tbody>
    </table></div>}
  </section>;
}

export default function RequestCard({ id }: { id: string }) {
  const [view, setView] = useState<View<Card>>(null);
  const [attempt, setAttempt] = useState(0);
  const [sending, setSending] = useState(false);
  const [reviewFeedback, setReviewFeedback] = useState<ReviewFeedback | null>(null);
  const [commentDraft, setCommentDraft] = useState<CommentDraft | null>(null);
  const reviewIntent = useRef<ReviewIntent | null>(null);
  const reviewRequest = useRef<AbortController | null>(null);

  useEffect(() => {
    const request = new AbortController();
    void readRequestCard(id, request.signal).then(data => {
      if (!request.signal.aborted) { setView({ data }); }
    }).catch((error: unknown) => {
      if (!request.signal.aborted) {
        setView({ error: error instanceof RequestCardError ? error.message : 'Не удалось загрузить карточку заявки.' });
      }
    });
    return () => { request.abort(); };
  }, [id, attempt]);

  useEffect(() => () => { reviewRequest.current?.abort(); }, []);

  const card = view && 'data' in view ? view.data : null;

  function refreshCard(draft: CommentDraft | null = null) {
    reviewIntent.current = null;
    setCommentDraft(draft);
    setView(null);
    setAttempt(value => value + 1);
  }

  async function startReview() {
    if (card?.kind !== 'full' || !card.startReview || reviewRequest.current) { return; }
    const proof = card.startReview;
    const active = new AbortController();
    reviewRequest.current = active;
    setSending(true);
    setReviewFeedback(null);
    try {
      const previous = reviewIntent.current;
      const key = previous?.id === card.id && previous.etag === proof.etag && previous.csrf === proof.csrf
        ? previous.key : crypto.randomUUID();
      reviewIntent.current = { id: card.id, ...proof, key };
      await startRequestReview(card, proof, key, active.signal);
      if (active.signal.aborted) { return; }
      setReviewFeedback({ role: 'status', message: 'Проверка заявки начата.' });
      refreshCard();
    } catch (error: unknown) {
      if (active.signal.aborted) { return; }
      const status = error instanceof P05WireError && error.problem?.status === error.status ? error.status : null;
      if (status === null || status === 408 || status === 429 || status >= 500) {
        setReviewFeedback({ role: 'alert', message: 'Не удалось подтвердить начало проверки. Повторите действие.' });
      } else {
        const message = status === 412 ? 'Заявка изменилась. Загружаем актуальную карточку и историю.'
          : status === 401 ? 'Войдите в CRM, чтобы начать проверку.'
          : status === 403 || status === 404 ? 'Начать проверку сейчас недоступно для этой учётной записи.'
          : 'Не удалось начать проверку. Загружаем актуальную карточку и историю.';
        setReviewFeedback({ role: status === 412 ? 'status' : 'alert', message });
        refreshCard();
      }
    } finally {
      reviewRequest.current = null;
      if (!active.signal.aborted) { setSending(false); }
    }
  }

  return <main className="desk" aria-busy={view === null}>
    <nav aria-label="Навигация по заявкам"><Link href="/crm/requests">К реестру заявок</Link></nav>
    <header><h1>{card?.kind === 'full' ? `Заявка № ${card.publicNumber}` : 'Карточка заявки'}</h1></header>
    {reviewFeedback && <p role={reviewFeedback.role}>{reviewFeedback.message}</p>}
    {view === null && <p role="status">Загрузка карточки…</p>}
    {view && 'error' in view && <div role="alert"><p>{view.error}</p>
      <button type="button" onClick={() => { refreshCard(commentDraft); }}>Повторить загрузку карточки</button>
    </div>}
    {card?.kind === 'restricted' && <section className="panel" aria-label="Ограниченный доступ">
      <p>Для вашей учётной записи доступна только версия заявки.</p>
      <dl><dt>Версия</dt><dd>{card.version}</dd></dl>
    </section>}
    {card?.kind === 'full' && <>
      <section className="panel" aria-labelledby="request-details">
        <h2 id="request-details">Основные сведения</h2>
        <dl>
          <dt>Статус</dt><dd>{statuses[card.status]}</dd>
          <dt>Тип заявки</dt><dd>{requestTypes[card.type]}</dd>
          <dt>Создана (UTC)</dt><dd><time dateTime={card.createdAt}>{date.format(new Date(card.createdAt))}</time></dd>
          <dt>Версия</dt><dd>{card.version}</dd>
          <dt>Источник</dt><dd>{card.facts.source ?? 'Не указан'}</dd>
          <dt>Категория техники</dt><dd>{card.facts.category ?? 'Не указана'}</dd>
          <dt>Район</dt><dd>{card.facts.district ?? 'Не указан'}</dd>
          <dt>Срочность</dt><dd>{card.facts.urgency ? urgency[card.facts.urgency] : 'Не указана'}</dd>
          <dt>Зона обслуживания</dt><dd>{card.facts.coverage ? coverage[card.facts.coverage] : 'Не оценена'}</dd>
          <dt>Способ связи</dt><dd>{card.contactMode ? contactModes[card.contactMode] : 'Не указан'}</dd>
          {card.provider && <><dt>Мессенджер</dt><dd>{providers[card.provider]}</dd></>}
        </dl>
        {card.startReview && <button type="button" disabled={sending} onClick={() => { void startReview(); }}>
          {sending ? 'Начинаем проверку…' : 'Начать проверку'}
        </button>}
        {card.canStartReview && !card.startReview && <>
          <p role="status">Для начала проверки обновите карточку.</p>
          <button type="button" onClick={() => { refreshCard(); }}>Обновить карточку</button>
        </>}
      </section>
      <Timeline id={card.id}/>
      {card.commentsAvailable && <RequestComments id={card.id} proof={card.addComment} draft={commentDraft} refreshCard={refreshCard}/>}
      {card.contactDetailsAvailable && <RequestContactDetails id={card.id}/>}
      <section className="panel" aria-labelledby="request-unavailable">
        <h2 id="request-unavailable">Пока недоступно</h2>
        <ul>{Object.entries(unavailableSections).filter(([key]) =>
          (key !== 'comments' || !card.commentsAvailable) && (key !== 'contactDetails' || !card.contactDetailsAvailable),
        ).map(([key, label]) => <li key={key}>{label}</li>)}</ul>
      </section>
    </>}
  </main>;
}
