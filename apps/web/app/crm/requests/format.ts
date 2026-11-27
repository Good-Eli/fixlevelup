import type { P05Status, P05Type } from '@fixlevelup/p03-contracts/p05';

export const statuses: Record<P05Status, string> = {
  NEW: 'Новая', CALLBACK_REQUIRED: 'Нужен звонок', WAITING_TELEGRAM_LINK: 'Ожидает привязки Telegram',
  WAITING_CHANNEL_LINK: 'Ожидает привязки канала', MANAGER_REVIEW: 'На проверке менеджера',
  WAITING_ASSIGNMENT: 'Ожидает назначения', ASSIGNED: 'Мастер назначен', TECHNICIAN_ACCEPTED: 'Мастер принял',
  ON_THE_WAY: 'Мастер в пути', ARRIVED: 'Мастер прибыл', DIAGNOSTICS: 'Диагностика',
  WAITING_ESTIMATE_APPROVAL: 'Ожидает согласования сметы', IN_PROGRESS: 'В работе', WAITING_PARTS: 'Ожидает запчастей',
  PAUSED: 'На паузе', TECHNICIAN_COMPLETED: 'Работа мастера завершена', REVISIT_REQUIRED: 'Нужен повторный визит',
  CLOSED: 'Закрыта', CANCELLED: 'Отменена',
};

export const requestTypes: Record<P05Type, string> = { REPAIR: 'Ремонт', CALLBACK: 'Обратный звонок' };
export const date = new Intl.DateTimeFormat('ru', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' });
