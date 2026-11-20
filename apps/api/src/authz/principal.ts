import type { WebRole } from '../auth/web-auth.service.js';

/** Server-trusted principal created only by the authentication guard from a validated session.
 * Client-supplied display names, phones or channel subjects never become principal fields.
 * staff-web comes from the P02-03 cookie session; staff-telegram (P02-05) and customer
 * request-scoped principals extend the Principal union with their own kind, never with staff roles.
 */
export interface StaffWebPrincipal {
  readonly kind: 'staff-web';
  readonly staffId: string;
  readonly role: WebRole;
  readonly authVersion: number;
}

/** P02-05 principal from a verified STAFF_TELEGRAM web_sessions row (Mini App bearer
 * token in memory). telegramUserId is the decimal string of the BIGINT Telegram id,
 * never a JavaScript number. role is metadata only; rights come from capability
 * grants, never from the login channel.
 */
export interface StaffTelegramPrincipal {
  readonly kind: 'staff-telegram';
  readonly staffId: string;
  readonly role: 'TECHNICIAN';
  readonly authVersion: number;
  readonly telegramUserId: string;
}

export type Principal = StaffWebPrincipal | StaffTelegramPrincipal;
