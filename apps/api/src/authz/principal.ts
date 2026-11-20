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

export type Principal = StaffWebPrincipal;
