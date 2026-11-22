export type P03Scope = 'GLOBAL' | 'CITY';
export type P03Target = { readonly scope: 'COMPANY'; readonly cityId?: never }
  | { readonly scope: 'CITY'; readonly cityId: string };

const GLOBAL = Object.freeze(['GLOBAL'] as const);
const CITY_GLOBAL = Object.freeze(['CITY', 'GLOBAL'] as const);

export const P03_SCOPE_CONTRACT = Object.freeze({
  'settings.fullread': GLOBAL,
  'settings.manage': GLOBAL,
  'settings.readiness.read': GLOBAL,
  'references.callbackinterval.read': CITY_GLOBAL,
  'references.callbackinterval.manage': CITY_GLOBAL,
  'references.paymentmethod.read': GLOBAL,
  'references.paymentmethod.manage': GLOBAL,
  'references.cancelreason.read': GLOBAL,
  'references.cancelreason.manage': GLOBAL,
  'references.declinereason.read': GLOBAL,
  'references.declinereason.manage': GLOBAL,
  'references.requestsource.read': GLOBAL,
  'references.requestsource.manage': GLOBAL,
  'content.read': CITY_GLOBAL,
  'content.manage': CITY_GLOBAL,
  'content.publish': CITY_GLOBAL,
  'legal.read': GLOBAL,
  'legal.manage': GLOBAL,
});
export type P03Capability = keyof typeof P03_SCOPE_CONTRACT;
export const P03_CAPABILITIES = Object.freeze(Object.keys(P03_SCOPE_CONTRACT) as P03Capability[]);
export interface P03Grant { readonly code: P03Capability; readonly scope: P03Scope }

export function isP03Capability(value: unknown): value is P03Capability {
  return typeof value === 'string' && Object.hasOwn(P03_SCOPE_CONTRACT, value);
}

const descriptions = {
  'settings.fullread': 'Просмотр полных настроек компании',
  'settings.manage': 'Публикация настроек компании',
  'settings.readiness.read': 'Просмотр состояния настройки',
  'references.callbackinterval.read': 'Просмотр интервалов обратного звонка',
  'references.callbackinterval.manage': 'Управление интервалами обратного звонка',
  'references.paymentmethod.read': 'Просмотр способов оплаты',
  'references.paymentmethod.manage': 'Управление способами оплаты',
  'references.cancelreason.read': 'Просмотр причин отмены',
  'references.cancelreason.manage': 'Управление причинами отмены',
  'references.declinereason.read': 'Просмотр причин отказа',
  'references.declinereason.manage': 'Управление причинами отказа',
  'references.requestsource.read': 'Просмотр источников заявок',
  'references.requestsource.manage': 'Управление источниками заявок',
  'content.read': 'Просмотр контента и истории',
  'content.manage': 'Создание и архивирование блоков контента',
  'content.publish': 'Публикация версий контента',
  'legal.read': 'Просмотр юридических документов и истории',
  'legal.manage': 'Создание и публикация юридических документов',
} as const satisfies Readonly<Record<P03Capability, string>>;

interface CapabilityMetadata {
  readonly scopes: readonly P03Scope[]; readonly module: string; readonly description: string;
  readonly systemAdminOnly: boolean; readonly globalSystemAdminOnly: boolean; readonly protected: false;
}
// Delegability/visibility still requires the trusted role, channel and current city assignment.
const metadata = {} as Record<P03Capability, CapabilityMetadata>;
for (const code of P03_CAPABILITIES) {
  const module = code.split('.')[0] ?? '';
  metadata[code] = Object.freeze({
    scopes: P03_SCOPE_CONTRACT[code], module, description: descriptions[code],
    systemAdminOnly: code === 'settings.fullread' || code === 'settings.manage' || module === 'legal',
    globalSystemAdminOnly: P03_SCOPE_CONTRACT[code] === CITY_GLOBAL,
    protected: false,
  });
}
export const P03_CAPABILITY_METADATA = Object.freeze(metadata);

export const P03_REFERENCE_TYPES = Object.freeze({
  callback_interval: Object.freeze({ dbType: 'CALLBACK_INTERVAL', scope: 'CITY', read: 'references.callbackinterval.read', manage: 'references.callbackinterval.manage' }),
  payment_method: Object.freeze({ dbType: 'PAYMENT_METHOD', scope: 'COMPANY', read: 'references.paymentmethod.read', manage: 'references.paymentmethod.manage' }),
  cancel_reason: Object.freeze({ dbType: 'CANCEL_REASON', scope: 'COMPANY', read: 'references.cancelreason.read', manage: 'references.cancelreason.manage' }),
  decline_reason: Object.freeze({ dbType: 'DECLINE_REASON', scope: 'COMPANY', read: 'references.declinereason.read', manage: 'references.declinereason.manage' }),
  request_source: Object.freeze({ dbType: 'REQUEST_SOURCE', scope: 'COMPANY', read: 'references.requestsource.read', manage: 'references.requestsource.manage' }),
} as const);
export type P03ReferenceType = keyof typeof P03_REFERENCE_TYPES;
export type P03ReferenceDbType = (typeof P03_REFERENCE_TYPES)[P03ReferenceType]['dbType'];
export const P03_REFERENCE_URL_TYPES = Object.freeze(Object.keys(P03_REFERENCE_TYPES) as P03ReferenceType[]);
export const P03_REFERENCE_DB_TYPES = Object.freeze(P03_REFERENCE_URL_TYPES.map(type => P03_REFERENCE_TYPES[type].dbType));
export function isP03ReferenceType(value: unknown): value is P03ReferenceType {
  return typeof value === 'string' && Object.hasOwn(P03_REFERENCE_TYPES, value);
}
