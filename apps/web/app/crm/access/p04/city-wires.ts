import { decodeP04Body, type P04Body, type P04Data, type P04MutationOperation } from '@fixlevelup/p03-contracts/p04';
import { choice, optional, value } from '../management-ui';
import { FormError } from '../p0305-client';

export const ITEM_KINDS = ['WORK', 'PART', 'MATERIAL', 'TRAVEL', 'DIAGNOSTICS'] as const;
export const RULE_METHODS = ['FIXED', 'RATE'] as const;
export const RULE_BASES = ['WORKS', 'WORKS_AND_PARTS', 'ORDER_BASE'] as const;
export const ROUNDING_MODES = ['HALF_UP', 'DOWN'] as const;
export const YES_NO = ['yes', 'no'] as const;
export const POLICY_LIMITS = { units: 32, priorities: 64, compatibilities: 128 } as const;
export type RuleKind = P04Data<'cityRules'>['items'][number]['kind'];
export type Label = { readonly id: string; readonly code: string; readonly title?: string };
export type PolicyRows = { readonly units: number; readonly priorities: number; readonly compatibilities: number };

export function minor(raw: FormDataEntryValue | null, required: true): string;
export function minor(raw: FormDataEntryValue | null, required?: false): string | null;
export function minor(raw: FormDataEntryValue | null, required = false) {
  if (!required && (raw === null || raw === '')) { return null; }
  if (typeof raw !== 'string' || !/^(?:0|[1-9]\d{0,18})$/.test(raw) || BigInt(raw) > 9223372036854775807n) {
    throw new FormError('Укажите целую сумму от 0 до 9223372036854775807 без пробелов и ведущих нулей.');
  }
  return raw;
}

export function utc(raw: FormDataEntryValue | null, required: true): string;
export function utc(raw: FormDataEntryValue | null, required?: false): string | null;
export function utc(raw: FormDataEntryValue | null, required = false) {
  if (!required && (raw === null || raw === '')) { return null; }
  if (typeof raw !== 'string' || !/^(?!0000)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(raw)
      || !Number.isFinite(Date.parse(raw)) || new Date(raw).toISOString() !== raw) {
    throw new FormError('Укажите точное время UTC: ГГГГ-ММ-ДДTчч:мм:сс.мммZ.');
  }
  return raw;
}

function currency(form: FormData) {
  const raw = form.get('currency');
  if (typeof raw !== 'string' || !/^[A-Z]{3}$/.test(raw)) { throw new FormError('Валюта — три заглавные латинские буквы.'); }
  return raw;
}
function integer(form: FormData, key: string, min: number, max: number) {
  const raw = form.get(key);
  if (typeof raw !== 'string' || !/^(0|[1-9]\d*)$/.test(raw) || raw.length > String(max).length) {
    throw new FormError(`Укажите целое число от ${String(min)} до ${String(max)}.`);
  }
  const result = Number(raw);
  if (result < min || result > max) { throw new FormError(`Укажите целое число от ${String(min)} до ${String(max)}.`); }
  return result;
}

export function body<Op extends P04MutationOperation>(operation: Op, input: P04Body<NoInfer<Op>>): P04Body<Op> {
  try { return decodeP04Body(operation, input); }
  catch { throw new FormError('Проверьте ограничения и связи между полями.'); }
}

export function rangeOrder(min: string | null, max: string | null) {
  if (min !== null && max !== null && BigInt(min) > BigInt(max)) {
    throw new FormError('Минимум не может превышать максимум.');
  }
}
export function schedule(form: FormData, field: 'validFrom' | 'at') {
  const at = utc(form.get(field), true);
  const validUntil = utc(form.get('validUntil'));
  if (validUntil !== null && validUntil <= at) { throw new FormError('Конец действия должен быть позже начала.'); }
  return { at, validUntil, sourceRef: value(form, 'sourceRef', 200) };
}
export function fixedFields(form: FormData) {
  const amountMinor = minor(form.get('amountMinor'), true);
  const zeroBasis = amountMinor === '0' ? value(form, 'zeroBasis', 200) : null;
  if (amountMinor !== '0' && optional(form, 'zeroBasis') !== null) { throw new FormError('Обоснование заполняется только для нулевой цены.'); }
  const cur = currency(form);
  return amountMinor === '0' && zeroBasis !== null
    ? { amountMinor, zeroBasis, currency: cur } as const : { amountMinor, zeroBasis: null, currency: cur } as const;
}
export function estimateFields(form: FormData) {
  const minMinor = minor(form.get('minMinor'), true);
  const maxMinor = minor(form.get('maxMinor'), true);
  rangeOrder(minMinor, maxMinor);
  const conditions = optional(form, 'conditions');
  return { title: value(form, 'title', 160), currency: currency(form), minMinor, maxMinor,
    conditions, disclaimer: value(form, 'disclaimer', 500) };
}

export function selectedLabel(raw: FormDataEntryValue | null, labels: readonly Label[]) {
  const entry = labels.find(option => option.id === raw);
  if (entry === undefined) { throw new FormError('Выберите запись из текущего списка.'); }
  return entry.id;
}
export function localMinute(raw: FormDataEntryValue | null) {
  if (typeof raw !== 'string' || !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(raw)) {
    throw new FormError('Укажите местное время в формате чч:мм.');
  }
  return Number(raw.slice(0, 2)) * 60 + Number(raw.slice(3));
}
export function ruleFields(form: FormData, kind: RuleKind, categories: readonly Label[]) {
  const minBase = minor(form.get('minBase')); const maxBase = minor(form.get('maxBase'));
  const minDelta = minor(form.get('minDelta')); const maxDelta = minor(form.get('maxDelta'));
  rangeOrder(minBase, maxBase); rangeOrder(minDelta, maxDelta);
  const categoryIds = form.getAll('categoryIds').map(raw => selectedLabel(raw, categories));
  const shared = { title: value(form, 'title', 160), base: choice(form, 'base', RULE_BASES), currency: currency(form), minBase,
    maxBase, minDelta, maxDelta, categoryIds };
  const method = choice(form, 'method', RULE_METHODS);
  if (optional(form, method === 'FIXED' ? 'rateBps' : 'fixedMinor') !== null) {
    throw new FormError('Заполните значение только для выбранного метода.');
  }
  const calculation = method === 'FIXED'
    ? { method, fixedMinor: minor(form.get('fixedMinor'), true), rateBps: null } as const
    : { method, fixedMinor: null, rateBps: integer(form, 'rateBps', 1, 10000) } as const;
  if (kind !== 'EVENING' && kind !== 'NIGHT') { return { ...shared, ...calculation, kind }; }
  const startMinute = localMinute(form.get('startMinute'));
  const endMinute = localMinute(form.get('endMinute'));
  const wrapsMidnight = choice(form, 'wrapsMidnight', YES_NO) === 'yes';
  if (startMinute === endMinute || wrapsMidnight !== (startMinute > endMinute)) {
    throw new FormError('Границы окна должны различаться; явно укажите, пересекает ли оно полночь.');
  }
  return { ...shared, ...calculation, kind, startMinute, endMinute, wrapsMidnight };
}

export function policyFields(form: FormData, rows: PolicyRows, rules: readonly Label[]) {
  if (rows.units < 1 || rows.units > POLICY_LIMITS.units || rows.priorities > POLICY_LIMITS.priorities
      || rows.compatibilities > POLICY_LIMITS.compatibilities) { throw new FormError('Проверьте количество строк политики.'); }
  const units = new Map<string, number>();
  for (let i = 0; i < rows.units; i++) {
    const key = form.get(`unit-${String(i)}`);
    if (typeof key !== 'string' || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(key) || key.length > 24 || units.has(key)) {
      throw new FormError('Коды единиц должны быть уникальны (строчные латинские буквы, цифры и дефис).');
    }
    units.set(key, integer(form, `scale-${String(i)}`, 0, 6));
  }
  const priorities = Array.from({ length: rows.priorities }, (_, i) => ({
    ruleId: selectedLabel(form.get(`priority-rule-${String(i)}`), rules), priority: integer(form, `priority-${String(i)}`, 0, 1_000_000),
  }));
  const compatibilities = Array.from({ length: rows.compatibilities }, (_, i) => ({
    leftRuleId: selectedLabel(form.get(`left-rule-${String(i)}`), rules), rightRuleId: selectedLabel(form.get(`right-rule-${String(i)}`), rules),
  }));
  if (new Set(priorities.map(row => row.ruleId)).size !== priorities.length || compatibilities.some(row => row.leftRuleId === row.rightRuleId)
      || new Set(compatibilities.map(row => [row.leftRuleId, row.rightRuleId].sort().join(':'))).size !== compatibilities.length) {
    throw new FormError('Приоритеты не должны повторять правило, а пары — повторяться или ссылаться на одно правило дважды.');
  }
  return { currency: currency(form), taxDisplay: value(form, 'taxDisplay', 200), roundingMode: choice(form, 'roundingMode', ROUNDING_MODES),
    units: Object.fromEntries(units), maxManualDeltaMinor: minor(form.get('maxManualDeltaMinor'), true), priorities, compatibilities };
}

export type TemporalRevision = Pick<P04Data<'fixedGet'>, 'id' | 'cityId' | 'cityVersionId' | 'seriesId' | 'version'
  | 'validFrom' | 'validUntil' | 'effectiveUntil' | 'publishedAt'>;
export function sameRevision(a: TemporalRevision, b: TemporalRevision) {
  return a.id === b.id && a.seriesId === b.seriesId && a.cityId === b.cityId && a.cityVersionId === b.cityVersionId
    && a.version === b.version && a.validFrom === b.validFrom && a.validUntil === b.validUntil
    && a.effectiveUntil === b.effectiveUntil && a.publishedAt === b.publishedAt;
}
export function periodStatus(row: TemporalRevision, now: string) {
  if (row.validFrom > now) { return 'Запланирована'; }
  if (row.effectiveUntil !== null && row.effectiveUntil <= now) { return 'Завершена'; }
  return row.validUntil === row.effectiveUntil ? 'Действует' : 'Действует до запланированного закрытия';
}
export function isClosable(row: TemporalRevision, now: string) {
  return row.validFrom <= now && row.validUntil === row.effectiveUntil && (row.effectiveUntil === null || now < row.effectiveUntil);
}
export function closeAt(row: TemporalRevision, at: string, now: string) {
  if (!isClosable(row, now) || at <= now || (row.effectiveUntil !== null && at >= row.effectiveUntil)) {
    throw new FormError('Граница должна быть в будущем и внутри действующего интервала. Перезагрузите историю при изменении периода.');
  }
  return at;
}
