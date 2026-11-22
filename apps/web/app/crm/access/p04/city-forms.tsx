import { useState, type ReactNode } from 'react';
import { type P04Body } from '@fixlevelup/p03-contracts/p04';
import { Text, value } from '../management-ui';
import { FormError } from '../p0305-client';
import { P04Form } from './shared';
import {
  estimateFields, fixedFields, POLICY_LIMITS, policyFields, RULE_BASES, RULE_METHODS, ROUNDING_MODES,
  ruleFields, schedule, selectedLabel, utc, type Label, type PolicyRows, type RuleKind,
} from './city-wires';

export function Option({ name, label, options }: { name: string; label: string; options: readonly string[] }) {
  return <label>{label}<select aria-label={label} name={name} required defaultValue=""><option value="">Выберите…</option>
    {options.map(option => <option key={option}>{option}</option>)}
  </select></label>;
}
export function LabelField({ name, label, options, multiple = false }: {
  name: string; label: string; options: readonly Label[]; multiple?: boolean;
}) {
  const choices = options.map(option => <option key={option.id} value={option.id}>{option.title ? `${option.title} · ${option.code}` : option.code}</option>);
  return <label>{label}{multiple ? <select aria-label={label} name={name} multiple size={Math.max(2, Math.min(options.length, 6))}>{choices}</select>
    : <select aria-label={label} name={name} required defaultValue=""><option value="">Выберите…</option>{choices}</select>}</label>;
}
function Minor({ name, label, required = true }: { name: string; label: string; required?: boolean }) {
  return <label>{label}<input name={name} inputMode="numeric" pattern="0|[1-9][0-9]{0,18}" maxLength={19} required={required}/></label>;
}
function Time({ name, label, required = true }: { name: string; label: string; required?: boolean }) {
  return <label>{label}<input name={name} placeholder="2030-01-02T03:04:05.000Z" maxLength={24} required={required}/></label>;
}
function Currency() { return <Text name="currency" label="Валюта" max={3} pattern="[A-Z]{3}"/>; }

interface TemporalFormProps<T> {
  noun: string;
  draftKey: string;
  parse: (form: FormData) => T;
  restore?: (form: FormData) => void;
  children: ReactNode;
  action: (period: ReturnType<typeof schedule>, payload: T) => void;
  replace?: boolean;
}
function TemporalForm<T>({ noun, draftKey, parse, restore, children, action, replace = false }: TemporalFormProps<T>) {
  const label = replace ? `Заменить ${noun}` : `Опубликовать ${noun}`;
  return <P04Form draftKey={draftKey} title={label} submit={label} {...(restore ? { restore } : {})} prompt={replace ? 'Закрыть действующую версию на указанной границе и опубликовать новую?' : 'Опубликовать новую версию с указанным периодом?'}
    action={form => { action(schedule(form, replace ? 'at' : 'validFrom'), parse(form)); }}>
    {children}
    <Time name={replace ? 'at' : 'validFrom'} label={replace ? 'Граница замены (UTC)' : 'Начало действия (UTC)'}/>
    <Time name="validUntil" label="Конец действия (UTC)" required={false}/>
    <Text name="sourceRef" label="Источник" max={200}/>
  </P04Form>;
}
type FormBindings<T> = Pick<TemporalFormProps<T>, 'draftKey' | 'replace' | 'action'>;
export function FixedForm(props: FormBindings<ReturnType<typeof fixedFields>>) {
  return <TemporalForm {...props} noun="цену" parse={fixedFields}>
    <Minor name="amountMinor" label="Сумма (минорные единицы)"/>
    <Currency/>
    <Text name="zeroBasis" label="Обоснование нуля" max={200} required={false}/>
    <small>Для суммы 0 необходимо обоснование. Пустая сумма не является нулём.</small>
  </TemporalForm>;
}
export function CloseForm({ noun, draftKey, action }: { noun: string; draftKey: string; action: (at: string) => void }) {
  return <P04Form draftKey={draftKey} title={`Закрыть ${noun}`} submit={`Закрыть ${noun}`} prompt="Закрыть именно эту версию на указанной границе?"
    action={form => { action(utc(form.get('at'), true)); }}><Time name="at" label="Граница закрытия (UTC)"/></P04Form>;
}
export function EstimateForm(props: FormBindings<ReturnType<typeof estimateFields>>) {
  return <TemporalForm {...props} noun="диапазон" parse={estimateFields}>
    <Text name="title" label="Название" max={160}/><Currency/>
    <Minor name="minMinor" label="Минимум (минорные единицы)"/>
    <Minor name="maxMinor" label="Максимум (минорные единицы)"/>
    <Text name="conditions" label="Условия" max={1000} required={false} area/>
    <Text name="disclaimer" label="Предупреждение об оценке" max={500} area/>
  </TemporalForm>;
}
export function EstimateCreateForm({ categories, draftKey, action }: {
  categories: readonly Label[]; draftKey: string; action: (input: P04Body<'estimateCreate'>) => void;
}) {
  return <P04Form draftKey={draftKey} title="Новый оценочный диапазон" submit="Создать диапазон"
    action={form => {
      const code = value(form, 'code', 64, false);
      if (code.length < 2 || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(code)) { throw new FormError('Проверьте код диапазона.'); }
      action({ code, categoryId: selectedLabel(form.get('categoryId'), categories) });
    }}>
    <Text name="code" label="Код диапазона" max={64} pattern="[a-z][a-z0-9]*(?:-[a-z0-9]+)*"/>
    <LabelField name="categoryId" label="Категория диапазона" options={categories}/>
  </P04Form>;
}
export function RuleForm({ kind, categories, ...props }: FormBindings<ReturnType<typeof ruleFields>> & { kind: RuleKind; categories: readonly Label[] }) {
  return <TemporalForm {...props} noun="правило" parse={form => ruleFields(form, kind, categories)}>
    <p>Вид правила: <strong>{kind}</strong></p>
    <Text name="title" label="Название" max={160}/><Currency/>
    <Option name="base" label="Основание расчёта" options={RULE_BASES}/>
    <Option name="method" label="Метод" options={RULE_METHODS}/>
    <Minor name="fixedMinor" label="Фиксированная дельта (минорные единицы)" required={false}/>
    <Text name="rateBps" label="Ставка (базисные пункты)" max={5} required={false} pattern="[0-9]+"/>
    <small>Заполните только значение выбранного метода: FIXED — целая сумма, RATE — от 1 до 10 000 б.п.</small>
    <Minor name="minBase" label="Минимум базы (минорные единицы)" required={false}/>
    <Minor name="maxBase" label="Максимум базы (минорные единицы)" required={false}/>
    <Minor name="minDelta" label="Минимум дельты (минорные единицы)" required={false}/>
    <Minor name="maxDelta" label="Максимум дельты (минорные единицы)" required={false}/>
    <LabelField name="categoryIds" label="Категории правила" options={categories} multiple/>
    <small>Без выбранных категорий правило не ограничено категорией.</small>
    {(kind === 'EVENING' || kind === 'NIGHT') && <>
      <Text name="startMinute" label="Начало местного окна (чч:мм)" max={5} pattern="[0-9]{2}:[0-9]{2}"/>
      <Text name="endMinute" label="Конец местного окна (чч:мм)" max={5} pattern="[0-9]{2}:[0-9]{2}"/>
      <label>Переход через полночь<select aria-label="Переход через полночь" name="wrapsMidnight" defaultValue="" required>
        <option value="">Выберите…</option><option value="yes">Да</option><option value="no">Нет</option>
      </select></label>
    </>}
  </TemporalForm>;
}

function Rows({ label, section, count, min = 0, change, render }: {
  label: string; section: keyof PolicyRows; count: number; min?: number; change: (count: number) => void; render: (i: number) => ReactNode;
}) {
  return <fieldset><legend>{label}</legend>
    {Array.from({ length: count }, (_, i) => <div key={i} className="p03-fields"><span>Строка {i + 1}</span>{render(i)}</div>)}
    <div><button type="button" disabled={count >= POLICY_LIMITS[section]} onClick={() => { change(count + 1); }}>Добавить: {label}</button>
      <button type="button" disabled={count <= min} onClick={() => { change(count - 1); }}>Удалить последнюю: {label}</button></div>
  </fieldset>;
}
export function PolicyForm({ rules, ...props }: FormBindings<ReturnType<typeof policyFields>> & { rules: readonly Label[] }) {
  const [rows, setRows] = useState<PolicyRows>({ units: 1, priorities: 0, compatibilities: 0 });
  const change = (section: keyof PolicyRows) => (count: number) => { setRows(previous => ({ ...previous, [section]: count })); };
  return <TemporalForm {...props} noun="политику" parse={form => policyFields(form, rows, rules)} restore={form => {
    function count(prefix: string, max: number) {
      let result = 0;
      while (result < max && form.has(`${prefix}-${String(result)}`)) { result++; }
      return result;
    }
    setRows({ units: Math.max(1, count('unit', POLICY_LIMITS.units)), priorities: count('priority-rule', POLICY_LIMITS.priorities),
      compatibilities: count('left-rule', POLICY_LIMITS.compatibilities) });
  }}>
    <Currency/><Text name="taxDisplay" label="Отображение налога" max={200}/>
    <Option name="roundingMode" label="Округление" options={ROUNDING_MODES}/>
    <Minor name="maxManualDeltaMinor" label="Максимальная ручная дельта (минорные единицы)"/>
    <Rows label="Точность единиц" section="units" count={rows.units} min={1} change={change('units')} render={i => <>
      <Text name={`unit-${String(i)}`} label="Код единицы" max={24} pattern="[a-z][a-z0-9]*(?:-[a-z0-9]+)*"/>
      <Text name={`scale-${String(i)}`} label="Шкала (0–6)" max={1} pattern="[0-6]"/>
    </>}/>
    <Rows label="Приоритеты" section="priorities" count={rows.priorities} change={change('priorities')} render={i => <>
      <LabelField name={`priority-rule-${String(i)}`} label="Правило приоритета" options={rules}/>
      <Text name={`priority-${String(i)}`} label="Приоритет (0–1000000)" max={7} pattern="[0-9]+"/>
    </>}/>
    <Rows label="Совместимости" section="compatibilities" count={rows.compatibilities} change={change('compatibilities')} render={i => <>
      <LabelField name={`left-rule-${String(i)}`} label="Первое совместимое правило" options={rules}/>
      <LabelField name={`right-rule-${String(i)}`} label="Второе совместимое правило" options={rules}/>
    </>}/>
  </TemporalForm>;
}
