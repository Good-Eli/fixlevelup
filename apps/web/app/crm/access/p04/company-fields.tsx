import { decodeP04Body, type P04Body, type P04Data, type P04MutationOperation } from '@fixlevelup/p03-contracts/p04';
import { Text, integer, optional, value } from '../management-ui';
import { FormError } from '../p0305-client';

const slugPattern = '[a-z][a-z0-9]*(?:-[a-z0-9]+)*';
export const itemLabels = { WORK: 'Работы (WORK)', PART: 'Запчасти (PART)', MATERIAL: 'Материалы (MATERIAL)', TRAVEL: 'Выезд (TRAVEL)', DIAGNOSTICS: 'Диагностика (DIAGNOSTICS)' } as const;
export const avitoLabels = { PROFILE: 'Профили (PROFILE)', REVIEW: 'Отзывы (REVIEW)' } as const;
export const ruleLabels = { EVENING: 'Вечернее (EVENING)', NIGHT: 'Ночное (NIGHT)', EXPRESS: 'Срочность (EXPRESS)', SURCHARGE: 'Надбавка (SURCHARGE)', DISCOUNT: 'Скидка (DISCOUNT)' } as const;
export type ItemKind = P04Body<'itemCreate'>['kind'];
export type AvitoKind = P04Body<'avitoCreate'>['kind'];

export function checkedBody<Op extends P04MutationOperation>(operation: Op, fields: P04Body<Op>): P04Body<Op> {
  try { return decodeP04Body(operation, fields); }
  catch { throw new FormError('Проверьте формат, длину и значения полей.'); }
}
export function Code() {
  return <label>Код<input name="code" required minLength={2} maxLength={64} pattern={slugPattern}/></label>;
}
export function Unit() {
  return <Text name="unit" label="Единица измерения" max={24} pattern={slugPattern}/>;
}
export function TitleDescription({ revision }: { revision: { title: string; description: string | null } | null }) {
  return <><Text name="title" label="Название" max={160} value={revision?.title}/>
    <Text name="description" label="Описание" max={1000} value={revision?.description} required={false} area/></>;
}
export function titleDescription(f: FormData) {
  return { title: value(f, 'title', 160), description: optional(f, 'description') };
}
export function ItemFields({ kind, revision }: { kind: ItemKind; revision: P04Data<'itemVersion'> | null }) {
  return <><TitleDescription revision={revision}/>
    {(kind === 'WORK' || kind === 'DIAGNOSTICS') && <label>Длительность, мин<input name="durationMinutes" type="number" min={1} max={1440} step={1} required defaultValue={revision?.durationMinutes ?? ''}/></label>}
    <label><input name="technicianVisible" type="checkbox" defaultChecked={revision?.technicianVisible ?? false}/>Видна мастеру</label>
    <label><input name="publicVisible" type="checkbox" defaultChecked={revision?.publicVisible ?? false}/>Публичная видимость</label></>;
}
export function itemPublication(kind: ItemKind, f: FormData): P04Body<'itemPublish'> {
  const fields = { ...titleDescription(f), technicianVisible: f.get('technicianVisible') === 'on', publicVisible: f.get('publicVisible') === 'on' };
  return checkedBody('itemPublish', kind === 'WORK' || kind === 'DIAGNOSTICS'
    ? { ...fields, kind, durationMinutes: integer(f, 'durationMinutes', 1, 1440) }
    : { ...fields, kind });
}
export function AvitoFields({ kind, revision }: { kind: AvitoKind; revision: P04Data<'avitoVersion'> | null }) {
  return <><Text name="title" label="Название" max={160} value={revision?.title}/>
    <Text name="sourceUrl" label="URL источника" max={2048} value={revision?.sourceUrl}/>
    <Text name="permissionRef" label="Основание разрешения" max={200} value={revision?.permissionRef}/>
    <p>Укажите ссылку или номер подтверждения разрешения. Формат URL не подтверждает согласие.</p>
    {kind === 'REVIEW' && <><Text name="sourceDate" label="Дата источника (ГГГГ-ММ-ДД)" max={10} pattern="[0-9]{4}-[0-9]{2}-[0-9]{2}" value={revision?.sourceDate}/>
      <Text name="excerpt" label="Выдержка" max={1500} value={revision?.excerpt} area/>
      <label>Оценка<input name="rating" type="number" min={1} max={5} step={1} defaultValue={revision?.rating ?? ''}/></label></>}</>;
}
export function avitoPublication(kind: AvitoKind, f: FormData): P04Body<'avitoPublish'> {
  const fields = { title: value(f, 'title', 160), sourceUrl: value(f, 'sourceUrl', 2048, false), permissionRef: value(f, 'permissionRef', 200) };
  return checkedBody('avitoPublish', kind === 'PROFILE' ? fields : {
    ...fields, sourceDate: value(f, 'sourceDate', 10, false), excerpt: value(f, 'excerpt', 1500),
    rating: optional(f, 'rating') === null ? null : integer(f, 'rating', 1, 5),
  });
}
export function ItemSnapshot({ revision }: { revision: P04Data<'itemVersion'> }) {
  return <dl><dt>Описание</dt><dd>{revision.description ?? 'Не указано'}</dd>
    {(revision.kind === 'WORK' || revision.kind === 'DIAGNOSTICS') && <><dt>Длительность, мин</dt><dd>{revision.durationMinutes}</dd></>}
    <dt>Видна мастеру</dt><dd>{revision.technicianVisible ? 'Да' : 'Нет'}</dd>
    <dt>Публичная видимость</dt><dd>{revision.publicVisible ? 'Да' : 'Нет'}</dd></dl>;
}
export function AvitoSnapshot({ revision }: { revision: P04Data<'avitoVersion'> }) {
  return <dl><dt>URL источника</dt><dd>{revision.sourceUrl}</dd><dt>Основание разрешения</dt><dd>{revision.permissionRef}</dd>
    {revision.kind === 'REVIEW' && <><dt>Дата источника</dt><dd>{revision.sourceDate}</dd><dt>Выдержка</dt><dd>{revision.excerpt}</dd>
      <dt>Оценка</dt><dd>{revision.rating ?? 'Не указана'}</dd><dt>Версия профиля на момент публикации</dt><dd>{revision.profileRevisionId}</dd></>}</dl>;
}
