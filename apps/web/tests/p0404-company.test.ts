import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it } from 'vitest';
import type { Access } from '../app/crm/access/api';
import { CompanyWorkspace } from '../app/crm/access/p04/company';
import { AvitoSnapshot, ItemFields, avitoPublication, itemPublication } from '../app/crm/access/p04/company-fields';
import type { P04IO } from '../app/crm/access/p04/client';

const id = '11111111-1111-4111-8111-111111111111';
const io: P04IO = { read: () => { throw new Error('Explicit read required'); }, write: () => { throw new Error('Explicit submit required'); } };
const admin: Access = { staffId:id,role:{ id,type:'SYSTEM',code:'ADMIN' },permissions:[] };
function catalog(access:Access) {
  return renderToStaticMarkup(createElement(CompanyWorkspace,{ area:'catalog',access,io }));
}
function form(fields:Record<string,string>) {
  const input = new FormData();
  for (const [key,value] of Object.entries(fields)) { input.set(key,value); }
  return input;
}

it('does not infer company controls from role labels, city pricing or legacy grants', () => {
  expect(catalog({ ...admin, permissions:['catalog.read','catalog.manage'], p04Permissions:[{ code:'pricing.manage',scope:'CITY' }] }))
    .not.toContain('Загрузить категории');
  const p04Permissions = [{ code:'catalog.read',scope:'GLOBAL' }] as const;
  expect(catalog({ ...admin,p04Permissions })).toContain('Загрузить категории');
  expect(catalog({ ...admin,p04Permissions })).not.toContain('Создать категорию');
  expect(catalog({ ...admin,p04Permissions:[...p04Permissions,{ code:'catalog.manage',scope:'GLOBAL' }] })).toContain('Создать категорию');
});

it('keeps all five item kinds exact, with duration only for work and diagnostics', () => {
  for (const kind of ['WORK','PART','MATERIAL','TRAVEL','DIAGNOSTICS'] as const) {
    const f = form({ title:'Позиция',durationMinutes:'45',technicianVisible:'on',categoryId:id,unit:'piece' });
    const timed = kind === 'WORK' || kind === 'DIAGNOSTICS';
    expect(itemPublication(kind,f)).toEqual({ kind,title:'Позиция',description:null,technicianVisible:true,publicVisible:false,...(timed ? { durationMinutes:45 } : {}) });
    const markup = renderToStaticMarkup(createElement(ItemFields,{ kind,revision:null }));
    expect(markup.includes('name="durationMinutes"')).toBe(timed);
    expect(markup).not.toMatch(/name="(?:categoryId|unit)"/u);
  }
  expect(() => itemPublication('WORK',form({ title:'Позиция',durationMinutes:'1441' }))).toThrow();
});

it('keeps typed manual profile/review evidence, rejects ambiguous URLs and does not render links or submitted HTML', () => {
  const common = { title:'Профиль',sourceUrl:'https://www.avito.ru/profile/example',permissionRef:'Согласие 1' };
  const detail = { sourceDate:'2024-02-29',excerpt:'Проверенный отзыв',rating:'5' };
  expect(avitoPublication('PROFILE',form({ ...common,...detail }))).toEqual(common);
  expect(avitoPublication('REVIEW',form({ ...common,...detail }))).toEqual({ ...common,...detail,rating:5 });
  expect(() => avitoPublication('REVIEW',form({ ...common,...detail,sourceDate:'2025-02-29' }))).toThrow();
  expect(() => avitoPublication('PROFILE',form({ ...common,permissionRef:' ' }))).toThrow();
  expect(() => avitoPublication('PROFILE',form({ ...common,sourceUrl:`${common.sourceUrl}?tracking=1` }))).toThrow();
  const markup = renderToStaticMarkup(createElement(AvitoSnapshot,{ revision:{ ...common,sourceDate:detail.sourceDate,
    excerpt:'<img src="//example.invalid/pixel"/>',rating:5,profileRevisionId:id,kind:'REVIEW',entryId:id,id,version:1,publishedAt:'2026-11-22T00:00:00.000Z' } }));
  expect(markup).toContain(common.sourceUrl);
  expect(markup).toContain('&lt;img');
  expect(markup).not.toMatch(/<a\b|<img\b|href=/u);
});
