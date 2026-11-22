import { type Access } from '../api';
import { hasGeo, hasP03 } from '../workspace';
import type { P04IO } from './client';
import { CompanyWorkspace } from './company';
import { CityWorkspace } from './city';
import { hasP04 } from './shared';

export function p04Tabs(access: Access) {
  return [
    ...(hasP04(access, 'catalog.read', 'COMPANY') ? [{ id: 'catalog', label: 'Каталог компании' } as const] : []),
    ...(hasP04(access, 'pricing.rules.read', 'COMPANY') ? [{ id: 'rules', label: 'Определения тарифов' } as const] : []),
    ...(hasP04(access, 'pricing.read') ? [{ id: 'pricing', label: 'Городские цены и тарифы' } as const] : []),
    ...(hasP04(access, 'content.externalreviews.read', 'COMPANY') ? [{ id: 'avito', label: 'Авито: ручные записи' } as const] : []),
  ];
}
export type P04Section = ReturnType<typeof p04Tabs>[number]['id'];

export function P04Desk({ access, section, io, openP03 }: {
  access: Access; section: P04Section; io: P04IO; openP03: (section: 'geography' | 'content') => void;
}) {
  return <section>
    {(hasGeo(access, 'geography.read') || hasP03(access, 'content.read')) && <nav aria-label="Связанные справочники P03">
      {hasGeo(access, 'geography.read') && <button onClick={() => { openP03('geography'); }}>Районы, зоны и контакты</button>}
      {hasP03(access, 'content.read') && <button onClick={() => { openP03('content'); }}>FAQ и публикации CRM</button>}
    </nav>}
    {section === 'pricing' ? <CityWorkspace access={access} io={io}/> : <CompanyWorkspace area={section} access={access} io={io}/>}
  </section>;
}
