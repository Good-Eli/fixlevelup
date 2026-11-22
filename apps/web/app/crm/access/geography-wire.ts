import { decodeP03Page, decodeP03VersionedPage, isP03Uuid, isP03Version } from '@fixlevelup/p03-contracts';

/* Compatibility decoders for the unchanged P03-02 catalog response fields. */
function object(v: unknown): Record<string, unknown> { if (!v || typeof v !== 'object' || Array.isArray(v)) { throw new Error('Invalid geography record'); } return v as Record<string, unknown>; }
const text = (v: unknown, max: number) => { if (typeof v !== 'string' || !v.length || v.length > max) { throw new Error('Invalid geography text'); } return v; };
const nullable = <T>(v: unknown, decode: (x: unknown) => T) => v === null ? null : decode(v);
function id(v: unknown) { if (!isP03Uuid(v)) { throw new Error('Invalid geography UUID'); } return v; }
function version(v: unknown) { if (!isP03Version(v)) { throw new Error('Invalid geography version'); } return v; }
function one<const T>(v: unknown, choices: readonly T[]) { const choice = choices.find(x => x === v); if (choice === undefined) { throw new Error('Invalid geography enum'); } return choice; }
function exact<T>(read: (v: unknown) => T) { return (v: unknown): T | null => { try { return read(v); } catch { return null; } }; }
function receipt(v: Record<string, unknown>) { return { id:id(v['id']),version:version(v['version']) }; }
export const geoReceipt = exact(v => { const r = object(v); if (Object.keys(r).length !== 2) { throw new Error('Invalid geography receipt'); } return receipt(r); });
function city(v: unknown) {
  const r = object(v); return { ...receipt(r), code:text(r['code'],32), lifecycle:one(r['lifecycle'],['DRAFT','ACTIVE','INACTIVE']), currentVersionId:nullable(r['currentVersionId'],id) };
}
export type OfficeHours = readonly (readonly (readonly [number, number])[])[];
export function decodeOfficeHours(v: unknown): OfficeHours {
  if (!Array.isArray(v) || v.length !== 7) { throw new Error('Invalid office hours'); }
  return (v as unknown[]).map(day => {
    if (!Array.isArray(day) || day.length > 12) { throw new Error('Invalid office hours'); }
    let last = 0;
    return (day as unknown[]).map((slot): [number,number] => {
      if (!Array.isArray(slot) || slot.length !== 2) { throw new Error('Invalid office hours'); }
      const [start,end] = slot as unknown[];
      if (typeof start !== 'number' || typeof end !== 'number' || !Number.isInteger(start) || !Number.isInteger(end) || start < last || end <= start || end > 1440) { throw new Error('Invalid office hours'); }
      last = end; return [start,end];
    });
  });
}
function cityVersion(v: unknown) {
  const r = object(v); return { id:id(r['id']),sequence:version(r['sequence']),displayName:text(r['displayName'],200),addressDisplay:nullable(r['addressDisplay'], x => text(x,500)),
    timezone:text(r['timezone'],64),publicContact:text(r['publicContact'],320),officeHours:decodeOfficeHours(r['officeHours']),publishedAt:text(r['publishedAt'],40) };
}
export const geoCity = exact(v => ({ ...city(v), currentVersion:nullable(object(v)['currentVersion'],cityVersion) }));
export const geoCities = (v: unknown) => decodeP03Page(v,exact(city));
export const geoCityVersions = (v: unknown) => decodeP03VersionedPage(v,exact(cityVersion));
export type City = NonNullable<ReturnType<typeof geoCity>>;
export type CityVersion = ReturnType<typeof cityVersion>;
export const geoDistrict = exact(v => {
  const r = object(v); return { ...receipt(r),cityId:id(r['cityId']),code:text(r['code'],32),name:text(r['name'],200),archivedAt:nullable(r['archivedAt'], x => text(x,40)) };
});
export const geoDistricts = (v: unknown) => decodeP03VersionedPage(v,geoDistrict);
export const geoArea = exact(v => {
  const r = object(v); return { ...receipt(r),cityId:id(r['cityId']),code:text(r['code'],32),currentVersionId:nullable(r['currentVersionId'],id),archivedAt:nullable(r['archivedAt'], x => text(x,40)) };
});
export const geoAreas = (v: unknown) => decodeP03VersionedPage(v,geoArea);
export const geoAreaVersion = exact(v => {
  const r = object(v); return { ...receipt(r),cityId:id(r['cityId']),areaId:id(r['areaId']),sequence:version(r['sequence']),name:text(r['name'],200),
    coverageDescription:nullable(r['coverageDescription'], x => text(x,2000)),addressCriteria:nullable(r['addressCriteria'], x => text(x,2000)),publishedAt:nullable(r['publishedAt'],x => text(x,40)) };
});
export const geoAreaVersions = (v: unknown) => decodeP03VersionedPage(v,geoAreaVersion);
export interface Mapping { districtId:string; relation:'FULL'|'PARTIAL'; description:string|null }
export const geoCoverage = exact(v => {
  const r = object(v); const items = r['items'];
  if (!Array.isArray(items) || items.length > 200 || Object.keys(r).length !== 3) { throw new Error('Invalid full coverage'); }
  const seen = new Set<string>();
  const mappings = (items as unknown[]).map((v): Mapping => {
    const i = object(v); const districtId = id(i['districtId']);
    if (seen.has(districtId) || Object.keys(i).length !== 3) { throw new Error('Invalid coverage mapping'); }
    seen.add(districtId); return { districtId,relation:one(i['relation'],['FULL','PARTIAL']),description:nullable(i['description'],x => text(x,500)) };
  });
  return { areaVersionId:id(r['areaVersionId']),version:version(r['version']),items:mappings };
});
function membership(v: unknown) {
  const r = object(v); return { id:id(r['id']),cityId:id(r['cityId']),revokedAt:nullable(r['revokedAt'],x => text(x,40)),active:one(r['active'],[true,false]) };
}
const adminRow = exact(v => ({ ...membership(v),staffId:id(object(v)['staffId']),grantedAt:text(object(v)['grantedAt'],40) }));
function technicianRow(v: unknown) {
  const r = object(v); return { ...membership(v),validFrom:text(r['validFrom'],40),validTo:nullable(r['validTo'], x => text(x,40)) };
}
// Staff auth_version + profile_version starts at zero, unlike geography catalog rows.
export const geoAdmins = (v: unknown) => decodeP03VersionedPage(v,adminRow,true);
export const geoTechCities = (v: unknown) => decodeP03VersionedPage(v,exact(technicianRow),true);
export const geoTechAreas = (v: unknown) => decodeP03VersionedPage(v,exact(raw => ({ ...technicianRow(raw),areaId:id(object(raw)['areaId']),membershipId:id(object(raw)['membershipId']) })),true);