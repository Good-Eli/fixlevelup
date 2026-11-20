import 'reflect-metadata';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { checkTarget, displayName, nextChannelMarker, staffReadFilter, staffTargetFilter } from '../src/staff/staff-policy.js';
import type { EffectiveRole } from '../src/authz/authorization.service.js';

const role = (type: EffectiveRole['type'], code: string): EffectiveRole => ({ type, code, id: 'e104e66e-1111-4123-9999-101112131415' });
const id = 'ff04e66e-1111-4123-9999-101112131415';
describe('staff resource policy', () => {
  it('treats SYSTEM ADMIN as the only unrestricted role; custom codes and channel markers never suffice', () => {
    for (const restricted of [role('CUSTOM', 'ADMIN'), role('SYSTEM', 'MANAGER'), role('SYSTEM', 'TECHNICIAN'), role('CUSTOM', 'SUPERVISOR')]) {
      expect(staffTargetFilter(restricted)).toBe("(r.role_type='SYSTEM' AND r.code='TECHNICIAN')");
    }
    expect(staffTargetFilter(role('SYSTEM', 'ADMIN'))).toBe('TRUE');
    expect(staffReadFilter(role('SYSTEM', 'ADMIN'), '$1', '$2')).toContain('($1::boolean OR s.id<>$2::uuid)');
  });
  it('binds self to the verified subject and blocks ordinary mutations against self, including case aliases', () => {
    expect(() => { checkTarget(id, { kind: 'self', id }, true); }).not.toThrow();
    for (const write of [true, false]) { expect(() => { checkTarget(id, { kind: 'self', id: 'another' }, write); }).toThrow(ForbiddenException); }
    expect(() => { checkTarget(id, { kind: 'general', id: id.toUpperCase() }, true); }).toThrow(ForbiddenException);
    expect(() => { checkTarget(id, { kind: 'general', id: 'another' }, true); }).not.toThrow();
  });
  it('maintains channel eligibility on customs without granting system administration', () => {
    const custom = role('CUSTOM', 'REVIEWER');
    expect(nextChannelMarker('ADMIN', custom)).toBe('MANAGER');
    expect(nextChannelMarker('MANAGER', custom)).toBe('MANAGER');
    expect(nextChannelMarker('TECHNICIAN', custom)).toBe('TECHNICIAN');
    expect(nextChannelMarker('TECHNICIAN', role('SYSTEM', 'MANAGER'))).toBe('MANAGER');
    expect(() => nextChannelMarker('ADMIN', role('SYSTEM', 'UNKNOWN'))).toThrow(ForbiddenException);
  });
  it('accepts a bounded display name, not control characters, whitespace-only or mass assignment objects', () => {
    expect(displayName('  Сотрудник  ')).toBe('Сотрудник');
    expect(displayName('😀'.repeat(80))).toBe('😀'.repeat(80));
    for (const value of [null, '', '  ', 'a\nb', 'x\u202ey', '\ud800', '😀'.repeat(81), { role: 'ADMIN' }]) {
      expect(() => displayName(value)).toThrow(BadRequestException);
    }
  });
});
