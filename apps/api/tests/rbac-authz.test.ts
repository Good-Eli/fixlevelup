import { describe, expect, it } from 'vitest';
import type { Capability, Scope } from '../src/authz/capability.js';
import { GLOBAL_SCOPE, isCapability, PERMISSION_CONTRACT, PROTECTED_CAPABILITIES, scopeMatches, STAFF_CAPABILITIES, staffScope } from '../src/authz/capability.js';
import { isSystemAdmin } from '../src/authz/authorization.service.js';

describe('server permission contracts are not grants', () => {
  it('knows only the thirteen implemented operations, not legacy or future modules', () => {
    expect(new Set(STAFF_CAPABILITIES).size).toBe(13);
    for (const input of [null, [], {}, 'staff.manage', 'jobs.create', '__proto__', 'constructor', 'roles.READ']) {
      expect(isCapability(input)).toBe(false);
    }
    expect(PROTECTED_CAPABILITIES).toHaveLength(5);
    expect(PROTECTED_CAPABILITIES.every(c => isCapability(c) && PERMISSION_CONTRACT[c] === 'GLOBAL')).toBe(true);
    expect(isSystemAdmin({ id: 'role', code: 'ADMIN', type: 'CUSTOM' })).toBe(false);
  });
  it.each(STAFF_CAPABILITIES)('requires the supported scope and checks SELF ownership for %s', capability => {
    const own = { kind: 'SELF', ownerId: 'caller' } as const;
    expect(scopeMatches(capability, staffScope(capability, 'caller'), 'caller')).toBe(true);
    expect(scopeMatches(capability, own, 'another')).toBe(false);
    expect(scopeMatches(capability, GLOBAL_SCOPE, 'caller')).toBe(!capability.startsWith('staff.self.'));
    expect(scopeMatches(capability, { kind: 'CITY', cityId: 'untrusted' } as unknown as Scope, 'caller')).toBe(false);
    expect(scopeMatches('staff.manage' as Capability, GLOBAL_SCOPE, 'caller')).toBe(false);
  });
});
