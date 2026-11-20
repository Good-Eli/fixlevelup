import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { loadWebAuthConfig } from '../src/auth/web-auth.config.js';
import { ConfigurationError } from '../src/runtime/config.js';

const csrfSecret = randomBytes(32).toString('hex');
let throttleSecret = randomBytes(32).toString('hex');
while (throttleSecret === csrfSecret) { throttleSecret = randomBytes(32).toString('hex'); }
const valid: NodeJS.ProcessEnv = {
  WEB_AUTH_ENABLED: '1',
  WEB_AUTH_ORIGIN: 'https://auth.example.com',
  WEB_AUTH_CSRF_SECRET: csrfSecret,
  WEB_AUTH_THROTTLE_SECRET: throttleSecret,
};

describe('loadWebAuthConfig', () => {
  it.each([undefined, '0'])('is disabled when WEB_AUTH_ENABLED is %s', (enabled) => {
    expect(loadWebAuthConfig({ WEB_AUTH_ENABLED: enabled })).toBeUndefined();
  });

  it.each(['WEB_AUTH_ORIGIN', 'WEB_AUTH_CSRF_SECRET', 'WEB_AUTH_THROTTLE_SECRET'])('rejects partial configuration while disabled: %s', (field) => {
    for (const enabled of [undefined, '0']) {
      expect(() => loadWebAuthConfig({ WEB_AUTH_ENABLED: enabled, [field]: valid[field] })).toThrow(ConfigurationError);
    }
  });

  it('accepts an exact HTTPS origin and independent 32-byte secrets', () => {
    const config = loadWebAuthConfig(valid);
    expect(config).toEqual({ origin: valid['WEB_AUTH_ORIGIN'], csrfSecret, throttleSecret });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it.each(['', 'true', 'false', '2'])('rejects invalid enable value %s', (enabled) => {
    expect(() => loadWebAuthConfig({ ...valid, WEB_AUTH_ENABLED: enabled })).toThrow(ConfigurationError);
  });

  it.each([
    undefined, '', 'not a url', 'http://auth.example.com', 'https://auth.example.com/',
    'https://auth.example.com/path', 'https://auth.example.com?query=1',
    'https://auth.example.com#fragment', 'https://user:password@auth.example.com',
    'https://AUTH.example.com', 'https://auth.example.com:443',
  ])('rejects invalid or non-exact origin %s', (origin) => {
    expect(() => loadWebAuthConfig({ ...valid, WEB_AUTH_ORIGIN: origin })).toThrow(ConfigurationError);
  });

  it.each(['WEB_AUTH_CSRF_SECRET', 'WEB_AUTH_THROTTLE_SECRET'])('rejects missing or malformed %s', (field) => {
    for (const value of [undefined, '', 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), 'A'.repeat(64), `${'a'.repeat(63)} `]) {
      expect(() => loadWebAuthConfig({ ...valid, [field]: value })).toThrow(ConfigurationError);
    }
  });

  it('rejects identical secrets', () => {
    expect(() => loadWebAuthConfig({ ...valid, WEB_AUTH_THROTTLE_SECRET: csrfSecret })).toThrow(ConfigurationError);
  });

  it('does not expose either secret in the thrown error', () => {
    try {
      loadWebAuthConfig({ ...valid, WEB_AUTH_ORIGIN: 'http://invalid.example' });
      expect.fail('expected invalid configuration to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigurationError);
      const rendered = `${String(error)} ${error instanceof Error ? (error.stack ?? '') : ''} ${JSON.stringify(error)}`;
      expect(rendered).not.toContain(csrfSecret);
      expect(rendered).not.toContain(throttleSecret);
    }
  });
});
