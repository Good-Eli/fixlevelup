import { describe, expect, it } from 'vitest';
import { ConfigurationError, loadConfig } from '../src/runtime/config.js';

const valid = { NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' };

describe('technical configuration', () => {
  it('accepts explicit technical configuration and freezes it', () => {
    const config = loadConfig(valid);
    expect(config).toEqual({ environment: 'test', host: '127.0.0.1', port: 0, shutdownTimeoutMs: 10000 });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it.each([
    {}, { ...valid, NODE_ENV: 'unknown' }, { ...valid, APP_HOST: '0.0.0.0' },
    { ...valid, APP_PORT: '-1' }, { ...valid, APP_PORT: '65536' },
    { ...valid, APP_PORT: '3.2' }, { ...valid, NODE_ENV: 'production' },
    { ...valid, SHUTDOWN_TIMEOUT_MS: '0' }, { ...valid, SHUTDOWN_TIMEOUT_MS: '30001' },
  ])('rejects invalid or incomplete configuration', (env) => {
    expect(() => loadConfig(env)).toThrow(ConfigurationError);
  });

  it('does not include env values or unrelated secrets in errors', () => {
    expect(() => loadConfig({ APP_PORT: 'synthetic-secret-canary', BOT_TOKEN: 'synthetic-secret-canary' }))
      .toThrow('Invalid technical configuration');
  });
});
