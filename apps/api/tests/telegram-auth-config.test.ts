import { describe, expect, it } from 'vitest';
import { loadTelegramAuthConfig } from '../src/auth/telegram-auth.config.js';
import { ConfigurationError } from '../src/runtime/config.js';

/** Synthetic well-formed token: exercises format validation only, not a live secret. */
const botToken = `7000000001:${'A'.repeat(43)}`;
const valid: NodeJS.ProcessEnv = { TELEGRAM_AUTH_ENABLED: '1', TELEGRAM_BOT_TOKEN: botToken };

describe('loadTelegramAuthConfig', () => {
  it.each([undefined, '0'])('is disabled when TELEGRAM_AUTH_ENABLED is %s', (enabled) => {
    expect(loadTelegramAuthConfig({ TELEGRAM_AUTH_ENABLED: enabled })).toBeUndefined();
  });

  it('rejects a bot token set while disabled', () => {
    for (const enabled of [undefined, '0']) {
      expect(() => loadTelegramAuthConfig({ TELEGRAM_AUTH_ENABLED: enabled, TELEGRAM_BOT_TOKEN: botToken }))
        .toThrow(ConfigurationError);
    }
  });

  it('accepts a well-formed bot token and freezes the config', () => {
    const config = loadTelegramAuthConfig(valid);
    expect(config).toEqual({ botToken });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it.each(['', 'true', 'false', '2', 'on'])('rejects invalid enable value %s', (enabled) => {
    expect(() => loadTelegramAuthConfig({ ...valid, TELEGRAM_AUTH_ENABLED: enabled })).toThrow(ConfigurationError);
  });

  it.each([
    undefined, '', 'not-a-token', '7000000001', `:${'A'.repeat(43)}`,
    'abc' + ':' + 'A'.repeat(43), '7000000001:short',
    `${botToken}\n`, `${botToken} `, `${'a'.repeat(64)}:${'A'.repeat(30)}`,
  ])('rejects missing or malformed bot token %j', (token) => {
    expect(() => loadTelegramAuthConfig({ ...valid, TELEGRAM_BOT_TOKEN: token })).toThrow(ConfigurationError);
  });

  it('does not expose the bot token in the thrown error', () => {
    try {
      loadTelegramAuthConfig({ TELEGRAM_AUTH_ENABLED: '1', TELEGRAM_BOT_TOKEN: 'invalid' });
      expect.fail('expected invalid configuration to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigurationError);
      const rendered = `${String(error)} ${error instanceof Error ? (error.stack ?? '') : ''} ${JSON.stringify(error)}`;
      expect(rendered).not.toContain(botToken);
    }
  });
});
