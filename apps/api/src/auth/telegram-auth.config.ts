import { ConfigurationError } from '../runtime/config.js';

/** Telegram Mini App staff authentication is absent unless explicitly enabled.
 * Partial or unsafe configuration fails closed, mirroring web auth config.
 * The bot token comes only from the environment, is never logged and is not
 * committed; missing/invalid secrets close the real connection but do not
 * block offline fixtures (DECISIONS §21).
 */
export interface TelegramAuthConfig {
  readonly botToken: string;
}

export function loadTelegramAuthConfig(env: NodeJS.ProcessEnv): TelegramAuthConfig | undefined {
  const enabled = env['TELEGRAM_AUTH_ENABLED'];
  if (enabled === undefined || enabled === '0') {
    if (env['TELEGRAM_BOT_TOKEN']) { throw new ConfigurationError(['TELEGRAM_AUTH_ENABLED']); }
    return undefined;
  }
  const fields: string[] = [];
  if (enabled !== '1') { fields.push('TELEGRAM_AUTH_ENABLED'); }
  const botToken = env['TELEGRAM_BOT_TOKEN'] ?? '';
  if (!/^[0-9]+:[A-Za-z0-9_-]{30,}$/.test(botToken)) { fields.push('TELEGRAM_BOT_TOKEN'); }
  if (fields.length) { throw new ConfigurationError(fields); }
  return Object.freeze({ botToken });
}
