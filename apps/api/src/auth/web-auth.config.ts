import { ConfigurationError } from '../runtime/config.js';

/** Web auth is absent unless explicitly enabled. Partial or unsafe configuration fails closed. */
export interface WebAuthConfig {
  readonly origin: string;
  readonly csrfSecret: string;
  readonly throttleSecret: string;
}

export function loadWebAuthConfig(env: NodeJS.ProcessEnv): WebAuthConfig | undefined {
  const enabled = env['WEB_AUTH_ENABLED'];
  if (enabled === undefined || enabled === '0') {
    if (env['WEB_AUTH_ORIGIN'] || env['WEB_AUTH_CSRF_SECRET'] || env['WEB_AUTH_THROTTLE_SECRET']) {
      throw new ConfigurationError(['WEB_AUTH_ENABLED']);
    }
    return undefined;
  }
  const fields: string[] = [];
  if (enabled !== '1') { fields.push('WEB_AUTH_ENABLED'); }
  const origin = env['WEB_AUTH_ORIGIN'] ?? '';
  try {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' || parsed.origin !== origin) { fields.push('WEB_AUTH_ORIGIN'); }
  } catch { fields.push('WEB_AUTH_ORIGIN'); }
  const csrfSecret = env['WEB_AUTH_CSRF_SECRET'] ?? '';
  const throttleSecret = env['WEB_AUTH_THROTTLE_SECRET'] ?? '';
  if (!/^[0-9a-f]{64}$/.test(csrfSecret)) { fields.push('WEB_AUTH_CSRF_SECRET'); }
  if (!/^[0-9a-f]{64}$/.test(throttleSecret) || csrfSecret === throttleSecret) { fields.push('WEB_AUTH_THROTTLE_SECRET'); }
  if (fields.length) { throw new ConfigurationError(fields); }
  return Object.freeze({ origin, csrfSecret, throttleSecret });
}
