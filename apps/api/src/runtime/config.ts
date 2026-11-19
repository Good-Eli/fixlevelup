export type ProcessRole = 'api' | 'worker';
export type RuntimeEnvironment = 'development' | 'test' | 'production';

export interface RuntimeConfig {
  readonly environment: RuntimeEnvironment;
  readonly host: '127.0.0.1';
  readonly port: number;
  readonly shutdownTimeoutMs: number;
}

export class ConfigurationError extends Error {
  constructor(readonly fields: readonly string[]) {
    super('Invalid technical configuration');
    this.name = 'ConfigurationError';
  }
}

// Only technical configuration is read. There are no provider/DB secrets yet.
export function loadConfig(env: NodeJS.ProcessEnv): RuntimeConfig {
  const fields: string[] = [];
  const environment = env['NODE_ENV'];
  if (environment !== 'development' && environment !== 'test' && environment !== 'production') {
    fields.push('NODE_ENV');
  }
  const host = env['APP_HOST'];
  if (host !== '127.0.0.1') {
    fields.push('APP_HOST');
  }
  const portText = env['APP_PORT'] ?? '';
  const port = Number(portText);
  if (!/^\d{1,5}$/.test(portText) || !Number.isInteger(port) || port > 65535 || (port === 0 && environment !== 'test')) {
    fields.push('APP_PORT');
  }
  const timeoutText = env['SHUTDOWN_TIMEOUT_MS'] ?? '10000';
  const shutdownTimeoutMs = Number(timeoutText);
  if (!/^\d{1,5}$/.test(timeoutText) || shutdownTimeoutMs < 100 || shutdownTimeoutMs > 30000) {
    fields.push('SHUTDOWN_TIMEOUT_MS');
  }
  if (fields.length || (environment !== 'development' && environment !== 'test' && environment !== 'production')) {
    throw new ConfigurationError(fields);
  }
  return Object.freeze({ environment, host: '127.0.0.1', port, shutdownTimeoutMs });
}
