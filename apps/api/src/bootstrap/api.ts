import 'reflect-metadata';
import { createApi } from './factories.js';
import { loadConfig } from '../runtime/config.js';
import { SafeLogger } from '../runtime/safe-logger.js';
import { registerShutdown } from '../runtime/lifecycle.js';
import { loadDatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { loadWebAuthConfig } from '../auth/web-auth.config.js';
import { loadTelegramAuthConfig } from '../auth/telegram-auth.config.js';

const logger = new SafeLogger('api');
try {
  const config = loadConfig(process.env);
  const database = loadDatabaseConfig(process.env);
  const webAuth = loadWebAuthConfig(process.env);
  const telegramAuth = loadTelegramAuthConfig(process.env);
  const app = await createApi(config, logger, database, webAuth, telegramAuth);
  registerShutdown(app, config, logger);
  logger.event('started');
} catch {
  logger.event('startup_failed');
  process.exitCode = 1;
}
