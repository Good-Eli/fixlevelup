import 'reflect-metadata';
import { createWorker } from './factories.js';
import { loadConfig } from '../runtime/config.js';
import { SafeLogger } from '../runtime/safe-logger.js';
import { registerShutdown } from '../runtime/lifecycle.js';

const logger = new SafeLogger('worker');
try {
  const config = loadConfig(process.env);
  const app = await createWorker(logger);
  registerShutdown(app, config, logger);
  logger.event('started');
} catch {
  logger.event('startup_failed');
  process.exitCode = 1;
}
