import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { WebAuthConfig } from '../auth/web-auth.config.js';
import type { TelegramAuthConfig } from '../auth/telegram-auth.config.js';
import { AppModule } from '../app.module.js';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { WorkerModule } from '../worker.module.js';
import { ConfigurationError } from '../runtime/config.js';
import type { RuntimeConfig } from '../runtime/config.js';
import { SafeLogger } from '../runtime/safe-logger.js';
import { ProblemFilter } from '../runtime/problem.filter.js';
import { boundedJson } from '../settings/management/body-parser.js';
import type { ProcessAuthorization } from '../infrastructure/admission/process-admission.js';

export async function createApi(config: RuntimeConfig, logger: SafeLogger, database?: DatabaseConfig, webAuth?: WebAuthConfig, telegramAuth?: TelegramAuthConfig, admission?: ProcessAuthorization) {
  // P05-01 §7: no runtime DB consumer may be constructed without the launch
  // admission; the application never composes it from environment variables here.
  if (database && !admission) { throw new ConfigurationError(['LAUNCH_PROOF_TOKEN']); }
  // Nest's public options contract uses a structural class with no methods.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  const app = await NestFactory.create(AppModule.register(database, webAuth, telegramAuth, admission), {
    logger,
    abortOnError: false,
    bodyParser: false,
  });
  if (webAuth || telegramAuth) {
    app.use(boundedJson);
  }
  app.useGlobalFilters(new ProblemFilter(logger));
  const server = app.getHttpAdapter().getInstance() as { disable: (name: string) => void };
  server.disable('x-powered-by');
  try {
    await app.listen(config.port, config.host);
    return app;
  } catch (error) {
    await app.close();
    throw error;
  }
}

export async function createWorker(logger: SafeLogger, database?: DatabaseConfig, admission?: ProcessAuthorization) {
  // P05-01 §7: the worker's DB consumers exist only behind the launch admission.
  if (database && !admission) { throw new ConfigurationError(['LAUNCH_PROOF_TOKEN']); }
  // Same structural Nest options contract as create() above.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  return NestFactory.createApplicationContext(WorkerModule.register(database, admission), { logger, abortOnError: false });
}
