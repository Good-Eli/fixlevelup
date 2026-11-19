import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { WorkerModule } from '../worker.module.js';
import type { RuntimeConfig } from '../runtime/config.js';
import { SafeLogger } from '../runtime/safe-logger.js';
import { ProblemFilter } from '../runtime/problem.filter.js';

export async function createApi(config: RuntimeConfig, logger: SafeLogger, database?: DatabaseConfig) {
  // Nest's public options contract uses a structural class with no methods.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  const app = await NestFactory.create(AppModule.register(database), {
    logger,
    abortOnError: false,
    bodyParser: false,
  });
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

export async function createWorker(logger: SafeLogger) {
  // Same structural Nest options contract as create() above.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
  return NestFactory.createApplicationContext(WorkerModule, { logger, abortOnError: false });
}
