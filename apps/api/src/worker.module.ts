import { Inject, Injectable, Module } from '@nestjs/common';
import { SafeLogger } from './runtime/safe-logger.js';
import { OutboxWorker } from './infrastructure/outbox/outbox-worker.js';
import type { DatabaseConfig } from './infrastructure/database/runtime-database.js';
import type { DynamicModule } from '@nestjs/common';
import type { OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';

@Injectable()
export class WorkerLifetime implements OnApplicationBootstrap, OnModuleDestroy {
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(@Inject(SafeLogger) private readonly logger: SafeLogger) {}

  onApplicationBootstrap(): void {
    // A real process lifetime; no pretend jobs, senders or domain operations.
    this.timer = setInterval(() => { this.logger.event('heartbeat'); }, 60_000);
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}

@Module({ providers: [
  { provide: SafeLogger, useFactory: () => new SafeLogger('worker') },
  WorkerLifetime,
] })
export class WorkerModule {
  static register(database?: DatabaseConfig): DynamicModule {
    return { module: WorkerModule, providers: [{ provide: OutboxWorker,
      useFactory: (logger: SafeLogger) => new OutboxWorker(database, logger), inject: [SafeLogger] }] };
  }
}
