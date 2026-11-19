import { Module } from '@nestjs/common';
import type { DynamicModule } from '@nestjs/common';
import { RuntimeDatabase } from './infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from './infrastructure/database/runtime-database.js';
import { HealthController, HealthService } from './health/health.controller.js';

@Module({})
export class AppModule {
  static register(database?: DatabaseConfig): DynamicModule {
    return { module: AppModule, controllers: [HealthController], providers: [
      HealthService, { provide: RuntimeDatabase, useFactory: () => new RuntimeDatabase(database) },
    ] };
  }
}
