import { Module } from '@nestjs/common';
import type { DynamicModule } from '@nestjs/common';
import { RuntimeDatabase } from './infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from './infrastructure/database/runtime-database.js';
import { HealthController, HealthService } from './health/health.controller.js';
import type { WebAuthConfig } from './auth/web-auth.config.js';
import { WEB_AUTH_HTTP_CONFIG, WEB_AUTH_SERVICE, WebAuthController } from './auth/web-auth.controller.js';
import { WebAuthResources } from './auth/web-auth.resources.js';

@Module({})
export class AppModule {
  static register(database?: DatabaseConfig, webAuth?: WebAuthConfig): DynamicModule {
    if (webAuth && !database) { throw new Error('Web authentication requires a database'); }
    const controllers = webAuth ? [HealthController, WebAuthController] : [HealthController];
    const providers = [
      HealthService, { provide: RuntimeDatabase, useFactory: () => new RuntimeDatabase(database, Boolean(webAuth)) },
      ...(webAuth && database ? [
        { provide: WebAuthResources, useFactory: () => new WebAuthResources(database, webAuth) },
        { provide: WEB_AUTH_SERVICE, useFactory: (resources: WebAuthResources) => resources.service, inject: [WebAuthResources] },
        { provide: WEB_AUTH_HTTP_CONFIG, useValue: { origin: webAuth.origin, csrfSecret: webAuth.csrfSecret } },
      ] : []),
    ];
    return { module: AppModule, controllers, providers };
  }
}
