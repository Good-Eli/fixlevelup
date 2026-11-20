import { Module } from '@nestjs/common';
import type { DynamicModule } from '@nestjs/common';
import { RuntimeDatabase } from './infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from './infrastructure/database/runtime-database.js';
import { HealthController, HealthService } from './health/health.controller.js';
import type { WebAuthConfig } from './auth/web-auth.config.js';
import { WEB_AUTH_HTTP_CONFIG, WEB_AUTH_SERVICE, WebAuthController } from './auth/web-auth.controller.js';
import { WebAuthResources } from './auth/web-auth.resources.js';
import { AUTHORIZATION_SERVICE, AuthorizationResources } from './authz/authorization.resources.js';
import { StaffWebAuthGuard } from './authz/authorization.guard.js';
import { StaffController, StaffService } from './staff/staff.controller.js';

@Module({})
export class AppModule {
  static register(database?: DatabaseConfig, webAuth?: WebAuthConfig): DynamicModule {
    if (webAuth && !database) { throw new Error('Web authentication requires a database'); }
    const controllers = webAuth ? [HealthController, WebAuthController, StaffController] : [HealthController];
    const providers = [
      HealthService, { provide: RuntimeDatabase, useFactory: () => new RuntimeDatabase(database, Boolean(webAuth)) },
      ...(webAuth && database ? [
        StaffService,
        // Explicit DI registration of the class-reference guard: Nest resolves it
        // from the module injector; registration makes missing dependencies fail
        // at startup instead of at first request, and proves the guard is wired.
        StaffWebAuthGuard,
        { provide: WebAuthResources, useFactory: () => new WebAuthResources(database, webAuth) },
        { provide: WEB_AUTH_SERVICE, useFactory: (resources: WebAuthResources) => resources.service, inject: [WebAuthResources] },
        { provide: WEB_AUTH_HTTP_CONFIG, useValue: { origin: webAuth.origin, csrfSecret: webAuth.csrfSecret } },
        { provide: AuthorizationResources, useFactory: () => new AuthorizationResources(database) },
        { provide: AUTHORIZATION_SERVICE, useFactory: (resources: AuthorizationResources) => resources.service, inject: [AuthorizationResources] },
      ] : []),
    ];
    return { module: AppModule, controllers, providers };
  }
}
