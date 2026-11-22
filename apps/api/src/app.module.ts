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
import { StaffTelegramAuthGuard } from './authz/telegram-auth.guard.js';
import { TELEGRAM_AUTH_SERVICE, TelegramAuthController } from './auth/telegram-auth.controller.js';
import { TelegramAuthResources } from './auth/telegram-auth.resources.js';
import type { TelegramAuthConfig } from './auth/telegram-auth.config.js';
import { AccessController } from './authz/access.controller.js';
import { StaffController, TelegramStaffController } from './staff/staff.controller.js';
import { StaffService } from './staff/staff.service.js';
import { GeoRunner } from './settings/geography/geo-runner.js';
import { ManagementRunner } from './settings/management/management-runner.js';
import { ManagementController } from './settings/management/management.controller.js';
import { GeographyController, TechnicianTerritoryController } from './settings/geography/geography.controller.js';
import { PermissionsController, RolesController, RolesService, TelegramPermissionsController, TelegramRolesController } from './roles/index.js';

@Module({})
export class AppModule {
  static register(database?: DatabaseConfig, webAuth?: WebAuthConfig, telegramAuth?: TelegramAuthConfig): DynamicModule {
    if ((webAuth || telegramAuth) && !database) { throw new Error('Web authentication requires a database'); }
    if (telegramAuth && !webAuth) { throw new Error('Telegram authentication requires web authentication configuration'); }
    const controllers = webAuth
      ? [HealthController, WebAuthController, AccessController, StaffController, RolesController,
          PermissionsController, GeographyController, ManagementController, ...(telegramAuth ? [TelegramAuthController, TelegramStaffController, TelegramRolesController, TelegramPermissionsController, TechnicianTerritoryController] : [])]
      : [HealthController];
    const providers = [
      HealthService, { provide: RuntimeDatabase, useFactory: () => new RuntimeDatabase(database, Boolean(webAuth)) },
      ...(webAuth && database ? [
        StaffService, RolesService, GeoRunner, ManagementRunner,
        // Explicit DI registration makes missing security dependencies a startup failure.
        StaffWebAuthGuard,
        { provide: WebAuthResources, useFactory: () => new WebAuthResources(database, webAuth) },
        { provide: WEB_AUTH_SERVICE, useFactory: (resources: WebAuthResources) => resources.service, inject: [WebAuthResources] },
        { provide: WEB_AUTH_HTTP_CONFIG, useValue: { origin: webAuth.origin, csrfSecret: webAuth.csrfSecret } },
        { provide: AuthorizationResources, useFactory: () => new AuthorizationResources(database) },
        { provide: AUTHORIZATION_SERVICE, useFactory: (resources: AuthorizationResources) => resources.service, inject: [AuthorizationResources] },
        ...(telegramAuth ? [
          // No bearer routes without a configured exchange and guard.
          StaffTelegramAuthGuard,
          { provide: TelegramAuthResources, useFactory: () => new TelegramAuthResources(database, telegramAuth, webAuth.throttleSecret) },
          { provide: TELEGRAM_AUTH_SERVICE, useFactory: (resources: TelegramAuthResources) => resources.service, inject: [TelegramAuthResources] },
        ] : []),
      ] : []),
    ];
    return { module: AppModule, controllers, providers };
  }
}
