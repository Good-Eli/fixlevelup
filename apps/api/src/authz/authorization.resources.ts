import type { OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { AuthorizationService } from './authorization.service.js';

/** DI token for the authorization service API consumed by the guard and controllers. */
export const AUTHORIZATION_SERVICE = Symbol('AUTHORIZATION_SERVICE');

/** A separate bounded pool isolates authorization queries from other pools; raw driver
 * errors and credentials are never logged, matching WebAuthResources.
 */
export class AuthorizationResources implements OnModuleDestroy {
  private readonly pool: Pool;
  readonly service: AuthorizationService;

  constructor(database: DatabaseConfig) {
    this.pool = new Pool({ ...database, max: 4, connectionTimeoutMillis: 1000,
      query_timeout: 5000, statement_timeout: 5000, idleTimeoutMillis: 1000,
      application_name: 'fixlevelup-authz' });
    this.pool.on('error', () => { /* Never log raw driver errors. */ });
    this.service = new AuthorizationService(this.pool);
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
