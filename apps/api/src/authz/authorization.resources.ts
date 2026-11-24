import type { OnModuleDestroy } from '@nestjs/common';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { admittedPool } from '../infrastructure/admission/pool-guard.js';
import type { GuardedPool } from '../infrastructure/admission/pool-guard.js';
import type { RuntimeAdmission } from '../infrastructure/admission/runtime-admission.js';
import { AuthorizationService } from './authorization.service.js';

/** DI token for the authorization service API consumed by the guard and controllers. */
export const AUTHORIZATION_SERVICE = Symbol('AUTHORIZATION_SERVICE');

/** A separate bounded pool isolates authorization queries from other pools; raw
 * driver errors and credentials are never logged, matching WebAuthResources.
 */
export class AuthorizationResources implements OnModuleDestroy {
  private readonly pool: GuardedPool;
  readonly service: AuthorizationService;

  constructor(database: DatabaseConfig, admission: RuntimeAdmission) {
    // P05-01 §7: this pool is admitted per checkout by the launch gate.
    this.pool = admittedPool({ gate: admission.gate }, { ...database, max: 4, connectionTimeoutMillis: 1000,
      query_timeout: 5500, statement_timeout: 5000, idleTimeoutMillis: 1000, options: '-c lock_timeout=4500',
      application_name: 'fixlevelup-authz' });
    this.pool.on('error', () => { /* Never log raw driver errors. */ });
    this.service = new AuthorizationService(this.pool);
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
