import type { OnModuleDestroy } from '@nestjs/common';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { admittedPool } from '../infrastructure/admission/pool-guard.js';
import type { GuardedPool } from '../infrastructure/admission/pool-guard.js';
import type { ProcessAuthorization } from '../infrastructure/admission/process-admission.js';
import type { TelegramAuthConfig } from './telegram-auth.config.js';
import { TelegramAuthService } from './telegram-auth.service.js';

/** A separate bounded pool keeps Telegram auth queries isolated from other pools;
 * raw driver errors and credentials are never logged, matching WebAuthResources.
 * Session cleanup itself is shared: telegram sessions live in foundation.web_sessions
 * and are removed by the existing cleanup_web_sessions() timer in WebAuthResources,
 * which itself starts only after admission.
 */
export class TelegramAuthResources implements OnModuleDestroy {
  private readonly pool: GuardedPool;
  readonly service: TelegramAuthService;

  constructor(database: DatabaseConfig, config: TelegramAuthConfig, throttleSecret: string, authorization: ProcessAuthorization) {
    // P05-01 §7: this pool is admitted per checkout by the launch gate.
    this.pool = admittedPool({ authorization, kind: 'API' }, database, { max: 4, connectionTimeoutMillis: 1000,
      query_timeout: 5000, statement_timeout: 5000, idleTimeoutMillis: 1000,
      application_name: 'fixlevelup-telegram-auth' });
    this.pool.on('error', () => { /* Never log raw driver errors. */ });
    this.service = new TelegramAuthService(this.pool, { botToken: config.botToken, throttleSecret });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
