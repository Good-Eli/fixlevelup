import type { OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import type { WebAuthConfig } from './web-auth.config.js';
import { WebAuthService } from './web-auth.service.js';

/** A separate bounded pool prevents leaked credentials or raw driver errors in logs. */
export class WebAuthResources implements OnModuleDestroy {
  private readonly pool: Pool;
  private readonly timer: NodeJS.Timeout;
  private cleanup: Promise<void> | undefined;
  readonly service: WebAuthService;

  constructor(database: DatabaseConfig, config: WebAuthConfig) {
    this.pool = new Pool({ ...database, max: 4, connectionTimeoutMillis: 1000,
      query_timeout: 5000, statement_timeout: 5000, idleTimeoutMillis: 1000,
      application_name: 'fixlevelup-web-auth' });
    this.pool.on('error', () => { /* Never log raw driver errors. */ });
    this.service = new WebAuthService(this.pool, { throttleSecret: config.throttleSecret });
    this.timer = setInterval(() => {
      this.cleanup ??= this.cleanExpired().finally(() => { this.cleanup = undefined; });
    }, 10_000);
    this.timer.unref();
  }

  private async cleanExpired(): Promise<void> {
    for (const sql of ['SELECT foundation.cleanup_web_auth_attempts()', 'SELECT foundation.cleanup_web_auth_throttles()', 'SELECT foundation.cleanup_web_sessions()']) {
      try { await this.pool.query(sql); }
      catch { /* No untrusted DB error in logs; retry separately on next bounded tick. */ }
    }
  }

  async onModuleDestroy(): Promise<void> {
    clearInterval(this.timer);
    await this.cleanup;
    await this.pool.end();
  }
}
