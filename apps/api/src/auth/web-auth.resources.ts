import type { OnModuleDestroy } from '@nestjs/common';
import type { DatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { admittedPool } from '../infrastructure/admission/pool-guard.js';
import type { GuardedPool } from '../infrastructure/admission/pool-guard.js';
import type { ProcessAuthorization } from '../infrastructure/admission/process-admission.js';
import type { WebAuthConfig } from './web-auth.config.js';
import { WebAuthService } from './web-auth.service.js';

/** A separate bounded pool prevents leaked credentials or raw driver errors in logs. */
export class WebAuthResources implements OnModuleDestroy {
  private readonly pool: GuardedPool;
  private closing = false;
  private timer: NodeJS.Timeout | undefined;
  private cleanup: Promise<void> | undefined;
  readonly service: WebAuthService;

  constructor(database: DatabaseConfig, config: WebAuthConfig, authorization: ProcessAuthorization) {
    // P05-01 §7: this pool is admitted per checkout by the launch gate.
    this.pool = admittedPool({ authorization, kind: 'API' }, database, { max: 4, connectionTimeoutMillis: 1000,
      query_timeout: 5000, statement_timeout: 5000, idleTimeoutMillis: 1000,
      application_name: 'fixlevelup-web-auth' });
    this.pool.on('error', () => { /* Never log raw driver errors. */ });
    this.service = new WebAuthService(this.pool, { throttleSecret: config.throttleSecret });
    // The cleanup timer is periodic DB work, so it starts only after this pool's
    // first successful admission verification: no tick (and no connection attempt)
    // can happen before the gate has verified a connection.
    void this.pool.whenAdmitted().then(() => { this.startCleanupTimer(); });
  }

  private startCleanupTimer(): void {
    if (this.closing || this.timer) { return; }
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
    this.closing = true;
    if (this.timer) { clearInterval(this.timer); this.timer = undefined; }
    await this.cleanup;
    await this.pool.end();
  }
}
