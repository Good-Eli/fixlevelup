import type { INestApplicationContext } from '@nestjs/common';
import type { RuntimeConfig } from './config.js';
import { SafeLogger } from './safe-logger.js';

export function registerShutdown(app: INestApplicationContext, config: RuntimeConfig, logger: SafeLogger): void {
  let closing = false;
  const shutdown = (): void => {
    if (closing) {
      return;
    }
    closing = true;
    logger.event('shutdown_started');
    const deadline = setTimeout(() => {
      logger.event('shutdown_timeout');
      process.exit(1);
    }, config.shutdownTimeoutMs);
    void app.close().then(() => {
      clearTimeout(deadline);
      process.removeListener('SIGINT', shutdown);
      process.removeListener('SIGTERM', shutdown);
      logger.event('shutdown_completed');
    }).catch(() => {
      // Keep the force-exit deadline active if close leaves live handles.
      logger.event('shutdown_failed');
      process.exitCode = 1;
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
