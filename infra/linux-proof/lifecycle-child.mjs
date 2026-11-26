import { SafeLogger } from '../../apps/api/dist/runtime/safe-logger.js';
import { registerShutdown } from '../../apps/api/dist/runtime/lifecycle.js';

const role = process.argv[2];
if (role !== 'api' && role !== 'worker') {
  throw new Error('Invalid lifecycle smoke role');
}

const logger = new SafeLogger(role);
const config = Object.freeze({ environment: 'test', host: '127.0.0.1', port: 0, shutdownTimeoutMs: 5000 });
// Mirror the liveness of a real API/worker: an active service handle keeps
// the process alive until app.close() releases it during graceful shutdown.
const keepAlive = setInterval(() => undefined, 1000);
const app = Object.freeze({ close: async () => { clearInterval(keepAlive); } });

// This child imports the compiled production lifecycle implementation. The
// parent sends real OS SIGTERM/SIGINT; the child must emit the ordered events
// and exit naturally after app.close(), not through a test-only signal shim.
registerShutdown(app, config, logger);
logger.event('started');
