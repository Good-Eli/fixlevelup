import 'reflect-metadata';
import { createApi } from './factories.js';
import { loadConfig } from '../runtime/config.js';
import { SafeLogger } from '../runtime/safe-logger.js';
import { registerShutdown } from '../runtime/lifecycle.js';
import { loadDatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { loadRuntimeAdmission } from '../infrastructure/admission/runtime-admission.js';
import { admitProcess, ProcessAdmissionError } from '../infrastructure/admission/process-admission.js';
import { loadWebAuthConfig } from '../auth/web-auth.config.js';
import { loadTelegramAuthConfig } from '../auth/telegram-auth.config.js';

const logger = new SafeLogger('api');
/** Sentinel: the admission stage already logged its own typed event. */
const STAGE_DONE = new Error('admission-stage-logged');
try {
  const config = loadConfig(process.env);
  const database = loadDatabaseConfig(process.env);
  // P05-01 §7: the admission contour is loaded from the operator environment
  // before any resource exists; the pinned consumer kind must be API here.
  let admission;
  try {
    admission = loadRuntimeAdmission(process.env, { database, requiredConsumer: 'API' });
  } catch {
    logger.event('admission_missing');
    throw STAGE_DONE;
  }
  // Process admission handshake: live binding + exact physical profile, the
  // launcher-side one-time consumption over the private IPC channel, and the
  // final pre-start re-check. Its result (ProcessAuthorization) is the ONLY
  // value the factory boundary accepts; no listener opens before it exists.
  let authorization;
  try {
    authorization = await admitProcess(admission, {
      database,
      approvalTimeoutMs: Number(process.env['LAUNCH_APPROVAL_TIMEOUT_MS'] ?? 10_000),
    });
  } catch (error) {
    logger.event(error instanceof ProcessAdmissionError ? 'admission_denied' : 'startup_failed');
    throw STAGE_DONE;
  }
  const webAuth = loadWebAuthConfig(process.env);
  const telegramAuth = loadTelegramAuthConfig(process.env);
  const app = await createApi(config, logger, database, webAuth, telegramAuth, authorization);
  registerShutdown(app, config, logger);
  logger.event('started');
} catch (error) {
  if (error !== STAGE_DONE) { logger.event('startup_failed'); }
  // An unadmitted process must terminate now: the open IPC handle would keep
  // the event loop alive otherwise.
  if (process.connected && typeof process.disconnect === 'function') { process.disconnect(); }
  process.exit(1);
}
