import 'reflect-metadata';
import { createWorker } from './factories.js';
import { loadConfig } from '../runtime/config.js';
import { SafeLogger } from '../runtime/safe-logger.js';
import { registerShutdown } from '../runtime/lifecycle.js';
import { loadDatabaseConfig } from '../infrastructure/database/runtime-database.js';
import { loadRuntimeAdmission } from '../infrastructure/admission/runtime-admission.js';
import { admitProcess, ProcessAdmissionError } from '../infrastructure/admission/process-admission.js';
import type { LauncherChannel } from '../infrastructure/admission/process-admission.js';
import { physicalProfileVerifier } from '../infrastructure/admission/physical-profile.js';

const logger = new SafeLogger('worker');
/** Sentinel: the admission stage already logged its own typed event. */
const STAGE_DONE = new Error('admission-stage-logged');
try {
  const config = loadConfig(process.env);
  const database = loadDatabaseConfig(process.env);
  // P05-01 §7: the admission contour is loaded before the worker module
  // exists; the pinned consumer kind must be WORKER here.
  let admission;
  try {
    admission = loadRuntimeAdmission(process.env, { database, requiredConsumer: 'WORKER' });
  } catch {
    logger.event('admission_missing');
    throw STAGE_DONE;
  }
  // Process admission handshake: live binding + exact physical profile, the
  // launcher-side one-time consumption over the private IPC channel, and the
  // final pre-start re-check. Its result (ProcessAuthorization) is the ONLY
  // value the worker factory accepts; no tick happens before it exists.
  let authorization;
  try {
    authorization = await admitProcess(admission, {
      database,
      channel: (typeof process.send === 'function'
        ? process as unknown as LauncherChannel : undefined),
      verifyProfile: physicalProfileVerifier(database),
      approvalTimeoutMs: Number(process.env['LAUNCH_APPROVAL_TIMEOUT_MS'] ?? 10_000),
    });
  } catch (error) {
    logger.event(error instanceof ProcessAdmissionError ? 'admission_denied' : 'startup_failed');
    throw STAGE_DONE;
  }
  const app = await createWorker(logger, database, authorization);
  registerShutdown(app, config, logger);
  logger.event('started');
} catch (error) {
  if (error !== STAGE_DONE) { logger.event('startup_failed'); }
  // An unadmitted process must terminate now: the open IPC handle would keep
  // the event loop alive otherwise.
  if (typeof process.disconnect === 'function') { process.disconnect(); }
  process.exit(1);
}
