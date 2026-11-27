/**
 * Control-database contour for the LAUNCHER-side one-time consumption (§7):
 * the launcher's registry lives on a separate control database with its own
 * operator credentials; the child never sees these. The proof identity is NOT
 * supplied here — the digest is derived from the offline-verified token
 * (RuntimeAdmission.proofDigest), binding the consumed row to the exact
 * signed payload (round-5 audit MUST 2).
 */
import { ConfigurationError } from '../../runtime/config.js';

export interface ControlContour {
  readonly control: { readonly host: string; readonly port: number; readonly database: string;
    readonly user: string; readonly password: string };
}

/**
 * Strict env contour for the launcher's control connection. The password is
 * the launcher's own operator credential, validated for shape only; it is
 * never an application or migrator credential.
 */
export function loadControlContour(env: NodeJS.ProcessEnv): ControlContour {
  const fields: string[] = [];
  const host = env['LAUNCH_CONTROL_HOST'] ?? '';
  const portText = env['LAUNCH_CONTROL_PORT'] ?? '';
  const port = Number(portText);
  const database = env['LAUNCH_CONTROL_DATABASE'] ?? '';
  const user = env['LAUNCH_CONTROL_USER'] ?? '';
  const password = env['LAUNCH_CONTROL_PASSWORD'] ?? '';
  if (host.length === 0) { fields.push('LAUNCH_CONTROL_HOST'); }
  if (!/^\d+$/.test(portText) || !Number.isInteger(port) || port <= 0 || port > 65535) { fields.push('LAUNCH_CONTROL_PORT'); }
  if (database.length === 0) { fields.push('LAUNCH_CONTROL_DATABASE'); }
  if (user.length === 0) { fields.push('LAUNCH_CONTROL_USER'); }
  if (password.length < 16 || password.length > 256 || /[\r\n\0]/.test(password)) { fields.push('LAUNCH_CONTROL_PASSWORD'); }
  if (fields.length) { throw new ConfigurationError(fields); }
  return { control: Object.freeze({ host, port, database, user, password }) };
}
