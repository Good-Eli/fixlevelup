import { refusePrivacy } from './contract.js';
import type { FilePrivacyGrant, FilePrivacyRole, HoldGrant, HoldReason } from './contract.js';
import { epochNumber, snapshotRecord, uuid } from './input.js';

interface Operator { readonly namespace: string; readonly actorId: string; readonly role: FilePrivacyRole }
type HoldCommand = { readonly intentId: string; readonly expectedRowVersion: bigint } &
  ({ readonly action: 'PLACE'; readonly reason: HoldReason } | { readonly action: 'RELEASE' });
const operators = new WeakMap<object, Operator>();
const holds = new WeakMap<object, HoldCommand & { readonly operator: Operator }>();

/** Trusted synthetic wiring only. These grants are neither F proof nor serializable authority. */
export function makeFilePrivacyGrant(input: Operator & { readonly mode: 'local-synthetic' }): FilePrivacyGrant {
  const cmd = snapshotRecord(input, ['mode','namespace','actorId','role']);
  const role = cmd['role'];
  if (cmd['mode'] !== 'local-synthetic' || (role !== 'HOLD' && role !== 'RETENTION' && role !== 'DELETE' && role !== 'SOURCE_DRAIN')) {
    return refusePrivacy('NOT_CONFIGURED');
  }
  const token = Object.freeze({}) as FilePrivacyGrant;
  operators.set(token, Object.freeze({ role, namespace: uuid(cmd['namespace']), actorId: uuid(cmd['actorId']) }));
  return token;
}

function getOperator(token: unknown): Operator {
  const facts = typeof token === 'object' && token !== null ? operators.get(token) : undefined;
  return facts ?? refusePrivacy('NOT_CONFIGURED');
}
export function requireOperator(token: unknown, namespace: string, role: FilePrivacyRole): void {
  const facts = getOperator(token);
  if (facts.namespace !== namespace || facts.role !== role) { refusePrivacy('NOT_CONFIGURED'); }
}
export function makeHoldGrant(token: FilePrivacyGrant, command: HoldCommand): HoldGrant {
  const operator = getOperator(token);
  requireOperator(token, operator.namespace, 'HOLD');
  let cmd: Readonly<Record<string, unknown>>;
  try {
    cmd = snapshotRecord(command, ['intentId','expectedRowVersion','action','reason']);
  } catch {
    cmd = snapshotRecord(command, ['intentId','expectedRowVersion','action']);
  }
  const intentId = uuid(cmd['intentId']);
  const expectedRowVersion = epochNumber(cmd['expectedRowVersion']);
  const grant = Object.freeze({}) as HoldGrant;
  if (cmd['action'] === 'RELEASE' && !Object.hasOwn(cmd, 'reason')) {
    holds.set(grant, Object.freeze({ action: 'RELEASE', operator, intentId, expectedRowVersion }));
  } else if (cmd['action'] === 'PLACE' && (cmd['reason'] === 'LEGAL_HOLD' || cmd['reason'] === 'OPERATOR_REVIEW')) {
    holds.set(grant, Object.freeze({ action: 'PLACE', reason: cmd['reason'], operator, intentId, expectedRowVersion }));
  } else {
    return refusePrivacy('INVALID_INPUT');
  }
  return grant;
}
export function readHoldGrant(grant: unknown, namespace: string): HoldCommand & { readonly operator: Operator } {
  const facts = typeof grant === 'object' && grant !== null ? holds.get(grant) : undefined;
  if (facts === undefined || facts.operator.namespace !== namespace) { return refusePrivacy('NOT_CONFIGURED'); }
  return facts;
}
