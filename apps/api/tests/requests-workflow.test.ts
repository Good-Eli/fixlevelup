/**
 * P05-01 X01 unit matrix for the pure workflow registry (docs/P05-PLAN.md §6).
 *
 * Enumerates every cell: 10 workflow-version values (the supported
 * `wf-r2-p05-v1` plus 9 malformed/unknown ones) x all statuses (plus the ∅
 * pre-create null) x all §6.1 commands x actors F/S x type
 * CALLBACK/REPAIR/none x branch PHONE/MESSENGER/none —
 * 10 * 11 * 2 * 20 * 3 * 3 = 39600 cells. The expected classification below
 * is written by hand from the plan table as an independent oracle; it does
 * not read the runtime registry. Any `AWAIT_DEPENDENCY` must deny before a
 * domain write, so its result carries no target.
 */
import { describe, expect, it } from 'vitest';
import {
  ALL_STATUSES, WORKFLOW_VERSION, classifyPolicyPair, decide, policyPairKey,
  type ActorClass, type CommandName, type Decision, type DispatchBranch,
  type RegistryQuery, type RequestStatus, type RequestType,
} from '../src/requests/workflow/registry.js';

/**
 * Handwritten literal of the 19 §6 statuses — the test's own inventory,
 * independent of the runtime export. The single equality assertion below
 * checks the runtime ALL_STATUSES against it, so drift fails loudly instead
 * of silently narrowing the matrix.
 */
const STATUS_INVENTORY: readonly RequestStatus[] = [
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK',
  'MANAGER_REVIEW', 'WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED',
  'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL',
  'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED',
  'REVISIT_REQUIRED', 'CLOSED', 'CANCELLED',
];

interface Expected {
  readonly decision: Decision;
  readonly target: RequestStatus | null;
  readonly awaitDependency: string | null;
  readonly resultingType: RequestType | null;
  readonly reason: string;
}

const DENIED: Expected = { decision: 'DENIED', target: null, awaitDependency: null, resultingType: null, reason: 'NO_ROW' };
const DENIED_UNKNOWN_VERSION: Expected = {
  decision: 'DENIED', target: null, awaitDependency: null, resultingType: null, reason: 'UNKNOWN_WORKFLOW_VERSION',
};

/** Oracle-side literal of the only supported version (independent of exports). */
const SUPPORTED_VERSION_ORACLE = 'wf-r2-p05-v1';

/** The supported version plus 9 unknown/malformed ones (near-misses included). */
const VERSIONS: readonly string[] = [
  SUPPORTED_VERSION_ORACLE,
  'wf-r1', 'wf-r2-p05-v0', 'wf-r2-p05-v2', 'wf-r2-p06-v1', 'wf-r2-p05-v1-beta',
  'WF-R2-P05-V1', 'wf-r2-p05-v1 ', ' wf-r2-p05-v1', '',
];

const COMMANDS: readonly CommandName[] = [
  'CreateCallback', 'CreateRepair', 'StartReview', 'ConvertCallback', 'ChangeDetails',
  'RecordCoverageAssessment', 'ChangeContact', 'ChooseCallback', 'WithdrawPhonePermission',
  'ReadyForDispatch', 'CancelRequest',
];

const ACTORS: readonly ActorClass[] = ['F', 'S'];
const TYPES: readonly RequestType[] = ['CALLBACK', 'REPAIR'];
const BRANCHES: readonly (DispatchBranch | undefined)[] = [undefined, 'PHONE', 'MESSENGER'];

const EARLY: readonly RequestStatus[] = [
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK', 'MANAGER_REVIEW',
];
const W: readonly RequestStatus[] = ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'];

function executable(
  target: RequestStatus | null, resultingType: RequestType | null = null,
): Expected {
  return { decision: 'EXECUTABLE', target, awaitDependency: null, resultingType, reason: 'MATCHED' };
}

/** Handwritten §6.1 oracle, independent of the registry data. */
function expected(command: CommandName, actor: ActorClass, status: RequestStatus | null,
  type: RequestType | null, branch: DispatchBranch | undefined): Expected {
  switch (command) {
    case 'CreateCallback':
      return status === null
        ? executable('CALLBACK_REQUIRED', 'CALLBACK')
        : DENIED;
    case 'CreateRepair':
      // Two rows: F -> messenger multi-target (channel resolved by the caller,
      // branch PHONE never matches a row), S -> branch PHONE -> NEW.
      if (status !== null || type === 'CALLBACK') { return DENIED; }
      if (actor === 'S') {
        return branch === 'PHONE' ? executable('NEW', 'REPAIR') : DENIED;
      }
      return branch === 'PHONE' ? DENIED : executable(null, 'REPAIR');
    case 'StartReview':
      return actor === 'S' && (status === 'NEW' || status === 'CALLBACK_REQUIRED')
        ? executable('MANAGER_REVIEW')
        : DENIED;
    case 'ConvertCallback':
      return actor === 'S' && type === 'CALLBACK'
        && (status === 'CALLBACK_REQUIRED' || status === 'MANAGER_REVIEW')
        ? executable('MANAGER_REVIEW', 'REPAIR')
        : DENIED;
    case 'ChangeDetails':
      return actor === 'S' && type === 'REPAIR' && status === 'MANAGER_REVIEW'
        ? executable(null)
        : DENIED;
    case 'RecordCoverageAssessment':
      return actor === 'S' && type === 'REPAIR' && status === 'MANAGER_REVIEW'
        ? executable(null)
        : DENIED;
    case 'ChangeContact':
      return actor === 'S' && (status === 'CALLBACK_REQUIRED' || status === 'MANAGER_REVIEW')
        ? executable(null)
        : DENIED;
    case 'ChooseCallback':
      return actor === 'F' && type === 'REPAIR' && status !== null && W.includes(status)
        ? executable('CALLBACK_REQUIRED', 'REPAIR')
        : DENIED;
    case 'WithdrawPhonePermission':
      return status !== null
        ? executable(null)
        : DENIED;
    case 'ReadyForDispatch':
      if (actor !== 'S' || type !== 'REPAIR' || status !== 'MANAGER_REVIEW') { return DENIED; }
      if (branch === 'PHONE') { return executable('WAITING_ASSIGNMENT'); }
      if (branch === 'MESSENGER') {
        return { decision: 'AWAIT_DEPENDENCY', target: null, awaitDependency: 'P07', resultingType: null, reason: 'MATCHED' };
      }
      return DENIED;
    case 'CancelRequest':
      if (status === null) { return DENIED; }
      if (status === 'WAITING_ASSIGNMENT') {
        return actor === 'S' ? executable('CANCELLED') : DENIED;
      }
      if (!EARLY.includes(status)) { return DENIED; }
      return executable('CANCELLED');
  }
}

describe('P05-01 workflow registry X01 matrix (wf-r2-p05-v1)', () => {
  it('classifies the full version x command x actor x status x type x branch cross-product exactly', () => {
    let checked = 0;
    for (const workflowVersion of VERSIONS) {
      for (const command of COMMANDS) {
        for (const actor of ACTORS) {
          for (const status of [null, ...STATUS_INVENTORY] as readonly (RequestStatus | null)[]) {
            for (const type of [...TYPES, null] as readonly (RequestType | null)[]) {
              for (const branch of BRANCHES) {
                const query: RegistryQuery = branch === undefined
                  ? { workflowVersion, command, actor, status, type }
                  : { workflowVersion, command, actor, status, type, branch };
                const want = workflowVersion === SUPPORTED_VERSION_ORACLE
                  ? expected(command, actor, status, type, branch)
                  : DENIED_UNKNOWN_VERSION;
                expect(decide(query), `${workflowVersion || '∅v'}/${command}/${actor}/${status ?? '∅'}/${type ?? '-'}/${branch ?? '-'}`)
                  .toEqual(want);
                checked += 1;
              }
            }
          }
        }
      }
    }
    expect(checked).toBe(39600);
  });

  it('splits CreateRepair: F -> messenger multi-target, S+PHONE -> NEW, F+PHONE finds no row', () => {
    const base = { workflowVersion: WORKFLOW_VERSION, command: 'CreateRepair' as const, status: null, type: 'REPAIR' as const };
    // F: branch undefined or MESSENGER -> multi-target (null) with type REPAIR.
    expect(decide({ ...base, actor: 'F' })).toEqual(executable(null, 'REPAIR'));
    expect(decide({ ...base, actor: 'F', branch: 'MESSENGER' })).toEqual(executable(null, 'REPAIR'));
    // F + PHONE has no row at all.
    expect(decide({ ...base, actor: 'F', branch: 'PHONE' })).toEqual(DENIED);
    // S: only the explicit PHONE branch leads to NEW.
    expect(decide({ ...base, actor: 'S', branch: 'PHONE' })).toEqual(executable('NEW', 'REPAIR'));
    expect(decide({ ...base, actor: 'S' }).decision).toBe('DENIED');
    expect(decide({ ...base, actor: 'S', branch: 'MESSENGER' }).decision).toBe('DENIED');
    // A conflicting explicit CALLBACK type refuses for both actors.
    expect(decide({ ...base, actor: 'F', type: 'CALLBACK' }).decision).toBe('DENIED');
    expect(decide({ ...base, actor: 'S', branch: 'PHONE', type: 'CALLBACK' }).decision).toBe('DENIED');
  });

  it('denies an unknown workflow version regardless of actor, command or state', () => {
    for (const workflowVersion of ['wf-r1', 'wf-r2-p05-v0', '']) {
      for (const query of [
        { command: 'CreateCallback' as const, actor: 'F' as const, status: null, type: null },
        { command: 'CancelRequest' as const, actor: 'S' as const, status: 'MANAGER_REVIEW' as const, type: 'REPAIR' as const },
        { command: 'WithdrawPhonePermission' as const, actor: 'S' as const, status: 'CLOSED' as const, type: null },
      ]) {
        expect(decide({ workflowVersion, ...query })).toEqual({
          decision: 'DENIED', target: null, awaitDependency: null, resultingType: null, reason: 'UNKNOWN_WORKFLOW_VERSION',
        });
      }
    }
  });

  it('keeps ∅ reachable only through the create commands', () => {
    for (const command of COMMANDS) {
      for (const actor of ACTORS) {
        for (const type of [...TYPES, null] as readonly (RequestType | null)[]) {
          const result = decide({ workflowVersion: WORKFLOW_VERSION, command, actor, status: null, type });
          const creates = command === 'CreateCallback' || command === 'CreateRepair';
          // Without a branch only the F CreateRepair row is reachable; the S
          // row needs the explicit PHONE branch, and CALLBACK never creates a
          // repair.
          const want = creates
            && (command === 'CreateCallback' || (actor === 'F' && type !== 'CALLBACK'));
          expect(result.decision === 'EXECUTABLE', `${command}/${actor}/∅/${type ?? '-'}`).toBe(want);
        }
      }
    }
  });

  it('denies ChooseCallback for the staff actor even on the exact F row inputs', () => {
    for (const status of W) {
      expect(decide({ workflowVersion: WORKFLOW_VERSION, command: 'ChooseCallback', actor: 'S', status, type: 'REPAIR' }).decision)
        .toBe('DENIED');
    }
  });

  it('denies ReadyForDispatch outside MANAGER_REVIEW of a REPAIR request', () => {
    for (const status of STATUS_INVENTORY.filter((candidate) => candidate !== 'MANAGER_REVIEW')) {
      for (const branch of ['PHONE', 'MESSENGER'] as const) {
        expect(decide({ workflowVersion: WORKFLOW_VERSION, command: 'ReadyForDispatch', actor: 'S', status, type: 'REPAIR', branch }).decision)
          .toBe('DENIED');
      }
    }
  });

  it('keeps WithdrawPhonePermission executable from terminal statuses without a target change', () => {
    for (const status of ['TECHNICIAN_COMPLETED', 'REVISIT_REQUIRED', 'CLOSED', 'CANCELLED'] as const) {
      for (const actor of ACTORS) {
        expect(decide({ workflowVersion: WORKFLOW_VERSION, command: 'WithdrawPhonePermission', actor, status, type: 'REPAIR' }))
          .toEqual(executable(null));
      }
    }
  });

  it('splits CancelRequest: S cancels from WAITING_ASSIGNMENT, F there is denied', () => {
    expect(decide({ workflowVersion: WORKFLOW_VERSION, command: 'CancelRequest', actor: 'S', status: 'WAITING_ASSIGNMENT', type: 'REPAIR' }))
      .toEqual(executable('CANCELLED'));
    expect(decide({ workflowVersion: WORKFLOW_VERSION, command: 'CancelRequest', actor: 'F', status: 'WAITING_ASSIGNMENT', type: 'REPAIR' }).decision)
      .toBe('DENIED');
  });

  it('runtime ALL_STATUSES equals the handwritten 19-status inventory', () => {
    expect(ALL_STATUSES).toEqual(STATUS_INVENTORY);
    expect(ALL_STATUSES).toHaveLength(19);
  });
});

describe('P05-01 policy pair classification (classifyPolicyPair / policyPairKey)', () => {
  const WORKFLOW_V1 = 'wf-r2-p05-v1';
  const KEY_R1 = policyPairKey(WORKFLOW_V1, 'p05-intake-r1');
  const KEY_R2 = policyPairKey(WORKFLOW_V1, 'p05-intake-r2');

  it('saved supported packages classify as SUPPORTED (r1 and r2)', () => {
    const supported = new Set([KEY_R1, KEY_R2]);
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r1' }, supported)).toBe('SUPPORTED');
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r2' }, supported)).toBe('SUPPORTED');
  });

  it('a historical workflow version is UNSUPPORTED_POLICY even when otherwise well-formed', () => {
    const supported = new Set([KEY_R1, KEY_R2]);
    // 'wf-r2-p05-v0' parses as a workflow version string but predates the
    // supported package: no saved pair of this build selects it.
    expect(classifyPolicyPair({ workflowVersion: 'wf-r2-p05-v0', policyRevision: 'p05-intake-r1' }, supported))
      .toBe('UNSUPPORTED_POLICY');
  });

  // This is the 503 REQUEST_RULES_UNAVAILABLE classification (the server
  // cannot evaluate rules for the saved pair at all), deliberately distinct
  // from a stale ETag, which stays a caller-side 412 for a SUPPORTED pair.
  it('an unknown policy revision under the supported workflow is UNSUPPORTED_POLICY (503, not 412)', () => {
    const supported = new Set([KEY_R1]);
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r9' }, supported))
      .toBe('UNSUPPORTED_POLICY');
  });

  it('historical replay is served by its saved pair: both packages pass, removal flips only the removed one', () => {
    // Package A (older) and B (current) are both in the supported set: a
    // historical replay under A is classified by A's own saved pair, not by
    // "the latest package" — historical data keeps working.
    const both = new Set([KEY_R1, KEY_R2]);
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r1' }, both)).toBe('SUPPORTED');
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r2' }, both)).toBe('SUPPORTED');

    // Dropping the historical package A from the build flips only A to
    // UNSUPPORTED_POLICY; the current package B stays SUPPORTED.
    const onlyCurrent = new Set([KEY_R2]);
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r1' }, onlyCurrent))
      .toBe('UNSUPPORTED_POLICY');
    expect(classifyPolicyPair({ workflowVersion: WORKFLOW_V1, policyRevision: 'p05-intake-r2' }, onlyCurrent))
      .toBe('SUPPORTED');
  });
});
