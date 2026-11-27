/**
 * P05 §6.2 late-command classification (X01) — independent literal oracle.
 *
 * Scope: the pure registry only. No database, no HTTP, no handlers. This file
 * proves that every §6.2 late cell is classified as `AWAIT_DEPENDENCY` (never
 * `EXECUTABLE`, never with a write target) and that every other late cell —
 * including unacceptable actor/status/effect/branch combinations — is `DENIED`.
 *
 * The oracle below is handwritten from the §6.2 table and from WF-R2 in
 * `docs/DATABASE.md#L510-L558`; it deliberately does not import `REGISTRY`,
 * `LATE_COMMANDS` or any status-group constant from the module. Only the
 * decision function is exercised, so a change to the runtime rows can never
 * move the expected values with it.
 *
 * The two commands that already have §6.1 cells — `CancelRequest` and
 * `ChooseCallback` — are covered separately: their §6.1 cells must stay
 * executable and their §6.2 cells must stay late-only, in both directions.
 */
import { describe, expect, it } from 'vitest';
import {
  ALL_STATUSES, LATE_COMMANDS, REGISTRY, WORKFLOW_VERSION, decide, isLateCommand,
  type ActorClass, type CommandName, type Decision, type DispatchBranch, type LateCommandName,
  type RegistryCommand, type RegistryQuery, type RequestStatus, type RequestType,
} from '../src/requests/workflow/registry.js';

/* ------------------------- independent literals --------------------------- */

/** Handwritten 19-status inventory of §6 (independent of ALL_STATUSES). */
const STATUSES: readonly RequestStatus[] = [
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK',
  'MANAGER_REVIEW', 'WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED',
  'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL',
  'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED',
  'REVISIT_REQUIRED', 'CLOSED', 'CANCELLED',
];

/** Handwritten §6 actor vocabulary: F/S act in P05, the rest are late classes. */
const ACTORS: readonly ActorClass[] = ['F', 'S', 'T', 'C', 'System', 'F+CLAIMANT'];
const P05_ACTORS: readonly ActorClass[] = ['F', 'S'];
const TYPES: readonly (RequestType | null)[] = ['CALLBACK', 'REPAIR', null];
const BRANCHES: readonly (DispatchBranch | undefined)[] = [undefined, 'PHONE', 'MESSENGER'];
const SUPPORTED_VERSION = 'wf-r2-p05-v1';
const UNSUPPORTED_VERSIONS: readonly string[] = ['wf-r2-p05-v0', 'wf-r2-p06-v1', ''];

/* Handwritten §6 status groups (WF-R2 line ranges are in the comments). */
const W = ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'] as const;
const EARLY = ['NEW', 'CALLBACK_REQUIRED', ...W, 'MANAGER_REVIEW'] as const;
const NON_TERMINAL = [
  'NEW', 'CALLBACK_REQUIRED', ...W, 'MANAGER_REVIEW', 'WAITING_ASSIGNMENT',
  'ASSIGNED', 'TECHNICIAN_ACCEPTED', 'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS',
  'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED',
  'TECHNICIAN_COMPLETED', 'REVISIT_REQUIRED',
] as const;
const BEFORE_DEPARTURE = ['ASSIGNED', 'TECHNICIAN_ACCEPTED'] as const;
const ACTIVE = ['ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS',
  'WAITING_PARTS', 'PAUSED'] as const;
/** WF-R2:518 — request-reschedule window. */
const REQUEST_RESCHEDULE = ['ASSIGNED', 'TECHNICIAN_ACCEPTED', ...ACTIVE] as const;
/** WF-R2:526. */
const QUOTE_DECISION = ['WAITING_ESTIMATE_APPROVAL', 'WAITING_PARTS', 'PAUSED'] as const;
/** WF-R2:529. */
const WAIT_PARTS = ['DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS'] as const;
/** WF-R2:532-535. */
const RETURN_PLAN = ['WAITING_PARTS', 'PAUSED'] as const;
/** WF-R2:538. */
const NO_REPAIR = ['DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'WAITING_PARTS', 'PAUSED'] as const;
/** WF-R2:549. */
const PAUSE = ['ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS'] as const;
/** WF-R2:547-548. */
const STOP = [...PAUSE, 'WAITING_PARTS', 'PAUSED'] as const;

/** §6.2 dependency column, handwritten per group (ASCII-normalized). */
const DEP = {
  channel: 'P07',
  schedule: 'P07/P09',
  visit: 'P09/P10',
  quote: 'P11+P09B',
  parts: 'P09/P11/P12',
  report: 'P09/P11-P12',
  close: 'P12/P13/P13P',
  lateCancel: 'P07/P09/P12',
  stop: 'P09/P11/P12',
  expire: 'P07/P13P',
} as const;

interface LateCell {
  readonly actors: readonly ActorClass[];
  /** Statuses the cell is allowed from (∅ is never a late cell). */
  readonly from: readonly RequestStatus[];
  readonly dependency: string;
}

/**
 * Handwritten §6.2 oracle for the 49 late-only commands (the two commands that
 * also have §6.1 cells are handled in dedicated tests below).
 */
const LATE_ORACLE: Readonly<Record<string, LateCell>> = {
  // WF-R2:510-513 — channel link, additional endpoint, required link.
  CompleteChannelLink: { actors: ['F+CLAIMANT'], from: W, dependency: DEP.channel },
  BindAdditionalRequestEndpoint: { actors: ['F+CLAIMANT'], from: NON_TERMINAL, dependency: DEP.channel },
  RequireChannelLink: { actors: ['S'], from: ['MANAGER_REVIEW'], dependency: DEP.channel },
  // WF-R2:515-518 — assignment, ACK, confirmation, reschedule request.
  Assign: { actors: ['S'], from: ['WAITING_ASSIGNMENT'], dependency: DEP.schedule },
  Acknowledge: { actors: ['T'], from: ['ASSIGNED'], dependency: DEP.schedule },
  ConfirmAppointment: { actors: ['C', 'S'], from: BEFORE_DEPARTURE, dependency: DEP.schedule },
  RequestReschedule: { actors: ['C'], from: REQUEST_RESCHEDULE, dependency: DEP.schedule },
  // WF-R2:519-523 — replan/revoke and visit logistics.
  Reschedule: { actors: ['S'], from: BEFORE_DEPARTURE, dependency: DEP.visit },
  Reassign: { actors: ['S'], from: BEFORE_DEPARTURE, dependency: DEP.visit },
  Revoke: { actors: ['T', 'S'], from: BEFORE_DEPARTURE, dependency: DEP.visit },
  Decline: { actors: ['T', 'S'], from: BEFORE_DEPARTURE, dependency: DEP.visit },
  Depart: { actors: ['T'], from: ['TECHNICIAN_ACCEPTED'], dependency: DEP.visit },
  Arrive: { actors: ['T'], from: ['ON_THE_WAY'], dependency: DEP.visit },
  StartDiagnostics: { actors: ['T'], from: ['ARRIVED', 'TECHNICIAN_ACCEPTED'], dependency: DEP.visit },
  // WF-R2:524-528, 536 — quotes and paid-work start.
  SendQuote: { actors: ['S'], from: ['DIAGNOSTICS'], dependency: DEP.quote },
  ReplacePendingQuote: { actors: ['S'], from: ['WAITING_ESTIMATE_APPROVAL'], dependency: DEP.quote },
  Requote: { actors: ['S'], from: ['IN_PROGRESS'], dependency: DEP.quote },
  PublishPausedQuote: { actors: ['S'], from: RETURN_PLAN, dependency: DEP.quote },
  QuoteDecision: { actors: ['C', 'S'], from: QUOTE_DECISION, dependency: DEP.quote },
  StartRepair: { actors: ['T'], from: ['WAITING_ESTIMATE_APPROVAL'], dependency: DEP.quote },
  // WF-R2:529-535 — parts and return-visit logistics.
  WaitParts: { actors: ['T', 'S'], from: WAIT_PARTS, dependency: DEP.parts },
  PlanPartsReturn: { actors: ['S'], from: ['WAITING_PARTS'], dependency: DEP.parts },
  ResumeParts: { actors: ['T'], from: ['WAITING_PARTS'], dependency: DEP.parts },
  ReturnVisitAcknowledge: { actors: ['T'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitConfirm: { actors: ['C', 'S'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitDepart: { actors: ['T'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitArrive: { actors: ['T'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitReschedule: { actors: ['S'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitReassign: { actors: ['S'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitRevoke: { actors: ['T', 'S'], from: RETURN_PLAN, dependency: DEP.parts },
  ReturnVisitDecline: { actors: ['T', 'S'], from: RETURN_PLAN, dependency: DEP.parts },
  // WF-R2:537-540 — reports.
  SubmitReport: { actors: ['T'], from: ['IN_PROGRESS'], dependency: DEP.report },
  SubmitNoRepairReport: { actors: ['T', 'S'], from: NO_REPAIR, dependency: DEP.report },
  ReturnReport: { actors: ['S'], from: ['TECHNICIAN_COMPLETED'], dependency: DEP.report },
  ResubmitReconciledReport: { actors: ['T', 'S'], from: ['PAUSED'], dependency: DEP.report },
  // WF-R2:541-545, 554 — revisit, closure, follow-up, terminal corrections.
  MarkRevisit: { actors: ['S'], from: ['TECHNICIAN_COMPLETED'], dependency: DEP.close },
  ResolveRevisit: { actors: ['S'], from: ['REVISIT_REQUIRED'], dependency: DEP.close },
  Close: { actors: ['S'], from: ['TECHNICIAN_COMPLETED'], dependency: DEP.close },
  CreateFollowup: { actors: ['S'], from: ['CLOSED'], dependency: DEP.close },
  TerminalCorrections: { actors: ['S'], from: ['CLOSED', 'CANCELLED'], dependency: DEP.close },
  // WF-R2:545-546/556 — appointment cancellation (the request stays alive). Two
  // effect families, both late: before departure → WAITING_ASSIGNMENT, and a
  // planned return while WAITING_PARTS/PAUSED → the SAME status + attention.
  CancelAppointment: { actors: ['C', 'S'], from: [...BEFORE_DEPARTURE, ...RETURN_PLAN], dependency: DEP.lateCancel },
  // WF-R2:547-558 — stop, pause, paused/parts cancellation.
  RequestStop: { actors: ['S', 'C'], from: STOP, dependency: DEP.stop },
  ConfirmStop: { actors: ['T', 'S'], from: STOP, dependency: DEP.stop },
  PauseForReschedule: { actors: ['S'], from: PAUSE, dependency: DEP.stop },
  PlanPausedReturn: { actors: ['S'], from: ['PAUSED'], dependency: DEP.stop },
  ResumePaused: { actors: ['T', 'S'], from: ['PAUSED'], dependency: DEP.stop },
  CancelPaused: { actors: ['C', 'S'], from: ['PAUSED'], dependency: DEP.stop },
  CancelWaitingParts: { actors: ['C', 'S'], from: ['WAITING_PARTS'], dependency: DEP.stop },
  // WF-R2:554-556 — system expiry is a candidate predicate, not a plain cancel.
  ExpireWaitingLink: { actors: ['System'], from: W, dependency: DEP.expire },
};

/** The 49 late-only command names, handwritten (no collision with §6.1). */
const LATE_ONLY: readonly string[] = Object.keys(LATE_ORACLE);
/** §6.1 command names, handwritten narrow vocabulary. */
const P05_COMMANDS: readonly CommandName[] = [
  'CreateCallback', 'CreateRepair', 'StartReview', 'ConvertCallback', 'ChangeDetails',
  'RecordCoverageAssessment', 'ChangeContact', 'ChooseCallback', 'WithdrawPhonePermission',
  'ReadyForDispatch', 'CancelRequest',
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

/** §6.2: a late cell never exposes a target or a type change. */
function late(dependency: string): Expected {
  return { decision: 'AWAIT_DEPENDENCY', target: null, awaitDependency: dependency, resultingType: null, reason: 'MATCHED' };
}

function expectedLateOnly(command: string, actor: ActorClass, status: RequestStatus | null): Expected {
  const cell = LATE_ORACLE[command];
  if (!cell) { return DENIED; }
  if (status === null || !cell.from.includes(status) || !cell.actors.includes(actor)) { return DENIED; }
  return late(cell.dependency);
}

function queryOf(command: RegistryCommand, actor: ActorClass, status: RequestStatus | null,
  type: RequestType | null, branch: DispatchBranch | undefined, workflowVersion = SUPPORTED_VERSION): RegistryQuery {
  return branch === undefined
    ? { workflowVersion, command, actor, status, type }
    : { workflowVersion, command, actor, status, type, branch };
}

function cellName(command: string, actor: ActorClass, status: RequestStatus | null,
  type: RequestType | null, branch: DispatchBranch | undefined): string {
  return `${command}/${actor}/${status ?? '∅'}/${type ?? '-'}/${branch ?? '-'}`;
}

/* ------------------------------ the matrix -------------------------------- */

describe('§6.2 late classification: full actor x status x type x branch matrix', () => {
  it('classifies every late-only cell exactly and never executes one', () => {
    let checked = 0;
    let lateCells = 0;
    for (const command of LATE_ONLY) {
      for (const actor of ACTORS) {
        for (const status of [null, ...STATUSES] as readonly (RequestStatus | null)[]) {
          for (const type of TYPES) {
            for (const branch of BRANCHES) {
              const want = expectedLateOnly(command, actor, status);
              const result = decide(queryOf(command as LateCommandName, actor, status, type, branch));
              expect(result, cellName(command, actor, status, type, branch)).toEqual(want);
              // A late cell must never be executable and must never hand out a
              // write target, whatever the type/branch axes say.
              if (want.decision === 'AWAIT_DEPENDENCY') {
                expect(result.target).toBeNull();
                expect(result.resultingType).toBeNull();
                expect(result.awaitDependency).toBe(want.awaitDependency);
                lateCells += 1;
              } else {
                expect(result.decision).not.toBe('EXECUTABLE');
              }
              checked += 1;
            }
          }
        }
      }
    }
    expect(checked).toBe(LATE_ONLY.length * ACTORS.length * 20 * TYPES.length * BRANCHES.length);
    expect(checked).toBe(49 * 6 * 20 * 3 * 3);
    expect(lateCells).toBeGreaterThan(0);
  });

  it('refuses every unsupported or malformed workflow version for every late command', () => {
    for (const workflowVersion of UNSUPPORTED_VERSIONS) {
      for (const command of LATE_ONLY) {
        for (const actor of ACTORS) {
          const result = decide(queryOf(command as LateCommandName, actor, 'WAITING_ASSIGNMENT', 'REPAIR', undefined, workflowVersion));
          expect(result, `${workflowVersion || '∅v'}/${command}/${actor}`).toEqual(DENIED_UNKNOWN_VERSION);
        }
      }
    }
  });

  it('keeps the closed late vocabulary complete and disjoint from the §6.1 commands', () => {
    // Handwritten inventory of every §6.2 LATE-ONLY command name. `ChooseCallback`
    // and `CancelRequest` are not here: they already exist in §6.1 and only gain
    // extra late cells, proven in the two dedicated describes above.
    const expectedLateNames: readonly string[] = [
      'CompleteChannelLink', 'BindAdditionalRequestEndpoint', 'RequireChannelLink',
      'Assign', 'Acknowledge', 'ConfirmAppointment', 'RequestReschedule',
      'Reschedule', 'Reassign', 'Revoke', 'Decline',
      'Depart', 'Arrive', 'StartDiagnostics',
      'SendQuote', 'ReplacePendingQuote', 'Requote', 'PublishPausedQuote', 'QuoteDecision', 'StartRepair',
      'WaitParts', 'PlanPartsReturn', 'ResumeParts',
      'ReturnVisitAcknowledge', 'ReturnVisitConfirm', 'ReturnVisitDepart', 'ReturnVisitArrive',
      'ReturnVisitReschedule', 'ReturnVisitReassign', 'ReturnVisitRevoke', 'ReturnVisitDecline',
      'SubmitReport', 'SubmitNoRepairReport', 'ReturnReport', 'ResubmitReconciledReport',
      'MarkRevisit', 'ResolveRevisit', 'Close', 'CreateFollowup', 'TerminalCorrections',
      'CancelAppointment',
      'RequestStop', 'ConfirmStop', 'PauseForReschedule', 'PlanPausedReturn', 'ResumePaused',
      'CancelPaused', 'CancelWaitingParts',
      'ExpireWaitingLink',
    ];
    expect([...LATE_COMMANDS].sort()).toEqual([...expectedLateNames].sort());
    expect(LATE_COMMANDS).toHaveLength(49);
    expect(new Set(LATE_COMMANDS).size).toBe(LATE_COMMANDS.length);
    // The late-only vocabulary never overlaps the §6.1 narrow vocabulary, so a
    // late-only name can never be typed into an execution call site.
    for (const command of P05_COMMANDS) {
      expect((LATE_COMMANDS as readonly string[]).includes(command), command).toBe(false);
      expect(isLateCommand(command), command).toBe(false);
    }
    for (const command of LATE_COMMANDS) { expect(isLateCommand(command)).toBe(true); }
  });

  it('has a reachable row for every late command and no dead late row', () => {
    // Every §6.2 command must be classifiable somewhere, otherwise the row is a
    // promise the registry does not keep.
    for (const command of LATE_COMMANDS) {
      const oracle = LATE_ORACLE[command];
      if (!oracle) { continue; }
      let reachable = false;
      for (const actor of oracle.actors) {
        for (const status of oracle.from) {
          const result = decide(queryOf(command, actor, status, 'REPAIR', undefined));
          expect(result.decision, `${command}/${actor}/${status}`).toBe('AWAIT_DEPENDENCY');
          expect(result.awaitDependency).toBe(oracle.dependency);
          reachable = true;
        }
      }
      expect(reachable, command).toBe(true);
    }
  });
});

/* ------------------- §6.1/§6.2 collision: CancelRequest -------------------- */

describe('§6.2 late CancelRequest keeps the §6.1 cells executable', () => {
  const lateFrom = new Set<RequestStatus>(['WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED']);

  it('keeps every §6.1 EARLY cell executable for F and S', () => {
    for (const status of EARLY) {
      for (const actor of P05_ACTORS) {
        expect(decide(queryOf('CancelRequest', actor, status, 'REPAIR', undefined)),
          `CancelRequest/${actor}/${status}`).toEqual({
          decision: 'EXECUTABLE', target: 'CANCELLED', awaitDependency: null, resultingType: null, reason: 'MATCHED',
        });
      }
    }
  });

  it('keeps the staff WAITING_ASSIGNMENT cell executable and makes the F one late-only', () => {
    expect(decide(queryOf('CancelRequest', 'S', 'WAITING_ASSIGNMENT', 'REPAIR', undefined)).decision).toBe('EXECUTABLE');
    const staffLate = decide(queryOf('CancelRequest', 'F', 'WAITING_ASSIGNMENT', 'REPAIR', undefined));
    expect(staffLate).toEqual(late(DEP.lateCancel));
    expect(staffLate.target).toBeNull();
  });

  it('classifies the C and F/S late cells and denies everything after departure', () => {
    for (const status of lateFrom) {
      // C: EARLY + WAITING_ASSIGNMENT + before departure are late.
      if (status === 'WAITING_ASSIGNMENT') {
        expect(decide(queryOf('CancelRequest', 'C', status, 'REPAIR', undefined)).decision).toBe('AWAIT_DEPENDENCY');
      }
      for (const actor of ['F', 'S'] as const) {
        const result = decide(queryOf('CancelRequest', actor, status, 'REPAIR', undefined));
        // F/S keep §6.1 for EARLY; WAITING_ASSIGNMENT is executable only for S.
        if (status === 'WAITING_ASSIGNMENT' && actor === 'S') {
          expect(result.decision).toBe('EXECUTABLE');
        } else {
          expect(result).toEqual(late(DEP.lateCancel));
          expect(result.target).toBeNull();
        }
      }
    }
    for (const status of ['NEW', 'CALLBACK_REQUIRED', ...W, 'MANAGER_REVIEW'] as const) {
      const result = decide(queryOf('CancelRequest', 'C', status, 'REPAIR', undefined));
      expect(result).toEqual(late(DEP.lateCancel));
    }
    for (const status of ['ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL',
      'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED', 'REVISIT_REQUIRED',
      'CLOSED', 'CANCELLED'] as const) {
      for (const actor of ACTORS) {
        expect(decide(queryOf('CancelRequest', actor, status, 'REPAIR', undefined)).decision,
          `CancelRequest/${actor}/${status}`).toBe('DENIED');
      }
    }
  });

  it('never lets a late CancelRequest be received as a write (target/type/effect all null)', () => {
    for (const actor of ['C', 'F', 'S'] as const) {
      for (const status of lateFrom) {
        const result = decide(queryOf('CancelRequest', actor, status, 'REPAIR', undefined));
        if (result.decision !== 'AWAIT_DEPENDENCY') { continue; }
        expect(result.target).toBeNull();
        expect(result.resultingType).toBeNull();
        expect(result.awaitDependency).toBe(DEP.lateCancel);
      }
    }
  });
});

/* ------------------ §6.2 conditional: associated plan ---------------------- */

describe('§6.2 associatedPlan overlay on staff cancellation', () => {
  /** Same cell with the extra caller-proven fact. */
  const withPlan = (actor: ActorClass, status: RequestStatus | null, associatedPlan: boolean): RegistryQuery =>
    ({ workflowVersion: SUPPORTED_VERSION, command: 'CancelRequest', actor, status, type: 'REPAIR', associatedPlan });

  it('turns only S/WAITING_ASSIGNMENT into the late case and leaves the default executable', () => {
    // Default (flag absent) and explicit false keep the §6.1 staff cell.
    for (const associatedPlan of [undefined, false] as const) {
      const result = decide({ workflowVersion: SUPPORTED_VERSION, command: 'CancelRequest', actor: 'S',
        status: 'WAITING_ASSIGNMENT', type: 'REPAIR', ...(associatedPlan === undefined ? {} : { associatedPlan }) });
      expect(result, String(associatedPlan)).toEqual({
        decision: 'EXECUTABLE', target: 'CANCELLED', awaitDependency: null, resultingType: null, reason: 'MATCHED',
      });
    }
    // A related plan makes that same cell late-only, with no write target.
    const lateCell = decide(withPlan('S', 'WAITING_ASSIGNMENT', true));
    expect(lateCell).toEqual(late(DEP.lateCancel));
    expect(lateCell.target).toBeNull();
    expect(lateCell.resultingType).toBeNull();
  });

  it('never widens or narrows any other cell', () => {
    for (const actor of ACTORS) {
      for (const status of [null, ...STATUSES] as readonly (RequestStatus | null)[]) {
        const plain = decide(queryOf('CancelRequest', actor, status, 'REPAIR', undefined));
        const flagged = decide(withPlan(actor, status, true));
        // The overlay may only downgrade S/WAITING_ASSIGNMENT; everything else is
        // byte-for-byte the same decision.
        if (actor === 'S' && status === 'WAITING_ASSIGNMENT') {
          expect(plain.decision).toBe('EXECUTABLE');
          expect(flagged.decision).toBe('AWAIT_DEPENDENCY');
        } else {
          expect(flagged, `CancelRequest/${actor}/${status ?? '∅'}`).toEqual(plain);
        }
      }
    }
    // The flag is meaningless for other commands and must not change them.
    for (const command of [...P05_COMMANDS, ...LATE_COMMANDS] as readonly RegistryCommand[]) {
      if (command === 'CancelRequest') { continue; }
      for (const actor of ACTORS) {
        for (const status of [null, 'WAITING_ASSIGNMENT', 'NEW'] as readonly (RequestStatus | null)[]) {
          const plain = decide(queryOf(command, actor, status, 'REPAIR', undefined));
          const flagged = decide({ ...queryOf(command, actor, status, 'REPAIR', undefined), associatedPlan: true });
          expect(flagged, `${command}/${actor}/${status ?? '∅'}`).toEqual(plain);
        }
      }
    }
  });

  it('keeps the early staff cells executable with the flag set', () => {
    for (const status of EARLY) {
      expect(decide(withPlan('S', status, true))).toEqual({
        decision: 'EXECUTABLE', target: 'CANCELLED', awaitDependency: null, resultingType: null, reason: 'MATCHED',
      });
    }
  });
});

/* ------------------ §6.1/§6.2 collision: ChooseCallback -------------------- */

describe('§6.2 ChooseCallback adds only the C waiting-link cell', () => {
  it('keeps the F REPAIR waiting-link cell executable', () => {
    for (const status of W) {
      expect(decide(queryOf('ChooseCallback', 'F', status, 'REPAIR', undefined))).toEqual({
        decision: 'EXECUTABLE', target: 'CALLBACK_REQUIRED', awaitDependency: null, resultingType: 'REPAIR', reason: 'MATCHED',
      });
    }
    // F outside the waiting links is still denied: the late row is C-only.
    for (const status of ['NEW', 'CALLBACK_REQUIRED', 'MANAGER_REVIEW', 'CLOSED'] as const) {
      expect(decide(queryOf('ChooseCallback', 'F', status, 'REPAIR', undefined)).decision).toBe('DENIED');
    }
  });

  it('classifies only the C waiting-link cell and denies the staff class entirely', () => {
    // Plan §6.2 L163 gives the C class exactly one effect: W→CALLBACK_REQUIRED.
    // MANAGER_REVIEW→the corresponding W belongs to RequireChannelLink S, so a C
    // ChooseCallback there is NOT a cell and must stay DENIED.
    for (const status of W) {
      expect(decide(queryOf('ChooseCallback', 'C', status, 'REPAIR', undefined))).toEqual(late(DEP.channel));
    }
    for (const status of STATUSES) {
      expect(decide(queryOf('ChooseCallback', 'S', status, 'REPAIR', undefined)).decision,
        `ChooseCallback/S/${status}`).toBe('DENIED');
    }
    for (const status of ['NEW', 'CALLBACK_REQUIRED', 'MANAGER_REVIEW', 'WAITING_ASSIGNMENT', 'ASSIGNED', 'CLOSED', 'CANCELLED'] as const) {
      expect(decide(queryOf('ChooseCallback', 'C', status, 'REPAIR', undefined)).decision,
        `ChooseCallback/C/${status}`).toBe('DENIED');
    }
  });

  it('keeps the MANAGER_REVIEW→W effect on RequireChannelLink S only', () => {
    expect(decide(queryOf('RequireChannelLink', 'S', 'MANAGER_REVIEW', 'REPAIR', undefined)))
      .toEqual(late(DEP.channel));
    for (const status of ['NEW', 'CALLBACK_REQUIRED', ...W, 'WAITING_ASSIGNMENT', 'CLOSED'] as const) {
      expect(decide(queryOf('RequireChannelLink', 'S', status, 'REPAIR', undefined)).decision,
        `RequireChannelLink/S/${status}`).toBe('DENIED');
    }
  });
});

/* ---------------- §6.2 late appointment cancellation (both families) ------ */

describe('§6.2 CancelAppointment covers the planned-return cell', () => {
  it('classifies the planned-return WAITING_PARTS/PAUSED cell as late, not DENIED', () => {
    // Plan §6.2 L170 + WF-R2:556: cancelling a FUTURE return visit keeps
    // WAITING_PARTS/PAUSED ("тот же status + attention", explicitly "не
    // WAITING_ASSIGNMENT"). This cell used to be a wrong DENIED.
    for (const actor of ['C', 'S'] as const) {
      for (const status of RETURN_PLAN) {
        const result = decide(queryOf('CancelAppointment', actor, status, 'REPAIR', undefined));
        expect(result, `CancelAppointment/${actor}/${status}`).toEqual(late(DEP.lateCancel));
        // A late cell never exposes a write effect.
        expect(result.target).toBeNull();
        expect(result.resultingType).toBeNull();
      }
    }
  });

  it('keeps both effect families distinct: before departure → WAITING_ASSIGNMENT, planned return → SAME', () => {
    const rows = REGISTRY.filter((row) => row.command === 'CancelAppointment');
    expect(rows).toHaveLength(2);
    const beforeDeparture = rows.find((row) => row.from !== null && row.from.includes('ASSIGNED'));
    const plannedReturn = rows.find((row) => row.from !== null && row.from.includes('WAITING_PARTS'));
    expect(beforeDeparture?.from).toEqual([...BEFORE_DEPARTURE]);
    expect(beforeDeparture?.to).toEqual(['WAITING_ASSIGNMENT']);
    // `to: null` is the SAME-status effect: the request stage must not move.
    expect(plannedReturn?.from).toEqual([...RETURN_PLAN]);
    expect(plannedReturn?.to).toBeNull();
    for (const row of rows) {
      expect(row.decision).toBe('AWAIT_DEPENDENCY');
      expect(row.awaitDependency).toBe(DEP.lateCancel);
    }
  });

  it('needs no caller flag: the plan-existence guard is evidence, not a classification axis', () => {
    // Unlike staff cancellation while WAITING_ASSIGNMENT (§6.1 EXECUTABLE vs §6.2
    // late compete for one cell, so `associatedPlan` selects between them), here
    // there is no competing classification: the cell is late regardless, and
    // whether a scheduled return plan exists is a guard of the future P09/P12
    // slice against its own rows. The flag must therefore be irrelevant.
    for (const actor of ['C', 'S'] as const) {
      for (const status of [...BEFORE_DEPARTURE, ...RETURN_PLAN]) {
        const plain = decide(queryOf('CancelAppointment', actor, status, 'REPAIR', undefined));
        for (const associatedPlan of [true, false]) {
          expect(decide({ ...queryOf('CancelAppointment', actor, status, 'REPAIR', undefined), associatedPlan }),
            `CancelAppointment/${actor}/${status}/associatedPlan=${String(associatedPlan)}`).toEqual(plain);
        }
      }
    }
  });

  it('denies every other status, every other actor and adds no F late write', () => {
    const allowed = new Set<string>([...BEFORE_DEPARTURE, ...RETURN_PLAN]);
    for (const actor of ACTORS) {
      for (const status of [null, ...STATUSES] as readonly (RequestStatus | null)[]) {
        const result = decide(queryOf('CancelAppointment', actor, status, 'REPAIR', undefined));
        const expectedCell = actor === 'C' || actor === 'S'
          ? status !== null && allowed.has(status)
          : false;
        expect(result.decision, `CancelAppointment/${actor}/${status ?? '∅'}`)
          .toBe(expectedCell ? 'AWAIT_DEPENDENCY' : 'DENIED');
        expect(result.target).toBeNull();
      }
    }
    // The plan is explicit that none of these combinations adds an F late write.
    for (const status of [...BEFORE_DEPARTURE, ...RETURN_PLAN]) {
      expect(decide(queryOf('CancelAppointment', 'F', status, 'REPAIR', undefined)).decision,
        `CancelAppointment/F/${status}`).toBe('DENIED');
    }
  });

  it('is invariant on the type and branch axes', () => {
    for (const status of [...BEFORE_DEPARTURE, ...RETURN_PLAN]) {
      for (const type of TYPES) {
        for (const branch of BRANCHES) {
          expect(decide(queryOf('CancelAppointment', 'C', status, type, branch)))
            .toEqual(late(DEP.lateCancel));
        }
      }
    }
  });
});

/* --------------------------- defensive totality --------------------------- */

describe('registry totality and safety invariants', () => {
  it('never throws and never executes an unknown command string', () => {
    const forged = ['DropTable', 'Assign2', '', 'assign'] as readonly string[];
    for (const command of forged) {
      for (const actor of ACTORS) {
        const result = decide(queryOf(command as RegistryCommand, actor, 'WAITING_ASSIGNMENT', 'REPAIR', undefined));
        expect(result.decision).toBe('DENIED');
        expect(result.target).toBeNull();
      }
    }
  });

  it('refuses an unsupported version before it looks at command or actor', () => {
    for (const workflowVersion of UNSUPPORTED_VERSIONS) {
      for (const command of [...P05_COMMANDS, ...LATE_COMMANDS] as readonly RegistryCommand[]) {
        for (const actor of ACTORS) {
          for (const status of [null, 'CLOSED'] as readonly (RequestStatus | null)[]) {
            expect(decide(queryOf(command, actor, status, null, undefined, workflowVersion)))
              .toEqual(DENIED_UNKNOWN_VERSION);
          }
        }
      }
    }
  });

  it('exposes a target only for EXECUTABLE results', () => {
    // Broad sweep over the whole classification vocabulary.
    for (const command of [...P05_COMMANDS, ...LATE_COMMANDS] as readonly RegistryCommand[]) {
      for (const actor of ACTORS) {
        for (const status of [null, ...STATUSES] as readonly (RequestStatus | null)[]) {
          const result = decide(queryOf(command, actor, status, 'REPAIR', undefined));
          if (result.decision === 'EXECUTABLE') {
            expect(result.awaitDependency).toBeNull();
          } else {
            expect(result.target).toBeNull();
            expect(result.resultingType).toBeNull();
          }
        }
      }
    }
  });

  it('keeps the §6.1 narrow vocabulary free of late command names', () => {
    for (const command of P05_COMMANDS) {
      expect((LATE_COMMANDS as readonly string[]).includes(command), command).toBe(false);
    }
    expect(P05_COMMANDS).toHaveLength(11);
  });

  it('runtime ALL_STATUSES equals the handwritten inventory', () => {
    expect(ALL_STATUSES).toEqual(STATUSES);
    expect(WORKFLOW_VERSION).toBe(SUPPORTED_VERSION);
  });
});

/* ---------------------- registry data invariants --------------------------- */

describe('registry data invariants (first exact row wins, no dead rows)', () => {
  const statusSet = new Set<string>(STATUSES);

  it('every row is reachable: no earlier row shadows it', () => {
    for (const row of REGISTRY) {
      const status = row.from === null ? null : row.from[0] ?? null;
      if (row.from !== null && status === null) { throw new Error(`empty from on ${row.command}`); }
      const type = row.requiresType;
      const query = queryOf(row.command, row.actors[0] as ActorClass, status, type,
        row.branch ?? undefined);
      const result = decide(query);
      const expectedTarget = row.decision === 'EXECUTABLE' && row.to !== null && row.to.length === 1
        ? row.to[0] ?? null : null;
      expect(result, `${row.command}/${row.actors.join('+')}/${status ?? '∅'}/${row.branch ?? '-'}`).toEqual({
        decision: row.decision,
        target: expectedTarget,
        awaitDependency: row.awaitDependency,
        resultingType: row.decision === 'EXECUTABLE' ? row.resultingType : null,
        reason: 'MATCHED',
      });
    }
  });

  it('never declares a dependency on an executable row or an effect on a late row', () => {
    for (const row of REGISTRY) {
      const label = `${row.command}/${row.actors.join('+')}/${row.from === null ? '∅' : String(row.from.length)}`;
      // DENIED is "no row": a stored row is either executable or late.
      expect(['EXECUTABLE', 'AWAIT_DEPENDENCY'], label).toContain(row.decision);
      if (row.decision === 'AWAIT_DEPENDENCY') {
        expect(row.awaitDependency, label).toMatch(/^P[0-9]{2}/);
        expect(row.resultingType, label).toBeNull();
      } else {
        expect(row.awaitDependency, label).toBeNull();
      }
    }
  });

  it('uses only the persisted §6 statuses and non-empty actor/status sets', () => {
    for (const row of REGISTRY) {
      const label = `${row.command}/${row.actors.join('+')}`;
      expect(row.actors.length, label).toBeGreaterThan(0);
      for (const actor of row.actors) { expect(ACTORS, label).toContain(actor); }
      if (row.from !== null) {
        expect(row.from.length, label).toBeGreaterThan(0);
        for (const status of row.from) { expect(statusSet.has(status), `${label}:${status}`).toBe(true); }
      }
      if (row.to !== null) {
        expect(row.to.length, label).toBeGreaterThan(0);
        for (const status of row.to) { expect(statusSet.has(status), `${label}:${status}`).toBe(true); }
      }
    }
  });

  it('has no duplicate cells (which would make a later row dead)', () => {
    const seen = new Set<string>();
    for (const row of REGISTRY) {
      const key = JSON.stringify([
        row.command, [...row.actors].sort(), row.from === null ? null : [...row.from].sort(),
        row.requiresType, row.branch, row.decision, row.to === null ? null : [...row.to].sort(),
        row.excludeBranches ?? null,
      ]);
      expect(seen.has(key), `duplicate row for ${row.command}`).toBe(false);
      seen.add(key);
    }
  });

  it('covers every late-only command with an AWAIT_DEPENDENCY row', () => {
    for (const command of LATE_COMMANDS) {
      const rows = REGISTRY.filter((row) => row.command === command);
      expect(rows.length, command).toBeGreaterThan(0);
      for (const row of rows) { expect(row.decision, command).toBe('AWAIT_DEPENDENCY'); }
    }
  });
});
