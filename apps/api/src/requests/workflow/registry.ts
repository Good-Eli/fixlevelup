/**
 * P05 workflow registry (docs/P05-PLAN.md §6, package `wf-r2-p05-v1`).
 *
 * Pure total data + decision function, no I/O. Every row is one literal §6.1/§6.2
 * cell: the first exact matching row gives its class, no row means DENIED, and an
 * unknown workflow version refuses regardless of actor. Registry rows only
 * classify a command; normative guards of adjacent aggregates stay with the
 * caller and are not implied by a match.
 *
 * ## Two vocabularies, deliberately separate
 *
 * - `CommandName` is the narrow §6.1 set this build can actually EXECUTE. Every
 *   execution caller (command service, receipts, effects, DTO wiring) keeps using
 *   this union, so a late P07+ command cannot be typed into a write path by
 *   accident.
 * - `RegistryCommand` = `CommandName | LateCommandName` is the widened
 *   CLASSIFICATION vocabulary of `RegistryQuery`. §6.2 rows are normative
 *   classification only: they are always `AWAIT_DEPENDENCY` and no handler, route
 *   or domain effect exists for them in P05.
 *
 * The one command that appears in both vocabularies is `CancelRequest`: §6.1 owns
 * its EARLY (and staff `WAITING_ASSIGNMENT`) cells, §6.2 owns the later cells for
 * `F`/`C`/`S`. Because rows are matched in order and §6.1 rows come first, a
 * §6.1 cell can never be re-classified by a late row, and a late cell can never be
 * received as an executable write: `decide()` returns a target only for
 * `EXECUTABLE`, so an `AWAIT_DEPENDENCY` result always carries `target: null`,
 * `resultingType: null`.
 *
 * ## Actor classes
 *
 * §6: `S` — web staff with exact capabilities/city; `F` — only the live original
 * form session; `T`, `C`, `System`, `F+CLAIMANT` are distinct classes that P05
 * staff/S synthetic grants can never obtain. `C` (verified request grant) and
 * `F+CLAIMANT` (form session + verified private endpoint candidate) are not staff.
 * "PHONE S" / "PHONE M" cells of §6.2 are the same staff actor class with a phone
 * evidence guard owned by the later slice, not a separate class here.
 */
export const WORKFLOW_VERSION = 'wf-r2-p05-v1' as const;

export type RequestStatus =
  | 'NEW' | 'CALLBACK_REQUIRED' | 'WAITING_TELEGRAM_LINK' | 'WAITING_CHANNEL_LINK'
  | 'MANAGER_REVIEW' | 'WAITING_ASSIGNMENT' | 'ASSIGNED' | 'TECHNICIAN_ACCEPTED'
  | 'ON_THE_WAY' | 'ARRIVED' | 'DIAGNOSTICS' | 'WAITING_ESTIMATE_APPROVAL'
  | 'IN_PROGRESS' | 'WAITING_PARTS' | 'PAUSED' | 'TECHNICIAN_COMPLETED'
  | 'REVISIT_REQUIRED' | 'CLOSED' | 'CANCELLED';

export type RequestType = 'CALLBACK' | 'REPAIR';

/**
 * Closed §6 actor vocabulary. `F`/`S` are the only classes P05 can act as;
 * `T`/`C`/`System`/`F+CLAIMANT` are late (P07+) classes that this build only
 * classifies.
 */
export type ActorClass = 'F' | 'S' | 'T' | 'C' | 'System' | 'F+CLAIMANT';

/** §6.1 commands this build can EXECUTE. Deliberately narrow: no late command. */
export type CommandName =
  | 'CreateCallback' | 'CreateRepair' | 'StartReview' | 'ConvertCallback' | 'ChangeDetails'
  | 'RecordCoverageAssessment' | 'ChangeContact' | 'ChooseCallback' | 'WithdrawPhonePermission'
  | 'ReadyForDispatch' | 'CancelRequest';

/**
 * §6.2 late commands: normatively allowed later, never executable here. The list
 * is literal from the §6.2 table; it exists so classification is total and so a
 * future route can reject a late command before any write.
 */
export type LateCommandName =
  // channel link / endpoint binding
  | 'CompleteChannelLink' | 'BindAdditionalRequestEndpoint' | 'RequireChannelLink'
  // assignment and appointment
  | 'Assign' | 'Acknowledge' | 'ConfirmAppointment' | 'RequestReschedule'
  | 'Reschedule' | 'Reassign' | 'Revoke' | 'Decline'
  // visit logistics
  | 'Depart' | 'Arrive' | 'StartDiagnostics'
  // quotes and repair start
  | 'SendQuote' | 'ReplacePendingQuote' | 'Requote' | 'PublishPausedQuote' | 'QuoteDecision' | 'StartRepair'
  // parts and return visits
  | 'WaitParts' | 'PlanPartsReturn' | 'ResumeParts'
  | 'ReturnVisitAcknowledge' | 'ReturnVisitConfirm' | 'ReturnVisitDepart' | 'ReturnVisitArrive'
  | 'ReturnVisitReschedule' | 'ReturnVisitReassign' | 'ReturnVisitRevoke' | 'ReturnVisitDecline'
  // reports
  | 'SubmitReport' | 'SubmitNoRepairReport' | 'ReturnReport' | 'ResubmitReconciledReport'
  // closure and follow-ups
  | 'MarkRevisit' | 'ResolveRevisit' | 'Close' | 'CreateFollowup' | 'TerminalCorrections'
  // late cancellation
  | 'CancelAppointment'
  // stop / pause
  | 'RequestStop' | 'ConfirmStop' | 'PauseForReschedule' | 'PlanPausedReturn' | 'ResumePaused'
  | 'CancelPaused' | 'CancelWaitingParts'
  // system
  | 'ExpireWaitingLink';

/** Classification vocabulary of `RegistryQuery` (§6.1 executable + §6.2 late). */
export type RegistryCommand = CommandName | LateCommandName;

/**
 * Every §6.2 late-ONLY command, literal and closed; none of them is executable
 * here and none of them is in `CommandName`.
 *
 * `ChooseCallback` and `CancelRequest` are deliberately absent: they already
 * exist in §6.1 and only gain extra late cells, so a caller must not be able to
 * treat the whole command name as late (or as executable).
 */
export const LATE_COMMANDS: readonly LateCommandName[] = Object.freeze([
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
]);

const LATE_COMMAND_SET: ReadonlySet<string> = new Set(LATE_COMMANDS);

/**
 * Narrowing guard for the late-only vocabulary. A late-only command must be
 * refused before any domain write. `ChooseCallback`/`CancelRequest` are §6.1
 * commands with additional late cells, so they are not "late" as a whole and
 * this guard is false for them; their late cells are classified by `decide()`
 * exactly like every other cell and always yield `AWAIT_DEPENDENCY` (never a
 * target) for the late actor/status combinations.
 */
export function isLateCommand(command: RegistryCommand): command is LateCommandName {
  return LATE_COMMAND_SET.has(command);
}

export type Decision = 'EXECUTABLE' | 'DENIED' | 'AWAIT_DEPENDENCY';

export type DispatchBranch = 'PHONE' | 'MESSENGER';

/**
 * How the target status of a create row is resolved. `REPAIR_MESSENGER`
 * marks the F-actor CreateRepair row whose target depends on the messenger
 * channel: TG -> WAITING_TELEGRAM_LINK, VK/MAX -> WAITING_CHANNEL_LINK; the
 * caller resolves the exact one. `to` lists all allowed targets.
 */
export type TargetSelector = 'REPAIR_MESSENGER' | null;

export interface CommandSpec {
  readonly command: RegistryCommand;
  readonly actors: readonly ActorClass[];
  /** `null` = ∅ (pre-create only). */
  readonly from: readonly RequestStatus[] | null;
  readonly requiresType: RequestType | null;
  /**
   * The status effect this row names. `null` = SAME (no status change); multiple
   * entries = caller-resolved target.
   *
   * For an `AWAIT_DEPENDENCY` row this is the NORMATIVE FUTURE effect of the
   * dependency owner, never an effect this build may apply: `decide()` drops it
   * from the result and no code may read `REGISTRY[].to` for a write.
   */
  readonly to: readonly RequestStatus[] | null;
  readonly targetSelector: TargetSelector;
  readonly resultingType: RequestType | null;
  readonly decision: Decision;
  /** Non-null exactly for `AWAIT_DEPENDENCY` rows (§6.2 dependency column). */
  readonly awaitDependency: string | null;
  readonly branch: DispatchBranch | null;
  /** Query branch values this row must never match (F create has no PHONE path). */
  readonly excludeBranches?: readonly DispatchBranch[];
  /**
   * §6.2 conditional overlay on a §6.1 row. The §6.1 cell stays EXECUTABLE for
   * the default query, but when the caller proves the extra fact
   * (`associatedPlan: true` on `RegistryQuery`) for exactly `status`, the cell is
   * classified `AWAIT_DEPENDENCY` instead. Used only by staff cancellation while
   * the request still waits for assignment, where a related plan makes the
   * cancellation a §6.2 case. The flag can only tighten a decision.
   *
   * When a flag is justified, and when it is not: a caller-supplied fact belongs
   * in the query ONLY if it selects between two different CLASSIFICATIONS of the
   * same cell (here: §6.1 EXECUTABLE vs §6.2 late). A guard that merely qualifies
   * a late cell inside its future owner aggregate — "exact dual proof + E", "with
   * reserve", "current approved quote", "planned return exists" — is EVIDENCE the
   * later slice must verify against real adjacent rows, never a classification
   * axis: the cell is already `AWAIT_DEPENDENCY` regardless, and a required flag
   * would silently turn a normative §6.2 cell into a missing one.
   */
  readonly planDependent?: { readonly status: RequestStatus; readonly awaitDependency: string };
}

export const ALL_STATUSES: readonly RequestStatus[] = [
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK',
  'MANAGER_REVIEW', 'WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED',
  'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL',
  'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED',
  'REVISIT_REQUIRED', 'CLOSED', 'CANCELLED',
];

const EARLY_STATUSES: readonly RequestStatus[] = [
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK', 'MANAGER_REVIEW',
];

/** EARLY = NEW ∪ CALLBACK_REQUIRED ∪ W ∪ MANAGER_REVIEW (§6). */
export function isEarlyStatus(status: RequestStatus): boolean {
  return EARLY_STATUSES.includes(status);
}

export const SUPPORTED_WORKFLOW_VERSIONS: readonly string[] = [WORKFLOW_VERSION];

/* -------------------------------------------------------------------------- */
/* §6.2 status groups (literal from the plan table)                           */
/* -------------------------------------------------------------------------- */

const W_STATUSES: readonly RequestStatus[] = ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'];
/** Every persisted status except the two terminal ones. */
const NON_TERMINAL_STATUSES: readonly RequestStatus[] = [
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK',
  'MANAGER_REVIEW', 'WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED',
  'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL',
  'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED', 'REVISIT_REQUIRED',
];
const BEFORE_DEPARTURE: readonly RequestStatus[] = ['ASSIGNED', 'TECHNICIAN_ACCEPTED'];
/** WF-R2:517-518 — request-reschedule window (before and after departure). */
const REQUEST_RESCHEDULE_FROM: readonly RequestStatus[] = [
  'ASSIGNED', 'TECHNICIAN_ACCEPTED', 'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS',
  'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED',
];
/** WF-R2:526 — a quote decision is possible in these stages. */
const QUOTE_DECISION_FROM: readonly RequestStatus[] = [
  'WAITING_ESTIMATE_APPROVAL', 'WAITING_PARTS', 'PAUSED',
];
/** WF-R2:529 — WaitParts may finish the current visit from these stages. */
const WAIT_PARTS_FROM: readonly RequestStatus[] = [
  'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS',
];
/** WF-R2:532-535 — return-visit logistics keep the request stage. */
const RETURN_PLAN_STATUSES: readonly RequestStatus[] = ['WAITING_PARTS', 'PAUSED'];
/** WF-R2:538 — a no-repair / STOPPED outcome is possible from these stages. */
const NO_REPAIR_FROM: readonly RequestStatus[] = [
  'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'WAITING_PARTS', 'PAUSED',
];
/** WF-R2:549 — pause for reschedule before/inside active work. */
const PAUSE_FROM: readonly RequestStatus[] = [
  'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS',
];
/** WF-R2:547-548 — a stop request/confirmation is possible from these stages. */
const STOP_FROM: readonly RequestStatus[] = [
  'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS',
  'WAITING_PARTS', 'PAUSED',
];

/* §6.2 dependency column, one literal token per group (ASCII-normalized). */
const DEP_CHANNEL = 'P07';
const DEP_SCHEDULE = 'P07/P09';
const DEP_VISIT = 'P09/P10';
const DEP_QUOTE = 'P11+P09B';
const DEP_PARTS = 'P09/P11/P12';
const DEP_REPORT = 'P09/P11-P12';
const DEP_CLOSE = 'P12/P13/P13P';
const DEP_LATE_CANCEL = 'P07/P09/P12';
const DEP_STOP = 'P09/P11/P12';
const DEP_EXPIRE = 'P07/P13P';

/**
 * One §6.2 classification row. `awaitDependency` is mandatory: a late row without
 * a named dependency would be an unclassified promise, so the type forbids it.
 */
type LateRow = Omit<CommandSpec, 'decision' | 'awaitDependency' | 'to' | 'targetSelector'
  | 'resultingType' | 'branch' | 'requiresType' | 'excludeBranches'>
  & {
    /** Normative future effect only; never applied by this build. */
    readonly to?: readonly RequestStatus[] | null;
    readonly awaitDependency: string;
  };

function lateRow(row: LateRow): CommandSpec {
  return {
    command: row.command,
    actors: row.actors,
    from: row.from,
    requiresType: null,
    to: row.to ?? null,
    targetSelector: null,
    resultingType: null,
    decision: 'AWAIT_DEPENDENCY',
    awaitDependency: row.awaitDependency,
    branch: null,
  };
}

export const REGISTRY: readonly CommandSpec[] = [
  /* ------------------------------ §6.1 rows ------------------------------- */
  {
    command: 'CreateCallback', actors: ['F', 'S'], from: null, requiresType: null,
    to: ['CALLBACK_REQUIRED'], targetSelector: null, resultingType: 'CALLBACK',
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'CreateRepair', actors: ['F'], from: null, requiresType: 'REPAIR',
    to: ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'], targetSelector: 'REPAIR_MESSENGER',
    resultingType: 'REPAIR', decision: 'EXECUTABLE', awaitDependency: null, branch: null,
    excludeBranches: ['PHONE'],
  },
  {
    command: 'CreateRepair', actors: ['S'], from: null, requiresType: 'REPAIR',
    to: ['NEW'], targetSelector: null, resultingType: 'REPAIR',
    decision: 'EXECUTABLE', awaitDependency: null, branch: 'PHONE',
  },
  {
    command: 'CreateRepair', actors: ['S'], from: null, requiresType: 'REPAIR',
    to: ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'], targetSelector: 'REPAIR_MESSENGER',
    resultingType: 'REPAIR', decision: 'EXECUTABLE', awaitDependency: null, branch: 'MESSENGER',
  },
  {
    command: 'StartReview', actors: ['S'], from: ['NEW', 'CALLBACK_REQUIRED'], requiresType: null,
    to: ['MANAGER_REVIEW'], targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'ConvertCallback', actors: ['S'], from: ['CALLBACK_REQUIRED', 'MANAGER_REVIEW'],
    requiresType: 'CALLBACK', to: ['MANAGER_REVIEW'], targetSelector: null,
    resultingType: 'REPAIR', decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'ChangeDetails', actors: ['S'], from: ['MANAGER_REVIEW'], requiresType: 'REPAIR',
    to: null, targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'RecordCoverageAssessment', actors: ['S'], from: ['MANAGER_REVIEW'], requiresType: 'REPAIR',
    to: null, targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'ChangeContact', actors: ['S'], from: ['CALLBACK_REQUIRED', 'MANAGER_REVIEW'],
    requiresType: null, to: null, targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'ChooseCallback', actors: ['F'],
    from: ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'], requiresType: 'REPAIR',
    to: ['CALLBACK_REQUIRED'], targetSelector: null, resultingType: 'REPAIR',
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'WithdrawPhonePermission', actors: ['F', 'S'], from: ALL_STATUSES, requiresType: null,
    to: null, targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'ReadyForDispatch', actors: ['S'], from: ['MANAGER_REVIEW'], requiresType: 'REPAIR',
    to: ['WAITING_ASSIGNMENT'], targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: 'PHONE',
  },
  {
    command: 'ReadyForDispatch', actors: ['S'], from: ['MANAGER_REVIEW'], requiresType: 'REPAIR',
    to: null, targetSelector: null, resultingType: null,
    decision: 'AWAIT_DEPENDENCY', awaitDependency: 'P07', branch: 'MESSENGER',
  },
  {
    command: 'CancelRequest', actors: ['F'], from: EARLY_STATUSES, requiresType: null,
    to: ['CANCELLED'], targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
  },
  {
    command: 'CancelRequest', actors: ['S'], from: [...EARLY_STATUSES, 'WAITING_ASSIGNMENT'],
    requiresType: null, to: ['CANCELLED'], targetSelector: null, resultingType: null,
    decision: 'EXECUTABLE', awaitDependency: null, branch: null,
    // §6.2: staff may cancel while waiting for assignment only when a related
    // plan needs processing; that variant is late, the default stays §6.1.
    planDependent: { status: 'WAITING_ASSIGNMENT', awaitDependency: DEP_LATE_CANCEL },
  },

  /* ------------------------------ §6.2 rows ------------------------------- */
  // Plan §6.2 L163 (WF-R2:510-513) — channel link and additional endpoint
  // binding. The line's effect list is shared across four commands, and each
  // cell belongs to exactly one of them: W→MANAGER_REVIEW = CompleteChannelLink
  // (F+CLAIMANT), nonterminal→same = BindAdditionalRequestEndpoint
  // (F+CLAIMANT), W→CALLBACK_REQUIRED for the grant holder = ChooseCallback C,
  // and MANAGER_REVIEW→the corresponding W (only after a proven choice change
  // before the visit) = RequireChannelLink S. The C class therefore has NO
  // MANAGER_REVIEW cell.
  lateRow({
    command: 'CompleteChannelLink', actors: ['F+CLAIMANT'], from: W_STATUSES,
    to: ['MANAGER_REVIEW'], awaitDependency: DEP_CHANNEL,
  }),
  lateRow({
    command: 'BindAdditionalRequestEndpoint', actors: ['F+CLAIMANT'], from: NON_TERMINAL_STATUSES,
    awaitDependency: DEP_CHANNEL,
  }),
  lateRow({
    command: 'ChooseCallback', actors: ['C'], from: W_STATUSES,
    to: ['CALLBACK_REQUIRED'], awaitDependency: DEP_CHANNEL,
  }),
  lateRow({
    command: 'RequireChannelLink', actors: ['S'], from: ['MANAGER_REVIEW'],
    to: W_STATUSES, awaitDependency: DEP_CHANNEL,
  }),
  // WF-R2:515-518 — assignment, technician ACK and appointment confirmation.
  lateRow({
    command: 'Assign', actors: ['S'], from: ['WAITING_ASSIGNMENT'],
    to: ['ASSIGNED'], awaitDependency: DEP_SCHEDULE,
  }),
  lateRow({
    command: 'Acknowledge', actors: ['T'], from: ['ASSIGNED'],
    to: ['TECHNICIAN_ACCEPTED'], awaitDependency: DEP_SCHEDULE,
  }),
  lateRow({
    command: 'ConfirmAppointment', actors: ['C', 'S'], from: BEFORE_DEPARTURE,
    awaitDependency: DEP_SCHEDULE,
  }),
  lateRow({
    command: 'RequestReschedule', actors: ['C'], from: REQUEST_RESCHEDULE_FROM,
    awaitDependency: DEP_SCHEDULE,
  }),
  // WF-R2:519-523 — replan/revoke and visit logistics.
  lateRow({
    command: 'Reschedule', actors: ['S'], from: BEFORE_DEPARTURE,
    to: ['ASSIGNED'], awaitDependency: DEP_VISIT,
  }),
  lateRow({
    command: 'Reassign', actors: ['S'], from: BEFORE_DEPARTURE,
    to: ['ASSIGNED'], awaitDependency: DEP_VISIT,
  }),
  lateRow({
    command: 'Revoke', actors: ['T', 'S'], from: BEFORE_DEPARTURE,
    to: ['WAITING_ASSIGNMENT'], awaitDependency: DEP_VISIT,
  }),
  lateRow({
    command: 'Decline', actors: ['T', 'S'], from: BEFORE_DEPARTURE,
    to: ['WAITING_ASSIGNMENT'], awaitDependency: DEP_VISIT,
  }),
  lateRow({
    command: 'Depart', actors: ['T'], from: ['TECHNICIAN_ACCEPTED'],
    to: ['ON_THE_WAY'], awaitDependency: DEP_VISIT,
  }),
  lateRow({
    command: 'Arrive', actors: ['T'], from: ['ON_THE_WAY'],
    to: ['ARRIVED'], awaitDependency: DEP_VISIT,
  }),
  lateRow({
    command: 'StartDiagnostics', actors: ['T'], from: ['ARRIVED', 'TECHNICIAN_ACCEPTED'],
    to: ['DIAGNOSTICS'], awaitDependency: DEP_VISIT,
  }),
  // WF-R2:524-528, 536 — quotes and the start of paid work.
  lateRow({
    command: 'SendQuote', actors: ['S'], from: ['DIAGNOSTICS'],
    to: ['WAITING_ESTIMATE_APPROVAL'], awaitDependency: DEP_QUOTE,
  }),
  lateRow({
    command: 'ReplacePendingQuote', actors: ['S'], from: ['WAITING_ESTIMATE_APPROVAL'],
    awaitDependency: DEP_QUOTE,
  }),
  lateRow({
    command: 'Requote', actors: ['S'], from: ['IN_PROGRESS'],
    to: ['WAITING_ESTIMATE_APPROVAL'], awaitDependency: DEP_QUOTE,
  }),
  lateRow({
    command: 'PublishPausedQuote', actors: ['S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_QUOTE,
  }),
  lateRow({
    command: 'QuoteDecision', actors: ['C', 'S'], from: QUOTE_DECISION_FROM,
    awaitDependency: DEP_QUOTE,
  }),
  lateRow({
    command: 'StartRepair', actors: ['T'], from: ['WAITING_ESTIMATE_APPROVAL'],
    to: ['IN_PROGRESS'], awaitDependency: DEP_QUOTE,
  }),
  // WF-R2:529-535 — parts and return-visit logistics.
  lateRow({
    command: 'WaitParts', actors: ['T', 'S'], from: WAIT_PARTS_FROM,
    to: ['WAITING_PARTS'], awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'PlanPartsReturn', actors: ['S'], from: ['WAITING_PARTS'],
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ResumeParts', actors: ['T'], from: ['WAITING_PARTS'],
    to: ['DIAGNOSTICS', 'IN_PROGRESS'], awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitAcknowledge', actors: ['T'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitConfirm', actors: ['C', 'S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitDepart', actors: ['T'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitArrive', actors: ['T'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitReschedule', actors: ['S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitReassign', actors: ['S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitRevoke', actors: ['T', 'S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  lateRow({
    command: 'ReturnVisitDecline', actors: ['T', 'S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_PARTS,
  }),
  // WF-R2:537-540 — reports.
  lateRow({
    command: 'SubmitReport', actors: ['T'], from: ['IN_PROGRESS'],
    to: ['TECHNICIAN_COMPLETED'], awaitDependency: DEP_REPORT,
  }),
  lateRow({
    command: 'SubmitNoRepairReport', actors: ['T', 'S'], from: NO_REPAIR_FROM,
    to: ['TECHNICIAN_COMPLETED'], awaitDependency: DEP_REPORT,
  }),
  lateRow({
    command: 'ReturnReport', actors: ['S'], from: ['TECHNICIAN_COMPLETED'],
    to: ['TECHNICIAN_COMPLETED', 'PAUSED'], awaitDependency: DEP_REPORT,
  }),
  lateRow({
    command: 'ResubmitReconciledReport', actors: ['T', 'S'], from: ['PAUSED'],
    to: ['TECHNICIAN_COMPLETED'], awaitDependency: DEP_REPORT,
  }),
  // WF-R2:541-545, 554 — revisit, closure, follow-up, terminal corrections.
  lateRow({
    command: 'MarkRevisit', actors: ['S'], from: ['TECHNICIAN_COMPLETED'],
    to: ['REVISIT_REQUIRED'], awaitDependency: DEP_CLOSE,
  }),
  lateRow({
    command: 'ResolveRevisit', actors: ['S'], from: ['REVISIT_REQUIRED'],
    to: ['TECHNICIAN_COMPLETED'], awaitDependency: DEP_CLOSE,
  }),
  lateRow({
    command: 'Close', actors: ['S'], from: ['TECHNICIAN_COMPLETED'],
    to: ['CLOSED'], awaitDependency: DEP_CLOSE,
  }),
  lateRow({
    command: 'CreateFollowup', actors: ['S'], from: ['CLOSED'],
    to: ['CLOSED'], awaitDependency: DEP_CLOSE,
  }),
  lateRow({
    command: 'TerminalCorrections', actors: ['S'], from: ['CLOSED', 'CANCELLED'],
    awaitDependency: DEP_CLOSE,
  }),
  // WF-R2:545-556 — late cancellation of the request and of one appointment.
  // `C` never appears in §6.1, so its EARLY cells are late here; `F`/`S` keep
  // their §6.1 rows first and only the later cells are added.
  lateRow({
    command: 'CancelRequest', actors: ['C'],
    from: [...EARLY_STATUSES, 'WAITING_ASSIGNMENT', ...BEFORE_DEPARTURE],
    to: ['CANCELLED'], awaitDependency: DEP_LATE_CANCEL,
  }),
  lateRow({
    command: 'CancelRequest', actors: ['F'], from: ['WAITING_ASSIGNMENT', ...BEFORE_DEPARTURE],
    to: ['CANCELLED'], awaitDependency: DEP_LATE_CANCEL,
  }),
  lateRow({
    command: 'CancelRequest', actors: ['S'], from: BEFORE_DEPARTURE,
    to: ['CANCELLED'], awaitDependency: DEP_LATE_CANCEL,
  }),
  // Plan §6.2 L170 + WF-R2:546/556 — late appointment cancellation. It cancels
  // ONE appointment, never the request, and the plan gives it two effect
  // families that must not be conflated:
  //   - before departure (ASSIGNED/TECHNICIAN_ACCEPTED) -> WAITING_ASSIGNMENT;
  //   - a future/planned RETURN visit while the request sits in WAITING_PARTS or
  //     PAUSED -> the SAME status plus an attention marker (explicitly NOT
  //     WAITING_ASSIGNMENT: «не WAITING_ASSIGNMENT», WF-R2:556).
  // No `planDependent`-style argument is added for the second family: unlike
  // staff cancellation while waiting for assignment (where §6.1 EXECUTABLE and
  // §6.2 late compete for the SAME cell and the plan decides which one applies),
  // here there is no competing classification — the only question is whether the
  // adjacent scheduling aggregate currently holds a scheduled return plan, which
  // is a guard of the future P09/P12 slice against its own rows, not a
  // classification axis of this pure table. Encoding it as a caller flag would
  // turn a normatively allowed-later cell into a missing cell for any caller that
  // omits the flag, and could never be verified by P05 (it holds no return plan).
  lateRow({
    command: 'CancelAppointment', actors: ['C', 'S'], from: BEFORE_DEPARTURE,
    to: ['WAITING_ASSIGNMENT'], awaitDependency: DEP_LATE_CANCEL,
  }),
  lateRow({
    command: 'CancelAppointment', actors: ['C', 'S'], from: RETURN_PLAN_STATUSES,
    awaitDependency: DEP_LATE_CANCEL,
  }),
  // WF-R2:547-558 — stop, pause and paused/parts cancellation.
  lateRow({
    command: 'RequestStop', actors: ['S', 'C'], from: STOP_FROM,
    awaitDependency: DEP_STOP,
  }),
  lateRow({
    command: 'ConfirmStop', actors: ['T', 'S'], from: STOP_FROM,
    to: ['CANCELLED', 'TECHNICIAN_COMPLETED'], awaitDependency: DEP_STOP,
  }),
  lateRow({
    command: 'PauseForReschedule', actors: ['S'], from: PAUSE_FROM,
    to: ['PAUSED'], awaitDependency: DEP_STOP,
  }),
  lateRow({
    command: 'PlanPausedReturn', actors: ['S'], from: ['PAUSED'],
    awaitDependency: DEP_STOP,
  }),
  lateRow({
    command: 'ResumePaused', actors: ['T', 'S'], from: ['PAUSED'],
    to: ['DIAGNOSTICS', 'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS'], awaitDependency: DEP_STOP,
  }),
  lateRow({
    command: 'CancelPaused', actors: ['C', 'S'], from: ['PAUSED'],
    to: ['CANCELLED', 'TECHNICIAN_COMPLETED'], awaitDependency: DEP_STOP,
  }),
  lateRow({
    command: 'CancelWaitingParts', actors: ['C', 'S'], from: ['WAITING_PARTS'],
    to: ['CANCELLED', 'TECHNICIAN_COMPLETED'], awaitDependency: DEP_STOP,
  }),
  // WF-R2:554-556 — system expiry is a candidate predicate, never a plain cancel.
  lateRow({
    command: 'ExpireWaitingLink', actors: ['System'], from: W_STATUSES,
    awaitDependency: DEP_EXPIRE,
  }),
];

export interface RegistryQuery {
  readonly workflowVersion: string;
  /** Widened classification vocabulary; execution callers keep `CommandName`. */
  readonly command: RegistryCommand;
  readonly actor: ActorClass;
  /** `null` = ∅ (pre-create). */
  readonly status: RequestStatus | null;
  readonly type: RequestType | null;
  readonly branch?: DispatchBranch;
  /**
   * Staff cancellation of a request that is already waiting for assignment is
   * only a late (§6.2) case when a related plan still needs processing; without
   * one, the §6.1 staff cell applies. `undefined`/`false` keeps the §6.1
   * classification exactly as before, so no existing caller changes behaviour.
   * It is an INPUT FACT, not authority: the caller must obtain it from the
   * reviewed scheduling state, and it can only ever move a cell from EXECUTABLE
   * to AWAIT_DEPENDENCY, never the other way.
   */
  readonly associatedPlan?: boolean;
}

export interface DecisionResult {
  readonly decision: Decision;
  /** Non-null only for `EXECUTABLE` with an unambiguous single target. */
  readonly target: RequestStatus | null;
  readonly awaitDependency: string | null;
  /** Non-null only for `EXECUTABLE` rows that change the request type. */
  readonly resultingType: RequestType | null;
  readonly reason: string;
}

function matches(row: CommandSpec, query: RegistryQuery): boolean {
  if (row.command !== query.command || !row.actors.includes(query.actor)) {
    return false;
  }
  if (row.from === null) {
    if (query.status !== null) { return false; }
  } else if (query.status === null || !row.from.includes(query.status)) {
    return false;
  }
  if (row.requiresType !== null && row.requiresType !== query.type) {
    // Pre-create (∅) rows: the request has no type yet, so a null query type
    // is compatible while a conflicting explicit type (e.g. CALLBACK against
    // a REPAIR create) still refuses.
    if (!(row.from === null && query.type === null)) {
      return false;
    }
  }
  if (row.branch !== null && row.branch !== query.branch) {
    return false;
  }
  if (row.excludeBranches !== undefined && query.branch !== undefined && row.excludeBranches.includes(query.branch)) {
    return false;
  }
  return true;
}

const DENIED_DEPENDENCY: Pick<DecisionResult, 'target' | 'awaitDependency' | 'resultingType'> = {
  target: null, awaitDependency: null, resultingType: null,
};

/**
 * Total: any query yields a classified decision, never throws.
 *
 * Only `EXECUTABLE` exposes a write target/type. An `AWAIT_DEPENDENCY` row keeps
 * its normative future effect in `REGISTRY[].to` for documentation, but the
 * result never carries it, so no caller can turn a late classification into a
 * domain write.
 *
 * The one conditional overlay is `planDependent` (§6.2 staff cancellation while
 * waiting for assignment): it is consulted only when the caller passes
 * `associatedPlan: true` for the exact cell, and it can only downgrade an
 * EXECUTABLE cell to AWAIT_DEPENDENCY — never the reverse, and it never affects
 * any other command, actor or status.
 */
export function decide(query: RegistryQuery): DecisionResult {
  if (!SUPPORTED_WORKFLOW_VERSIONS.includes(query.workflowVersion)) {
    return { decision: 'DENIED', ...DENIED_DEPENDENCY, reason: 'UNKNOWN_WORKFLOW_VERSION' };
  }
  const row = REGISTRY.find((candidate) => matches(candidate, query));
  if (!row) {
    return { decision: 'DENIED', ...DENIED_DEPENDENCY, reason: 'NO_ROW' };
  }
  if (row.decision !== 'EXECUTABLE') {
    return {
      decision: row.decision,
      target: null,
      awaitDependency: row.awaitDependency,
      resultingType: null,
      reason: 'MATCHED',
    };
  }
  const overlay = row.planDependent;
  if (overlay !== undefined && query.associatedPlan === true && query.status === overlay.status) {
    return {
      decision: 'AWAIT_DEPENDENCY',
      target: null,
      awaitDependency: overlay.awaitDependency,
      resultingType: null,
      reason: 'MATCHED',
    };
  }
  const unambiguous = row.to !== null && row.to.length === 1 ? row.to.at(0) ?? null : null;
  return {
    decision: row.decision,
    target: unambiguous,
    awaitDependency: row.awaitDependency,
    resultingType: row.resultingType,
    reason: 'MATCHED',
  };
}

/**
 * Classifies the SAVED (workflow_version, intake_policy_revision) pair of a
 * request against the packages this build supports (plan §3: the internal set
 * of supported packages is selected by the SAVED pair, not "last version").
 * Distinct from an HTTP validator: an unsupported/stale policy pair is the
 * safe 503 REQUEST_RULES_UNAVAILABLE classification, never a 412, and a
 * supported package with a stale client ETag stays a caller-side 412.
 */
export type PolicyPairClassification = 'SUPPORTED' | 'UNSUPPORTED_POLICY';

export function classifyPolicyPair(pair: {
  readonly workflowVersion: string;
  readonly policyRevision: string;
}, supported: ReadonlySet<string>): PolicyPairClassification {
  const key = `${pair.workflowVersion}\u0000${pair.policyRevision}`;
  return supported.has(key) ? 'SUPPORTED' : 'UNSUPPORTED_POLICY';
}

/** Canonical key builder for a supported-package set entry. */
export function policyPairKey(workflowVersion: string, policyRevision: string): string {
  return `${workflowVersion}\u0000${policyRevision}`;
}
