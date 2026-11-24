/**
 * P05-01 workflow registry (docs/P05-PLAN.md §6, package `wf-r2-p05-v1`).
 *
 * Pure total data + decision function, no I/O. Every row is a literal §6.1
 * cell: the first exact matching row gives its class, no row means DENIED,
 * and an unknown workflow version refuses regardless of actor. Registry rows
 * only classify a command; normative guards of adjacent aggregates stay with
 * the caller and are not implied by a match.
 */
export const WORKFLOW_VERSION = 'wf-r2-p05-v1' as const;

export type RequestStatus =
  | 'NEW' | 'CALLBACK_REQUIRED' | 'WAITING_TELEGRAM_LINK' | 'WAITING_CHANNEL_LINK'
  | 'MANAGER_REVIEW' | 'WAITING_ASSIGNMENT' | 'ASSIGNED' | 'TECHNICIAN_ACCEPTED'
  | 'ON_THE_WAY' | 'ARRIVED' | 'DIAGNOSTICS' | 'WAITING_ESTIMATE_APPROVAL'
  | 'IN_PROGRESS' | 'WAITING_PARTS' | 'PAUSED' | 'TECHNICIAN_COMPLETED'
  | 'REVISIT_REQUIRED' | 'CLOSED' | 'CANCELLED';

export type RequestType = 'CALLBACK' | 'REPAIR';

/** S = web staff with exact capabilities/city; F = live original session only. */
export type ActorClass = 'F' | 'S';

export type CommandName =
  | 'CreateCallback' | 'CreateRepair' | 'StartReview' | 'ConvertCallback' | 'ChangeDetails'
  | 'RecordCoverageAssessment' | 'ChangeContact' | 'ChooseCallback' | 'WithdrawPhonePermission'
  | 'ReadyForDispatch' | 'CancelRequest';

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
  readonly command: CommandName;
  readonly actors: readonly ActorClass[];
  /** `null` = ∅ (pre-create only). */
  readonly from: readonly RequestStatus[] | null;
  readonly requiresType: RequestType | null;
  /** `null` = SAME (no status change). Multiple entries = caller-resolved target. */
  readonly to: readonly RequestStatus[] | null;
  readonly targetSelector: TargetSelector;
  readonly resultingType: RequestType | null;
  readonly decision: Decision;
  readonly awaitDependency: string | null;
  readonly branch: DispatchBranch | null;
  /** Query branch values this row must never match (F create has no PHONE path). */
  readonly excludeBranches?: readonly DispatchBranch[];
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

export const REGISTRY: readonly CommandSpec[] = [
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
  },
];

export interface RegistryQuery {
  readonly workflowVersion: string;
  readonly command: CommandName;
  readonly actor: ActorClass;
  /** `null` = ∅ (pre-create). */
  readonly status: RequestStatus | null;
  readonly type: RequestType | null;
  readonly branch?: DispatchBranch;
}

export interface DecisionResult {
  readonly decision: Decision;
  readonly target: RequestStatus | null;
  readonly awaitDependency: string | null;
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

/** Total: any query yields a classified decision, never throws. */
export function decide(query: RegistryQuery): DecisionResult {
  if (!SUPPORTED_WORKFLOW_VERSIONS.includes(query.workflowVersion)) {
    return { decision: 'DENIED', ...DENIED_DEPENDENCY, reason: 'UNKNOWN_WORKFLOW_VERSION' };
  }
  const row = REGISTRY.find((candidate) => matches(candidate, query));
  if (!row) {
    return { decision: 'DENIED', ...DENIED_DEPENDENCY, reason: 'NO_ROW' };
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
