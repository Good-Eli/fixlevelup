// Test-side oracle for P05-PLAN §4, §6.1 and §7. Do NOT derive these routes,
// actors, states, outcomes or effects from the controller, dispatcher or X01.
// X01 separately checks §6.2 across ALL persisted codes, including the codes
// below that require future authenticated commands to reach. A writable SQL
// status literal is not a lawful P05 fixture; the live suite never seeds one.
export const futureStates = [
  'ASSIGNED','TECHNICIAN_ACCEPTED','ON_THE_WAY','ARRIVED','DIAGNOSTICS','WAITING_ESTIMATE_APPROVAL',
  'IN_PROGRESS','WAITING_PARTS','PAUSED','TECHNICIAN_COMPLETED','REVISIT_REQUIRED','CLOSED',
] as const;

export const staffCommands = {
  StartReview: 'start-review',
  ConvertCallback: 'convert-callback',
  ChangeDetails: 'change-details',
  RecordCoverageAssessment: 'record-coverage',
  ChangeContact: 'change-contact',
  ReadyForDispatch: 'ready-for-dispatch',
  WithdrawPhonePermission: 'withdraw-phone',
  CancelRequest: 'cancel',
} as const;
export const formCommands = {
  ChooseCallback: 'contact-mode',
  WithdrawPhonePermission: 'phone-permissions',
  CancelRequest: 'cancel',
} as const;
export type StaffCommand = keyof typeof staffCommands;
export type FormCommand = keyof typeof formCommands;
export type MatrixCommand = StaffCommand | FormCommand;
export type MatrixActor = 'STAFF' | 'F';
export type MatrixStatus = 'NEW' | 'CALLBACK_REQUIRED' | 'WAITING_TELEGRAM_LINK' | 'WAITING_CHANNEL_LINK'
  | 'MANAGER_REVIEW' | 'WAITING_ASSIGNMENT' | 'CANCELLED';
export type MatrixType = 'CALLBACK' | 'REPAIR';
export type Provider = 'TG' | 'VK' | 'MAX';
export type Recipe = 'callback' | 'manual-phone' | Provider;
export type Preparation = 'review' | 'convert' | 'assess' | 'ready' | 'choose' | 'cancel' | 'change-contact';
export interface Witness {
  readonly label: string;
  readonly origin: MatrixActor;
  readonly recipe: Recipe;
  readonly via: readonly Preparation[];
  readonly status: MatrixStatus;
  readonly type: MatrixType;
  readonly phone: boolean;
  readonly coverage?: true;
}

// PHONE=false on waiting rows (including both canonical waiting codes), and
// on a live row after contact replacement. AFTER ready/cancel, the historical
// current-contact GIVEN still exists and can be explicitly withdrawn.
export const witnesses: readonly Witness[] = [
  {label:'manual NEW',origin:'STAFF',recipe:'manual-phone',via:[],status:'NEW',type:'REPAIR',phone:true},
  {label:'manual CALLBACK_REQUIRED',origin:'STAFF',recipe:'callback',via:[],status:'CALLBACK_REQUIRED',type:'CALLBACK',phone:true},
  {label:'form CALLBACK_REQUIRED',origin:'F',recipe:'callback',via:[],status:'CALLBACK_REQUIRED',type:'CALLBACK',phone:true},
  {label:'form TG waiting',origin:'F',recipe:'TG',via:[],status:'WAITING_TELEGRAM_LINK',type:'REPAIR',phone:false},
  {label:'form VK waiting',origin:'F',recipe:'VK',via:[],status:'WAITING_CHANNEL_LINK',type:'REPAIR',phone:false},
  // MAX has the same post-create authorization semantics as VK; exercise each
  // provider's actual create separately (for both surfaces).
  {label:'manual TG waiting',origin:'STAFF',recipe:'TG',via:[],status:'WAITING_TELEGRAM_LINK',type:'REPAIR',phone:false},
  {label:'manual MAX waiting',origin:'STAFF',recipe:'MAX',via:[],status:'WAITING_CHANNEL_LINK',type:'REPAIR',phone:false},
  {label:'form REPAIR after explicit PHONE choice',origin:'F',recipe:'TG',via:['choose'],status:'CALLBACK_REQUIRED',type:'REPAIR',phone:true},
  {label:'form CALLBACK in review',origin:'F',recipe:'callback',via:['review'],status:'MANAGER_REVIEW',type:'CALLBACK',phone:true},
  {label:'manual CALLBACK in review',origin:'STAFF',recipe:'callback',via:['review'],status:'MANAGER_REVIEW',type:'CALLBACK',phone:true},
  {label:'form REPAIR in review, no assessment',origin:'F',recipe:'callback',via:['convert'],status:'MANAGER_REVIEW',type:'REPAIR',phone:true},
  {label:'manual REPAIR in review, assessed',origin:'STAFF',recipe:'manual-phone',via:['review','assess'],status:'MANAGER_REVIEW',type:'REPAIR',phone:true,coverage:true},
  {label:'form REPAIR in review, assessed',origin:'F',recipe:'callback',via:['convert','assess'],status:'MANAGER_REVIEW',type:'REPAIR',phone:true,coverage:true},
  {label:'manual REPAIR in review after contact replacement',origin:'STAFF',recipe:'manual-phone',via:['review','assess','change-contact'],status:'MANAGER_REVIEW',type:'REPAIR',phone:false,coverage:true},
  {label:'manual WAITING_ASSIGNMENT',origin:'STAFF',recipe:'manual-phone',via:['review','assess','ready'],status:'WAITING_ASSIGNMENT',type:'REPAIR',phone:true},
  {label:'form WAITING_ASSIGNMENT',origin:'F',recipe:'callback',via:['convert','assess','ready'],status:'WAITING_ASSIGNMENT',type:'REPAIR',phone:true},
  {label:'manual CANCELLED',origin:'STAFF',recipe:'manual-phone',via:['cancel'],status:'CANCELLED',type:'REPAIR',phone:true},
  {label:'form CANCELLED',origin:'F',recipe:'callback',via:['cancel'],status:'CANCELLED',type:'CALLBACK',phone:true},
];

export const closingCommands: ReadonlySet<MatrixCommand> = new Set(['CancelRequest','WithdrawPhonePermission']);
export const changedPointers = {
  contact:'current_contact_revision_id',address:'current_address_revision_id',appliance:'current_appliance_revision_id',
  preference:'current_preference_revision_id',assessment:'current_assessment_id',
} as const;
type Revision = keyof typeof changedPointers;
export type Mutation = { readonly status: MatrixStatus; readonly type: MatrixType;
  readonly pointers: readonly Revision[]; readonly extraRows: readonly string[] };
export type Refusal = { readonly code: 'CONFLICT' | 'NOT_READY' | 'COVERAGE_ASSESSMENT_STALE';
  readonly http: 409 | 503 };
export function expectedMutation(w: Witness, actor: MatrixActor, cmd: MatrixCommand): Mutation | Refusal {
  const {status,type}=w;
  const waiting=status === 'WAITING_TELEGRAM_LINK' || status === 'WAITING_CHANNEL_LINK';
  const reviewing=status === 'MANAGER_REVIEW';
  const callback=status === 'CALLBACK_REQUIRED';
  const repairReview=type === 'REPAIR' && reviewing;
  const early=status === 'NEW' || waiting || callback || reviewing;
  const conflict={http:409,code:'CONFLICT'} as const;
  const dependency={http:503,code:'NOT_READY'} as const;
  const success=(pointers:readonly Revision[]=[],extraRows:readonly string[]=[], next=status, kind=type):Mutation =>
    ({status:next,type:kind,pointers,extraRows});
  switch (cmd) {
    case 'StartReview': return status === 'NEW' || callback ? success([],[],'MANAGER_REVIEW') : conflict;
    case 'ConvertCallback': return type === 'CALLBACK' && (callback || reviewing)
      ? success(['address','appliance','preference'],['address','appliance','preference','fault','payload','payload'],'MANAGER_REVIEW','REPAIR') : conflict;
    case 'ChangeDetails': return repairReview ? success(['preference'],['preference']) : conflict;
    case 'RecordCoverageAssessment': return repairReview ? success(['assessment'],['assessment','addressReview']) : conflict;
    case 'ChangeContact': return callback || reviewing ? success(['contact'],['contact','payload','staffEvidence']) : conflict;
    case 'ReadyForDispatch': return !repairReview || !w.phone ? conflict : w.coverage
      ? success([],[],'WAITING_ASSIGNMENT') : {http:409,code:'COVERAGE_ASSESSMENT_STALE'};
    case 'ChooseCallback': return waiting ? success(['preference'],['preference','phone'],'CALLBACK_REQUIRED') : conflict;
    case 'WithdrawPhonePermission': return w.phone ? success([],actor === 'STAFF' ? ['staffEvidence','phone'] : ['phone']) : conflict;
    case 'CancelRequest': return early || (actor === 'STAFF' && status === 'WAITING_ASSIGNMENT') ? success([],[],'CANCELLED')
      : status === 'WAITING_ASSIGNMENT' ? dependency : conflict;
  }
}

// Live names are explicitly restricted to the tables above. Use one known
// registered §6.2 overlay (F at WAITING_ASSIGNMENT) plus narrow negative probes
// of not-mapped families; we do not invent an official future path/method.
export const noP05CommandRoutes = ['complete-channel-link','assign','acknowledge','send-quote','request-stop','close','expire-waiting-link'] as const;
