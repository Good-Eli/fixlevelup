import { createP04Client, matchP04Route, P04_ROUTES, type P04Data, type P04MutationOperation,
  type P04Operation, type P04Request, type P04Transport, type P04TransportRequest } from '@fixlevelup/p03-contracts/p04';
import { parseP04JsonText } from '@fixlevelup/p03-contracts/p04-json';
import { ApiError, type Identity } from '../api';
import { boundedResponseText, FormError, sameSession, SessionChanged } from '../p0305-client';

export type P04ReadOperation = Exclude<P04Operation, P04MutationOperation>;
const opaqueStreams = ['fixedPublish','fixedClose','fixedReplace','ruleVersionPublish','ruleVersionClose','ruleVersionReplace',
  'policyPublish','policyClose','policyReplace'] as const satisfies readonly P04MutationOperation[];
type OpaqueStream = typeof opaqueStreams[number];
const opaqueStreamOps: ReadonlySet<P04Operation> = new Set(opaqueStreams);
const companyPublishes = ['categoryPublish', 'brandPublish', 'modelPublish', 'faultPublish',
  'itemPublish', 'avitoPublish'] as const satisfies readonly P04MutationOperation[];
type CompanyPublish = typeof companyPublishes[number];
const companyPublishOps: ReadonlySet<P04Operation> = new Set(companyPublishes);
type CompanyRevisionProof = Readonly<{ id: string; version: number }> | null;

// Receipt proofs are local, never request params. null means a verified empty
// temporal stream or an identity without any published COMPANY revision.
export type P04CommandInput<Op extends P04MutationOperation> = Op extends P04MutationOperation
  ? Omit<P04Request<Op>, 'csrfToken' | 'idempotencyKey' | 'query'>
    & (Op extends OpaqueStream ? { readonly receiptSeriesId: Op extends `${string}Publish` ? string | null : string }
      : { readonly receiptSeriesId?: never })
    & (Op extends CompanyPublish ? { readonly receiptCompanyRevision: CompanyRevisionProof }
      : { readonly receiptCompanyRevision?: never }) : never;
export interface P04IO {
  read<Op extends P04ReadOperation>(op: Op, input: P04Request<NoInfer<Op>>, show: (data: P04Data<NoInfer<Op>>) => void): void;
  write<Op extends P04MutationOperation>(op: Op, input: P04CommandInput<NoInfer<Op>>): void;
}

function record(data: unknown): Readonly<Record<string, unknown>> {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) { throw new Error('Invalid staff response'); }
  return data as Readonly<Record<string, unknown>>;
}

function checkReadTarget(op: P04ReadOperation, params: Readonly<Record<string, string>>, data: unknown) {
  const dto = record(data);
  function match(row: Readonly<Record<string, unknown>>) {
    if ((params['cityId'] && Object.hasOwn(row, 'cityId') && row['cityId'] !== params['cityId'])
      || (params['itemId'] && row['itemId'] !== params['itemId'])
      || (params['ruleId'] && row['ruleId'] !== params['ruleId'])
      || (params['id'] && (op.endsWith('Get') ? row['id'] : row[op.startsWith('item') ? 'itemId' : 'entryId']) !== params['id'])
      || (params['estimateId'] && row[op === 'estimateGet' ? 'id' : 'seriesId'] !== params['estimateId'])
      || (params['versionId'] && row['id'] !== params['versionId'])) {
      throw new Error('Mismatched staff response target');
    }
  }
  const items = dto['items'];
  if (Array.isArray(items)) {
    const rows = items.map(record);
    if (new Set(rows.map(row => row['id'])).size !== rows.length) { throw new Error('Duplicate items in staff response'); }
    rows.forEach(match);
  } else { match(dto); }
}

const p04IdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function isP04Id(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && p04IdPattern.test(value);
}

async function strictResponseJson(response: Response, limit: number) {
  return parseP04JsonText(await boundedResponseText(response, limit, true));
}

async function confirmedProblem(response: Response): Promise<never> {
  const error = record(await strictResponseJson(response, 4096));
  const { status, type, title, code, requestId } = error;
  if (Object.keys(error).length !== 5 || type !== 'about:blank' || status !== response.status
    || typeof title !== 'string' || title.length < 1 || title.length > 48
    || typeof code !== 'string' || code.length < 1 || code.length > 48
    || !isP04Id(requestId)) { throw new Error('Unverified staff response'); }
  throw new ApiError(response.status);
}

function safeRoute(wire: P04TransportRequest) {
  const path = wire.path.split('?', 1)[0] ?? '';
  const match = matchP04Route(wire.method, path);
  if (match?.operation !== wire.operation || /[\s#\\]/u.test(wire.path)) { throw new Error('Invalid staff request target'); }
  return match;
}

function matchesCompanyRevision(proof: CompanyRevisionProof | undefined, aggregate: number | undefined): boolean {
  return proof === null ? aggregate === 1 : proof !== undefined && typeof proof === 'object' && isP04Id(proof.id)
    && Number.isSafeInteger(proof.version) && proof.version > 0 && aggregate === proof.version + 1;
}

export function p04Transport(signal: AbortSignal, receiptSeriesId?: string | null, companyRevision?: CompanyRevisionProof): P04Transport {
  return async wire => {
    const match = safeRoute(wire);
    const route = P04_ROUTES[wire.operation];
    const sentVersion = wire.headers['If-Match'];
    const previous = sentVersion ? Number(/^"p04-v([0-9]+)"$/.exec(sentVersion)?.[1]) : 0;
    const companyPublish = companyPublishOps.has(wire.operation);
    if (companyPublish && !matchesCompanyRevision(companyRevision, previous)) { throw new Error('Missing current staff revision'); }
    const lifetime = AbortSignal.any([signal, AbortSignal.timeout(18_000)]);
    lifetime.throwIfAborted();
    const response = await fetch(wire.path, {
      method: wire.method, headers: { ...wire.headers, 'X-Auth-Request': '1' },
      signal: lifetime, cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
      ...(wire.body === undefined ? {} : { body: wire.body }),
    });
    try {
      lifetime.throwIfAborted();
      if (response.headers.get('cache-control') !== 'no-store') { throw new Error('Staff response is not private'); }
      const media = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
      if (!response.ok) {
        if (media !== 'application/problem+json' || response.status < 400 || response.status > 599) { throw new Error('Unverified staff response'); }
        return await confirmedProblem(response);
      }
      if (media !== 'application/json') { throw new Error('Invalid staff response type'); }
      const body = await strictResponseJson(response, route.responseLimit);
      lifetime.throwIfAborted();
      const data = record(record(body)['data']);
      if (wire.method === 'POST') {
        const version = data['version'];
        const params: Partial<Record<string, string>> = match.params;
        // A known temporal stream may not share an ID with any route parameter.
        // Bind its receipt to the selected history, not only to the CAS outcome.
        const targetId = params['id'] ?? params['estimateId'] ?? receiptSeriesId ?? undefined;
        // A versioned CITY command with a 201 contract is Publish or Replace.
        // Its new revision uses the aggregate sequence, unlike COMPANY metadata.
        const appendsPeriod = route.scope === 'CITY' && route.versioned && route.status === 201;
        const closesRevision = params['versionId'];
        const wrongCompanyRevision = companyPublish && (data['revisionVersion'] !== (companyRevision?.version ?? 0) + 1
          || (companyRevision !== null && companyRevision !== undefined && data['revisionId'] === companyRevision.id));
        if (typeof version !== 'number' || version !== previous + 1 || response.headers.get('etag') !== `"p04-v${String(version)}"`
          || (targetId !== undefined && data['id'] !== targetId) || wrongCompanyRevision
          || (appendsPeriod && (data['revisionVersion'] !== version
            || (closesRevision !== undefined && data['revisionId'] === closesRevision)))) { throw new Error('Invalid staff receipt'); }
      } else {
        checkReadTarget(wire.operation as P04ReadOperation, match.params, data);
      }
      return { status: response.status, body };
    } finally { if (!response.body?.locked) { void response.body?.cancel().catch(() => undefined); } }
  };
}

export async function readP04<Op extends P04ReadOperation>(signal: AbortSignal, op: Op, input: P04Request<NoInfer<Op>>) {
  return (await createP04Client(p04Transport(signal)).request(op, input)).data;
}

export interface PreparedP04 {
  readonly family: 'P04';
  readonly actor: Identity;
  readonly wire: P04TransportRequest;
  readonly send: (signal: AbortSignal) => Promise<void>;
}

export async function prepareP04Command<Op extends P04MutationOperation>(op: Op, input: P04CommandInput<NoInfer<Op>>, actor: Identity): Promise<PreparedP04> {
  const { receiptSeriesId, receiptCompanyRevision, ...copy } = structuredClone(input);
  const expected = 'expectedVersion' in copy ? copy.expectedVersion : undefined;
  if (opaqueStreamOps.has(op)) {
    const first = op.endsWith('Publish') && expected === 0;
    if (first ? receiptSeriesId !== null : !isP04Id(receiptSeriesId)) {
      throw new FormError('Нужна проверенная история выбранного набора версий.');
    }
  } else if (receiptSeriesId !== undefined) { throw new FormError('Идентификатор набора версий здесь не предусмотрен.'); }
  if (companyPublishOps.has(op)) {
    if (!matchesCompanyRevision(receiptCompanyRevision, expected)) {
      throw new FormError('Загрузите текущую версию карточки перед публикацией.');
    }
  } else if (receiptCompanyRevision !== undefined) { throw new FormError('Версия карточки здесь не предусмотрена.'); }
  const bound = Object.freeze({ ...actor });
  // The expected receipt identity stays local. The generated validator aligns
  // only request fields with the exact operation and captures the replay bytes.
  const request = { ...copy, idempotencyKey: crypto.randomUUID(), csrfToken: bound.csrf } as unknown as P04Request<NoInfer<Op>>;
  const capture = new Error('Prepared generated staff request');
  let frozen: P04TransportRequest | undefined;
  try {
    await createP04Client(wire => {
      safeRoute(wire);
      frozen = Object.freeze({ ...wire, headers: Object.freeze({ ...wire.headers }) });
      return Promise.reject(capture);
    }).request(op, request);
  } catch (error) {
    if (error !== capture) { throw new FormError('Проверьте поля, целевой объект, версию и размер команды.'); }
  }
  if (!frozen) { throw new FormError('Не удалось подготовить команду.'); }
  const exact = frozen;
  return Object.freeze({ family: 'P04', actor: bound, wire: exact,
    send: async (signal: AbortSignal) => {
      await createP04Client(wire => {
        if (wire.path !== exact.path || wire.body !== exact.body || wire.method !== exact.method || wire.operation !== exact.operation
          || JSON.stringify(wire.headers) !== JSON.stringify(exact.headers)) { throw new Error('Prepared request changed'); }
        return p04Transport(signal, receiptSeriesId, receiptCompanyRevision)(exact);
      }).request(op, request);
    },
  });
}

export async function sendPreparedP04(signal: AbortSignal, live: Identity, command: PreparedP04): Promise<void> {
  if (!sameSession(command.actor, live)) { throw new SessionChanged(); }
  await command.send(signal);
}
