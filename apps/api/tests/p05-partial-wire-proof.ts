import { Client } from 'pg';
import { expect } from 'vitest';
import { record } from './rbac-fixture.js';

export interface PartialWireTarget {
  readonly sessionId: string;
  readonly requestId: string;
  readonly eventId: string;
}

const modes = ['submitEdge','good_audit','good_outbox'] as const;
export type PartialWireMode = typeof modes[number];
export type PartialWireSend<Reply> = () => Promise<Reply>;
export type PartialWireClosed<Reply> = (reply: Reply, mode: PartialWireMode) => void | Promise<void>;
export type PartialWireSnapshot = (target: PartialWireTarget) => Promise<unknown>;
export type PartialWireRecovery = (target: PartialWireTarget) => void | Promise<void>;

export interface PartialWireOptions<Reply> {
  readonly target: PartialWireTarget;
  /** Each real HTTPS send must take the selected fault path exactly once. */
  readonly sends: Readonly<Record<PartialWireMode, readonly PartialWireSend<Reply>[]>>;
  readonly assertClosed503: PartialWireClosed<Reply>;
  /** Read durable rows independently of the fault, including event/edge/receipt/audit/outbox. */
  readonly snapshot: PartialWireSnapshot;
  /** Assert healthy wire behavior (e.g. same-key replay) without new durable effects. */
  readonly assertRecovered: PartialWireRecovery;
}

const edgeSelect = 'SELECT session_id,request_id,event_id,submit_command,consent_id AS id,document_id,document_version_id'
  + ' FROM foundation.request_session_submits WHERE session_id=$1';
const partialSelect = 'SELECT e.id FROM foundation.request_events e WHERE e.actor_session_id=$1'
  + " AND e.command IN ('CreateCallback','CreateRepair') LIMIT 1";
const receiptPrefix = 'SELECT r.event_id,r.request_id,r.version,r.resulting_status AS status,';

type Observation = PartialWireMode | 'noPartialForm';

/** Test-only result faults against one already-committed F callback. Run serially:
 * this temporarily intercepts the shared real pg Client.prototype.query. */
export async function provePartialWire<Reply>(options: PartialWireOptions<Reply>): Promise<void> {
  const { target, sends, snapshot, assertClosed503, assertRecovered } = options;
  const { sessionId, requestId, eventId } = target;
  const original = Object.getOwnPropertyDescriptor(Client.prototype,'query')?.value as Client['query'] | undefined;
  if (typeof original !== 'function') { throw new Error('Missing real PG query method'); }
  const before = await snapshot(target);
  for (const mode of modes) {
    expect(sends[mode].length,`${mode}: exercise the fault over HTTPS`).toBeGreaterThan(0);
    let started: Observation[] = [];
    let verified: Observation[] = [];
    Client.prototype.query = function(this: Client,...args: unknown[]) {
      const result: unknown = Reflect.apply(original,this,args);
      const [sql,params] = args;
      if (typeof sql !== 'string' || !Array.isArray(params)) { return result; }
      const select = sql.trim().replace(/\s+/g,' ');
      let observed: Observation;
      if (mode === 'submitEdge') {
        if (params.length !== 1 || params[0] !== sessionId) { return result; }
        if (select === edgeSelect) { observed = mode; }
        else if (select === partialSelect) { observed = 'noPartialForm'; }
        else { return result; }
      } else {
        if (params.length !== 2 || params[0] !== eventId || params[1] !== requestId
          || !select.startsWith(receiptPrefix) || !select.endsWith('WHERE e.id=$1 AND e.request_id=$2')) { return result; }
        observed = mode;
      }
      started.push(observed);
      return Promise.resolve(result).then((value: unknown) => {
        const rowset = record(value);
        const rows = rowset['rows'];
        expect(rowset['rowCount'],`${observed}: real SELECT row count`).toBe(1);
        if (!Array.isArray(rows)) { throw new Error(`Missing real PG rows for ${observed}`); }
        expect(rows).toHaveLength(1);
        const row = record(rows[0]);
        if (observed === 'submitEdge') {
          expect(row).toMatchObject({session_id:sessionId,request_id:requestId,event_id:eventId,submit_command:'CreateCallback'});
          verified.push(observed);
          // Affect only the session lookup. Leave the real event lookup intact.
          return {...rowset,rows:[],rowCount:0};
        }
        if (observed === 'noPartialForm') {
          expect(row).toEqual({id:eventId});
          verified.push(observed);
          return value;
        }
        expect(row).toMatchObject({event_id:eventId,request_id:requestId,principal:`F:${sessionId}`,command:'CreateCallback',
          good_audit:true,good_outbox:true,good_phone:true});
        verified.push(observed);
        return {...rowset,rows:[{...row,[observed]:false}]};
      });
    } as typeof original;
    try {
      const trace: readonly Observation[] = mode === 'submitEdge' ? [mode,'noPartialForm'] : [mode];
      for (const [index,send] of sends[mode].entries()) {
        started = [];
        verified = [];
        const reply = await send();
        // A thrown assertion/PG error can itself become NOT_READY. Require both
        // the exact matched queries and verified real results before trusting 503.
        expect(started,`${mode} send ${String(index+1)}: exact driver reads`).toEqual(trace);
        expect(verified,`${mode} send ${String(index+1)}: real rows verified before substitution`).toEqual(trace);
        await assertClosed503(reply,mode);
      }
    } finally { Client.prototype.query = original; }
    expect(await snapshot(target),`${mode}: unchanged durable state`).toEqual(before);
  }
  await assertRecovered(target);
  expect(await snapshot(target),'recovery replay: unchanged durable state').toEqual(before);
}
