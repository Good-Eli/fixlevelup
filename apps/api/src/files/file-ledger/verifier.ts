import { randomBytes, verify, type KeyObject } from 'node:crypto';
import { array, chainHash, counter, deny, encodeGraph, hash, HEAD_FIELDS, headMessage, keyPin, ledgerFloor, ledgerGraphSha256,
  ledgerHead, ledgerLimits, ledgerScope, MAX_PROOF_BYTES, plain, sameNamespace, scopeOf } from './codec.js';
import type { DurableFloorStore, FileLedgerVerifier, LedgerEvent, LedgerHead, LedgerLimits, LedgerMembership,
  LedgerMembershipFacts, LedgerReadPort, LedgerScope } from './contract.js';

const MEMBERSHIPS = new WeakMap<object, LedgerMembershipFacts>();
export function readLedgerMembership(value: unknown): LedgerMembershipFacts {
  const facts = typeof value === 'object' && value !== null ? MEMBERSHIPS.get(value) : undefined;
  return facts ?? deny();
}
interface Config {
  readonly ledger: LedgerReadPort;
  readonly signerPublicKey: KeyObject;
  readonly floor: DurableFloorStore;
  readonly limits: LedgerLimits;
}
export function createFileLedgerVerifier(config: Config): FileLedgerVerifier {
  const { floor, ledger, signerPublicKey, limits: rawLimits } = plain(config,
    ['floor', 'ledger', 'signerPublicKey', 'limits']) as unknown as Config;
  if (signerPublicKey.type !== 'public') {deny();}
  const keySha256 = keyPin(signerPublicKey);
  const limits = ledgerLimits(rawLimits);
  async function prove(scope: LedgerScope, base?: LedgerHead, eventSeq?: bigint) {
    // Contention retries obtain a new nonce, signed current primary head and anchor.
    for (let retry = 0; retry < 4; retry++) {
      const anchor = ledgerFloor(await floor.read(scope.namespace));
      if (!sameNamespace(scope, anchor) || anchor.keySha256 !== keySha256 || scope.writerEpoch < anchor.writerEpoch
        || (base && (!sameNamespace(base, scope) || base.writerEpoch > scope.writerEpoch))) {deny();}
      const challenge = randomBytes(32).toString('hex');
      const signed = plain(await ledger.getHead(scope, challenge), [...HEAD_FIELDS, 'v', 'challenge', 'signature']);
      const { v, challenge: echoed, signature, ...facts } = signed;
      const head = ledgerHead(facts);
      if (v !== 1 || echoed !== challenge || typeof signature !== 'string' || signature.length !== 128 || !/^[0-9a-f]{128}$/.test(signature)
        || !sameNamespace(scope, head) || head.writerEpoch !== scope.writerEpoch
        || !verify(null, headMessage(head, challenge), signerPublicKey, Buffer.from(signature, 'hex'))
        || head.seq < anchor.seq || (head.seq === anchor.seq && head.hash !== anchor.hash)
        || (base && head.seq < base.seq) || (eventSeq !== undefined && head.seq < eventSeq)) {deny();}
      let start = anchor.seq;
      if (base && base.seq < start) {start = base.seq;}
      if (eventSeq !== undefined && eventSeq <= start) {start = eventSeq - 1n;}
      if (head.seq - start > BigInt(limits.maxProofEvents)) {deny();}
      const rows = head.seq === start ? [] : array(await ledger.getEvents(scope, start, head.seq), limits.maxProofEvents, Number(head.seq - start));
      const events: LedgerEvent[] = [];
      let seq = start, bytes = 0;
      let lastHash = start === anchor.seq ? anchor.hash : base?.seq === start ? base.hash : undefined;
      let lastEpoch = 0n;
      const checkAnchors = () => {
        // Several epoch fences may share one sequence/hash. Compare both anchors
        // to the last actual event, then carry the greater epoch into the suffix.
        let nextEpoch = lastEpoch;
        for (const point of [base, anchor]) {
          if (!point || seq !== point.seq) {continue;}
          if (lastHash !== point.hash || lastEpoch > point.writerEpoch) {deny();}
          if (point.writerEpoch > nextEpoch) {nextEpoch = point.writerEpoch;}
        }
        lastEpoch = nextEpoch;
      };
      // A historical membership can precede the floor. Its suffix must still
      // reach the exact anchored hash; its predecessor is not itself evidence.
      checkAnchors();
      for (const row of rows) {
        const v = plain(row, ['seq', 'hash', 'previousHash', 'graph']);
        const { graph, payload } = encodeGraph(v.graph as LedgerEvent['graph'], limits.maxItems);
        const event = Object.freeze({ seq: counter(v.seq), hash: hash(v.hash), previousHash: hash(v.previousHash), graph });
        bytes += payload.length;
        if (bytes > MAX_PROOF_BYTES || event.seq !== ++seq || !sameNamespace(graph, scope) || graph.writerEpoch < lastEpoch
          || graph.writerEpoch > head.writerEpoch || (lastHash !== undefined && event.previousHash !== lastHash)
          || event.hash !== chainHash(event.previousHash, seq, payload)) {deny();}
        lastHash = event.hash;
        lastEpoch = graph.writerEpoch;
        events.push(event);
        checkAnchors();
      }
      if (seq !== head.seq || lastHash !== head.hash || lastEpoch > head.writerEpoch) {deny();}
      if (await floor.compareAndPin(anchor, Object.freeze({ ...head, keySha256 }))) {return { head, events };}
    }
    deny();
  }
  return Object.freeze<FileLedgerVerifier>({
    async verifyMembership(input, rawSeq, currentScope) {
      try {
        const { graph } = encodeGraph(input, limits.maxItems);
        const seq = counter(rawSeq), scope = ledgerScope(currentScope ?? scopeOf(graph));
        if (!sameNamespace(graph, scope) || graph.writerEpoch > scope.writerEpoch) {deny();}
        const { head, events } = await prove(scope, undefined, seq);
        const event = events.find((row) => row.seq === seq) ?? deny();
        const graphSha256 = ledgerGraphSha256(graph, limits.maxItems);
        if (graphSha256 !== ledgerGraphSha256(event.graph, limits.maxItems)) {deny();}
        const receipt = Object.freeze(Object.create(null)) as LedgerMembership;
        MEMBERSHIPS.set(receipt, Object.freeze({ ...scopeOf(graph), seq, hash: event.hash, eventId: graph.eventId,
          intentId: graph.intentId, accessEpoch: graph.accessEpoch, graphSha256, head }));
        return receipt;
      } catch { deny(); }
    },
    async verifyLineage(input, rawBase) {
      try {
        const base = ledgerHead(rawBase);
        const { head, events } = await prove(ledgerScope(input), base);
        return Object.freeze({ head, events: Object.freeze(events.filter((event) => event.seq > base.seq)) });
      } catch { deny(); }
    },
  });
}