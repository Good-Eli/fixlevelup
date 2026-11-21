/**
 * Bounded raw HTTP response body, installed *below* the SDK deserializer (B1, MUST2).
 *
 * The S3 client is built with the default Node request handler. That handler returns
 * `{ response: { statusCode, headers, body } }` where `body` is the live
 * `IncomingMessage`; only later does the protocol layer call `collectBody`, i.e.
 * read the *whole* body into memory before deserializing it. A raw cap has to sit
 * between those two steps, because a cap applied after the SDK collected the body
 * is applied too late: the process already buffered it.
 *
 * `installResponseBodyCap` therefore replaces `client.config.requestHandler` with a
 * thin structural wrapper around the handler the SDK itself resolved
 * (`NodeHttpHandler.create(...)`), and rewrites the *service* response body into a
 * bounded stream before returning it to the SDK. No `@smithy/*` module is imported:
 * the wrapper is typed from the SDK's own public config (`typeof client.config`), so
 * there is no hidden transitive dependency and no version coupling.
 *
 * What is capped — and what is deliberately not:
 *
 * - every HTTP error body (`status >= 300`) is a *service* body: the SDK collects it
 *   in full only to build an exception, so it is capped;
 * - every non-GET response body (notably a successful `PUT`, whose 200/204 body the
 *   adapter never reads) is capped, because the SDK would otherwise collect it before
 *   `client.send()` resolves;
 * - a successful `GET` body is the *object payload itself*, not a service body. Its
 *   size is the caller's business bound (`VerifyQuarantinedInput.maxBytes`, enforced
 *   by the adapter's own bounded drain), so it is handed downstream as an ordinary
 *   unbuffered stream. Applying this technical service cap to it would silently
 *   impose a second, undocumented file-size limit.
 *
 * For a capped body:
 *
 * - a declared `content-length` above the cap is refused before a single body byte
 *   is read (the socket is destroyed immediately);
 * - a body without `content-length` (chunked) is counted while it streams, and the
 *   source is destroyed as soon as the counter would exceed the cap — so a chunked
 *   error body cannot be collected in full either.
 *
 * Cancellation: destroying the bounded stream destroys the underlying socket, and a
 * source error is turned into one fixed value-free error so no raw HTTP text can
 * reach an adapter caller. The wrapper never changes the promise shape of the
 * handler (`handle` still resolves to `{ response }`), so SDK middleware, retries and
 * `client.destroy()` keep working.
 */
import { IncomingMessage } from 'node:http';
import { Readable, Transform } from 'node:stream';

/**
 * The single failure this module produces. It is deliberately not a
 * `PrivateStorageError`: the adapter maps any non-internal failure to its own fixed
 * code (`WRITE_OUTCOME_UNKNOWN`/`READ_FAILED` + `TRANSPORT`), so this module cannot
 * inject a code, a cause or a raw HTTP detail into the adapter's vocabulary.
 */
export class ResponseBodyLimitError extends Error {
  readonly code = 'RESPONSE_BODY_LIMIT_EXCEEDED';

  constructor() {
    super('RESPONSE_BODY_LIMIT_EXCEEDED');
    this.name = 'ResponseBodyLimitError';
  }
}

/** Minimal structural view of one SDK response, as the request handler sees it. */
interface RawResponse {
  statusCode: number;
  headers: Record<string, string | undefined>;
  body?: unknown;
}

/** Minimal structural view of one SDK request, as the request handler sees it. */
interface RawRequest {
  method?: string;
}

type RawHandler = {
  metadata?: { handlerProtocol: string } | undefined;
  destroy?: (() => void) | undefined;
  handle: (request: RawRequest, options?: { abortSignal?: unknown }) => Promise<{ response: RawResponse }>;
  updateHttpClientConfig?: ((key: never, value: never) => void) | undefined;
  httpHandlerConfigs?: (() => unknown) | undefined;
};

/** The client surface this module needs: the resolved config and nothing else. */
interface ClientWithHandler {
  config: { requestHandler: RawHandler };
}

/** Read-only probes additionally track the handler and raw body, not just SDK send(). */
export class ProbeTransport {
  #pending = new Set<Promise<unknown>>();
  #uncertain = false;
  #fullResponse = false;

  get settled(): boolean {
    return !this.#uncertain && this.#pending.size === 0;
  }

  get fullResponse(): boolean {
    return this.#fullResponse;
  }

  track(operation: Promise<unknown>): void {
    this.#pending.add(operation);
    const finished = (): void => { this.#pending.delete(operation); };
    operation.then(finished, finished);
  }

  markUncertain(): void {
    this.#uncertain = true;
  }

  async wait(): Promise<void> {
    // A pending handler can register a body after the first snapshot was taken.
    while (this.#pending.size > 0) {
      await Promise.allSettled([...this.#pending]);
    }
  }

  watchResponse(body: unknown, signal: AbortSignal): void {
    if (!(body instanceof IncomingMessage)) {
      this.markUncertain();
      return;
    }
    const socket = body.socket;
    const cancel = (): void => { destroySource(body); };
    this.track(new Promise<void>((resolve) => {
      const finished = (): void => {
        body.removeListener('end', end);
        body.removeListener('close', closed);
        signal.removeEventListener('abort', cancel);
        resolve();
      };
      const closed = (): void => {
        if (socket.closed) {
          finished();
        } else {
          // A prematurely destroyed IncomingMessage may have finished emitting
          // before the underlying request socket emitted close.
          socket.once('close', finished);
          destroySource(socket);
        }
      };
      const end = (): void => {
        this.#fullResponse = body.complete;
        if (this.#fullResponse) {
          finished(); // Normal EOF; an idle keep-alive socket is not pending IO.
        }
      };
      body.once('end', end);
      body.once('close', closed);
      signal.addEventListener('abort', cancel, { once: true });
      if (body.readableEnded && body.complete) {
        end();
      } else if (body.closed) {
        closed();
      } else if (signal.aborted) {
        cancel();
      }
    }));
  }
}

const PROBE_TRANSPORTS = new WeakMap<object, ProbeTransport>();

/** Bind only the private per-operation signal sent to the SDK, never a caller signal. */
export function bindProbeTransport(signal: AbortSignal, transport: ProbeTransport): void {
  PROBE_TRANSPORTS.set(signal, transport);
}

/** One fixed, value-free failure for a broken source stream. */
function streamFailed(): ResponseBodyLimitError {
  return new ResponseBodyLimitError();
}

/** Destroys the raw source without letting a destroy error escape. */
function destroySource(source: unknown): void {
  const destroy = (source as { destroy?: unknown } | null)?.destroy;
  if (typeof destroy === 'function') {
    try {
      destroy.call(source);
    } catch {
      // A destroy that throws cannot change the already-decided outcome.
    }
  }
}

/**
 * Counts bytes flowing downstream and fails closed the moment the cap is crossed.
 *
 * Backpressure is the ordinary Node `Transform` contract: the SDK collector pipes
 * into it (or reads it), so the source is paused while the consumer is busy and the
 * adapter never holds more than one chunk plus the stream high-water mark.
 */
class ResponseCapStream extends Transform {
  readonly #limit: number;
  #seen = 0;

  constructor(limit: number) {
    super({ highWaterMark: Math.min(limit, 65_536) });
    this.#limit = limit;
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null, data?: Buffer) => void): void {
    this.#seen += chunk.byteLength;
    if (this.#seen > this.#limit) {
      callback(new ResponseBodyLimitError());
      return;
    }
    callback(null, chunk);
  }
}

/** Wraps one Node readable so every byte it yields passes through the counter. */
function boundNodeBody(source: Readable, limit: number): Readable {
  const capped = new ResponseCapStream(limit);
  // A consumer attaches its own 'error' listener when it starts reading; this
  // listener only guarantees a failure raised before that cannot become an
  // unhandled 'error' event and crash the process.
  capped.on('error', () => { /* The consumer receives the same event. */ });
  // One source failure is one fixed failure: raw HTTP/SDK text never propagates.
  source.once('error', () => { capped.destroy(streamFailed()); });
  // `destroy()` can close without an error or EOF (e.g. a probe aborting after
  // headers). A pipe does not forward premature close, so terminate the SDK's
  // capped-body collector explicitly rather than orphaning its pending promise.
  source.once('close', () => {
    if (!source.readableEnded && !capped.destroyed) {
      capped.destroy(streamFailed());
    }
  });
  // Consumer destroy (cap reached, adapter abort, close) must release the socket.
  capped.once('close', () => { destroySource(source); });
  source.pipe(capped);
  return capped;
}

/** Reads a declared content-length, or `undefined` when it is absent/not a size. */
function declaredLength(headers: Record<string, string | undefined>): number | undefined {
  const raw = headers['content-length'];
  if (typeof raw !== 'string' || raw.trim() === '') {
    return undefined;
  }
  const value = Number(raw);
  return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/**
 * Applies the raw cap to one response body and returns the body to hand downstream.
 *
 * `undefined`/`null` bodies (HEAD, 204) need no work. A plain byte body is checked
 * by length. A Node stream and a web `ReadableStream` are both bounded. An
 * unrecognised body is refused: a response this module cannot bound is not a
 * response it can vouch for.
 */
function boundBody(body: unknown, limit: number): unknown {
  if (body === undefined || body === null) {
    return body;
  }
  if (body instanceof Readable) {
    return boundNodeBody(body, limit);
  }
  if (body instanceof Uint8Array) {
    if (body.byteLength > limit) {
      throw new ResponseBodyLimitError();
    }
    return body;
  }
  if (typeof body === 'string') {
    if (Buffer.byteLength(body) > limit) {
      throw new ResponseBodyLimitError();
    }
    return body;
  }
  const reader = (body as { getReader?: unknown }).getReader;
  if (typeof reader === 'function') {
    // A web ReadableStream (not produced by the Node handler in this client, but a
    // future handler swap must not silently lose the cap).
    const web = body as Parameters<typeof Readable.fromWeb>[0];
    return boundNodeBody(Readable.fromWeb(web), limit);
  }
  throw new ResponseBodyLimitError();
}

/**
 * Whether this response carries a *service* body that must be capped.
 *
 * A successful GET is the object payload: the adapter's own `maxBytes` drain is its
 * documented bound, so it stays an ordinary stream. Everything else — any HTTP
 * error, and any non-GET response (a successful PUT whose body nobody reads) — is a
 * service body and is capped. An unknown method is treated as "cap it" (fail closed).
 */
function isServiceBody(request: RawRequest, statusCode: number): boolean {
  if (statusCode >= 300) {
    return true;
  }
  return request.method !== 'GET';
}

/**
 * Installs the raw response cap on a client that has already been constructed.
 *
 * The handler the SDK resolved (`NodeHttpHandler.create(...)`) is kept as the only
 * transport: its `handle` is called unchanged, and only the response it resolves is
 * rewritten. `metadata`, `destroy`, `updateHttpClientConfig` and
 * `httpHandlerConfigs` are preserved so host-header selection, `client.destroy()`
 * and config extensions keep seeing a normal handler.
 */
export function installResponseBodyCap(client: ClientWithHandler, maxResponseBodyBytes: number): void {
  const original = client.config.requestHandler;
  const capped: RawHandler = {
    metadata: original.metadata,
    destroy: (): void => { original.destroy?.(); },
    updateHttpClientConfig: (key: never, value: never): void => {
      original.updateHttpClientConfig?.(key, value);
    },
    httpHandlerConfigs: (): unknown => original.httpHandlerConfigs?.(),
    handle: async (request: RawRequest, options?: { abortSignal?: unknown }): Promise<{ response: RawResponse }> => {
      const signal = options?.abortSignal;
      const probe = signal instanceof AbortSignal ? PROBE_TRANSPORTS.get(signal) : undefined;
      const raw = (async () => {
        try {
          const result = await original.handle(request, options);
          if (probe !== undefined && signal instanceof AbortSignal) {
            probe.watchResponse(result.response.body, signal);
          }
          return result;
        } catch (error: unknown) {
          // No IncomingMessage means the handler did not expose the request/socket.
          // It may have rejected early on abort/timeout while closing that socket;
          // without positive cleanup evidence, keep the durable probe debt.
          probe?.markUncertain();
          throw error;
        }
      })();
      probe?.track(raw);
      const { response } = await raw;
      if (!isServiceBody(request, response.statusCode)) {
        // Successful GET: the object payload is bounded by the caller's own maxBytes.
        return { response };
      }
      const length = declaredLength(response.headers);
      if (length !== undefined && length > maxResponseBodyBytes) {
        // Refuse before the body is read; release the socket, then fail closed.
        destroySource(response.body);
        throw new ResponseBodyLimitError();
      }
      response.body = boundBody(response.body, maxResponseBodyBytes);
      return { response };
    },
  };
  client.config.requestHandler = capped;
}
