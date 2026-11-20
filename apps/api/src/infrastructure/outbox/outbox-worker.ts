import { randomUUID } from 'node:crypto';
import type { OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { RuntimeDatabase } from '../database/runtime-database.js';
import type { DatabaseConfig } from '../database/runtime-database.js';
import { SafeLogger } from '../../runtime/safe-logger.js';
import { OutboxStore } from './outbox-store.js';
import type { OutboxLease } from './outbox-store.js';

export type OutboxHandler = (lease: OutboxLease, signal: AbortSignal) => Promise<void>;

/** No handlers are registered in production until a real implementation exists. */
export class OutboxWorker implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly owner = randomUUID();
  private readonly database: RuntimeDatabase | undefined;
  private readonly store: OutboxStore | undefined;
  private readonly handlers: ReadonlyMap<string, OutboxHandler>;
  private readonly abort = new AbortController();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private pending: Promise<void> | undefined;
  private closing = false;
  private shutdown: Promise<void> | undefined;

  constructor(config: DatabaseConfig | undefined, private readonly logger: SafeLogger,
    handlers: ReadonlyMap<string, OutboxHandler> = new Map()) {
    this.handlers = new Map(handlers);
    if (config) { this.database = new RuntimeDatabase(config); this.store = new OutboxStore(config); }
  }

  onApplicationBootstrap(): void {
    if (this.database && !this.closing) { void this.runOnce(); }
  }

  runOnce(): Promise<void> {
    if (this.closing) { return Promise.resolve(); }
    if (this.timer) { clearTimeout(this.timer); this.timer = undefined; }
    this.pending ??= this.processOne().catch(() => {
      this.logger.event('outbox_unavailable');
    }).finally(() => {
      this.pending = undefined;
      if (!this.closing && this.database) {
        this.timer = setTimeout(() => { this.timer = undefined; void this.runOnce(); }, 1000);
      }
    });
    return this.pending;
  }

  private async processOne(): Promise<void> {
    if (!this.database || !this.store) { return; }
    if (!await this.database.ready()) { this.logger.event('outbox_unavailable'); return; }
    if (this.closing) { return; }
    const lease = await this.store.claim(this.owner, [...this.handlers.keys()]);
    if (!lease) { return; }
    // Shutdown can race the claim commit. Leave that lease to expire; never
    // execute a new handler after closing starts or mark it successful.
    if (this.isClosing()) { return; }
    const handler = this.handlers.get(lease.eventType);
    if (!handler) { return; }
    try {
      await handler(lease, this.abort.signal);
    } catch {
      if (!this.isClosing() && !await this.store.retry(lease)) { this.logger.event('outbox_lease_lost'); }
      return;
    }
    if (!this.isClosing() && !await this.store.complete(lease)) { this.logger.event('outbox_lease_lost'); }
  }

  private isClosing(): boolean { return this.closing; }

  onModuleDestroy(): Promise<void> {
    this.shutdown ??= this.stop();
    return this.shutdown;
  }

  private async stop(): Promise<void> {
    this.closing = true;
    if (this.timer) { clearTimeout(this.timer); this.timer = undefined; }
    this.abort.abort();
    // The process lifecycle supplies the final force-exit deadline for a handler
    // that ignores cancellation. Do not detach a still-running handler/SQL call.
    await this.pending;
    try { await this.store?.close(); }
    finally { await this.database?.onModuleDestroy(); }
  }
}
