import { ConsoleLogger } from '@nestjs/common';
import type { LoggerService } from '@nestjs/common';
import type { ProcessRole } from './config.js';

export type TechnicalEvent =
  | 'started' | 'heartbeat' | 'shutdown_started' | 'shutdown_completed'
  | 'shutdown_failed' | 'shutdown_timeout' | 'startup_failed' | 'request_failed';

export class SafeLogger implements LoggerService {
  private readonly output: ConsoleLogger;

  constructor(private readonly role: ProcessRole) {
    this.output = new ConsoleLogger({ json: true, colors: false, timestamp: false, logLevels: ['log'] });
  }

  event(event: TechnicalEvent): void {
    this.output.log({ event, role: this.role });
  }

  // Arbitrary Nest/dependency messages can contain configuration or payloads.
  // Only the fixed technical event schema above is emitted at this stage.
  log(): void { /* framework message suppressed */ }
  error(): void { /* arbitrary errors/stacks suppressed */ }
  warn(): void { /* arbitrary warnings suppressed */ }
  debug(): void { /* arbitrary debug messages suppressed */ }
  verbose(): void { /* arbitrary verbose messages suppressed */ }
  fatal(): void { /* arbitrary fatal messages suppressed */ }
}
