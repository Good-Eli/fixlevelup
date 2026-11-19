import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { Catch, HttpException } from '@nestjs/common';
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common';
import { SafeLogger } from './safe-logger.js';

@Catch()
export class ProblemFilter implements ExceptionFilter {
  constructor(private readonly logger: SafeLogger) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<ServerResponse>();
    const proposedStatus = exception instanceof HttpException ? exception.getStatus() : 500;
    const status = proposedStatus >= 400 && proposedStatus <= 599 ? proposedStatus : 500;
    const code = status === 503 ? 'NOT_READY' : status === 404 ? 'NOT_FOUND' : status === 500 ? 'INTERNAL_ERROR' : 'REQUEST_REJECTED';
    if (status >= 500 && status !== 503) {
      this.logger.event('request_failed');
    }
    response.statusCode = status;
    response.setHeader('Content-Type', 'application/problem+json');
    response.setHeader('Cache-Control', 'no-store');
    response.end(JSON.stringify({
      type: 'about:blank',
      title: code,
      status,
      code,
      requestId: randomUUID(),
    }));
  }
}
