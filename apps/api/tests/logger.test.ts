import type { LoggerService } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { SafeLogger } from '../src/runtime/safe-logger.js';

describe('safe technical logging', () => {
  it('emits structured events and suppresses arbitrary framework payloads', () => {
    const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const errors = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const previousLevel = process.env['NEST_LOG_LEVEL'];
    process.env['NEST_LOG_LEVEL'] = 'synthetic-secret-canary';
    try {
      const logger = new SafeLogger('api');
      logger.event('started');
      const frameworkLogger: LoggerService = logger;
      frameworkLogger.error(new Error('synthetic-secret-canary'));
      frameworkLogger.log({ token: 'synthetic-secret-canary' });
      const text = output.mock.calls.map(([chunk]) => String(chunk)).join('');
      expect(text).toContain('"event":"started"');
      expect(text).toContain('"role":"api"');
      expect(text).not.toContain('synthetic-secret-canary');
      expect(errors).not.toHaveBeenCalled();
    } finally {
      if (previousLevel === undefined) { delete process.env['NEST_LOG_LEVEL']; }
      else { process.env['NEST_LOG_LEVEL'] = previousLevel; }
      output.mockRestore();
      errors.mockRestore();
    }
  });
});
