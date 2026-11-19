import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import { describe, expect, it, vi } from 'vitest';
import { WorkerModule } from '../src/worker.module.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';

describe('technical worker lifecycle', () => {
  it('starts a heartbeat and clears it on application close', async () => {
    vi.useFakeTimers();
    const logger = new SafeLogger('worker');
    const event = vi.spyOn(logger, 'event').mockImplementation(() => undefined);
    const module = await Test.createTestingModule({ imports: [WorkerModule] })
      .overrideProvider(SafeLogger).useValue(logger).compile();
    try {
      await module.init();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(event).toHaveBeenCalledExactlyOnceWith('heartbeat');
      await module.close();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(event).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      await module.close();
      vi.useRealTimers();
    }
  });
});
