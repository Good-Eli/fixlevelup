/** Vitest-only delivery simulation. Real compiled children never load this setup. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { vi } from 'vitest';
import type { LauncherChannel } from '../src/infrastructure/admission/private-launch-channel.js';

const channels = new AsyncLocalStorage<LauncherChannel>();

vi.mock(import('../src/infrastructure/admission/private-launch-channel.js'), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, createPrivateLaunchChannel: () => channels.getStore() ?? actual.createPrivateLaunchChannel() };
});

export function withTestLaunchChannel<T>(channel: LauncherChannel, run: () => T): T {
  return channels.run(channel, run);
}

/** Translate test-specific message delivery into the shared admission protocol. */
export function testLaunchChannel(onSend: (message: object) => void): {
  channel: LauncherChannel;
  deliver(message: unknown): void;
  disconnect(): void;
} {
  const listeners = new Set<(message: unknown) => void>();
  const loss = new Set<() => void>();
  let live = true;
  return {
    channel: {
      live: () => live,
      send: (message, done) => { onSend(message); done(null); },
      onMessage: (listener) => { listeners.add(listener); return () => { listeners.delete(listener); }; },
      onLoss: (listener) => { loss.add(listener); return () => { loss.delete(listener); }; },
      unref: () => undefined,
      stopAfterLoss: () => undefined,
    },
    deliver: (message) => { for (const listener of [...listeners]) { listener(message); } },
    disconnect: () => {
      live = false;
      for (const listener of [...loss]) { listener(); }
      listeners.clear();
      loss.clear();
    },
  };
}
