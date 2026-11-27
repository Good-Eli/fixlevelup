/** The released admission path uses only this process's inherited Node IPC. */
import process from 'node:process';

export interface LauncherChannel {
  live(): boolean;
  send(message: object, done: (error: Error | null) => void): void;
  onMessage(listener: (message: unknown) => void): () => void;
  onLoss(listener: () => void): () => void;
  unref(): void;
  stopAfterLoss(): void;
}

// Capture the native transport at module load, not from caller arguments or
// environment. A process without inherited IPC never claims this channel.
const childIpc = process.channel;
const send = process.send?.bind(process);
let claimed = false;

export function createPrivateLaunchChannel(): LauncherChannel | undefined {
  if (claimed || !childIpc || !send || !process.connected || process.channel !== childIpc) { return undefined; }
  claimed = true;
  return Object.freeze<LauncherChannel>({
    live: () => process.connected && process.channel === childIpc,
    send: (message, done) => { send(message, done); },
    onMessage: (listener) => {
      process.on('message', listener);
      return () => { process.off('message', listener); };
    },
    onLoss: (listener) => {
      process.once('disconnect', listener);
      process.on('error', listener);
      return () => { process.off('disconnect', listener); process.off('error', listener); };
    },
    unref: () => { childIpc.unref(); },
    stopAfterLoss: () => {
      if (process.listenerCount('SIGTERM') === 0) { process.exit(1); }
      process.emit('SIGTERM');
    },
  });
}
