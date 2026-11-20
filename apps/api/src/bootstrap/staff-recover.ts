import { emitKeypressEvents } from 'node:readline';
import { Pool } from 'pg';
import { recoverAdmin } from '../staff/recovery.js';

// Kept local because the bootstrap CLI is an executable, not an importable module.
async function readCredentials(): Promise<{ login: string; password: string }> {
  const input = process.stdin;
  const output = process.stdout;
  if (!input.isTTY || !output.isTTY) { throw new Error('Terminal required'); }
  const wasRaw = input.isRaw;
  let text = '';
  let login = '';
  let password = '';
  let stage = 0;
  try {
    emitKeypressEvents(input);
    input.setRawMode(true);
    input.resume();
    output.write('Login: ');
    return await new Promise((resolve, reject) => {
      let finished = false;
      const finish = (error?: Error): void => {
        if (finished) { return; }
        finished = true;
        input.removeListener('keypress', onKey);
        input.removeListener('error', onError);
        input.removeListener('end', onEnd);
        input.removeListener('close', onEnd);
        process.removeListener('SIGINT', onSignal);
        process.removeListener('SIGTERM', onSignal);
        if (error) { reject(error); } else { resolve({ login, password }); }
      };
      const onError = (): void => { finish(new Error('Terminal error')); };
      const onEnd = (): void => { finish(new Error('Terminal closed')); };
      const onSignal = (): void => { finish(new Error('Interrupted')); };
      const onKey = (value: string | undefined, key: { name?: string; ctrl?: boolean; meta?: boolean }): void => {
        if (key.ctrl && (key.name === 'c' || key.name === 'd')) { finish(new Error('Interrupted')); return; }
        if (key.name === 'return' || key.name === 'enter') {
          output.write('\n');
          if (stage === 0) { login = text; text = ''; stage = 1; output.write('Password: '); }
          else if (stage === 1) {
            if (Buffer.byteLength(text, 'utf8') < 16) { finish(new Error('Invalid password length')); return; }
            password = text; text = ''; stage = 2; output.write('Confirm password: ');
          }
          else if (text !== password) { finish(new Error('Passwords differ')); }
          else { finish(); }
          return;
        }
        if (key.name === 'backspace') {
          const chars = Array.from(text);
          if (chars.length) { chars.pop(); text = chars.join(''); if (stage === 0) { output.write('\b \b'); } }
          return;
        }
        // eslint-disable-next-line no-control-regex
        if (!value || key.ctrl || key.meta || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) { return; }
        if (Buffer.byteLength(text + value, 'utf8') > 1024) { finish(new Error('Input too long')); return; }
        if (stage === 0 && !/^[A-Za-z0-9._@+-]+$/.test(value)) { return; }
        text += value;
        if (stage === 0) { output.write(value); }
      };
      input.on('keypress', onKey);
      input.on('error', onError);
      input.on('end', onEnd);
      input.on('close', onEnd);
      process.on('SIGINT', onSignal);
      process.on('SIGTERM', onSignal);
    });
  } finally {
    text = '';
    input.setRawMode(wasRaw);
    input.pause();
  }
}

let pool: Pool | undefined;
try {
  if (process.argv.length !== 2 || !process.stdin.isTTY || !process.stdout.isTTY || !process.env['DB_PASSWORD']) {
    throw new Error('Invalid invocation');
  }
  const credentials = await readCredentials();
  pool = new Pool({ host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_migrator',
    password: process.env['DB_PASSWORD'], ssl: false, max: 1, application_name: 'fixlevelup-staff-recovery' });
  pool.on('error', () => { /* Never disclose driver errors. */ });
  await recoverAdmin(pool, credentials);
  process.stdout.write('Staff recovery completed.\n');
} catch {
  process.stderr.write('Staff recovery failed.\n');
  process.exitCode = 1;
} finally {
  if (pool) {
    try { await pool.end(); }
    catch { process.stderr.write('Staff recovery failed.\n'); process.exitCode = 1; }
  }
}
