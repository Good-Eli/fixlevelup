import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../..');

describe('Next production build', () => {
  it('serves technical HTML and JS on loopback without business routes or secret canaries', async () => {
    const env: NodeJS.ProcessEnv = { ...process.env, NODE_ENV: 'production', CI: '1', NEXT_TELEMETRY_DISABLED: '1',
      DATABASE_URL: 'synthetic-server-secret-canary', BOT_TOKEN: 'synthetic-server-secret-canary' };
    delete env['NEXT_TELEMETRY_DEBUG'];
    const child = spawn(process.execPath, ['apps/web/tests/server.mjs'], {
      cwd: root, env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once('exit', (code, signal) => { resolve({ code, signal }); });
      child.once('error', reject);
    });
    let output = '';
    child.stdout?.on('data', (chunk: Buffer) => { output += chunk.toString(); });
    child.stderr?.on('data', (chunk: Buffer) => { output += chunk.toString(); });
    const deadline = setTimeout(() => { child.kill(); }, 25000);
    try {
      const address = await Promise.race([
        once(child, 'message').then(([message]: unknown[]) => message as { port: number }),
        exited.then(() => { throw new Error(`Next exited before ready: ${output}`); }),
      ]);
      const base = `http://127.0.0.1:${String(address.port)}`;
      const response = await fetch(base);
      const html = await response.text();
      expect(response.status).toBe(200);
      expect(html).toContain('web-foundation-ok');
      expect(html).toContain('lang="ru"');
      expect(response.headers.get('x-powered-by')).toBeNull();
      expect(response.headers.get('x-robots-tag')).toContain('noindex');
      expect(html).toContain('noindex');
      expect(html).not.toContain('synthetic-server-secret-canary');
      const scripts = [...html.matchAll(/<script[^>]+src="([^"]+\.js[^"]*)"/g)]
        .map((match) => match[1]).filter((url): url is string => !!url);
      expect(scripts.length).toBeGreaterThan(0);
      for (const url of scripts) {
        const asset = await fetch(new URL(url.replaceAll('&amp;', '&'), base));
        expect(asset.status).toBe(200);
        expect(await asset.text()).not.toContain('synthetic-server-secret-canary');
      }
      for (const path of ['/crm', '/api/v1/requests', '/missing-technical-route']) {
        const missing = await fetch(base + path);
        expect(missing.status).toBe(404);
        expect(await missing.text()).not.toContain('synthetic-server-secret-canary');
      }
      child.send('close');
      const result = await exited;
      expect(result.code).toBe(0);
      expect(result.signal).toBeNull();
      expect(output).not.toContain('synthetic-server-secret-canary');
    } finally {
      clearTimeout(deadline);
      if (child.exitCode === null && child.signalCode === null) { child.kill(); }
      await exited;
    }
  }, 30000);
});
