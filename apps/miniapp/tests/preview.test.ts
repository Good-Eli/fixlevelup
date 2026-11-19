import { preview } from 'vite';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../', import.meta.url));

describe('Mini App local production assets', () => {
  it('serves built HTML and JS only on loopback and closes the listener', async () => {
    const server = await preview({ root, preview: { port: 0, host: '127.0.0.1', strictPort: true } });
    let base: string;
    try {
      const address = server.httpServer.address();
      if (!address || typeof address === 'string') { throw new Error('Expected TCP listener'); }
      base = `http://127.0.0.1:${String(address.port)}`;
      expect(address.address).toBe('127.0.0.1');
      const response = await fetch(base);
      const html = await response.text();
      expect(response.status).toBe(200);
      expect(html).toContain('lang="ru"');
      expect(html).toContain('id="root"');
      expect(html).toContain('noindex');
      expect(response.headers.get('x-robots-tag')).toContain('noindex');
      const scripts = [...html.matchAll(/<script[^>]+src="([^"]+\.js)"/g)]
        .map((match) => match[1]).filter((url): url is string => !!url);
      expect(scripts.length).toBeGreaterThan(0);
      for (const path of scripts) {
        const asset = await fetch(new URL(path, base));
        expect(asset.status).toBe(200);
        expect(await asset.text()).toContain('miniapp-foundation-ok');
      }
    } finally {
      await server.close();
    }
    await expect(fetch(base)).rejects.toThrow();
  });
});
