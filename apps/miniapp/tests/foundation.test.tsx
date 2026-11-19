import { readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { ESLint } from 'eslint';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../src/App.js';

const root = resolve(import.meta.dirname, '../../..');
const appRoot = resolve(root, 'apps/miniapp');

function filesIn(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === 'node_modules') { return []; }
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesIn(path) : [path];
  });
}

describe('Mini App foundation', () => {
  it('renders technical React markup, not staff business functionality', () => {
    const html = renderToStaticMarkup(<App />);
    expect(html).toContain('miniapp-foundation-ok');
    expect(html).toContain('<main>');
    expect(html).not.toContain('<form');
  });

  it('builds JS assets without server packages, env canary or source maps', () => {
    const files = filesIn(resolve(appRoot, 'dist'));
    expect(files.some((path) => path.endsWith('.js'))).toBe(true);
    expect(files.some((path) => path.endsWith('.map'))).toBe(false);
    for (const path of files) {
      const text = readFileSync(path, 'utf8');
      expect(text).not.toContain('synthetic-miniapp-server-secret');
      expect(text).not.toContain('@prisma/client');
      expect(text).not.toContain('@nestjs/core');
      expect(text).not.toContain('Telegram.WebApp');
    }
    const js = files.filter((path) => path.endsWith('.js')).map((path) => readFileSync(path, 'utf8')).join('\n');
    expect(js).toContain('miniapp-foundation-ok');
    expect(readFileSync(resolve(appRoot, 'dist/index.html'), 'utf8')).toContain('noindex');
  });

  it('rejects server globals/imports in browser source while accepting DOM access', async () => {
    const eslint = new ESLint({ cwd: root });
    const filePath = resolve(appRoot, 'src/main.tsx');
    const invalid = await eslint.lintText('import fs from "node:fs";\nprocess.cwd();\nexport { fs };\n', { filePath });
    const rules = invalid.flatMap((result) => result.messages.map((message) => message.ruleId));
    expect(rules).toContain('no-restricted-imports');
    expect(rules).toContain('no-restricted-globals');
    const bare = await eslint.lintText('import fs from "fs";\nexport { fs };\n', { filePath });
    expect(bare.flatMap((result) => result.messages.map((message) => message.ruleId)))
      .toContain('no-restricted-imports');
    const valid = await eslint.lintText('export const root = document.getElementById("root");\n', { filePath });
    expect(valid.flatMap((result) => result.messages)).toEqual([]);
  });

  it('keeps new source/config/docs files UTF-8 LF', () => {
    const files = filesIn(appRoot).filter((path) => !/[\\/](?:node_modules|dist)[\\/]/.test(path));
    for (const path of files) {
      if (path.endsWith('.tsbuildinfo')) { continue; }
      const text = readFileSync(path, 'utf8');
      expect(text, path).not.toContain('\r');
      expect(text.charCodeAt(0), path).not.toBe(0xfeff);
      expect(text.endsWith('\n'), path).toBe(true);
    }
  });
});
