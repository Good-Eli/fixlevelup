import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

import { tmpdir } from 'node:os';

const root = resolve(import.meta.dirname, '../../..');

describe('Prisma Foundation isolation', () => {
  it('compiles and imports the technical ESM client without connecting automatically', () => {
    const source = `
      import {PrismaClient,Prisma} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/generated/prisma/client.js')).href)};
      import {createFoundationClient} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/infrastructure/database/foundation-client.js')).href)};
      const client=createFoundationClient({host:'127.0.0.1',port:55432,database:'fixlevelup_dev',user:'fixlevelup_dev',password:'a'.repeat(64)});
      // Prisma returns a proxy; instanceof is not its public contract.
      if(typeof PrismaClient!=='function'||typeof client.$queryRaw!=='function'||Prisma.prismaVersion.client!=='7.10.1')throw new Error('Client mismatch');
      await client.$disconnect();
      console.log('technical-esm-client-ok');
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
      cwd: root, encoding: 'utf8', timeout: 10000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('technical-esm-client-ok');
    expect(result.stderr).toBe('');
  });

  it('rejects any non-FixLevelUp database target without exposing credentials', () => {
    const source = `
      import {createFoundationClient} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/infrastructure/database/foundation-client.js')).href)};
      try {createFoundationClient({host:'elsewhere.invalid',port:5432,database:'other',user:'other',password:'synthetic-secret-canary'});process.exitCode=1;}
      catch(error){console.log(error.message);}
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
      cwd: root, encoding: 'utf8', timeout: 10000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Invalid foundation database configuration');
    expect(result.stdout + result.stderr).not.toContain('synthetic-secret-canary');
  });

  it('limits selected prereleases to the exact owner-approved graph', () => {
    const exceptions = JSON.parse(readFileSync(resolve(root, 'packages/database-tooling/prerelease-exceptions.json'), 'utf8')) as {
      packages: Record<string, string>;
    };
    const lock = readFileSync(resolve(root, 'pnpm-lock.yaml'), 'utf8');
    const records = [...lock.matchAll(/^ {2}(?:'([^']+)'|([^\s][^:]*)):\s*\n {4}resolution:/gm)]
      .map((match) => match[1] ?? match[2]).filter((key): key is string => !!key);
    let count = 0;
    for (const key of records) {
      const at = key.lastIndexOf('@');
      const name = key.slice(0, at);
      const version = key.slice(at + 1);
      if (/^\d+\.\d+\.\d+-/.test(version)) {
        expect(exceptions.packages[name], key).toBe(version);
        count++;
      }
    }
    expect(count).toBe(10);
    expect(Object.keys(exceptions.packages)).toHaveLength(10);
  });

  it('rejects forbidden optional packages and side-effect compiled imports in synthetic audit fixtures', () => {
    const fixture = mkdtempSync(resolve(tmpdir(), 'fixlevelup-runtime-graph-'));
    mkdirSync(resolve(fixture, 'node_modules/react'), { recursive: true });
    writeFileSync(resolve(fixture, 'package.json'), JSON.stringify({ name: 'fixture', version: '0.0.0', optionalDependencies: { react: '19.3.1' } }));
    writeFileSync(resolve(fixture, 'node_modules/react/package.json'), JSON.stringify({ name: 'react', version: '19.3.1' }));
    writeFileSync(resolve(fixture, 'side-effect.js'), 'import "react";');
    const source = `
      import {inspectRuntimeGraph,inspectCompiledImports} from ${JSON.stringify(pathToFileURL(resolve(root, 'packages/database-tooling/scripts/runtime-graph.mjs')).href)};
      let rejected=0;
      try{inspectRuntimeGraph(${JSON.stringify(resolve(fixture, 'package.json'))});}catch{rejected++;}
      try{inspectCompiledImports(${JSON.stringify(fixture)});}catch{rejected++;}
      if(rejected!==2)process.exitCode=1;
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], { cwd: root, encoding: 'utf8', timeout: 10000 });
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
  });

  it('keeps CLI/Studio/React/Visx outside the complete installed API production graph', () => {
    const result = spawnSync(process.execPath, ['packages/database-tooling/scripts/audit-runtime.mjs'], {
      cwd: root, encoding: 'utf8', timeout: 10000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no CLI/Studio/React/Visx');
    expect(result.stderr).toBe('');
  });
});
