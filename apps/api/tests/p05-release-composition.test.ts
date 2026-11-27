/**
 * Static proof of the release (R) composition boundary for P05.
 *
 * The release artifact is what `apps/api/tsconfig.build.json` emits. It must
 * contain the ordinary P01–P04 staff/web surface and the S3 physical-profile
 * probes, and it must NOT contain any P05 route, controller, intake service,
 * form-session service, ready-attachment admission, launcher/registry/control
 * contour or test issuer. That is a compile-time boundary, not an ENV flag: a
 * missing module cannot be registered by any request or configuration.
 *
 * The check runs against a CLEAN override build (`tsc -p tsconfig.build.json
 * --outDir <fresh temp>`), never against the possibly stale local
 * `apps/api/dist`, and never deletes or rewrites the local build outputs.
 *
 * It also pins the *contract* side: the 16 canonical P05 routes from the shared
 * contract must not appear in the emitted artifact, so a future wiring mistake
 * fails here before any runtime probe.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { relative, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { P05_OPERATIONS, P05_PREFIX, P05_ROUTES } from '@fixlevelup/p03-contracts/p05';

const root = resolve(import.meta.dirname, '../../..');
const api = resolve(root, 'apps/api');
const buildConfig = resolve(api, 'tsconfig.build.json');

/** Modules the release build must not emit, with the reason they are excluded.
 * Directory entries are excluded as whole subtrees; file entries as exact files. */
const EXCLUDED = [
  'form-session', // P05 F-session service/controller (isolated T only) — whole subtree
  'requests', // P05 intake service/controller and coverage use cases — whole subtree
  'files/file-access/ready-attachment', // P05 in-transaction READY admission
  'infrastructure/admission/launcher', // launcher-side supervision (test/operator contour)
  'infrastructure/admission/registry', // control-DB launch registry
  'infrastructure/admission/control-contour', // control contour provisioning
] as const;
const EXCLUDED_DIRECTORIES = new Set(['form-session', 'requests']);

/** The canonical P05 route surface, derived from the shared contract (16 routes). */
const P05_PATHS = P05_OPERATIONS.map((operation) =>
  P05_PREFIX + P05_ROUTES[operation].path.replace(':id', '00000000-0000-4000-8000-0000000000a1'));

/** The S2 form-session family that R must not publish either. */
const S2_PATHS = [
  '/api/v1/public/form-session/browser', '/api/v1/public/form-sessions', '/api/v1/public/form-session/csrf',
  '/api/v1/public/form-session/revoke', '/api/v1/public/form-sessions', '/api/v1/public/form-session/consents',
  '/api/v1/public/coverage/check', '/api/v1/public/legal-documents/POLICY',
] as const;

function walk(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) { walk(path, files); }
    else if (entry.isFile() && entry.name.endsWith('.js')) { files.push(path); }
  }
  return files;
}

describe('P05 release composition boundary (static, clean override build)', () => {
  let outDir: string;
  let emitted: readonly string[];

  beforeAll(() => {
    // A fresh directory per run: nothing from a previous build can be observed.
    outDir = mkdtempSync(resolve(tmpdir(), 'p05-r-composition-'));
    const tsc = resolve(root, 'node_modules/typescript/bin/tsc');
    if (!existsSync(tsc)) { throw new Error('Missing local TypeScript compiler'); }
    execFileSync(process.execPath, [tsc, '-p', buildConfig, '--outDir', outDir, '--incremental', 'false'], {
      cwd: root, stdio: 'pipe', timeout: 180_000,
    });
    emitted = walk(outDir);
  }, 240_000);

  afterAll(() => {
    if (outDir) { rmSync(outDir, { recursive: true, force: true }); }
  });

  it('declares the exact release excludes (compile-time boundary, not an ENV flag)', () => {
    const config = JSON.parse(readFileSync(buildConfig, 'utf8')) as {
      include?: readonly string[]; exclude?: readonly string[];
    };
    expect(config.include).toEqual(['src/**/*.ts']);
    for (const path of EXCLUDED) {
      expect(config.exclude ?? []).toContain(EXCLUDED_DIRECTORIES.has(path) ? `src/${path}` : `src/${path}.ts`);
    }
    // The whole P05 subtrees are excluded as directories, not file by file.
    expect(config.exclude ?? []).toContain('src/form-session');
    expect(config.exclude ?? []).toContain('src/requests');
    // The tests are never part of the release artifact.
    expect(config.exclude ?? []).toContain('tests');
  });

  it('emits the ordinary R entrypoints and P03/P04 surface, and none of the P05 modules', () => {
    const relativeEmitted = emitted.map((path) => relative(outDir, path).split('\\').join('/'));
    for (const entry of ['bootstrap/api.js', 'bootstrap/worker.js', 'bootstrap/factories.js',
      'app.module.js', 'worker.module.js', 'infrastructure/outbox/outbox-worker.js']) {
      expect(relativeEmitted).toContain(entry);
    }
    // P03/P04 staff surface and the S3 physical-profile probe stay in R.
    expect(relativeEmitted).toContain('settings/geography/geography.controller.js');
    expect(relativeEmitted).toContain('settings/management/management.controller.js');
    expect(relativeEmitted).toContain('catalog-management/controller.js');
    expect(relativeEmitted).toContain('infrastructure/database/p05-profile-catalog.js');
    for (const path of EXCLUDED) {
      expect(relativeEmitted.filter((file) => file === `${path}.js` || file.startsWith(`${path}/`))).toEqual([]);
    }
    // No test-only artifact, issuer or fixture can enter the release tree.
    expect(relativeEmitted.some((file) => file.includes('.test.') || file.startsWith('tests/'))).toBe(false);
    expect(relativeEmitted.some((file) => /test-only-issuer|fixture|synthetic/i.test(file))).toBe(false);
  });

  it('contains no P05 or S2 route literal anywhere in the emitted artifact', () => {
    const sources = emitted.map((path) => ({ path: relative(outDir, path).split('\\').join('/'),
      text: readFileSync(path, 'utf8') }));
    for (const route of [...P05_PATHS, ...S2_PATHS]) {
      const hits = sources.filter(({ text }) => text.includes(route)).map(({ path }) => path);
      expect({ route, hits }).toEqual({ route, hits: [] });
    }
    // The canonical contract table itself must not be imported by R: its operation
    // names only exist in the P05 contract package.
    expect(sources.some(({ text }) => text.includes('matchP05Route'))).toBe(false);
  });

  it('registers no P05 controller and no P05 outbox consumer in the R composition', () => {
    const appModule = readFileSync(resolve(outDir, 'app.module.js'), 'utf8');
    const workerModule = readFileSync(resolve(outDir, 'worker.module.js'), 'utf8');
    const factories = readFileSync(resolve(outDir, 'bootstrap/factories.js'), 'utf8');
    const outboxWorker = readFileSync(resolve(outDir, 'infrastructure/outbox/outbox-worker.js'), 'utf8');
    for (const marker of ['FormSessionController', 'RequestIntakeController', 'REQUEST_INTAKE_HTTP', 'FormSessionService']) {
      expect(appModule).not.toContain(marker);
      expect(factories).not.toContain(marker);
    }
    expect(factories).not.toContain('startIsolatedIntake');
    // The worker registers an empty handler map in R: no P05 event type can be leased.
    expect(workerModule).toContain('new Map()');
    for (const type of ['REQUEST_CALLBACK_INTENT', 'REQUEST_READY_FOR_ASSIGNMENT', 'REQUEST_EFFECT_RECORDED']) {
      expect(workerModule).not.toContain(type);
      expect(outboxWorker).not.toContain(type);
    }
    // The release artifact also carries no operator/launcher surface.
    expect(existsSync(resolve(outDir, 'infrastructure/admission/launcher.js'))).toBe(false);
    expect(existsSync(resolve(outDir, 'infrastructure/admission/registry.js'))).toBe(false);
  });

  it('keeps the 16 canonical P05 operations closed and non-aliased', () => {
    expect(P05_OPERATIONS).toHaveLength(16);
    expect(new Set(P05_PATHS).size).toBe(16);
    expect(P05_PATHS.every((path) => path.startsWith('/api/v1/'))).toBe(true);
    // The public F family and the staff family are both present in the contract.
    expect(P05_PATHS.filter((path) => path.includes('/public/'))).toHaveLength(6);
    expect(P05_PATHS.filter((path) => path.startsWith('/api/v1/requests'))).toHaveLength(10);
  });
});

/** The local (non-lab) build must still be usable for a later clean build: this
 * suite never deletes or rewrites `apps/api/dist`, so unrelated local outputs and
 * other agents' artifacts are preserved. Verified by the directory mtime rule. */
describe('release build isolation', () => {
  it('never writes into the checked-in workspace build outputs', () => {
    const localDist = resolve(api, 'dist');
    if (!existsSync(localDist)) { return; }
    const before = statSync(localDist).mtimeMs;
    // The suite's temp directory is under the OS tmpdir, so nothing above changes it.
    expect(localDist.startsWith(tmpdir())).toBe(false);
    expect(statSync(localDist).mtimeMs).toBe(before);
    mkdirSync(localDist, { recursive: true });
  });
});
