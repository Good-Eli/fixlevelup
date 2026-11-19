import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ESLint } from 'eslint';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../..');

function read(relativePath: string): string {
  return readFileSync(resolve(root, relativePath), 'utf8');
}

function parseConfig(relativePath: string): ts.ParsedCommandLine {
  const parsed = ts.getParsedCommandLineOfConfigFile(resolve(root, relativePath), {}, {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic(diagnostic) {
      throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
    },
  });
  if (!parsed) {
    throw new Error(`Cannot load ${relativePath}`);
  }
  return parsed;
}

function diagnosticsFor(source: string): readonly ts.Diagnostic[] {
  const { options } = parseConfig('tsconfig.json');
  const virtualPath = resolve(root, 'packages/tooling/tests/virtual-proof.ts');
  const host = ts.createCompilerHost(options);
  const originalGetSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreateNewSourceFile) => {
    if (resolve(fileName) === virtualPath) {
      return ts.createSourceFile(fileName, source, languageVersion, true);
    }
    return originalGetSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile);
  };
  const program = ts.createProgram([virtualPath], options, host);
  return ts.getPreEmitDiagnostics(program);
}

describe('workspace tooling', () => {
  it('pins the package manager and only tooling dependencies', () => {
    const manifest = JSON.parse(read('package.json')) as {
      private: boolean;
      packageManager: string;
      dependencies?: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    expect(manifest.private).toBe(true);
    expect(manifest.packageManager).toBe('pnpm@12.21.0');
    expect(manifest.dependencies).toBeUndefined();
    expect(manifest.devDependencies).toEqual({
      '@eslint/js': '10.0.1',
      '@fixlevelup/tooling': 'workspace:*',
      '@next/eslint-plugin-next': '16.4.6',
      '@types/node': '24.19.2',
      eslint: '10.15.0',
      globals: '17.14.0',
      typescript: '6.0.3',
      'typescript-eslint': '8.73.0',
      vite: '8.3.8',
      vitest: '5.1.1',
    });
  });

  it('keeps installation scripts and automatic dependency changes disabled', () => {
    const policy = read('pnpm-workspace.yaml');
    for (const setting of [
      'ignoreScripts: true', 'allowBuilds: {}', 'strictDepBuilds: true',
      'strictPeerDependencies: true', 'autoInstallPeers: false',
      'ignorePnpmfile: true', 'verifyDepsBeforeRun: error', 'pmOnFail: error',
      'dangerouslyAllowAllBuilds: false', 'sideEffectsCache: false',
      'enablePrePostScripts: false', 'runtime: false', 'runtimeOnFail: error',
      'strictSsl: true', '  dirs: []',
    ]) {
      expect(policy).toContain(setting);
    }
    expect(policy).not.toContain('permissions:');
    expect(policy).not.toContain('configDependencies:');
    expect(policy).not.toContain('remoteCache:');
  });

  it('loads the shared strict NodeNext configuration', () => {
    const parsed = parseConfig('tsconfig.json');
    expect(parsed.errors).toEqual([]);
    expect(parsed.options).toMatchObject({
      strict: true,
      noUncheckedIndexedAccess: true,
      exactOptionalPropertyTypes: true,
      noImplicitOverride: true,
      noFallthroughCasesInSwitch: true,
      noUnusedLocals: true,
      noUnusedParameters: true,
      noPropertyAccessFromIndexSignature: true,
      skipLibCheck: false,
      noEmit: true,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
    });
  });

  it('accepts valid TypeScript without emitting files', () => {
    const diagnostics = diagnosticsFor('export const value: string = "tooling";\n');
    expect(diagnostics.map((diagnostic) => diagnostic.code)).toEqual([]);
  });

  it('rejects null assignment, unchecked indexing and implicit any', () => {
    const diagnostics = diagnosticsFor([
      'export const required: string = undefined;',
      'export const indexed: string = ([] as string[])[0];',
      'export function identity(value) { return value; }',
    ].join('\n'));
    const codes = diagnostics.map((diagnostic) => diagnostic.code);
    expect(codes).toContain(2322);
    expect(codes).toContain(7006);
    expect(diagnostics.filter((diagnostic) => diagnostic.code === 2322)).toHaveLength(2);
  });

  it('rejects explicitly undefined optional properties', () => {
    const diagnostics = diagnosticsFor('export const item: { label?: string } = { label: undefined };\n');
    expect(diagnostics.map((diagnostic) => diagnostic.code)).toContain(2375);
  });

  it('keeps the browser bundler config separate from Node globals', () => {
    const { options } = parseConfig('packages/tooling/tsconfig/bundler.json');
    expect(options.moduleResolution).toBe(ts.ModuleResolutionKind.Bundler);
    expect(options.module).toBe(ts.ModuleKind.ESNext);
    expect(options.types).toEqual([]);
    expect(options.lib).toContain('lib.dom.d.ts');
  });

  it('loads ESLint and rejects an unknown JS global', async () => {
    const eslint = new ESLint({ cwd: root });
    const results = await eslint.lintText('unknownToolingGlobal();\n', {
      filePath: resolve(root, 'eslint.config.mjs'),
    });
    expect(results.flatMap((result) => result.messages.map((message) => message.ruleId)))
      .toContain('no-undef');
  });

  it('enforces type-aware TypeScript lint rules', async () => {
    const eslint = new ESLint({ cwd: root });
    const results = await eslint.lintText('Promise.resolve(1);\nexport {};\n', {
      filePath: resolve(root, 'packages/tooling/tests/tooling.test.ts'),
    });
    expect(results.flatMap((result) => result.messages.map((message) => message.ruleId)))
      .toContain('@typescript-eslint/no-floating-promises');
  });

  it('uses UTF-8 without BOM and LF in all new tooling files', () => {
    const paths = [
      '.editorconfig', '.gitattributes', '.npmrc', 'package.json', 'pnpm-workspace.yaml',
      'pnpm-lock.yaml', 'tsconfig.json', 'eslint.config.mjs', 'vitest.config.mts',
      'packages/tooling/package.json', 'packages/tooling/tsconfig/base.json',
      'packages/tooling/tsconfig/node.json', 'packages/tooling/tsconfig/bundler.json',
      'packages/tooling/tests/tooling.test.ts', 'packages/tooling/README.md',
    ];
    for (const path of paths) {
      const text = read(path);
      expect(text, path).not.toContain('\r');
      expect(text.charCodeAt(0), path).not.toBe(0xfeff);
      expect(text.endsWith('\n'), path).toBe(true);
    }
    expect(read('.gitattributes')).toContain('* text=auto eol=lf');
    expect(read('.gitattributes')).toContain('*.jpg binary');
  });
});
