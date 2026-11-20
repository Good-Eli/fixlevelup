import { readdirSync, lstatSync, readFileSync } from 'node:fs';
import { join, basename } from 'node:path';

function check(path) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const target = join(path, entry.name);
    if (lstatSync(target).isSymbolicLink()) { throw new Error('Unexpected source symlink'); }
    if (entry.isDirectory()) {
      if (['.git','node_modules','dist','.next','backups','secrets','private','uploads','local-data'].includes(entry.name)) {
        throw new Error('Local artifact entered Linux source context');
      }
      check(target);
    } else {
      const name = basename(target);
      if ((name === '.env' || name.startsWith('.env.')) && name !== '.env.example') { throw new Error('Local environment entered source context'); }
      if (/\.(dump|backup|pem|key|p12|pfx)$/.test(name)) { throw new Error('Private artifact entered source context'); }
    }
  }
}
check('.');
if (readFileSync('pnpm-workspace.yaml','utf8').includes('ignoreScripts: true') !== true) { throw new Error('Scripts policy missing'); }
console.log('Linux source context excludes local credentials, data and host artifacts: PASS');
