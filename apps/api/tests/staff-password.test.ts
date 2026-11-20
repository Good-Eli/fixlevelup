import { argon2, timingSafeEqual } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DUMMY_PASSWORD_HASH, hashPassword, isValidPassword, verifyPassword } from '../src/staff/password.js';

const password = 'Synthetic passphrase 🧪 2026';
const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const prefix = '$argon2id$v=19$m=19456,t=2,p=1$';

async function independentTag(value: string, nonce: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2('argon2id', { message: value, nonce, memory: 19456, passes: 2, parallelism: 1, tagLength: 32 },
      (error, result) => { if (error) { reject(error); } else { resolve(result); } });
  });
}

const b64 = (value: Buffer): string => value.toString('base64').replace(/=+$/, '');

describe('staff password hashing', () => {
  it('accepts independently generated bootstrap/recovery PHC and rejects wrong passwords', async () => {
    const phc = `${prefix}${b64(salt)}$${b64(await independentTag(password, salt))}`;
    expect(await verifyPassword(password, phc)).toBe(true);
    expect(await verifyPassword(`${password}!`, phc)).toBe(false);
  });

  it('emits canonical independently verifiable hashes with unique random salts', async () => {
    const first = await hashPassword(password);
    const second = await hashPassword(password);
    expect(first).not.toBe(second);
    const parts = first.split('$');
    expect(parts.slice(0, 4)).toEqual(['', 'argon2id', 'v=19', 'm=19456,t=2,p=1']);
    expect(parts).toHaveLength(6);
    const nonce = Buffer.from(parts[4] ?? '', 'base64');
    const tag = Buffer.from(parts[5] ?? '', 'base64');
    expect(nonce).toHaveLength(16);
    expect(tag).toHaveLength(32);
    expect(parts[4]).not.toBe(second.split('$')[4]);
    expect(timingSafeEqual(tag, await independentTag(password, nonce))).toBe(true);
    expect(await verifyPassword(password, first)).toBe(true);
  });

  it('provides a valid non-secret dummy with the same supported costs', async () => {
    expect(await verifyPassword('dummy fixture not a credential', DUMMY_PASSWORD_HASH)).toBe(true);
    expect(await verifyPassword(password, DUMMY_PASSWORD_HASH)).toBe(false);
  });

  it.each([
    ['short', 'a'.repeat(15), false], ['minimum', 'a'.repeat(16), true],
    ['maximum', 'a'.repeat(1024), true], ['too long', 'a'.repeat(1025), false],
    ['UTF-8 minimum', 'é'.repeat(8), true], ['UTF-8 maximum', 'é'.repeat(512), true],
    ['UTF-8 overflow', 'é'.repeat(512) + 'x', false], ['lone high', 'a'.repeat(16) + '\ud800', false],
    ['lone low', 'a'.repeat(16) + '\udc00', false], ['control', 'a'.repeat(16) + '\u0085', false],
    ['valid surrogate pair', 'a'.repeat(16) + '🧪', true],
  ])('validates %s', async (_name, value, valid) => {
    expect(isValidPassword(value)).toBe(valid);
    if (!valid) {
      await expect(hashPassword(value)).rejects.toThrow('Invalid password');
      expect(await verifyPassword(value, DUMMY_PASSWORD_HASH)).toBe(false);
    }
  });

  it('rejects malformed, noncanonical, weak, unsupported and excessive PHCs', async () => {
    const invalid = [
      '', DUMMY_PASSWORD_HASH + '$extra', DUMMY_PASSWORD_HASH + '=',
      DUMMY_PASSWORD_HASH.replace('argon2id', 'argon2i'), DUMMY_PASSWORD_HASH.replace('v=19', 'v=16'),
      DUMMY_PASSWORD_HASH.replace('m=19456', 'm=8'), DUMMY_PASSWORD_HASH.replace('t=2', 't=1'),
      DUMMY_PASSWORD_HASH.replace('p=1', 'p=2'), DUMMY_PASSWORD_HASH.replace('m=19456', 'm=999999999999999999999'),
      DUMMY_PASSWORD_HASH.replace('t=2', 't=999999999'), DUMMY_PASSWORD_HASH.replace('p=1', 'p=999999999'),
      DUMMY_PASSWORD_HASH.replace('msih9O89J2C1yWpxP4TS4A', 'msih9O89J2C1yWpxP4TS4B'),
      DUMMY_PASSWORD_HASH.replace('msih9O89J2C1yWpxP4TS4A', 'msih9O89J2C1yWpxP4TS4-'),
      DUMMY_PASSWORD_HASH.replace('JCRUytOyCbjyHmWbMGxUol6vMhupK9t3XWS8Od9+e5A', 'A'.repeat(42)),
      'x'.repeat(1_000_000),
    ];
    for (const phc of invalid) { expect(await verifyPassword(password, phc)).toBe(false); }
  });
});
