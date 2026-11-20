import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';

const prefix = '$argon2id$v=19$m=19456,t=2,p=1$';

/** Public, non-secret fixture for equal-cost verification when a login is absent.
 * Callers must still reject an absent login even if verification succeeds. */
export const DUMMY_PASSWORD_HASH = `${prefix}msih9O89J2C1yWpxP4TS4A$JCRUytOyCbjyHmWbMGxUol6vMhupK9t3XWS8Od9+e5A`;

/** Matches the bootstrap/recovery password policy; no Unicode normalization. */
export function isValidPassword(password: unknown): password is string {
  if (typeof password !== 'string' || password.length > 1024) { return false; }
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < 16 || bytes > 1024 || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(password)) { return false; }
  return !Array.from(password).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || (code >= 127 && code <= 159);
  });
}

function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2('argon2id', { message: password, nonce: salt, parallelism: 1, tagLength: 32, memory: 19456, passes: 2 },
      (error, result) => { if (error) { reject(error); } else { resolve(result); } });
  });
}

/** Rejects invalid passwords with a generic error; crypto failures propagate. */
export async function hashPassword(password: string): Promise<string> {
  if (!isValidPassword(password)) { throw new Error('Invalid password'); }
  const salt = randomBytes(16);
  const tag = await derive(password, salt);
  return `${prefix}${salt.toString('base64').replace(/=+$/, '')}$${tag.toString('base64').replace(/=+$/, '')}`;
}

/** Accepts only canonical bootstrap/recovery PHC strings and fixed safe costs. */
export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  if (!isValidPassword(password) || typeof encoded !== 'string' || encoded.length !== prefix.length + 22 + 1 + 43 || !encoded.startsWith(prefix)) { return false; }
  const fields = encoded.slice(prefix.length).split('$');
  const saltText = fields[0];
  const tagText = fields[1];
  if (fields.length !== 2 || !saltText || !tagText || !/^[A-Za-z0-9+/]{22}$/.test(saltText) || !/^[A-Za-z0-9+/]{43}$/.test(tagText)) { return false; }
  const salt = Buffer.from(saltText, 'base64');
  const expected = Buffer.from(tagText, 'base64');
  if (salt.length !== 16 || expected.length !== 32 || salt.toString('base64').replace(/=+$/, '') !== saltText || expected.toString('base64').replace(/=+$/, '') !== tagText) { return false; }
  try {
    const actual = await derive(password, salt);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}
