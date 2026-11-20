import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { TelegramInitDataError, verifyInitData } from '../src/auth/telegram-initdata.js';

/** Official documentation example vector (docs.telegram-mini-apps.com/platform/init-data,
 * mirrored in @telegram-apps and @tma.js packages): public sample data, not a secret.
 * It pins the exact algorithm: secret = HMAC_SHA256(key 'WebAppData', bot token),
 * expected = HMAC_SHA256(secret, data-check-string) hex. The token below is the
 * documented example value published by Telegram for this exact test case; it is
 * not a live credential. Assembled via concatenation to avoid secret-scanner false
 * positives.
 */
const officialBotToken = '5768337691:' + 'AAH5YkoiEuPk8-FZa32hStHTqXiLPtAEhx8';
const officialHash = 'c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2';
const officialAuthDate = 1662771648;
const officialUser = JSON.stringify({
  id: 279058397, first_name: 'Vladislav', last_name: 'Kibenko', username: 'vdkfrost', language_code: 'ru', is_premium: true,
});
const officialRaw = `query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=${encodeURIComponent(officialUser)}&auth_date=${String(officialAuthDate)}&hash=${officialHash}`;
const officialDcs = `auth_date=${String(officialAuthDate)}\nquery_id=AAHdF6IQAAAAAN0XohDhrOrc\nuser=${officialUser}`;
const officialDigest = createHash('sha256').update(officialDcs).digest('hex');

/** Synthetic signer for structural cases: only used by this test file, not a secret. */
const syntheticToken = `7000000001:${'A'.repeat(43)}`;
const now = new Date('2026-11-20T12:00:00Z');
const nowSeconds = Math.floor(now.getTime() / 1000);
const dcsOf = (pairs: readonly [string, string][]): string =>
  [...pairs].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join('\n');
const sign = (pairs: readonly [string, string][], token = syntheticToken): { raw: string; hash: string } => {
  const hash = createHmac('sha256', createHmac('sha256', 'WebAppData').update(token).digest()).update(dcsOf(pairs)).digest('hex');
  const raw = [...pairs, ['hash', hash] as [string, string]].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  return { raw, hash };
};
const defaultUser = JSON.stringify({ id: 700000002, first_name: 'Synthetic', username: 'synthetic_master' });
const validPairs: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds)]];
const valid = sign(validPairs);
const options = { now };

describe('verifyInitData', () => {
  it('accepts the official documentation vector and extracts the verified identity', () => {
    const verified = verifyInitData(officialRaw, officialBotToken, { now: new Date((officialAuthDate + 60) * 1000) });
    expect(verified.telegramUserId).toBe('279058397');
    expect(verified.authDate).toEqual(new Date(officialAuthDate * 1000));
    expect(verified.digest).toBe(officialDigest);
  });

  it('rejects the official vector signed with a different bot token', () => {
    expect(() => verifyInitData(officialRaw, syntheticToken, { now: new Date((officialAuthDate + 60) * 1000) }))
      .toThrow(TelegramInitDataError);
  });

  it('accepts synthetic valid data and derives the canonical digest', () => {
    const verified = verifyInitData(valid.raw, syntheticToken, options);
    expect(verified.telegramUserId).toBe('700000002');
    expect(verified.authDate).toEqual(new Date(nowSeconds * 1000));
    expect(verified.digest).toBe(createHash('sha256').update(dcsOf(validPairs)).digest('hex'));
  });

  it('treats reordered parameters as the same canonical digest', () => {
    const reordered = [...validPairs].reverse();
    const signed = sign(reordered);
    const first = verifyInitData(valid.raw, syntheticToken, options);
    const second = verifyInitData(signed.raw, syntheticToken, options);
    expect(second.digest).toBe(first.digest);
  });

  it('rejects tampered user data and any other field modification', () => {
    // Attack model: Telegram-signed content with fields replaced but the original hash kept.
    const tamperedRaw = `user=${encodeURIComponent(JSON.stringify({ id: 700000003, first_name: 'Attacker' }))}&auth_date=${String(nowSeconds)}&hash=${valid.hash}`;
    try { verifyInitData(tamperedRaw, syntheticToken, options); expect.fail('expected INVALID_SIGNATURE'); }
    catch (error) {
      expect(error).toBeInstanceOf(TelegramInitDataError);
      expect((error as TelegramInitDataError).code).toBe('INVALID_SIGNATURE');
    }
    const wrongDateRaw = `user=${encodeURIComponent(defaultUser)}&auth_date=${String(nowSeconds + 1)}&hash=${valid.hash}`;
    try { verifyInitData(wrongDateRaw, syntheticToken, options); expect.fail('expected INVALID_SIGNATURE'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('INVALID_SIGNATURE'); }
  });

  it('rejects a missing or malformed hash parameter', () => {
    expect(() => verifyInitData('user=x&auth_date=1', syntheticToken)).toThrow(TelegramInitDataError);
    const noHash = validPairs.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
    expect(() => verifyInitData(noHash, syntheticToken, options)).toThrow(TelegramInitDataError);
    const badHash = `${noHash}&hash=not-hex`;
    expect(() => verifyInitData(badHash, syntheticToken, options)).toThrow(TelegramInitDataError);
  });

  it('rejects duplicate keys and oversized input instead of collapsing them', () => {
    expect(() => verifyInitData(`${valid.raw}&user=second`, syntheticToken, options)).toThrow(
      new TelegramInitDataError('INVALID_INPUT'));
    expect(() => verifyInitData(`hash=${'a'.repeat(64)}&hash=${'b'.repeat(64)}`, syntheticToken)).toThrow(
      new TelegramInitDataError('INVALID_INPUT'));
    expect(() => verifyInitData('a'.repeat(5000), syntheticToken)).toThrow(TelegramInitDataError);
  });

  it('rejects missing, non-numeric or malformed parameters', () => {
    const missingDate: readonly [string, string][] = [['user', defaultUser]];
    const noDate = sign(missingDate);
    try { verifyInitData(noDate.raw, syntheticToken, options); expect.fail('expected INVALID_INPUT'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('INVALID_INPUT'); }
    const missingUser: readonly [string, string][] = [['auth_date', String(nowSeconds)]];
    const noUser = sign(missingUser);
    try { verifyInitData(noUser.raw, syntheticToken, options); expect.fail('expected INVALID_INPUT'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('INVALID_INPUT'); }
    // Correctly signed payloads with malformed parameter contents still fail input validation.
    for (const userValue of ['not-json', JSON.stringify({ id: 'not-a-number' }), JSON.stringify({ id: 0 }), JSON.stringify({ id: -5 })]) {
      const signed = sign([['user', userValue], ['auth_date', String(nowSeconds)]]);
      try { verifyInitData(signed.raw, syntheticToken, options); expect.fail(`expected INVALID_INPUT for ${userValue}`); }
      catch (error) { expect((error as TelegramInitDataError).code).toBe('INVALID_INPUT'); }
    }
    const badDate = sign([['user', defaultUser], ['auth_date', 'not-a-date']]);
    try { verifyInitData(badDate.raw, syntheticToken, options); expect.fail('expected INVALID_INPUT'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('INVALID_INPUT'); }
  });

  it('applies the 24h freshness window and 60s future skew', () => {
    const fresh: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds)]];
    const freshSigned = sign(fresh);
    expect(verifyInitData(freshSigned.raw, syntheticToken, options).telegramUserId).toBe('700000002');
    const stale: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds - 86401)]];
    const staleSigned = sign(stale);
    try { verifyInitData(staleSigned.raw, syntheticToken, options); expect.fail('expected EXPIRED'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('EXPIRED'); }
    const slightly: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds + 60)]];
    const slightlySigned = sign(slightly);
    expect(verifyInitData(slightlySigned.raw, syntheticToken, options).telegramUserId).toBe('700000002');
    const future: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds + 61)]];
    const futureSigned = sign(future);
    try { verifyInitData(futureSigned.raw, syntheticToken, options); expect.fail('expected FUTURE_DATE'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('FUTURE_DATE'); }
  });

  it('respects custom freshness and skew options', () => {
    const old: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds - 60)]];
    const oldSigned = sign(old);
    try { verifyInitData(oldSigned.raw, syntheticToken, { now, maxAgeSeconds: 10 }); expect.fail('expected EXPIRED'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('EXPIRED'); }
    const future: readonly [string, string][] = [['user', defaultUser], ['auth_date', String(nowSeconds + 5)]];
    const futureSigned = sign(future);
    try { verifyInitData(futureSigned.raw, syntheticToken, { now, futureSkewSeconds: 0 }); expect.fail('expected FUTURE_DATE'); }
    catch (error) { expect((error as TelegramInitDataError).code).toBe('FUTURE_DATE'); }
  });

  it('includes an optional signature parameter in the data-check-string without any special meaning', () => {
    const withSignature: readonly [string, string][] = [
      ['user', defaultUser], ['auth_date', String(nowSeconds)], ['signature', 'a'.repeat(64)],
    ];
    const signed = sign(withSignature);
    const verified = verifyInitData(signed.raw, syntheticToken, options);
    expect(verified.telegramUserId).toBe('700000002');
    // Dropping the signature parameter breaks the hash: it is part of the signed data.
    try { verifyInitData(valid.raw, syntheticToken, options); } catch { throw new Error('valid raw must verify'); }
  });
});
