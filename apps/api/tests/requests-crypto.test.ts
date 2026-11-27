/**
 * Pure unit proofs for the P05-01 crypto module (docs/P05-PLAN.md §3): no
 * database, no network — only the cryptographic contract of the keyring and
 * the AEAD payload cipher.
 *
 * Proved here on every `vitest run`:
 *  - seal/open roundtrip for every payload kind;
 *  - tampering with ciphertext, authTag, AAD context or kind never yields a
 *    successful open (error code is TAMPERED or DOMAIN_MISMATCH);
 *  - swapping wrappedDek between two sealed payloads fails authentication;
 *  - key rotation: historical rows still open by saved keyId, a removed key
 *    refuses with UNKNOWN_KEY, new seals use the new active key;
 *  - wrap-domain material presented as payload (and vice versa) is rejected —
 *    the two domains never share an AAD string;
 *  - idempotency HMAC is stable per input, differs across namespace/intent,
 *    verifies constant-time by saved keyId and refuses wrong keys;
 *  - keyring loading fails closed on bad hex, duplicate ids, missing active
 *    ids and secret material reused across purposes or key entries;
 *  - oversized plaintext is refused before sealing so ciphertext + GCM tag
 *    fits the persisted 60000-byte bound (59984 ok, 59985 refused);
 *  - revision must be >= 1 and environment <= 24 chars (no AAD truncation);
 *  - the documented per-key rotation bound MAX_SEALED_PAYLOADS_PER_KEY.
 */
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { KeyringError, activeKey, keyById, loadKeyring } from '../src/requests/crypto/keyring.js';
import type { KeyringConfig } from '../src/requests/crypto/keyring.js';
import {
  MAX_SEALED_PAYLOADS_PER_KEY, PayloadCipherError, idempotencyHmac, openPayload, sealPayload,
  unwrapDekForProof, verifyIdempotencyHmac,
} from '../src/requests/crypto/payload-cipher.js';
import type { PayloadCipherErrorCode, PayloadKind, SealedPayload } from '../src/requests/crypto/payload-cipher.js';

const REQUEST_ID = '018f0000-0000-7000-8000-000000000001';

const secret = (): string => randomBytes(32).toString('hex');

function ring(): KeyringConfig {
  return loadKeyring({
    kek: [{ keyId: 'kek-a.v1', secretHex: secret() }],
    hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
    activeKekId: 'kek-a.v1',
    activeHmacKeyId: 'hmac-a.v1',
  });
}

/** Same keys as `base` plus new active keys: the rotation preserves history. */
function rotatedRing(base: KeyringConfig): KeyringConfig {
  const kekHex = base.keys.find((k) => k.purpose === 'PAYLOAD_KEK')?.material.toString('hex');
  const hmacHex = base.keys.find((k) => k.purpose === 'IDEMPOTENCY_HMAC')?.material.toString('hex');
  if (kekHex === undefined || hmacHex === undefined) { throw new Error('fixture key not found'); }
  return loadKeyring({
    kek: [
      { keyId: 'kek-a.v1', secretHex: kekHex },
      { keyId: 'kek-b.v1', secretHex: secret() },
    ],
    hmac: [
      { keyId: 'hmac-a.v1', secretHex: hmacHex },
      { keyId: 'hmac-b.v1', secretHex: secret() },
    ],
    activeKekId: 'kek-b.v1',
    activeHmacKeyId: 'hmac-b.v1',
  });
}

function sealInput(ringValue: KeyringConfig, plaintext: Buffer, kind: PayloadKind = 'CONTACT', requestId = '018f0000-0000-7000-8000-000000000001') {
  return {
    ring: ringValue,
    environment: 'test',
    schema: 'public',
    kind,
    requestId,
    revision: 1,
    plaintext,
  };
}

function cipherCode(run: () => unknown): PayloadCipherErrorCode {
  try {
    run();
  } catch (error) {
    if (error instanceof PayloadCipherError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a PayloadCipherError');
}

function keyringCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof KeyringError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a KeyringError');
}

const PLAIN = Buffer.from('Synthetic payload fixture 🧪 — not real personal data', 'utf8');

describe('keyring loading and lookup', () => {
  it('loads a valid keyring and resolves active keys per purpose', () => {
    const loaded = ring();
    expect(activeKey(loaded, 'PAYLOAD_KEK').keyId).toBe('kek-a.v1');
    expect(activeKey(loaded, 'IDEMPOTENCY_HMAC').keyId).toBe('hmac-a.v1');
    expect(activeKey(loaded, 'PAYLOAD_KEK').material).toHaveLength(32);
  });

  it.each([
    ['non-hex secret', () => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: 'zz' + secret().slice(2) }], hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-a.v1', activeHmacKeyId: 'hmac-a.v1',
    }), 'INVALID_KEY_MATERIAL'],
    ['uppercase hex', () => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: secret().toUpperCase() }], hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-a.v1', activeHmacKeyId: 'hmac-a.v1',
    }), 'INVALID_KEY_MATERIAL'],
    ['short secret', () => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: 'abcd' }], hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-a.v1', activeHmacKeyId: 'hmac-a.v1',
    }), 'INVALID_KEY_MATERIAL'],
    ['bad keyId format', () => loadKeyring({
      kek: [{ keyId: '-bad', secretHex: secret() }], hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: '-bad', activeHmacKeyId: 'hmac-a.v1',
    }), 'INVALID_KEY_MATERIAL'],
    ['duplicate keyIds in one purpose', () => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: secret() }, { keyId: 'kek-a.v1', secretHex: secret() }],
      hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-a.v1', activeHmacKeyId: 'hmac-a.v1',
    }), 'INVALID_KEY_MATERIAL'],
    ['missing active KEK', () => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: secret() }], hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-other', activeHmacKeyId: 'hmac-a.v1',
    }), 'MISSING_KEY'],
    ['missing active HMAC', () => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: secret() }], hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-a.v1', activeHmacKeyId: 'hmac-other',
    }), 'MISSING_KEY'],
  ])('rejects %s', (_name, run, code) => {
    expect(keyringCode(run)).toBe(code);
  });

  it('allows the same keyId across purposes but resolves them separately', () => {
    const loaded = loadKeyring({
      kek: [{ keyId: 'shared.v1', secretHex: secret() }],
      hmac: [{ keyId: 'shared.v1', secretHex: secret() }],
      activeKekId: 'shared.v1',
      activeHmacKeyId: 'shared.v1',
    });
    expect(keyById(loaded, 'PAYLOAD_KEK', 'shared.v1').purpose).toBe('PAYLOAD_KEK');
    expect(keyById(loaded, 'IDEMPOTENCY_HMAC', 'shared.v1').purpose).toBe('IDEMPOTENCY_HMAC');
  });

  it('rejects the same secret material reused across purposes (KEK = HMAC)', () => {
    const hex = secret();
    expect(keyringCode(() => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: hex }],
      hmac: [{ keyId: 'hmac-a.v1', secretHex: hex }],
      activeKekId: 'kek-a.v1', activeHmacKeyId: 'hmac-a.v1',
    }))).toBe('INVALID_KEY_MATERIAL');
  });

  it('rejects the same secret material reused inside one purpose under different keyIds', () => {
    const hex = secret();
    expect(keyringCode(() => loadKeyring({
      kek: [{ keyId: 'kek-a.v1', secretHex: hex }, { keyId: 'kek-b.v1', secretHex: hex }],
      hmac: [{ keyId: 'hmac-a.v1', secretHex: secret() }],
      activeKekId: 'kek-b.v1', activeHmacKeyId: 'hmac-a.v1',
    }))).toBe('INVALID_KEY_MATERIAL');
  });

  it('unknown keyId refuses with UNKNOWN_KEY, never falls back to active', () => {
    expect(keyringCode(() => keyById(ring(), 'PAYLOAD_KEK', 'kek-retired'))).toBe('UNKNOWN_KEY');
  });
});

describe('seal/open roundtrip', () => {
  it.each(['CONTACT', 'ADDRESS', 'DETAILS'] as const)('roundtrips a %s payload', (kind) => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN, kind));
    const opened = openPayload({ ...sealInput(loaded, PLAIN, kind), sealed });
    expect(opened.equals(PLAIN)).toBe(true);
    expect(sealed.keyId).toBe('kek-a.v1');
    expect(sealed.nonce).toHaveLength(12);
    expect(sealed.authTag).toHaveLength(16);
    expect(sealed.aadContext.startsWith('p05/payload/v1/')).toBe(true);
  });

  it('produces a fresh DEK/nonce per seal and bounded AAD context', () => {
    const loaded = ring();
    const first = sealPayload(sealInput(loaded, PLAIN));
    const second = sealPayload(sealInput(loaded, PLAIN));
    expect(first.nonce.equals(second.nonce)).toBe(false);
    expect(first.wrappedDek.equals(second.wrappedDek)).toBe(false);
    expect(first.aadContext.length).toBeGreaterThanOrEqual(8);
    expect(first.aadContext.length).toBeLessThanOrEqual(128);
  });

  it('rejects plaintext above the 59984-byte seal cap so ciphertext+tag stays within 60000', () => {
    expect(cipherCode(() => sealPayload(sealInput(ring(), Buffer.alloc(59985, 1))))).toBe('MALFORMED');
    expect(cipherCode(() => sealPayload(sealInput(ring(), Buffer.alloc(60000, 1))))).toBe('MALFORMED');
    const boundary = sealPayload(sealInput(ring(), Buffer.alloc(59984, 1)));
    expect(boundary.ciphertext).toHaveLength(59984);
    expect(boundary.ciphertext.length + boundary.authTag.length).toBe(60000);
  });

  it('rejects plaintext below the 16-byte SQL minimum so every persisted ciphertext column is valid', () => {
    expect(cipherCode(() => sealPayload(sealInput(ring(), Buffer.alloc(15, 1))))).toBe('MALFORMED');
    expect(cipherCode(() => sealPayload(sealInput(ring(), Buffer.alloc(1, 1))))).toBe('MALFORMED');
    const boundary = sealPayload(sealInput(ring(), Buffer.alloc(16, 1)));
    expect(boundary.ciphertext).toHaveLength(16);
    const reloaded = ring();
    const sealed = sealPayload(sealInput(reloaded, Buffer.alloc(16, 2)));
    expect(openPayload({ ...sealInput(reloaded, Buffer.alloc(16, 2)), sealed })).toHaveLength(16);
  });

  it('binds the wrap AAD to kind and revision: a same-request cross-cell DEK swap fails authentication', () => {
    const loaded = ring();
    const contact = sealPayload(sealInput(loaded, PLAIN));
    const address = sealPayload({ ...sealInput(loaded, PLAIN), kind: 'ADDRESS' });
    // Same request, different kind: the contact cell's entire sealed value
    // replayed as the address cell (wrap DEK included) must fail GCM.
    expect(['TAMPERED', 'DOMAIN_MISMATCH'])
      .toContain(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), kind: 'ADDRESS', sealed: contact })));
    // Same request+kind, different revision: the revision-1 value replayed as
    // revision 2 must also fail.
    expect(['TAMPERED', 'DOMAIN_MISMATCH'])
      .toContain(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), revision: 2, sealed: contact })));
    expect(openPayload({ ...sealInput(loaded, PLAIN), kind: 'ADDRESS', sealed: address }).equals(PLAIN)).toBe(true);
  });

  it('rejects revision 0 on seal and open (revisions start at 1)', () => {
    expect(cipherCode(() => sealPayload({ ...sealInput(ring(), PLAIN), revision: 0 }))).toBe('MALFORMED');
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), revision: 0, sealed }))).toBe('MALFORMED');
  });

  it('rejects environments longer than 24 chars on seal and open instead of truncating', () => {
    const long = 'a'.repeat(25);
    expect(cipherCode(() => sealPayload({ ...sealInput(ring(), PLAIN), environment: long }))).toBe('MALFORMED');
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), environment: long, sealed }))).toBe('MALFORMED');
    // Distinct 25-char environments that share the first 24 chars are both
    // refused — the truncation aliasing mask is gone.
    const aliased = sealPayload({ ...sealInput(loaded, PLAIN), environment: 'b'.repeat(24) });
    expect(openPayload({ ...sealInput(loaded, PLAIN), environment: 'b'.repeat(24), sealed: aliased }).equals(PLAIN))
      .toBe(true);
  });

  it('documents the per-key seal rotation bound MAX_SEALED_PAYLOADS_PER_KEY', () => {
    expect(MAX_SEALED_PAYLOADS_PER_KEY).toBe(1048576);
    expect(MAX_SEALED_PAYLOADS_PER_KEY).toBe(2 ** 20);
  });
});

describe('tamper and domain confusion', () => {
  it('tampered ciphertext byte -> TAMPERED', () => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    const tampered: SealedPayload = { ...sealed, ciphertext: flip(sealed.ciphertext) };
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), sealed: tampered }))).toBe('TAMPERED');
  });

  it('tampered authTag -> TAMPERED', () => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    const tampered: SealedPayload = { ...sealed, authTag: flip(sealed.authTag) };
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), sealed: tampered }))).toBe('TAMPERED');
  });

  it('changed environment (AAD) -> TAMPERED or DOMAIN_MISMATCH, never a successful open', () => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    const code = cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), environment: 'prod', sealed }));
    expect(['TAMPERED', 'DOMAIN_MISMATCH']).toContain(code);
  });

  it('wrong kind -> DOMAIN_MISMATCH/TAMPERED', () => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN, 'CONTACT'));
    const code = cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN, 'ADDRESS'), sealed }));
    expect(['TAMPERED', 'DOMAIN_MISMATCH']).toContain(code);
  });

  it('swapped wrappedDek between two payloads fails', () => {
    const loaded = ring();
    const first = sealPayload(sealInput(loaded, PLAIN, 'CONTACT', '018f0000-0000-7000-8000-000000000001'));
    const second = sealPayload(sealInput(loaded, PLAIN, 'CONTACT', '018f0000-0000-7000-8000-000000000002'));
    const swapped: SealedPayload = { ...first, wrappedDek: second.wrappedDek };
    const code = cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN, 'CONTACT', '018f0000-0000-7000-8000-000000000001'), sealed: swapped }));
    expect(['TAMPERED', 'DOMAIN_MISMATCH']).toContain(code);
  });

  it('wrapped DEK presented as payload-domain input is rejected, and payload ciphertext as wrap material too', () => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    // Wrap-domain blob (nonce||ciphertext||tag of the DEK) replayed as the payload fields:
    const confused: SealedPayload = {
      keyId: sealed.keyId,
      wrappedDek: sealed.wrappedDek,
      nonce: sealed.wrappedDek.subarray(0, 12),
      ciphertext: sealed.wrappedDek.subarray(12, 44),
      authTag: sealed.wrappedDek.subarray(44),
      aadContext: 'p05/payload/v1/test/public/CONTACT/018f0000-0000-7000-8000-000000000001/1',
    };
    expect(['TAMPERED', 'DOMAIN_MISMATCH']).toContain(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), sealed: confused })));
    // Payload-domain ciphertext replayed inside the wrappedDek slot (geometry
    // stays valid so the failure is authentication, not shape):
    const reverse: SealedPayload = {
      ...sealed,
      wrappedDek: Buffer.concat([randomBytes(12), sealed.ciphertext.subarray(0, 32), sealed.authTag]),
    };
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), sealed: reverse }))).toBe('TAMPERED');
  });

  it('isolated wrap-AAD binding: swapping ONLY the wrapped DEK between same-request cells fails at unwrap', () => {
    const loaded = ring();
    const contact = sealPayload(sealInput(loaded, PLAIN));
    const address = sealPayload({ ...sealInput(loaded, PLAIN), kind: 'ADDRESS' });
    // The address cell's envelope with the CONTACT cell's wrapped DEK: the
    // public aadContext is still the valid ADDRESS one, so the failure comes
    // from the WRAP-domain authentication (wrap AAD carries kind).
    const swapped: SealedPayload = { ...address, wrappedDek: contact.wrappedDek };
    expect(swapped.aadContext).toBe(address.aadContext);
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), kind: 'ADDRESS', sealed: swapped }))).toBe('TAMPERED');
    // Same isolated check for revision: revision-2 envelope with revision-1 DEK.
    const rev2 = sealPayload({ ...sealInput(loaded, PLAIN), revision: 2 });
    const swappedRev: SealedPayload = { ...rev2, wrappedDek: contact.wrappedDek };
    expect(cipherCode(() => openPayload({ ...sealInput(loaded, PLAIN), revision: 2, sealed: swappedRev }))).toBe('TAMPERED');
    // Controls: the untouched cells still open.
    expect(openPayload({ ...sealInput(loaded, PLAIN), kind: 'ADDRESS', sealed: address }).equals(PLAIN)).toBe(true);
    expect(openPayload({ ...sealInput(loaded, PLAIN), revision: 2, sealed: rev2 }).equals(PLAIN)).toBe(true);
  });

  it('wrap-domain diagnostic: unwrapDekForProof fails DIRECTLY with wrong kind or revision (wrap AAD carries them)', () => {
    const loaded = ring();
    const sealed = sealPayload(sealInput(loaded, PLAIN));
    // Correct kind/revision: the wrap decrypts.
    const dek = unwrapDekForProof(loaded, sealed.keyId, sealed.wrappedDek, 'test', 'public', 'CONTACT', REQUEST_ID, 1);
    expect(dek).toHaveLength(32);
    // Wrong KIND at the wrap level alone (everything else correct): the wrap
    // AEAD fails — proving the wrap AAD carries kind, independent of the
    // later payload-domain check.
    expect(cipherCode(() => unwrapDekForProof(loaded, sealed.keyId, sealed.wrappedDek, 'test', 'public', 'ADDRESS', REQUEST_ID, 1))).toBe('TAMPERED');
    // Wrong REVISION at the wrap level alone: fails.
    expect(cipherCode(() => unwrapDekForProof(loaded, sealed.keyId, sealed.wrappedDek, 'test', 'public', 'CONTACT', REQUEST_ID, 2))).toBe('TAMPERED');
    // Wrong REQUEST at the wrap level alone: fails (the wrap is cell-bound).
    expect(cipherCode(() => unwrapDekForProof(loaded, sealed.keyId, sealed.wrappedDek, 'test', 'public', 'CONTACT', '018f0000-0000-7000-8000-000000000099', 1))).toBe('TAMPERED');
  });
});

describe('key rotation', () => {
  it('opens historical rows by saved keyId after rotating the active key', () => {
    const before = ring();
    const sealed = sealPayload(sealInput(before, PLAIN));
    const after = rotatedRing(before);
    expect(sealed.keyId).toBe('kek-a.v1');
    expect(openPayload({ ...sealInput(after, PLAIN), sealed }).equals(PLAIN)).toBe(true);
    expect(sealPayload(sealInput(after, PLAIN)).keyId).toBe('kek-b.v1');
  });

  it('missing historical key refuses with UNKNOWN_KEY', () => {
    const sealed = sealPayload(sealInput(ring(), PLAIN));
    const after = loadKeyring({
      kek: [{ keyId: 'kek-b.v1', secretHex: secret() }],
      hmac: [{ keyId: 'hmac-b.v1', secretHex: secret() }],
      activeKekId: 'kek-b.v1',
      activeHmacKeyId: 'hmac-b.v1',
    });
    expect(cipherCode(() => openPayload({ ...sealInput(after, PLAIN), sealed }))).toBe('UNKNOWN_KEY');
  });
});

describe('idempotency HMAC', () => {
  it('is stable for the same input and differs across namespace/intent', () => {
    const loaded = ring();
    const first = idempotencyHmac({ ring: loaded, namespace: 'submit', canonicalIntent: '{"city":1}' });
    const second = idempotencyHmac({ ring: loaded, namespace: 'submit', canonicalIntent: '{"city":1}' });
    expect(first.digest.equals(second.digest)).toBe(true);
    expect(first.keyId).toBe('hmac-a.v1');
    expect(idempotencyHmac({ ring: loaded, namespace: 'repair', canonicalIntent: '{"city":1}' }).digest.equals(first.digest)).toBe(false);
    expect(idempotencyHmac({ ring: loaded, namespace: 'submit', canonicalIntent: '{"city":2}' }).digest.equals(first.digest)).toBe(false);
  });

  it('verifies with the saved keyId, including after rotation', () => {
    const before = ring();
    const { keyId, digest } = idempotencyHmac({ ring: before, namespace: 'submit', canonicalIntent: 'x' });
    const after = rotatedRing(before);
    expect(verifyIdempotencyHmac({ ring: after, keyId, namespace: 'submit', canonicalIntent: 'x', digest })).toBe(true);
    expect(verifyIdempotencyHmac({ ring: after, keyId, namespace: 'submit', canonicalIntent: 'y', digest })).toBe(false);
    // New digests use the rotated active key.
    expect(idempotencyHmac({ ring: after, namespace: 'submit', canonicalIntent: 'x' }).keyId).toBe('hmac-b.v1');
  });

  it('tampered digest fails constant-time comparison and wrong keyId refuses', () => {
    const loaded = ring();
    const { keyId, digest } = idempotencyHmac({ ring: loaded, namespace: 'submit', canonicalIntent: 'x' });
    expect(verifyIdempotencyHmac({ ring: loaded, keyId, namespace: 'submit', canonicalIntent: 'x', digest: flip(digest) })).toBe(false);
    expect(keyringCode(() => verifyIdempotencyHmac({
      ring: loaded, keyId: 'hmac-z.v1', namespace: 'submit', canonicalIntent: 'x', digest,
    }))).toBe('UNKNOWN_KEY');
  });
});

function flip(buffer: Buffer): Buffer {
  const copy = Buffer.from(buffer);
  copy.writeUInt8(copy.readUInt8(0) ^ 0xff, 0);
  return copy;
}
