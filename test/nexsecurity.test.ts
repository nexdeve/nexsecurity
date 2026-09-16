import { describe, it, expect } from 'vitest';
import {
  sanitize,
  sanitizeDeep,
  hashPassword,
  verifyPassword,
  generateCSRF,
  verifyCSRF,
  scanSQL,
  validateJWT,
  encryptData,
  decryptData,
  NexSecurity,
} from '../src/index.js';
import jwt from 'jsonwebtoken';

describe('sanitize', () => {
  it('strips script tags', () => {
    expect(sanitize('<script>alert(1)</script>hi')).toBe('hi');
  });

  it('strips all markup by default', () => {
    expect(sanitize('<b>bold</b> text')).toBe('bold text');
  });

  it('sanitizeDeep cleans nested objects', () => {
    const out = sanitizeDeep({ a: '<img src=x onerror=alert(1)>', b: { c: '<script>x</script>ok' } });
    expect(out.a).toBe('');
    expect(out.b.c).toBe('ok');
  });
});

describe('password', () => {
  it('hashes and verifies correctly', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong password', hash)).toBe(false);
  });
});

describe('csrf', () => {
  it('generates a token verifiable with the same secret', () => {
    const secret = 'test-secret';
    const token = generateCSRF(secret);
    expect(verifyCSRF(token, secret)).toBe(true);
  });

  it('rejects a token signed with a different secret', () => {
    const token = generateCSRF('secret-a');
    expect(verifyCSRF(token, 'secret-b')).toBe(false);
  });

  it('rejects malformed tokens', () => {
    expect(verifyCSRF('not-a-real-token', 'secret')).toBe(false);
    expect(verifyCSRF(undefined, 'secret')).toBe(false);
  });
});

describe('scanSQL', () => {
  it('flags common injection patterns', () => {
    expect(scanSQL("' OR 1=1--")).toBe(true);
    expect(scanSQL('UNION SELECT username, password FROM users')).toBe(true);
    expect(scanSQL('; DROP TABLE users;')).toBe(true);
  });

  it('leaves normal input alone', () => {
    expect(scanSQL('hello world')).toBe(false);
    expect(scanSQL('user@example.com')).toBe(false);
  });
});

describe('validateJWT', () => {
  it('returns the payload for a valid token', () => {
    const token = jwt.sign({ uid: 42 }, 'secret', { algorithm: 'HS256' });
    const payload = validateJWT<{ uid: number }>(token, 'secret');
    expect(payload?.uid).toBe(42);
  });

  it('returns null for a token signed with a different secret', () => {
    const token = jwt.sign({ uid: 42 }, 'secret', { algorithm: 'HS256' });
    expect(validateJWT(token, 'wrong-secret')).toBeNull();
  });

  it('rejects the "none" algorithm', () => {
    const token = jwt.sign({ uid: 42 }, '', { algorithm: 'none' });
    expect(validateJWT(token, 'secret')).toBeNull();
  });
});

describe('encryptData / decryptData', () => {
  it('round-trips data', () => {
    const key = 'super-secret-key';
    const encrypted = encryptData('sensitive payload', key);
    expect(decryptData(encrypted, key)).toBe('sensitive payload');
  });

  it('throws when the key is wrong', () => {
    const encrypted = encryptData('sensitive payload', 'key-a');
    expect(() => decryptData(encrypted, 'key-b')).toThrow();
  });
});

describe('NexSecurity class', () => {
  it('exposes all documented methods', async () => {
    const sec = new NexSecurity();
    expect(sec.sanitize('<script>x</script>')).toBe('');
    expect(typeof (await sec.hashPassword('pw'))).toBe('string');
    expect(typeof sec.generateCSRF()).toBe('string');
    expect(sec.scanSQL("' OR 1=1--")).toBe(true);
    expect(sec.encryptData('data', 'key')).not.toBe('data');
    expect(Array.isArray(sec.middleware({ headers: true }))).toBe(true);
  });
});
