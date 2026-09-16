import crypto from 'node:crypto';
import type { RequestHandler } from 'express';
import { sanitize } from './sanitize.js';
import { hashPassword, verifyPassword } from './password.js';
import { generateCSRF } from './csrf.js';
import { scanSQL } from './sqlGuard.js';
import { validateJWT } from './jwt.js';
import { encryptData, decryptData } from './encrypt.js';
import { buildMiddleware } from './middleware.js';
import type { NexSecurityMiddlewareConfig, NexSecurityOptions } from './types.js';

export class NexSecurity {
  private readonly csrfSecret: string;

  constructor(options: NexSecurityOptions = {}) {
    this.csrfSecret = options.csrfSecret ?? crypto.randomBytes(32).toString('hex');
  }

  /** Apply all configured protections at once; pass the result to app.use(). */
  middleware(config: NexSecurityMiddlewareConfig): RequestHandler[] {
    return buildMiddleware(config, this.csrfSecret);
  }

  sanitize(input: string): string {
    return sanitize(input);
  }

  async hashPassword(plain: string): Promise<string> {
    return hashPassword(plain);
  }

  async verifyPassword(plain: string, hash: string): Promise<boolean> {
    return verifyPassword(plain, hash);
  }

  generateCSRF(): string {
    return generateCSRF(this.csrfSecret);
  }

  scanSQL(input: string): boolean {
    return scanSQL(input);
  }

  validateJWT<T = Record<string, unknown>>(token: string, secret: string): T | null {
    return validateJWT<T>(token, secret);
  }

  encryptData(data: string, key: string): string {
    return encryptData(data, key);
  }

  decryptData(payload: string, key: string): string {
    return decryptData(payload, key);
  }
}

export * from './types.js';
export { sanitize, sanitizeDeep } from './sanitize.js';
export { hashPassword, verifyPassword } from './password.js';
export { generateCSRF, verifyCSRF } from './csrf.js';
export { scanSQL } from './sqlGuard.js';
export { validateJWT } from './jwt.js';
export { encryptData, decryptData } from './encrypt.js';
