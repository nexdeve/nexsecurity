import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

const COOKIE_NAME = '_csrf';
const HEADER_NAME = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function generateCSRF(secret: string): string {
  const raw = crypto.randomBytes(24).toString('hex');
  const sig = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  return `${raw}.${sig}`;
}

export function verifyCSRF(token: string | undefined, secret: string): boolean {
  if (!token) return false;
  const [raw, sig] = token.split('.');
  if (!raw || !sig) return false;
  const expected = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Double-submit-cookie CSRF middleware: issues a signed token as a readable
 * cookie on every request, and requires state-changing requests to echo it
 * back in the x-csrf-token header (mirrors the pattern the deprecated
 * `csurf` package used to provide).
 */
export function csrfMiddleware(secret: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const existing = (req as unknown as { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME];
    const token = existing && verifyCSRF(existing, secret) ? existing : generateCSRF(secret);
    res.cookie?.(COOKIE_NAME, token, { httpOnly: false, sameSite: 'strict' });
    (res.locals ??= {}).csrfToken = token;

    if (SAFE_METHODS.has(req.method)) return next();

    const submitted = (req.header(HEADER_NAME) || (req.body && req.body._csrf)) as string | undefined;
    if (!submitted || submitted !== token || !verifyCSRF(submitted, secret)) {
      return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    return next();
  };
}
