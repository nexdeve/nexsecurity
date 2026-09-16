import jwt from 'jsonwebtoken';

// Algorithms are pinned explicitly to block alg-confusion / "none" attacks.
const ALLOWED_ALGORITHMS: jwt.Algorithm[] = ['HS256', 'HS384', 'HS512'];

export function validateJWT<T = Record<string, unknown>>(token: string, secret: string): T | null {
  try {
    return jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS }) as T;
  } catch {
    return null;
  }
}
