import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { sanitizeDeep } from './sanitize.js';
import { scanSQL } from './sqlGuard.js';
import { csrfMiddleware } from './csrf.js';
import type { NexSecurityMiddlewareConfig } from './types.js';

function xssMiddleware(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (req.body) req.body = sanitizeDeep(req.body);
    if (req.query) req.query = sanitizeDeep(req.query) as typeof req.query;
    if (req.params) req.params = sanitizeDeep(req.params) as typeof req.params;
    next();
  };
}

function sqlInjectionMiddleware(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const haystacks = [req.body, req.query, req.params]
      .filter(Boolean)
      .flatMap((obj) => Object.values(obj as Record<string, unknown>));
    const hit = haystacks.some((v) => typeof v === 'string' && scanSQL(v));
    if (hit) return res.status(400).json({ error: 'Request blocked: possible SQL injection pattern' });
    next();
  };
}

export function buildMiddleware(config: NexSecurityMiddlewareConfig, csrfSecret: string): RequestHandler[] {
  const chain: RequestHandler[] = [];

  if (config.headers) chain.push(helmet());
  if (config.cors) chain.push(cors({ origin: config.cors.origin }));
  if (config.rateLimit) {
    chain.push(rateLimit({ windowMs: config.rateLimit.windowMs, max: config.rateLimit.max }));
  }
  if (config.xss) chain.push(xssMiddleware());
  if (config.sqlInjection) chain.push(sqlInjectionMiddleware());
  if (config.csrf) chain.push(csrfMiddleware(csrfSecret));

  return chain;
}
