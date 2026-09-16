export interface RateLimitConfig {
  windowMs: number;
  max: number;
}

export interface CorsConfig {
  origin: string | string[];
}

export interface NexSecurityMiddlewareConfig {
  rateLimit?: RateLimitConfig;
  cors?: CorsConfig;
  headers?: boolean;
  xss?: boolean;
  csrf?: boolean;
  sqlInjection?: boolean;
}

export interface NexSecurityOptions {
  /** HMAC secret used to sign CSRF tokens. Generated randomly if omitted (not stable across restarts). */
  csrfSecret?: string;
}
