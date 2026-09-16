import sanitizeHtml from 'sanitize-html';

/** Strips all markup/scripts from a string. Safe default for user-supplied text. */
export function sanitize(input: string): string {
  if (typeof input !== 'string') return input;
  return sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} });
}

/** Recursively sanitizes every string value in an object/array (used to clean req.body/query/params). */
export function sanitizeDeep<T>(value: T): T {
  if (typeof value === 'string') {
    return sanitize(value) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeDeep(item)) as unknown as T;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sanitizeDeep(v);
    }
    return out as T;
  }
  return value;
}
