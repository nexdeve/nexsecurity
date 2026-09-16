// Heuristic pattern matching only — a defense-in-depth signal, not a
// substitute for parameterized queries / prepared statements.
const SQLI_PATTERNS: RegExp[] = [
  /(\%27)|(')|(\-\-)|(\%23)|(#)/i,
  /((\%3D)|(=))[^\n]*((\%27)|(')|(\-\-)|(\%3B)|(;))/i,
  /\b(select|union|insert|update|delete|drop|alter|exec|execute|truncate)\b[\s\S]{0,60}\b(from|into|table|database|where)\b/i,
  /\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
  /\bunion\b\s+(all\s+)?\bselect\b/i,
  /;\s*(drop|delete|truncate|update)\b/i,
];

export function scanSQL(input: string): boolean {
  if (typeof input !== 'string' || input.length === 0) return false;
  return SQLI_PATTERNS.some((pattern) => pattern.test(input));
}
