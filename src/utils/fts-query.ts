/**
 * FTS5 query helpers for IAM MCP.
 * Handles query sanitization and variant generation for SQLite FTS5.
 */

/**
 * Sanitize user input for safe FTS5 queries.
 * Removes characters that have special meaning in FTS5 syntax.
 */
export function sanitizeFtsInput(input: string): string {
  return input
    .replace(/['"(){}[\]^~*:\-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Build FTS5 query variants for a search term.
 * Returns variants in order of specificity (most specific first):
 * 1. Exact phrase match (multi-word)
 * 2. All terms required (AND)
 * 3. Prefix match on last term
 */
export function buildFtsQueryVariants(sanitized: string): string[] {
  if (!sanitized || sanitized.trim().length === 0) {
    return [];
  }

  const terms = sanitized.split(/\s+/).filter(t => t.length > 0);
  if (terms.length === 0) return [];

  const variants: string[] = [];

  if (terms.length > 1) {
    // Exact phrase
    variants.push(`"${terms.join(' ')}"`);
    // AND query
    variants.push(terms.join(' AND '));
    // Prefix match on last term
    variants.push([...terms.slice(0, -1), `${terms[terms.length - 1]}*`].join(' AND '));
  } else {
    // Single term
    variants.push(terms[0]);
    if (terms[0].length >= 3) {
      variants.push(`${terms[0]}*`);
    }
  }

  return variants;
}
