/**
 * search-iam-requirements — Full-text and filtered search across IAM standards.
 */

import { sanitizeFtsInput, buildFtsQueryVariants } from '../utils/fts-query.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface SearchIamRequirementsInput {
  query?: string;
  framework?: string;
  category?: string;
  limit?: number;
}

export interface StandardEntry {
  id: string;
  framework: string;
  section: string | null;
  title: string;
  description: string;
  category: string;
  assurance_level: string | null;
  zero_trust_pillar: string | null;
  maturity_level: string | null;
  cross_references: string[];
}

interface RawStandardRow {
  id: string;
  framework: string;
  section: string | null;
  title: string;
  description: string;
  category: string;
  assurance_level: string | null;
  zero_trust_pillar: string | null;
  maturity_level: string | null;
  cross_references: string;
}

function parseStandard(row: RawStandardRow): StandardEntry {
  return {
    ...row,
    cross_references: JSON.parse(row.cross_references || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: SearchIamRequirementsInput,
): Promise<ToolResponse<StandardEntry[]>> {
  const effectiveLimit = Math.min(Math.max(params.limit ?? 20, 1), 50);

  // --- FTS path (query provided) ---
  if (params.query && params.query.trim().length > 0) {
    const sanitized = sanitizeFtsInput(params.query);
    const variants = buildFtsQueryVariants(sanitized);

    // Build optional WHERE filters for the join
    const filters: string[] = [];
    const filterParams: unknown[] = [];
    if (params.framework) {
      filters.push('s.framework = ?');
      filterParams.push(params.framework);
    }
    if (params.category) {
      filters.push('s.category = ?');
      filterParams.push(params.category);
    }
    const filterClause = filters.length > 0 ? ' AND ' + filters.join(' AND ') : '';

    // Try each FTS variant in order of specificity
    for (const variant of variants) {
      try {
        const sql = `SELECT s.* FROM standards s JOIN standards_fts f ON s.rowid = f.rowid WHERE standards_fts MATCH ?${filterClause} LIMIT ?`;
        const rows = db.prepare(sql).all(variant, ...filterParams, effectiveLimit) as RawStandardRow[];
        if (rows.length > 0) {
          return {
            results: rows.map(parseStandard),
            _metadata: generateResponseMetadata(),
          };
        }
      } catch {
        // FTS variant failed (e.g., syntax issue), try next
        continue;
      }
    }

    // All FTS variants returned nothing — fall through to filter-only
  }

  // --- Filter-only path (no query, or FTS returned nothing) ---
  const conditions: string[] = [];
  const conditionParams: unknown[] = [];

  if (params.framework) {
    conditions.push('framework = ?');
    conditionParams.push(params.framework);
  }
  if (params.category) {
    conditions.push('category = ?');
    conditionParams.push(params.category);
  }

  const whereClause = conditions.length > 0 ? ' WHERE ' + conditions.join(' AND ') : '';
  const sql = `SELECT * FROM standards${whereClause} LIMIT ?`;
  const rows = db.prepare(sql).all(...conditionParams, effectiveLimit) as RawStandardRow[];

  return {
    results: rows.map(parseStandard),
    _metadata: generateResponseMetadata(),
  };
}
