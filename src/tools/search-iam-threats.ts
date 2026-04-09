/**
 * search-iam-threats — Full-text and filtered search across IAM attack patterns.
 *
 * Supports FTS5 search on attack_patterns_fts + optional tactic/stride/severity filters.
 */

import { sanitizeFtsInput, buildFtsQueryVariants } from '../utils/fts-query.js';
import { generateResponseMetadata, type ToolResponse, type CitationEntry } from '../utils/metadata.js';

export interface SearchIamThreatsInput {
  query?: string;
  tactic?: string;
  stride?: string;
  severity?: string;
  limit?: number;
}

export interface AttackPatternEntry {
  id: string;
  name: string;
  tactic: string;
  description: string;
  sub_techniques: string[];
  detection_guidance: string | null;
  mitigation_controls: string[];
  stride_category: string;
  severity: string;
  real_world_examples: string | null;
  _citation: CitationEntry;
}

interface RawAttackPatternRow {
  id: string;
  name: string;
  tactic: string;
  description: string;
  sub_techniques: string;
  detection_guidance: string | null;
  mitigation_controls: string;
  stride_category: string;
  severity: string;
  real_world_examples: string | null;
}

function parseAttackPattern(row: RawAttackPatternRow): AttackPatternEntry {
  return {
    ...row,
    sub_techniques: JSON.parse(row.sub_techniques || '[]'),
    mitigation_controls: JSON.parse(row.mitigation_controls || '[]'),
    _citation: {
      canonical_ref: row.id,
      display_text: `MITRE ATT&CK ${row.id}`,
      lookup: 'get_iam_attack',
    },
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: SearchIamThreatsInput,
): Promise<ToolResponse<AttackPatternEntry[]>> {
  const effectiveLimit = Math.min(Math.max(params.limit ?? 20, 1), 50);

  // --- FTS path (query provided) ---
  if (params.query && params.query.trim().length > 0) {
    const sanitized = sanitizeFtsInput(params.query);
    const variants = buildFtsQueryVariants(sanitized);

    // Build optional WHERE filters for the join
    const filters: string[] = [];
    const filterParams: unknown[] = [];
    if (params.tactic) {
      filters.push('a.tactic = ?');
      filterParams.push(params.tactic);
    }
    if (params.stride) {
      filters.push('a.stride_category = ?');
      filterParams.push(params.stride);
    }
    if (params.severity) {
      filters.push('a.severity = ?');
      filterParams.push(params.severity);
    }
    const filterClause = filters.length > 0 ? ' AND ' + filters.join(' AND ') : '';

    // Try each FTS variant in order of specificity
    for (const variant of variants) {
      try {
        const sql = `SELECT a.* FROM attack_patterns a JOIN attack_patterns_fts f ON a.rowid = f.rowid WHERE attack_patterns_fts MATCH ?${filterClause} LIMIT ?`;
        const rows = db.prepare(sql).all(variant, ...filterParams, effectiveLimit) as RawAttackPatternRow[];
        if (rows.length > 0) {
          return {
            results: rows.map(parseAttackPattern),
            _meta: generateResponseMetadata(),
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

  if (params.tactic) {
    conditions.push('tactic = ?');
    conditionParams.push(params.tactic);
  }
  if (params.stride) {
    conditions.push('stride_category = ?');
    conditionParams.push(params.stride);
  }
  if (params.severity) {
    conditions.push('severity = ?');
    conditionParams.push(params.severity);
  }

  const whereClause = conditions.length > 0 ? ' WHERE ' + conditions.join(' AND ') : '';
  const sql = `SELECT * FROM attack_patterns${whereClause} LIMIT ?`;
  const rows = db.prepare(sql).all(...conditionParams, effectiveLimit) as RawAttackPatternRow[];

  return {
    results: rows.map(parseAttackPattern),
    _meta: generateResponseMetadata(),
  };
}
