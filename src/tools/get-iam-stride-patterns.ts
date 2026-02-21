/**
 * get-iam-stride-patterns — FTS5 search attack_patterns for a component keyword,
 * grouped by STRIDE category. Optional stride_category filter.
 */

import { sanitizeFtsInput, buildFtsQueryVariants } from '../utils/fts-query.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetIamStridePatternsInput {
  component: string;
  stride_category?: string;
}

export interface AttackPatternSummary {
  id: string;
  name: string;
  tactic: string;
  stride_category: string;
  severity: string;
  description: string;
}

export interface StrideGroup {
  category: string;
  patterns: AttackPatternSummary[];
}

interface RawAttackRow {
  id: string;
  name: string;
  tactic: string;
  stride_category: string;
  severity: string;
  description: string;
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetIamStridePatternsInput,
): Promise<ToolResponse<StrideGroup[]>> {
  const sanitized = sanitizeFtsInput(params.component);
  if (!sanitized || sanitized.trim().length === 0) {
    return {
      results: [],
      _metadata: generateResponseMetadata(),
    };
  }

  const variants = buildFtsQueryVariants(sanitized);

  // Build optional stride_category filter
  const filters: string[] = [];
  const filterParams: unknown[] = [];
  if (params.stride_category) {
    filters.push('a.stride_category = ?');
    filterParams.push(params.stride_category);
  }
  const filterClause = filters.length > 0 ? ' AND ' + filters.join(' AND ') : '';

  let matchedRows: RawAttackRow[] = [];

  for (const variant of variants) {
    try {
      const sql = `SELECT a.id, a.name, a.tactic, a.stride_category, a.severity, a.description FROM attack_patterns a JOIN attack_patterns_fts f ON a.rowid = f.rowid WHERE attack_patterns_fts MATCH ?${filterClause} LIMIT 50`;
      const rows = db.prepare(sql).all(variant, ...filterParams) as RawAttackRow[];
      if (rows.length > 0) {
        matchedRows = rows;
        break;
      }
    } catch {
      continue;
    }
  }

  // Group results by STRIDE category
  const groupMap = new Map<string, AttackPatternSummary[]>();
  for (const row of matchedRows) {
    const group = groupMap.get(row.stride_category) || [];
    group.push(row);
    groupMap.set(row.stride_category, group);
  }

  // Sort categories in canonical STRIDE order
  const strideOrder = [
    'spoofing',
    'tampering',
    'repudiation',
    'information_disclosure',
    'denial_of_service',
    'elevation_of_privilege',
  ];

  const results: StrideGroup[] = strideOrder
    .filter((cat) => groupMap.has(cat))
    .map((cat) => ({
      category: cat,
      patterns: groupMap.get(cat)!,
    }));

  return {
    results,
    _metadata: generateResponseMetadata(),
  };
}
