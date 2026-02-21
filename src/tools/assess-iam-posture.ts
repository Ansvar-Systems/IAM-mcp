/**
 * assess-iam-posture — Given architecture components, find applicable threats and weaknesses.
 *
 * For each component keyword, FTS-searches both attack_patterns and iam_weaknesses,
 * returning a deduplicated union of threats + weaknesses. Optional stride_filter.
 */

import { sanitizeFtsInput, buildFtsQueryVariants } from '../utils/fts-query.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface AssessIamPostureInput {
  components: string[];
  stride_filter?: string;
}

export interface AttackPatternSummary {
  id: string;
  name: string;
  tactic: string;
  stride_category: string;
  severity: string;
  description: string;
}

export interface WeaknessSummary {
  cwe_id: string;
  title: string;
  category: string;
  stride_category: string;
  severity: string;
  description: string;
}

export interface PostureAssessment {
  threats: AttackPatternSummary[];
  weaknesses: WeaknessSummary[];
  components_analyzed: string[];
}

interface RawAttackRow {
  id: string;
  name: string;
  tactic: string;
  stride_category: string;
  severity: string;
  description: string;
}

interface RawWeaknessRow {
  cwe_id: string;
  title: string;
  category: string;
  stride_category: string;
  severity: string;
  description: string;
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: AssessIamPostureInput,
): Promise<ToolResponse<PostureAssessment>> {
  const threatMap = new Map<string, AttackPatternSummary>();
  const weaknessMap = new Map<string, WeaknessSummary>();

  // Build stride filter clause fragments
  const strideFilter = params.stride_filter;

  for (const component of params.components) {
    const sanitized = sanitizeFtsInput(component);
    if (!sanitized || sanitized.trim().length === 0) continue;

    const variants = buildFtsQueryVariants(sanitized);

    // --- Search attack_patterns via FTS ---
    for (const variant of variants) {
      try {
        const attackFilters: string[] = [];
        const attackFilterParams: unknown[] = [variant];
        if (strideFilter) {
          attackFilters.push('a.stride_category = ?');
          attackFilterParams.push(strideFilter);
        }
        const attackFilterClause = attackFilters.length > 0 ? ' AND ' + attackFilters.join(' AND ') : '';

        const attackSql = `SELECT a.id, a.name, a.tactic, a.stride_category, a.severity, a.description FROM attack_patterns a JOIN attack_patterns_fts f ON a.rowid = f.rowid WHERE attack_patterns_fts MATCH ?${attackFilterClause} LIMIT 50`;
        const attackRows = db.prepare(attackSql).all(...attackFilterParams) as RawAttackRow[];
        for (const row of attackRows) {
          if (!threatMap.has(row.id)) {
            threatMap.set(row.id, row);
          }
        }
        if (attackRows.length > 0) break; // Got results from this variant, skip less specific ones
      } catch {
        continue;
      }
    }

    // --- Search iam_weaknesses via FTS ---
    for (const variant of variants) {
      try {
        const weakFilters: string[] = [];
        const weakFilterParams: unknown[] = [variant];
        if (strideFilter) {
          weakFilters.push('w.stride_category = ?');
          weakFilterParams.push(strideFilter);
        }
        const weakFilterClause = weakFilters.length > 0 ? ' AND ' + weakFilters.join(' AND ') : '';

        const weakSql = `SELECT w.cwe_id, w.title, w.category, w.stride_category, w.severity, w.description FROM iam_weaknesses w JOIN weaknesses_fts f ON w.rowid = f.rowid WHERE weaknesses_fts MATCH ?${weakFilterClause} LIMIT 50`;
        const weakRows = db.prepare(weakSql).all(...weakFilterParams) as RawWeaknessRow[];
        for (const row of weakRows) {
          if (!weaknessMap.has(row.cwe_id)) {
            weaknessMap.set(row.cwe_id, row);
          }
        }
        if (weakRows.length > 0) break; // Got results from this variant, skip less specific ones
      } catch {
        continue;
      }
    }
  }

  return {
    results: {
      threats: Array.from(threatMap.values()),
      weaknesses: Array.from(weaknessMap.values()),
      components_analyzed: params.components,
    },
    _metadata: generateResponseMetadata(),
  };
}
