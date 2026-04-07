/**
 * get-iam-attack — Lookup a MITRE ATT&CK IAM attack pattern by technique ID.
 *
 * Handles both exact match (T1110) and prefix search (T1078%) to find
 * all tactic variants of a technique (e.g., T1078-IA, T1078-PERS).
 */

import { buildCitation } from '../citation-universal.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetIamAttackInput {
  id: string;
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
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetIamAttackInput,
): Promise<ToolResponse<AttackPatternEntry[]>> {
  // Try exact match first
  const exactRow = db.prepare('SELECT * FROM attack_patterns WHERE id = ?').get(params.id) as RawAttackPatternRow | undefined;

  if (exactRow) {
    // Also find all tactic variants via prefix search (e.g., T1078-IA, T1078-PE)
    const variantRows = db
      .prepare('SELECT * FROM attack_patterns WHERE id LIKE ? AND id != ?')
      .all(params.id + '%', params.id) as RawAttackPatternRow[];

    const allRows = [exactRow, ...variantRows];
    const exactResults = allRows.map(parseAttackPattern);
    const _citations = exactResults.map((r) =>
      buildCitation(r.id, `${r.id} — ${r.name}`, 'get_iam_attack', { id: r.id }),
    );
    return {
      results: exactResults,
      _citations,
      _metadata: generateResponseMetadata(),
    };
  }

  // No exact match — try prefix search only (user may have passed partial ID)
  const prefixRows = db
    .prepare('SELECT * FROM attack_patterns WHERE id LIKE ?')
    .all(params.id + '%') as RawAttackPatternRow[];

  const prefixResults = prefixRows.map(parseAttackPattern);
  const _citations = prefixResults.map((r) =>
    buildCitation(r.id, `${r.id} — ${r.name}`, 'get_iam_attack', { id: r.id }),
  );

  return {
    results: prefixResults,
    _citations,
    _metadata: generateResponseMetadata(),
  };
}
