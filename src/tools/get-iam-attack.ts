/**
 * get-iam-attack — Lookup a MITRE ATT&CK IAM attack pattern by technique ID.
 *
 * Handles both exact match (T1110) and prefix search (T1078%) to find
 * all tactic variants of a technique (e.g., T1078-IA, T1078-PERS).
 */

import { generateResponseMetadata, type ToolResponse, type CitationEntry } from '../utils/metadata.js';

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
    return {
      results: allRows.map(parseAttackPattern),
      _meta: generateResponseMetadata(),
    };
  }

  // No exact match — try prefix search only (user may have passed partial ID)
  const prefixRows = db
    .prepare('SELECT * FROM attack_patterns WHERE id LIKE ?')
    .all(params.id + '%') as RawAttackPatternRow[];

  return {
    results: prefixRows.map(parseAttackPattern),
    _meta: generateResponseMetadata(),
  };
}
