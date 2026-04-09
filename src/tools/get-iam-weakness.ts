/**
 * get-iam-weakness — Lookup a CWE IAM weakness by CWE ID.
 */

import { generateResponseMetadata, type ToolResponse, type CitationEntry } from '../utils/metadata.js';

export interface GetIamWeaknessInput {
  cwe_id: string;
}

export interface WeaknessEntry {
  cwe_id: string;
  capec_ids: string[];
  title: string;
  description: string;
  category: string;
  affected_protocols: string[];
  stride_category: string;
  severity: string;
  detection_guidance: string | null;
  remediation: string | null;
  _citation: CitationEntry;
}

interface RawWeaknessRow {
  cwe_id: string;
  capec_ids: string;
  title: string;
  description: string;
  category: string;
  affected_protocols: string;
  stride_category: string;
  severity: string;
  detection_guidance: string | null;
  remediation: string | null;
}

function parseWeakness(row: RawWeaknessRow): WeaknessEntry {
  return {
    ...row,
    capec_ids: JSON.parse(row.capec_ids || '[]'),
    affected_protocols: JSON.parse(row.affected_protocols || '[]'),
    _citation: {
      canonical_ref: row.cwe_id,
      display_text: `CWE-${row.cwe_id}`,
      lookup: 'get_iam_weakness',
    },
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetIamWeaknessInput,
): Promise<ToolResponse<WeaknessEntry[]>> {
  const row = db.prepare('SELECT * FROM iam_weaknesses WHERE cwe_id = ?').get(params.cwe_id) as RawWeaknessRow | undefined;

  const results = row ? [parseWeakness(row)] : [];

  return {
    results,
    _meta: generateResponseMetadata(),
  };
}
