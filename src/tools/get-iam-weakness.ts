/**
 * get-iam-weakness — Lookup a CWE IAM weakness by CWE ID.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';
import { buildCitation } from '../citation-universal.js';

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
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetIamWeaknessInput,
): Promise<ToolResponse<WeaknessEntry[]>> {
  const row = db.prepare('SELECT * FROM iam_weaknesses WHERE cwe_id = ?').get(params.cwe_id) as RawWeaknessRow | undefined;

  const results = row ? [parseWeakness(row)] : [];

  const _citations = results.map((r) =>
    buildCitation(
      r.cwe_id,
      `${r.title} (${r.cwe_id})`,
      'get_iam_weakness',
      { cwe_id: r.cwe_id },
      `https://cwe.mitre.org/data/definitions/${r.cwe_id.replace('CWE-', '')}.html`,
    ),
  );

  return {
    results,
    _citations,
    _metadata: generateResponseMetadata(),
  };
}
