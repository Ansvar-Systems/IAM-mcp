/**
 * check-iam-compliance — Compare implemented controls against a target framework.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface CheckIamComplianceInput {
  implemented: string[];
  framework: string;
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

export interface ComplianceResult {
  compliant: StandardEntry[];
  gaps: StandardEntry[];
  coverage_percent: number;
}

function parseStandard(row: RawStandardRow): StandardEntry {
  return {
    ...row,
    cross_references: JSON.parse(row.cross_references || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: CheckIamComplianceInput,
): Promise<ToolResponse<ComplianceResult>> {
  const allRows = db
    .prepare('SELECT * FROM standards WHERE framework = ?')
    .all(params.framework) as RawStandardRow[];

  const implementedSet = new Set(params.implemented);

  const compliant: StandardEntry[] = [];
  const gaps: StandardEntry[] = [];

  for (const row of allRows) {
    const parsed = parseStandard(row);
    if (implementedSet.has(row.id)) {
      compliant.push(parsed);
    } else {
      gaps.push(parsed);
    }
  }

  const total = allRows.length;
  const coverage_percent = total === 0 ? 0 : Math.round((compliant.length / total) * 10000) / 100;

  return {
    results: { compliant, gaps, coverage_percent },
    _meta: generateResponseMetadata(),
  };
}
