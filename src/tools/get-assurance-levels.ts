/**
 * get-assurance-levels — Retrieve NIST 800-63 assurance-level standards (AAL/IAL/FAL).
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetAssuranceLevelsInput {
  type: string;   // 'AAL' | 'IAL' | 'FAL'
  level?: number;  // 1, 2, or 3
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

export interface AssuranceLevelGroup {
  level: string;
  standards: StandardEntry[];
}

function parseStandard(row: RawStandardRow): StandardEntry {
  return {
    ...row,
    cross_references: JSON.parse(row.cross_references || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetAssuranceLevelsInput,
): Promise<ToolResponse<AssuranceLevelGroup[]>> {
  const type = params.type.toUpperCase();

  let rows: RawStandardRow[];
  if (params.level != null) {
    const pattern = `${type}${params.level}`;
    rows = db
      .prepare('SELECT * FROM standards WHERE framework = ? AND assurance_level = ?')
      .all('nist-800-63', pattern) as RawStandardRow[];
  } else {
    const pattern = `${type}%`;
    rows = db
      .prepare('SELECT * FROM standards WHERE framework = ? AND assurance_level LIKE ?')
      .all('nist-800-63', pattern) as RawStandardRow[];
  }

  // Group by assurance_level
  const groupMap = new Map<string, StandardEntry[]>();
  for (const row of rows) {
    const level = row.assurance_level ?? 'unknown';
    if (!groupMap.has(level)) {
      groupMap.set(level, []);
    }
    groupMap.get(level)!.push(parseStandard(row));
  }

  // Sort groups by level name
  const results: AssuranceLevelGroup[] = Array.from(groupMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([level, standards]) => ({ level, standards }));

  return {
    results,
    _metadata: generateResponseMetadata(),
  };
}
