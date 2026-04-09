/**
 * get-zero-trust-pattern — Combine ZT standards with ZT architecture patterns.
 *
 * Searches `standards` WHERE zero_trust_pillar = pillar AND
 * (maturity_level = maturity if specified).
 * Also searches `architecture_patterns` WHERE category = 'zero-trust'.
 * Returns both standards-based ZT guidance and architectural patterns.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetZeroTrustPatternInput {
  pillar: string;
  maturity?: string;
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

export interface ArchitecturePatternEntry {
  id: string;
  name: string;
  category: string;
  description: string;
  when_to_use: string;
  when_not_to_use: string | null;
  components: string[];
  data_flow: string | null;
  strengths: string | null;
  weaknesses: string | null;
  compliance_mappings: string[];
  related_patterns: string[];
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

interface RawPatternRow {
  id: string;
  name: string;
  category: string;
  description: string;
  when_to_use: string;
  when_not_to_use: string | null;
  components: string;
  data_flow: string | null;
  strengths: string | null;
  weaknesses: string | null;
  compliance_mappings: string;
  related_patterns: string;
}

interface ZeroTrustResult {
  standards: StandardEntry[];
  patterns: ArchitecturePatternEntry[];
}

function parseStandard(row: RawStandardRow): StandardEntry {
  return {
    ...row,
    cross_references: JSON.parse(row.cross_references || '[]'),
  };
}

function parsePattern(row: RawPatternRow): ArchitecturePatternEntry {
  return {
    ...row,
    components: JSON.parse(row.components || '[]'),
    compliance_mappings: JSON.parse(row.compliance_mappings || '[]'),
    related_patterns: JSON.parse(row.related_patterns || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetZeroTrustPatternInput,
): Promise<ToolResponse<ZeroTrustResult>> {
  // --- Standards by ZT pillar (and optionally maturity level) ---
  let standardRows: RawStandardRow[];

  if (params.maturity) {
    standardRows = db
      .prepare('SELECT * FROM standards WHERE zero_trust_pillar = ? AND maturity_level = ?')
      .all(params.pillar, params.maturity) as RawStandardRow[];
  } else {
    standardRows = db
      .prepare('SELECT * FROM standards WHERE zero_trust_pillar = ?')
      .all(params.pillar) as RawStandardRow[];
  }

  // --- ZT architecture patterns ---
  const patternRows = db
    .prepare("SELECT * FROM architecture_patterns WHERE category = 'zero-trust'")
    .all() as RawPatternRow[];

  return {
    results: {
      standards: standardRows.map(parseStandard),
      patterns: patternRows.map(parsePattern),
    },
    _meta: generateResponseMetadata(),
  };
}
