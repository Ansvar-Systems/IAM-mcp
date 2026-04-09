/**
 * get-iam-standard — Lookup a single IAM standard/control by exact ID.
 */

import { generateResponseMetadata, type ToolResponse, type CitationEntry } from '../utils/metadata.js';

export interface GetIamStandardInput {
  id: string;
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
  _citation: CitationEntry;
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

function parseStandard(row: RawStandardRow): StandardEntry {
  const displayText = row.section
    ? `${row.framework} ${row.section}`
    : `${row.framework} ${row.id}`;
  return {
    ...row,
    cross_references: JSON.parse(row.cross_references || '[]'),
    _citation: {
      canonical_ref: row.id,
      display_text: displayText,
      lookup: 'get_iam_standard',
    },
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetIamStandardInput,
): Promise<ToolResponse<StandardEntry[]>> {
  const row = db.prepare('SELECT * FROM standards WHERE id = ?').get(params.id) as RawStandardRow | undefined;

  const results = row ? [parseStandard(row)] : [];

  return {
    results,
    _meta: generateResponseMetadata(),
  };
}
