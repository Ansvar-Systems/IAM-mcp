/**
 * get-iam-standard — Lookup a single IAM standard/control by exact ID.
 */

import { buildCitation } from '../citation-universal.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

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
  return {
    ...row,
    cross_references: JSON.parse(row.cross_references || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetIamStandardInput,
): Promise<ToolResponse<StandardEntry[]>> {
  const row = db.prepare('SELECT * FROM standards WHERE id = ?').get(params.id) as RawStandardRow | undefined;

  const results = row ? [parseStandard(row)] : [];

  const _citations = results.map((r) =>
    buildCitation(
      r.id,
      `${r.framework} — ${r.title}`,
      'get_iam_standard',
      { id: r.id },
    ),
  );

  return {
    results,
    _citations,
    _metadata: generateResponseMetadata(),
  };
}
