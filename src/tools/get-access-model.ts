/**
 * get-access-model — Lookup an access model (architecture pattern) by ID.
 *
 * Searches architecture_patterns with category='access-model' first.
 * Falls back to a lookup without category filter if no match is found,
 * since the caller may not know the exact category.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';
import { buildCitation } from '../citation-universal.js';

export interface GetAccessModelInput {
  id: string;
}

export interface AccessModelEntry {
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

function parsePattern(row: RawPatternRow): AccessModelEntry {
  return {
    ...row,
    components: JSON.parse(row.components || '[]'),
    compliance_mappings: JSON.parse(row.compliance_mappings || '[]'),
    related_patterns: JSON.parse(row.related_patterns || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetAccessModelInput,
): Promise<ToolResponse<AccessModelEntry[]>> {
  // Try with category filter first
  let row = db
    .prepare('SELECT * FROM architecture_patterns WHERE id = ? AND category = ?')
    .get(params.id, 'access-model') as RawPatternRow | undefined;

  // Fall back to lookup without category filter
  if (!row) {
    row = db
      .prepare('SELECT * FROM architecture_patterns WHERE id = ?')
      .get(params.id) as RawPatternRow | undefined;
  }

  const results = row ? [parsePattern(row)] : [];

  const _citations = results.map((r) =>
    buildCitation(
      r.id,
      `${r.name} (${r.category})`,
      'get_access_model',
      { id: r.id },
    ),
  );

  return {
    results,
    _citations,
    _metadata: generateResponseMetadata(),
  };
}
