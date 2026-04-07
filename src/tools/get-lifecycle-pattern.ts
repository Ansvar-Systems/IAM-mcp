/**
 * get-lifecycle-pattern — Lookup lifecycle architecture patterns.
 *
 * If `id` is provided: lookup by exact ID from architecture_patterns.
 * If only `category` is provided: list all patterns matching that category.
 * Parses JSON fields: components, compliance_mappings, related_patterns.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';
import { buildCitation } from '../citation-universal.js';

export interface GetLifecyclePatternInput {
  id?: string;
  category?: string;
}

export interface LifecyclePatternEntry {
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

function parsePattern(row: RawPatternRow): LifecyclePatternEntry {
  return {
    ...row,
    components: JSON.parse(row.components || '[]'),
    compliance_mappings: JSON.parse(row.compliance_mappings || '[]'),
    related_patterns: JSON.parse(row.related_patterns || '[]'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetLifecyclePatternInput,
): Promise<ToolResponse<LifecyclePatternEntry[]>> {
  const makeCitations = (items: LifecyclePatternEntry[]) =>
    items.map((r) =>
      buildCitation(r.id, `${r.name} (${r.category})`, 'get_lifecycle_pattern', { id: r.id }),
    );

  // ID lookup takes precedence
  if (params.id) {
    const row = db
      .prepare('SELECT * FROM architecture_patterns WHERE id = ?')
      .get(params.id) as RawPatternRow | undefined;

    const results = row ? [parsePattern(row)] : [];

    return {
      results,
      _citations: makeCitations(results),
      _metadata: generateResponseMetadata(),
    };
  }

  // Category listing
  if (params.category) {
    const rows = db
      .prepare('SELECT * FROM architecture_patterns WHERE category = ?')
      .all(params.category) as RawPatternRow[];

    const parsed = rows.map(parsePattern);

    return {
      results: parsed,
      _citations: makeCitations(parsed),
      _metadata: generateResponseMetadata(),
    };
  }

  // No params — return empty
  return {
    results: [],
    _metadata: generateResponseMetadata(),
  };
}
