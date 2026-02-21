/**
 * get-emerging-technology — Look up emerging IAM technologies.
 *
 * Supports lookup by exact ID, by category, or returns all technologies.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetEmergingTechnologyInput {
  id?: string;
  category?: string;
  limit?: number;
}

export interface EmergingTechnologyEntry {
  id: string;
  name: string;
  category: string;
  description: string;
  maturity: string;
  standards: string[];
  adoption_status: string | null;
  use_cases: string[];
  migration_from: string | null;
  vendor_support: Record<string, string>;
}

interface RawEmergingTechnologyRow {
  id: string;
  name: string;
  category: string;
  description: string;
  maturity: string;
  standards: string;
  adoption_status: string | null;
  use_cases: string;
  migration_from: string | null;
  vendor_support: string;
}

function parseEmergingTechnology(row: RawEmergingTechnologyRow): EmergingTechnologyEntry {
  return {
    ...row,
    standards: JSON.parse(row.standards || '[]'),
    use_cases: JSON.parse(row.use_cases || '[]'),
    vendor_support: JSON.parse(row.vendor_support || '{}'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetEmergingTechnologyInput,
): Promise<ToolResponse<EmergingTechnologyEntry[]>> {
  const effectiveLimit = Math.min(Math.max(params.limit ?? 50, 1), 100);

  let rows: RawEmergingTechnologyRow[];

  if (params.id && params.id.trim().length > 0) {
    const row = db.prepare('SELECT * FROM emerging_technologies WHERE id = ?').get(params.id.trim()) as RawEmergingTechnologyRow | undefined;
    rows = row ? [row] : [];
  } else if (params.category && params.category.trim().length > 0) {
    rows = db.prepare('SELECT * FROM emerging_technologies WHERE category = ? LIMIT ?').all(params.category.trim(), effectiveLimit) as RawEmergingTechnologyRow[];
  } else {
    rows = db.prepare('SELECT * FROM emerging_technologies LIMIT ?').all(effectiveLimit) as RawEmergingTechnologyRow[];
  }

  return {
    results: rows.map(parseEmergingTechnology),
    _metadata: generateResponseMetadata(),
  };
}
