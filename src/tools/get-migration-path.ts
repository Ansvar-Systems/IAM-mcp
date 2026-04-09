/**
 * get-migration-path — Migration guidance between IAM platforms.
 *
 * Looks up all configs for the source vendor, checks equivalent_in JSON
 * to find equivalent features in the target vendor, and returns a
 * mapping of source features to target equivalents with migration gaps.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetMigrationPathInput {
  from: string;
  to: string;
}

export interface FeatureMapping {
  source_id: string;
  source_feature: string;
  source_category: string;
  equivalent: string | null;
}

export interface MigrationPathResult {
  from_vendor: string;
  to_vendor: string;
  mappings: FeatureMapping[];
  gaps: FeatureMapping[];
}

interface RawVendorConfigRow {
  id: string;
  vendor: string;
  feature: string;
  category: string;
  equivalent_in: string;
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetMigrationPathInput,
): Promise<ToolResponse<MigrationPathResult>> {
  const sql = 'SELECT id, vendor, feature, category, equivalent_in FROM vendor_configurations WHERE vendor = ?';
  const rows = db.prepare(sql).all(params.from) as RawVendorConfigRow[];

  const mappings: FeatureMapping[] = [];
  const gaps: FeatureMapping[] = [];

  for (const row of rows) {
    const equivalents: Record<string, string> = JSON.parse(row.equivalent_in || '{}');
    const targetEquivalent = equivalents[params.to] ?? null;

    const mapping: FeatureMapping = {
      source_id: row.id,
      source_feature: row.feature,
      source_category: row.category,
      equivalent: targetEquivalent,
    };

    mappings.push(mapping);

    if (targetEquivalent === null || targetEquivalent === 'N/A') {
      gaps.push(mapping);
    }
  }

  return {
    results: {
      from_vendor: params.from,
      to_vendor: params.to,
      mappings,
      gaps,
    },
    _meta: generateResponseMetadata(),
  };
}
