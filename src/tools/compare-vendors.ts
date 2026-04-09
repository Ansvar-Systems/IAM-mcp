/**
 * compare-vendors — Side-by-side vendor feature comparison via FTS5.
 *
 * Searches vendor_fts for the feature keyword and optionally filters by vendor list.
 * Groups results by vendor for comparison.
 */

import { sanitizeFtsInput, buildFtsQueryVariants } from '../utils/fts-query.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface CompareVendorsInput {
  feature: string;
  vendors?: string[];
  limit?: number;
}

export interface MisconfigurationEntry {
  issue: string;
  impact: string;
  severity: string;
}

export interface VendorComparisonEntry {
  id: string;
  vendor: string;
  feature: string;
  category: string;
  description: string;
  best_practices: string | null;
  common_misconfigurations: MisconfigurationEntry[];
  compliance_controls: string[];
  equivalent_in: Record<string, string>;
}

interface RawVendorConfigRow {
  id: string;
  vendor: string;
  feature: string;
  category: string;
  description: string;
  best_practices: string | null;
  common_misconfigurations: string;
  compliance_controls: string;
  equivalent_in: string;
}

function parseVendorConfig(row: RawVendorConfigRow): VendorComparisonEntry {
  return {
    ...row,
    common_misconfigurations: JSON.parse(row.common_misconfigurations || '[]'),
    compliance_controls: JSON.parse(row.compliance_controls || '[]'),
    equivalent_in: JSON.parse(row.equivalent_in || '{}'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: CompareVendorsInput,
): Promise<ToolResponse<VendorComparisonEntry[]>> {
  const effectiveLimit = Math.min(Math.max(params.limit ?? 50, 1), 50);

  const sanitized = sanitizeFtsInput(params.feature);
  const variants = buildFtsQueryVariants(sanitized);

  if (variants.length === 0) {
    return {
      results: [],
      _meta: generateResponseMetadata(),
    };
  }

  // Build optional vendor filter
  const hasVendorFilter = params.vendors && params.vendors.length > 0;

  for (const variant of variants) {
    try {
      let sql: string;
      let queryParams: unknown[];

      if (hasVendorFilter) {
        const placeholders = params.vendors!.map(() => '?').join(', ');
        sql = `SELECT v.* FROM vendor_configurations v JOIN vendor_fts f ON v.rowid = f.rowid WHERE vendor_fts MATCH ? AND v.vendor IN (${placeholders}) LIMIT ?`;
        queryParams = [variant, ...params.vendors!, effectiveLimit];
      } else {
        sql = 'SELECT v.* FROM vendor_configurations v JOIN vendor_fts f ON v.rowid = f.rowid WHERE vendor_fts MATCH ? LIMIT ?';
        queryParams = [variant, effectiveLimit];
      }

      const rows = db.prepare(sql).all(...queryParams) as RawVendorConfigRow[];
      if (rows.length > 0) {
        return {
          results: rows.map(parseVendorConfig),
          _meta: generateResponseMetadata(),
        };
      }
    } catch {
      // FTS variant failed, try next
      continue;
    }
  }

  // All FTS variants returned nothing
  return {
    results: [],
    _meta: generateResponseMetadata(),
  };
}
