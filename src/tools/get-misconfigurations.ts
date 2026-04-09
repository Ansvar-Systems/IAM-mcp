/**
 * get-misconfigurations — Get common IAM misconfigurations.
 *
 * Extracts and flattens common_misconfigurations JSON arrays from vendor_configurations,
 * returning each misconfiguration with its parent vendor/feature context.
 * Supports filtering by vendor and severity.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetMisconfigurationsInput {
  vendor?: string;
  severity?: string;
  limit?: number;
}

export interface FlatMisconfigurationEntry {
  vendor: string;
  feature: string;
  category: string;
  config_id: string;
  issue: string;
  impact: string;
  severity: string;
}

interface RawVendorConfigRow {
  id: string;
  vendor: string;
  feature: string;
  category: string;
  common_misconfigurations: string;
}

interface MisconfigurationItem {
  issue: string;
  impact: string;
  severity: string;
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetMisconfigurationsInput,
): Promise<ToolResponse<FlatMisconfigurationEntry[]>> {
  // Limit applies to the flattened output (each parent row expands to multiple misconfigs)
  const effectiveLimit = Math.min(Math.max(params.limit ?? 200, 1), 500);

  let rows: RawVendorConfigRow[];

  if (params.vendor) {
    const sql = "SELECT id, vendor, feature, category, common_misconfigurations FROM vendor_configurations WHERE vendor = ? AND common_misconfigurations != '[]' LIMIT ?";
    rows = db.prepare(sql).all(params.vendor, effectiveLimit) as RawVendorConfigRow[];
  } else {
    const sql = "SELECT id, vendor, feature, category, common_misconfigurations FROM vendor_configurations WHERE common_misconfigurations != '[]'";
    rows = db.prepare(sql).all() as RawVendorConfigRow[];
  }

  // Extract and flatten misconfigurations
  const results: FlatMisconfigurationEntry[] = [];

  for (const row of rows) {
    const misconfigs: MisconfigurationItem[] = JSON.parse(row.common_misconfigurations || '[]');
    for (const misconfig of misconfigs) {
      // Apply severity filter if specified
      if (params.severity && misconfig.severity !== params.severity) {
        continue;
      }

      results.push({
        vendor: row.vendor,
        feature: row.feature,
        category: row.category,
        config_id: row.id,
        issue: misconfig.issue,
        impact: misconfig.impact,
        severity: misconfig.severity,
      });
    }
  }

  return {
    results: results.slice(0, effectiveLimit),
    _meta: generateResponseMetadata(),
  };
}
