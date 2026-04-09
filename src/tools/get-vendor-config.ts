/**
 * get-vendor-config — Look up vendor-specific IAM configuration guidance.
 *
 * Supports lookup by vendor + optional feature filter, with JSON field parsing.
 */

import { generateResponseMetadata, type ToolResponse, type CitationEntry } from '../utils/metadata.js';

export interface GetVendorConfigInput {
  vendor: string;
  feature?: string;
  limit?: number;
}

export interface MisconfigurationEntry {
  issue: string;
  impact: string;
  severity: string;
}

export interface VendorConfigEntry {
  id: string;
  vendor: string;
  feature: string;
  category: string;
  description: string;
  best_practices: string | null;
  common_misconfigurations: MisconfigurationEntry[];
  compliance_controls: string[];
  equivalent_in: Record<string, string>;
  _citation: CitationEntry;
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

function parseVendorConfig(row: RawVendorConfigRow): VendorConfigEntry {
  return {
    ...row,
    common_misconfigurations: JSON.parse(row.common_misconfigurations || '[]'),
    compliance_controls: JSON.parse(row.compliance_controls || '[]'),
    equivalent_in: JSON.parse(row.equivalent_in || '{}'),
    _citation: {
      canonical_ref: row.id,
      display_text: `${row.vendor} — ${row.feature}`,
      lookup: 'get_vendor_config',
    },
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetVendorConfigInput,
): Promise<ToolResponse<VendorConfigEntry[]>> {
  const effectiveLimit = Math.min(Math.max(params.limit ?? 20, 1), 50);

  let rows: RawVendorConfigRow[];

  if (params.feature && params.feature.trim().length > 0) {
    // Vendor + feature lookup
    const featurePattern = `%${params.feature.trim()}%`;
    const sql = 'SELECT * FROM vendor_configurations WHERE vendor = ? AND (feature LIKE ? OR id = ?) LIMIT ?';
    rows = db.prepare(sql).all(params.vendor, featurePattern, params.feature.trim(), effectiveLimit) as RawVendorConfigRow[];
  } else {
    // All configs for vendor
    const sql = 'SELECT * FROM vendor_configurations WHERE vendor = ? LIMIT ?';
    rows = db.prepare(sql).all(params.vendor, effectiveLimit) as RawVendorConfigRow[];
  }

  return {
    results: rows.map(parseVendorConfig),
    _meta: generateResponseMetadata(),
  };
}
