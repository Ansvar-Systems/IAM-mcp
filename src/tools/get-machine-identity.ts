/**
 * get-machine-identity — Non-human identity management guidance.
 *
 * Returns emerging technologies in the machine-identity category, and
 * optionally vendor-specific configuration guidance filtered by platform.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetMachineIdentityInput {
  platform?: string;
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

export interface VendorConfigEntry {
  id: string;
  vendor: string;
  feature: string;
  category: string;
  description: string;
  best_practices: string | null;
  common_misconfigurations: Array<{ issue: string; impact: string; severity: string }>;
  compliance_controls: string[];
  equivalent_in: Record<string, string>;
}

export interface MachineIdentityResult {
  technologies: EmergingTechnologyEntry[];
  vendor_configs: VendorConfigEntry[];
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

const PLATFORM_VENDOR_MAP: Record<string, string> = {
  azure: 'azure-entra',
  aws: 'aws-iam',
  gcp: 'gcp-iam',
};

function parseEmergingTechnology(row: RawEmergingTechnologyRow): EmergingTechnologyEntry {
  return {
    ...row,
    standards: JSON.parse(row.standards || '[]'),
    use_cases: JSON.parse(row.use_cases || '[]'),
    vendor_support: JSON.parse(row.vendor_support || '{}'),
  };
}

function parseVendorConfig(row: RawVendorConfigRow): VendorConfigEntry {
  return {
    ...row,
    common_misconfigurations: JSON.parse(row.common_misconfigurations || '[]'),
    compliance_controls: JSON.parse(row.compliance_controls || '[]'),
    equivalent_in: JSON.parse(row.equivalent_in || '{}'),
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetMachineIdentityInput,
): Promise<ToolResponse<MachineIdentityResult>> {
  // Get all machine-identity emerging technologies
  const techRows = db
    .prepare('SELECT * FROM emerging_technologies WHERE category = ?')
    .all('machine-identity') as RawEmergingTechnologyRow[];

  let vendorConfigRows: RawVendorConfigRow[] = [];

  if (params.platform && params.platform.trim().length > 0) {
    const platform = params.platform.trim().toLowerCase();
    const vendorName = PLATFORM_VENDOR_MAP[platform] ?? platform;

    // Get vendor configurations for the platform related to machine/service/workload identity
    vendorConfigRows = db
      .prepare(
        `SELECT * FROM vendor_configurations
         WHERE vendor = ?
           AND category IN ('authentication', 'authorization')
           AND (feature LIKE '%Managed Identit%'
             OR feature LIKE '%Service Principal%'
             OR feature LIKE '%Workload Identit%'
             OR feature LIKE '%service account%'
             OR feature LIKE '%Conditional Access for Workload%'
             OR feature LIKE '%App Registration%')`,
      )
      .all(vendorName) as RawVendorConfigRow[];
  }

  return {
    results: {
      technologies: techRows.map(parseEmergingTechnology),
      vendor_configs: vendorConfigRows.map(parseVendorConfig),
    },
    _meta: generateResponseMetadata(),
  };
}
