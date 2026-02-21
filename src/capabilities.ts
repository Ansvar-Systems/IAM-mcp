/**
 * Runtime capability detection for IAM Expert MCP.
 * Detects which database tables are available to enable/disable features.
 */

import type Database from '@ansvar/mcp-sqlite';

export type Capability =
  | 'standards'
  | 'protocols'
  | 'attack_patterns'
  | 'weaknesses'
  | 'architecture_patterns'
  | 'vendor_configurations'
  | 'compliance_mappings'
  | 'emerging_technologies';

const TABLE_MAP: Record<Capability, string[]> = {
  standards: ['standards', 'standards_fts'],
  protocols: ['protocols'],
  attack_patterns: ['attack_patterns', 'attack_patterns_fts'],
  weaknesses: ['iam_weaknesses', 'weaknesses_fts'],
  architecture_patterns: ['architecture_patterns', 'patterns_fts'],
  vendor_configurations: ['vendor_configurations', 'vendor_fts'],
  compliance_mappings: ['compliance_mappings'],
  emerging_technologies: ['emerging_technologies'],
};

export function detectCapabilities(db: InstanceType<typeof Database>): Set<Capability> {
  const caps = new Set<Capability>();
  const tables = new Set(
    (db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[])
      .map(r => r.name)
  );

  for (const [cap, required] of Object.entries(TABLE_MAP)) {
    if (required.every(t => tables.has(t))) {
      caps.add(cap as Capability);
    }
  }

  return caps;
}

export interface DbMetadata {
  tier: string;
  schema_version: string;
  built_at?: string;
  builder?: string;
}

export function readDbMetadata(db: InstanceType<typeof Database>): DbMetadata {
  const meta: Record<string, string> = {};
  try {
    const rows = db.prepare('SELECT key, value FROM db_metadata').all() as { key: string; value: string }[];
    for (const row of rows) {
      meta[row.key] = row.value;
    }
  } catch {
    // db_metadata table may not exist
  }
  return {
    tier: meta.tier ?? 'free',
    schema_version: meta.schema_version ?? '1.0',
    built_at: meta.built_at,
    builder: meta.builder,
  };
}

export function upgradeMessage(feature: string): string {
  return `The "${feature}" feature requires a professional-tier database. Contact hello@ansvar.ai for access.`;
}
