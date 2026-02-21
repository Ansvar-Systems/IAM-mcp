import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../scripts/build-db.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = join(__dirname, '..', '.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-build-db.db');

let db: InstanceType<typeof Database>;

/** Helper: return column names for a given table */
function getColumns(tableName: string): string[] {
  const rows = db.prepare(`PRAGMA table_info("${tableName}")`).all() as { name: string }[];
  return rows.map((r) => r.name);
}

beforeAll(() => {
  mkdirSync(TEST_DB_DIR, { recursive: true });
  buildDatabase(TEST_DB_PATH);
  db = new Database(TEST_DB_PATH, { readonly: true });
});

afterAll(() => {
  if (db) db.close();
  if (existsSync(TEST_DB_PATH)) unlinkSync(TEST_DB_PATH);
});

describe('build-db schema', () => {
  it('standards table has correct columns', () => {
    const cols = getColumns('standards');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'framework', 'section', 'title', 'description', 'category',
        'assurance_level', 'zero_trust_pillar', 'maturity_level', 'cross_references',
      ]),
    );
    expect(cols).toHaveLength(10);
  });

  it('protocols table has correct columns', () => {
    const cols = getColumns('protocols');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'protocol', 'flow_type', 'description', 'security_considerations',
        'recommended_for', 'deprecated', 'rfc', 'sequence_diagram',
      ]),
    );
    expect(cols).toHaveLength(9);
  });

  it('attack_patterns table has correct columns', () => {
    const cols = getColumns('attack_patterns');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'name', 'tactic', 'description', 'sub_techniques',
        'detection_guidance', 'mitigation_controls', 'stride_category', 'severity', 'real_world_examples',
      ]),
    );
    expect(cols).toHaveLength(10);
  });

  it('iam_weaknesses table has correct columns', () => {
    const cols = getColumns('iam_weaknesses');
    expect(cols).toEqual(
      expect.arrayContaining([
        'cwe_id', 'capec_ids', 'title', 'description', 'category',
        'affected_protocols', 'stride_category', 'severity', 'detection_guidance', 'remediation',
      ]),
    );
    expect(cols).toHaveLength(10);
  });

  it('architecture_patterns table has correct columns', () => {
    const cols = getColumns('architecture_patterns');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'name', 'category', 'description', 'when_to_use',
        'when_not_to_use', 'components', 'data_flow', 'strengths', 'weaknesses',
        'compliance_mappings', 'related_patterns',
      ]),
    );
    expect(cols).toHaveLength(12);
  });

  it('vendor_configurations table has correct columns', () => {
    const cols = getColumns('vendor_configurations');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'vendor', 'feature', 'category', 'description',
        'best_practices', 'common_misconfigurations', 'compliance_controls', 'equivalent_in',
      ]),
    );
    expect(cols).toHaveLength(9);
  });

  it('compliance_mappings table has correct columns', () => {
    const cols = getColumns('compliance_mappings');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'source_framework', 'source_control', 'target_framework',
        'target_control', 'relationship', 'notes',
      ]),
    );
    expect(cols).toHaveLength(7);
  });

  it('emerging_technologies table has correct columns', () => {
    const cols = getColumns('emerging_technologies');
    expect(cols).toEqual(
      expect.arrayContaining([
        'id', 'name', 'category', 'description', 'maturity',
        'standards', 'adoption_status', 'use_cases', 'migration_from', 'vendor_support',
      ]),
    );
    expect(cols).toHaveLength(10);
  });

  it('FTS5 virtual tables exist', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as { name: string }[];
    const tableNames = tables.map((t) => t.name);

    expect(tableNames).toEqual(
      expect.arrayContaining([
        'standards_fts',
        'attack_patterns_fts',
        'weaknesses_fts',
        'vendor_fts',
        'patterns_fts',
      ]),
    );
  });

  it('db_metadata has required keys', () => {
    const rows = db.prepare('SELECT key, value FROM db_metadata').all() as { key: string; value: string }[];
    const keys = rows.map((r) => r.key);

    expect(keys).toEqual(expect.arrayContaining(['tier', 'schema_version', 'built_at', 'domain']));

    const meta = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    expect(meta.tier).toBe('free');
    expect(meta.schema_version).toBe('1');
    expect(meta.domain).toBe('iam');
    expect(new Date(meta.built_at).toString()).not.toBe('Invalid Date');
  });
});
