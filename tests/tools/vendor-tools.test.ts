import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../../scripts/build-db.js';

// Tool handlers
import { handler as getVendorConfig } from '../../src/tools/get-vendor-config.js';
import { handler as compareVendors } from '../../src/tools/compare-vendors.js';
import { handler as getMisconfigurations } from '../../src/tools/get-misconfigurations.js';
import { handler as getMigrationPath } from '../../src/tools/get-migration-path.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = join(__dirname, '..', '..', '.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-vendor-tools.db');

let db: InstanceType<typeof Database>;

beforeAll(() => {
  mkdirSync(TEST_DB_DIR, { recursive: true });
  buildDatabase(TEST_DB_PATH);
  db = new Database(TEST_DB_PATH, { readonly: true });
});

afterAll(() => {
  if (db) db.close();
  if (existsSync(TEST_DB_PATH)) unlinkSync(TEST_DB_PATH);
});

// ---------------------------------------------------------------------------
// get-vendor-config
// ---------------------------------------------------------------------------
describe('get-vendor-config', () => {
  it('returns full config with misconfigurations for azure-entra Conditional Access', async () => {
    const res = await getVendorConfig(db, { vendor: 'azure-entra', feature: 'Conditional Access' });

    expect(res.results.length).toBeGreaterThanOrEqual(1);

    const config = res.results[0];
    expect(config.vendor).toBe('azure-entra');
    expect(config.feature).toContain('Conditional Access');
    expect(config.description).toBeTruthy();
    expect(config.best_practices).toBeTruthy();

    // common_misconfigurations should be parsed JSON array
    expect(Array.isArray(config.common_misconfigurations)).toBe(true);
    expect(config.common_misconfigurations.length).toBeGreaterThan(0);
    expect(config.common_misconfigurations[0]).toHaveProperty('issue');
    expect(config.common_misconfigurations[0]).toHaveProperty('impact');
    expect(config.common_misconfigurations[0]).toHaveProperty('severity');

    // compliance_controls should be parsed JSON array
    expect(Array.isArray(config.compliance_controls)).toBe(true);
    expect(config.compliance_controls.length).toBeGreaterThan(0);

    // equivalent_in should be parsed JSON object
    expect(typeof config.equivalent_in).toBe('object');
    expect(config.equivalent_in).not.toBeNull();
    expect(Array.isArray(config.equivalent_in)).toBe(false);

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns all configs for a vendor when only vendor is provided', async () => {
    const res = await getVendorConfig(db, { vendor: 'azure-entra' });

    // azure-entra has 40 configs but default limit is 20
    expect(res.results.length).toBe(20);
    for (const config of res.results) {
      expect(config.vendor).toBe('azure-entra');
      expect(Array.isArray(config.common_misconfigurations)).toBe(true);
      expect(typeof config.equivalent_in).toBe('object');
    }
  });

  it('returns empty results for NONEXISTENT vendor', async () => {
    const res = await getVendorConfig(db, { vendor: 'NONEXISTENT' });

    expect(res.results).toHaveLength(0);
    expect(res._metadata).toBeDefined();
    expect(res._metadata.domain).toBe('iam');
  });

  it('respects limit parameter', async () => {
    const res = await getVendorConfig(db, { vendor: 'azure-entra', limit: 5 });

    expect(res.results.length).toBe(5);
    for (const config of res.results) {
      expect(config.vendor).toBe('azure-entra');
    }
  });

  it('caps limit at 50', async () => {
    const res = await getVendorConfig(db, { vendor: 'azure-entra', limit: 100 });

    // azure-entra has 40, so we get all 40 (capped at 50 but only 40 exist)
    expect(res.results.length).toBe(40);
    expect(res.results.length).toBeLessThanOrEqual(50);
  });
});

// ---------------------------------------------------------------------------
// compare-vendors
// ---------------------------------------------------------------------------
describe('compare-vendors', () => {
  it('returns side-by-side comparison of MFA across specific vendors', async () => {
    const res = await compareVendors(db, {
      feature: 'MFA',
      vendors: ['azure-entra', 'okta', 'aws-iam'],
    });

    expect(res.results.length).toBeGreaterThan(0);

    // Results should be grouped by vendor
    const vendors = new Set(res.results.map((r: { vendor: string }) => r.vendor));
    // At least some of the requested vendors should be present
    expect(vendors.size).toBeGreaterThanOrEqual(1);
    for (const vendor of vendors) {
      expect(['azure-entra', 'okta', 'aws-iam']).toContain(vendor);
    }

    // Each result should have parsed JSON fields
    for (const config of res.results) {
      expect(Array.isArray(config.common_misconfigurations)).toBe(true);
      expect(Array.isArray(config.compliance_controls)).toBe(true);
      expect(typeof config.equivalent_in).toBe('object');
    }

    expect(res._metadata.domain).toBe('iam');
  });

  it('compares across all vendors when no vendor filter is provided', async () => {
    const res = await compareVendors(db, { feature: 'MFA' });

    expect(res.results.length).toBeGreaterThan(0);

    // Should have results from multiple vendors (not filtered)
    const vendors = new Set(res.results.map((r: { vendor: string }) => r.vendor));
    expect(vendors.size).toBeGreaterThan(1);

    expect(res._metadata.domain).toBe('iam');
  });
});

// ---------------------------------------------------------------------------
// get-misconfigurations
// ---------------------------------------------------------------------------
describe('get-misconfigurations', () => {
  it('returns all misconfigurations with severity for azure-entra', async () => {
    const res = await getMisconfigurations(db, { vendor: 'azure-entra' });

    expect(res.results.length).toBeGreaterThan(0);

    for (const misconfig of res.results) {
      expect(misconfig.vendor).toBe('azure-entra');
      expect(misconfig.feature).toBeTruthy();
      expect(misconfig.issue).toBeTruthy();
      expect(misconfig.impact).toBeTruthy();
      expect(misconfig.severity).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low']).toContain(misconfig.severity);
    }

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns misconfigurations across all vendors when no vendor specified', async () => {
    const res = await getMisconfigurations(db, {});

    expect(res.results.length).toBeGreaterThan(0);

    // Should have results from multiple vendors
    const vendors = new Set(res.results.map((r: { vendor: string }) => r.vendor));
    expect(vendors.size).toBeGreaterThan(1);

    for (const misconfig of res.results) {
      expect(misconfig.issue).toBeTruthy();
      expect(misconfig.severity).toBeTruthy();
    }

    expect(res._metadata.domain).toBe('iam');
  });

  it('filters misconfigurations by severity', async () => {
    const res = await getMisconfigurations(db, { vendor: 'azure-entra', severity: 'critical' });

    expect(res.results.length).toBeGreaterThan(0);
    for (const misconfig of res.results) {
      expect(misconfig.severity).toBe('critical');
      expect(misconfig.vendor).toBe('azure-entra');
    }
  });
});

// ---------------------------------------------------------------------------
// get-migration-path
// ---------------------------------------------------------------------------
describe('get-migration-path', () => {
  it('returns migration guidance from okta to azure-entra', async () => {
    const res = await getMigrationPath(db, { from: 'okta', to: 'azure-entra' });

    expect(res.results.mappings.length).toBeGreaterThan(0);

    // Each mapping should have source feature and target equivalent
    for (const mapping of res.results.mappings) {
      expect(mapping.source_feature).toBeTruthy();
      expect(mapping.source_id).toBeTruthy();
      // equivalent can be null (migration gap) or a string
      if (mapping.equivalent !== null) {
        expect(typeof mapping.equivalent).toBe('string');
      }
    }

    // Should have at least some features with equivalents
    const withEquivalent = res.results.mappings.filter(
      (m: { equivalent: string | null }) => m.equivalent !== null,
    );
    expect(withEquivalent.length).toBeGreaterThan(0);

    // Should identify migration gaps (features without equivalents)
    const gaps = res.results.gaps;
    expect(Array.isArray(gaps)).toBe(true);

    expect(res.results.from_vendor).toBe('okta');
    expect(res.results.to_vendor).toBe('azure-entra');

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns empty mappings when source vendor has no configs', async () => {
    const res = await getMigrationPath(db, { from: 'NONEXISTENT', to: 'azure-entra' });

    expect(res.results.mappings).toHaveLength(0);
    expect(res.results.gaps).toHaveLength(0);
    expect(res._metadata).toBeDefined();
  });
});
