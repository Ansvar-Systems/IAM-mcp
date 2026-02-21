import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../../scripts/build-db.js';

// Tool handlers
import { handler as getEmergingTechnology } from '../../src/tools/get-emerging-technology.js';
import { handler as getMachineIdentity } from '../../src/tools/get-machine-identity.js';
import { handler as assessIamMaturity } from '../../src/tools/assess-iam-maturity.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = join(__dirname, '..', '..', '.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-emerging-tools.db');

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
// get-emerging-technology
// ---------------------------------------------------------------------------
describe('get-emerging-technology', () => {
  it('returns full passkey details with vendor support for id "passkeys-fido2"', async () => {
    const res = await getEmergingTechnology(db, { id: 'passkeys-fido2' });

    expect(res.results.length).toBe(1);

    const tech = res.results[0];
    expect(tech.id).toBe('passkeys-fido2');
    expect(tech.name).toContain('Passkeys');
    expect(tech.category).toBe('passwordless');
    expect(tech.description).toBeTruthy();
    expect(tech.maturity).toBe('emerging');
    expect(tech.adoption_status).toBeTruthy();
    expect(tech.migration_from).toBeTruthy();

    // standards should be parsed JSON array
    expect(Array.isArray(tech.standards)).toBe(true);
    expect(tech.standards.length).toBeGreaterThan(0);
    expect(tech.standards).toContain('FIDO2 (CTAP2.2)');

    // use_cases should be parsed JSON array
    expect(Array.isArray(tech.use_cases)).toBe(true);
    expect(tech.use_cases.length).toBeGreaterThan(0);

    // vendor_support should be parsed JSON object
    expect(typeof tech.vendor_support).toBe('object');
    expect(tech.vendor_support).not.toBeNull();
    expect(Array.isArray(tech.vendor_support)).toBe(false);
    expect(tech.vendor_support).toHaveProperty('apple');
    expect(tech.vendor_support).toHaveProperty('google');
    expect(tech.vendor_support).toHaveProperty('microsoft');

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns all passwordless technologies for category "passwordless"', async () => {
    const res = await getEmergingTechnology(db, { category: 'passwordless' });

    expect(res.results.length).toBeGreaterThanOrEqual(3);

    for (const tech of res.results) {
      expect(tech.category).toBe('passwordless');
      expect(Array.isArray(tech.standards)).toBe(true);
      expect(Array.isArray(tech.use_cases)).toBe(true);
      expect(typeof tech.vendor_support).toBe('object');
      expect(Array.isArray(tech.vendor_support)).toBe(false);
    }

    // Should include passkeys-fido2
    const ids = res.results.map((t: { id: string }) => t.id);
    expect(ids).toContain('passkeys-fido2');

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns empty results for NONEXISTENT id', async () => {
    const res = await getEmergingTechnology(db, { id: 'NONEXISTENT' });

    expect(res.results).toHaveLength(0);
    expect(res._metadata).toBeDefined();
    expect(res._metadata.domain).toBe('iam');
  });
});

// ---------------------------------------------------------------------------
// get-machine-identity
// ---------------------------------------------------------------------------
describe('get-machine-identity', () => {
  it('returns managed identities and service principals for platform "azure"', async () => {
    const res = await getMachineIdentity(db, { platform: 'azure' });

    // Should have emerging_technologies in machine-identity category
    expect(res.results.technologies.length).toBeGreaterThan(0);
    for (const tech of res.results.technologies) {
      expect(tech.category).toBe('machine-identity');
      expect(Array.isArray(tech.standards)).toBe(true);
      expect(typeof tech.vendor_support).toBe('object');
    }

    // Should have vendor_configurations for azure-entra with machine/workload/service identity features
    expect(res.results.vendor_configs.length).toBeGreaterThan(0);
    for (const config of res.results.vendor_configs) {
      expect(config.vendor).toBe('azure-entra');
      expect(Array.isArray(config.common_misconfigurations)).toBe(true);
      expect(typeof config.equivalent_in).toBe('object');
    }

    // Should include features related to managed identities or service principals or workload identities
    const features = res.results.vendor_configs.map((c: { feature: string }) => c.feature.toLowerCase());
    const hasMachineRelated = features.some(
      (f: string) => f.includes('managed') || f.includes('service') || f.includes('workload'),
    );
    expect(hasMachineRelated).toBe(true);

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns all machine identity technologies when no platform specified', async () => {
    const res = await getMachineIdentity(db, {});

    // Should have emerging_technologies in machine-identity category
    expect(res.results.technologies.length).toBeGreaterThan(0);
    for (const tech of res.results.technologies) {
      expect(tech.category).toBe('machine-identity');
      expect(Array.isArray(tech.standards)).toBe(true);
      expect(Array.isArray(tech.use_cases)).toBe(true);
      expect(typeof tech.vendor_support).toBe('object');
    }

    // Should NOT have vendor_configs when no platform is specified
    expect(res.results.vendor_configs).toHaveLength(0);

    expect(res._metadata.domain).toBe('iam');
  });
});

// ---------------------------------------------------------------------------
// assess-iam-maturity
// ---------------------------------------------------------------------------
describe('assess-iam-maturity', () => {
  it('returns maturity assessment with current level, gaps, and recommendations', async () => {
    const res = await assessIamMaturity(db, {
      current: {
        authentication: 'passwords-only',
        authorization: 'rbac-basic',
      },
    });

    // Should have per-area assessment
    expect(res.results.areas).toBeDefined();
    expect(res.results.areas.authentication).toBeDefined();
    expect(res.results.areas.authentication.current_level).toBe('traditional');
    expect(res.results.areas.authorization).toBeDefined();
    expect(res.results.areas.authorization.current_level).toBeTruthy();

    // Should have overall maturity
    expect(res.results.overall_maturity).toBeTruthy();
    // passwords-only + rbac-basic should be at best traditional/initial
    expect(['traditional', 'initial']).toContain(res.results.overall_maturity);

    // Should have gaps
    expect(Array.isArray(res.results.gaps)).toBe(true);
    expect(res.results.gaps.length).toBeGreaterThan(0);

    // Should have recommendations
    expect(Array.isArray(res.results.recommendations)).toBe(true);
    expect(res.results.recommendations.length).toBeGreaterThan(0);

    // Should have CISA ZTMM reference standards
    expect(Array.isArray(res.results.reference_standards)).toBe(true);
    expect(res.results.reference_standards.length).toBeGreaterThan(0);

    expect(res._metadata.domain).toBe('iam');
  });
});
