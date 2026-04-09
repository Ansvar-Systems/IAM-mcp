import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../../scripts/build-db.js';

// Tool handlers
import { handler as getIamStandard } from '../../src/tools/get-iam-standard.js';
import { handler as searchIamRequirements } from '../../src/tools/search-iam-requirements.js';
import { handler as checkIamCompliance } from '../../src/tools/check-iam-compliance.js';
import { handler as mapFrameworks } from '../../src/tools/map-frameworks.js';
import { handler as getAssuranceLevels } from '../../src/tools/get-assurance-levels.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = join(__dirname, '..', '..', '.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-standards-tools.db');

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
// get-iam-standard
// ---------------------------------------------------------------------------
describe('get-iam-standard', () => {
  it('returns a result for NIST-800-53-AC-2', async () => {
    const res = await getIamStandard(db, { id: 'NIST-800-53-AC-2' });

    expect(res.results).toHaveLength(1);
    const std = res.results[0];
    expect(std.id).toBe('NIST-800-53-AC-2');
    expect(std.framework).toBe('nist-800-53');
    expect(std.title).toContain('Account Management');
    expect(Array.isArray(std.cross_references)).toBe(true);
    expect(std.cross_references.length).toBeGreaterThan(0);
    expect(res._meta.domain).toBe('iam');
  });

  it('returns empty array for NONEXISTENT', async () => {
    const res = await getIamStandard(db, { id: 'NONEXISTENT' });
    expect(res.results).toHaveLength(0);
    expect(res._meta).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// search-iam-requirements
// ---------------------------------------------------------------------------
describe('search-iam-requirements', () => {
  it('finds results for query "multi-factor authentication"', async () => {
    const res = await searchIamRequirements(db, { query: 'multi-factor authentication' });

    expect(res.results.length).toBeGreaterThan(0);
    // At least one result should mention MFA/multi-factor
    const hasMfa = res.results.some(
      (s) =>
        s.title.toLowerCase().includes('multi-factor') ||
        s.description.toLowerCase().includes('multi-factor'),
    );
    expect(hasMfa).toBe(true);
  });

  it('filters by framework "nist-800-53"', async () => {
    const res = await searchIamRequirements(db, { framework: 'nist-800-53' });

    expect(res.results.length).toBeGreaterThan(0);
    for (const std of res.results) {
      expect(std.framework).toBe('nist-800-53');
    }
  });

  it('filters by category "authentication"', async () => {
    const res = await searchIamRequirements(db, { category: 'authentication' });

    expect(res.results.length).toBeGreaterThan(0);
    for (const std of res.results) {
      expect(std.category).toBe('authentication');
    }
  });

  it('respects limit parameter', async () => {
    const res = await searchIamRequirements(db, { limit: 3 });

    expect(res.results.length).toBeLessThanOrEqual(3);
    expect(res.results.length).toBeGreaterThan(0);
  });

  it('combines query and framework filter', async () => {
    const res = await searchIamRequirements(db, {
      query: 'access control',
      framework: 'nist-800-53',
    });

    expect(res.results.length).toBeGreaterThan(0);
    for (const std of res.results) {
      expect(std.framework).toBe('nist-800-53');
    }
  });
});

// ---------------------------------------------------------------------------
// check-iam-compliance
// ---------------------------------------------------------------------------
describe('check-iam-compliance', () => {
  it('identifies gaps when only some controls are implemented', async () => {
    // Get all nist-800-53 standards to know the total
    const allRes = await searchIamRequirements(db, { framework: 'nist-800-53', limit: 50 });
    const totalCount = allRes.results.length;
    expect(totalCount).toBeGreaterThan(5);

    // Implement only the first 3
    const implemented = allRes.results.slice(0, 3).map((s) => s.id);

    const res = await checkIamCompliance(db, {
      implemented,
      framework: 'nist-800-53',
    });

    expect(res.results.compliant).toHaveLength(3);
    expect(res.results.gaps.length).toBeGreaterThan(0);
    expect(res.results.coverage_percent).toBeGreaterThan(0);
    expect(res.results.coverage_percent).toBeLessThan(100);
    // Verify coverage math
    const expectedPct = Math.round((3 / (3 + res.results.gaps.length)) * 10000) / 100;
    expect(res.results.coverage_percent).toBe(expectedPct);
  });

  it('returns 100% coverage when all controls implemented', async () => {
    // Get all nist-800-207 standards (smaller set for manageable test)
    const allRes = await searchIamRequirements(db, { framework: 'nist-800-207', limit: 50 });
    expect(allRes.results.length).toBeGreaterThan(0);

    const allIds = allRes.results.map((s) => s.id);
    const res = await checkIamCompliance(db, {
      implemented: allIds,
      framework: 'nist-800-207',
    });

    expect(res.results.compliant.length).toBe(allIds.length);
    expect(res.results.gaps).toHaveLength(0);
    expect(res.results.coverage_percent).toBe(100);
  });

  it('returns 0% for nonexistent framework', async () => {
    const res = await checkIamCompliance(db, {
      implemented: ['AC-2'],
      framework: 'nonexistent-framework',
    });

    expect(res.results.compliant).toHaveLength(0);
    expect(res.results.gaps).toHaveLength(0);
    expect(res.results.coverage_percent).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// map-frameworks
// ---------------------------------------------------------------------------
describe('map-frameworks', () => {
  it('maps NIST AC-2 to ISO equivalents', async () => {
    const res = await mapFrameworks(db, {
      control: 'AC-2',
      from: 'nist-800-53',
      to: 'iso-27001',
    });

    expect(res.results.length).toBeGreaterThan(0);
    // Should find the known mapping AC-2 → A.5.16
    const hasA516 = res.results.some((m) => m.target_control === 'A.5.16' || m.source_control === 'A.5.16');
    expect(hasA516).toBe(true);
  });

  it('returns all mappings when target framework is omitted', async () => {
    const res = await mapFrameworks(db, {
      control: 'AC-2',
      from: 'nist-800-53',
    });

    // Should include both forward (nist→iso) and reverse (cis→nist) mappings
    expect(res.results.length).toBeGreaterThan(0);
    // Forward mappings
    const forward = res.results.filter((m) => m.source_framework === 'nist-800-53' && m.source_control === 'AC-2');
    expect(forward.length).toBeGreaterThan(0);
    // Reverse mappings (other frameworks mapping TO nist-800-53 AC-2)
    const reverse = res.results.filter((m) => m.target_framework === 'nist-800-53' && m.target_control === 'AC-2');
    expect(reverse.length).toBeGreaterThan(0);
  });

  it('returns empty for unmapped control', async () => {
    const res = await mapFrameworks(db, {
      control: 'NONEXISTENT-99',
      from: 'nist-800-53',
    });

    expect(res.results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// get-assurance-levels
// ---------------------------------------------------------------------------
describe('get-assurance-levels', () => {
  it('returns all AAL levels when no level specified', async () => {
    const res = await getAssuranceLevels(db, { type: 'AAL' });

    expect(res.results.length).toBeGreaterThan(0);
    // Should have groups for AAL1, AAL2, AAL3
    const levelNames = res.results.map((g) => g.level);
    expect(levelNames).toContain('AAL1');
    expect(levelNames).toContain('AAL2');
    expect(levelNames).toContain('AAL3');

    // Each group should have standards
    for (const group of res.results) {
      expect(group.standards.length).toBeGreaterThan(0);
      expect(group.level).toMatch(/^AAL[123]$/);
    }
  });

  it('returns only AAL2 when level=2 specified', async () => {
    const res = await getAssuranceLevels(db, { type: 'AAL', level: 2 });

    expect(res.results).toHaveLength(1);
    expect(res.results[0].level).toBe('AAL2');
    expect(res.results[0].standards.length).toBeGreaterThan(0);

    // Verify all standards have AAL2 assurance level
    for (const std of res.results[0].standards) {
      expect(std.assurance_level).toBe('AAL2');
    }
  });

  it('returns FAL levels', async () => {
    const res = await getAssuranceLevels(db, { type: 'FAL' });

    expect(res.results.length).toBeGreaterThan(0);
    const levelNames = res.results.map((g) => g.level);
    expect(levelNames).toContain('FAL1');
  });

  it('handles lowercase type parameter', async () => {
    const res = await getAssuranceLevels(db, { type: 'ial' });

    expect(res.results.length).toBeGreaterThan(0);
    const levelNames = res.results.map((g) => g.level);
    expect(levelNames).toContain('IAL1');
  });
});
