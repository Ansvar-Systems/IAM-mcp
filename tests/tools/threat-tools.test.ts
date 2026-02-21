import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../../scripts/build-db.js';

// Tool handlers
import { handler as getIamAttack } from '../../src/tools/get-iam-attack.js';
import { handler as searchIamThreats } from '../../src/tools/search-iam-threats.js';
import { handler as getIamWeakness } from '../../src/tools/get-iam-weakness.js';
import { handler as assessIamPosture } from '../../src/tools/assess-iam-posture.js';
import { handler as getIamStridePatterns } from '../../src/tools/get-iam-stride-patterns.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = join(__dirname, '..', '..', '.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-threat-tools.db');

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
// get-iam-attack
// ---------------------------------------------------------------------------
describe('get-iam-attack', () => {
  it('returns full Brute Force details with sub-techniques for T1110', async () => {
    const res = await getIamAttack(db, { id: 'T1110' });

    // T1110 exact match + sub-techniques (T1110.001-004) all share the prefix
    expect(res.results.length).toBeGreaterThanOrEqual(1);

    // The first result is the exact match
    const attack = res.results[0];
    expect(attack.id).toBe('T1110');
    expect(attack.name).toBe('Brute Force');
    expect(attack.tactic).toBe('credential-access');
    expect(attack.description).toBeTruthy();
    expect(Array.isArray(attack.sub_techniques)).toBe(true);
    expect(attack.sub_techniques).toContain('T1110.001');
    expect(attack.sub_techniques).toContain('T1110.003');
    expect(attack.sub_techniques.length).toBe(4);
    expect(Array.isArray(attack.mitigation_controls)).toBe(true);
    expect(attack.mitigation_controls.length).toBeGreaterThan(0);
    expect(attack.stride_category).toBe('spoofing');
    expect(attack.severity).toBe('high');
    expect(res._metadata.domain).toBe('iam');

    // All results should have IDs starting with T1110
    for (const r of res.results) {
      expect(r.id).toMatch(/^T1110/);
    }
  });

  it('returns all T1078 variants via prefix search', async () => {
    const res = await getIamAttack(db, { id: 'T1078' });

    // T1078 exists in multiple tactics (credential-access, initial-access, persistence, etc.)
    expect(res.results.length).toBeGreaterThan(1);
    // All results should have an ID starting with T1078
    for (const attack of res.results) {
      expect(attack.id).toMatch(/^T1078/);
    }
  });

  it('returns empty array for nonexistent technique', async () => {
    const res = await getIamAttack(db, { id: 'T9999' });
    expect(res.results).toHaveLength(0);
    expect(res._metadata).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// search-iam-threats
// ---------------------------------------------------------------------------
describe('search-iam-threats', () => {
  it('returns all credential access techniques when filtering by tactic', async () => {
    const res = await searchIamThreats(db, { tactic: 'credential-access' });

    expect(res.results.length).toBeGreaterThan(0);
    for (const attack of res.results) {
      expect(attack.tactic).toBe('credential-access');
    }
  });

  it('returns STRIDE-mapped spoofing threats', async () => {
    const res = await searchIamThreats(db, { stride: 'spoofing' });

    expect(res.results.length).toBeGreaterThan(0);
    for (const attack of res.results) {
      expect(attack.stride_category).toBe('spoofing');
    }
  });

  it('FTS5 search for "password spray" returns relevant attack patterns', async () => {
    const res = await searchIamThreats(db, { query: 'password spray' });

    expect(res.results.length).toBeGreaterThan(0);
    // At least one result should relate to password spraying
    const hasSpray = res.results.some(
      (a) =>
        a.name.toLowerCase().includes('spray') ||
        a.description.toLowerCase().includes('spray'),
    );
    expect(hasSpray).toBe(true);
  });

  it('combines query and stride filter', async () => {
    const res = await searchIamThreats(db, {
      query: 'password',
      stride: 'spoofing',
    });

    expect(res.results.length).toBeGreaterThan(0);
    for (const attack of res.results) {
      expect(attack.stride_category).toBe('spoofing');
    }
  });

  it('respects limit parameter', async () => {
    const res = await searchIamThreats(db, { limit: 3 });

    expect(res.results.length).toBeLessThanOrEqual(3);
    expect(res.results.length).toBeGreaterThan(0);
  });

  it('filters by severity', async () => {
    const res = await searchIamThreats(db, { severity: 'critical' });

    expect(res.results.length).toBeGreaterThan(0);
    for (const attack of res.results) {
      expect(attack.severity).toBe('critical');
    }
  });
});

// ---------------------------------------------------------------------------
// get-iam-weakness
// ---------------------------------------------------------------------------
describe('get-iam-weakness', () => {
  it('returns Improper Authentication with CAPEC cross-refs for CWE-287', async () => {
    const res = await getIamWeakness(db, { cwe_id: 'CWE-287' });

    expect(res.results).toHaveLength(1);
    const weakness = res.results[0];
    expect(weakness.cwe_id).toBe('CWE-287');
    expect(weakness.title).toContain('Improper Authentication');
    expect(Array.isArray(weakness.capec_ids)).toBe(true);
    expect(weakness.capec_ids.length).toBeGreaterThan(0);
    expect(weakness.capec_ids).toContain('CAPEC-114');
    expect(Array.isArray(weakness.affected_protocols)).toBe(true);
    expect(weakness.affected_protocols.length).toBeGreaterThan(0);
    expect(weakness.stride_category).toBeTruthy();
    expect(weakness.severity).toBeTruthy();
    expect(res._metadata.domain).toBe('iam');
  });

  it('returns empty array for nonexistent CWE', async () => {
    const res = await getIamWeakness(db, { cwe_id: 'CWE-99999' });
    expect(res.results).toHaveLength(0);
    expect(res._metadata).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// assess-iam-posture
// ---------------------------------------------------------------------------
describe('assess-iam-posture', () => {
  it('returns applicable threats and weaknesses for architecture components', async () => {
    const res = await assessIamPosture(db, {
      components: ['password-auth', 'no-mfa', 'shared-accounts'],
    });

    expect(res.results.threats.length).toBeGreaterThan(0);
    expect(res.results.weaknesses.length).toBeGreaterThan(0);

    // Threats should be deduplicated (no duplicate IDs)
    const threatIds = res.results.threats.map((t: { id: string }) => t.id);
    expect(new Set(threatIds).size).toBe(threatIds.length);

    // Weaknesses should be deduplicated
    const weaknessIds = res.results.weaknesses.map((w: { cwe_id: string }) => w.cwe_id);
    expect(new Set(weaknessIds).size).toBe(weaknessIds.length);

    expect(res._metadata.domain).toBe('iam');
  });

  it('returns results filtered by stride category', async () => {
    const res = await assessIamPosture(db, {
      components: ['password'],
      stride_filter: 'spoofing',
    });

    expect(res.results.threats.length).toBeGreaterThan(0);
    for (const threat of res.results.threats) {
      expect(threat.stride_category).toBe('spoofing');
    }
    for (const weakness of res.results.weaknesses) {
      expect(weakness.stride_category).toBe('spoofing');
    }
  });

  it('returns empty results for irrelevant components', async () => {
    const res = await assessIamPosture(db, {
      components: ['xyznonexistent123'],
    });

    expect(res.results.threats).toHaveLength(0);
    expect(res.results.weaknesses).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// get-iam-stride-patterns
// ---------------------------------------------------------------------------
describe('get-iam-stride-patterns', () => {
  it('returns all STRIDE threats for SSO gateway', async () => {
    const res = await getIamStridePatterns(db, { component: 'SSO gateway' });

    // Should have results grouped by STRIDE category
    expect(res.results.length).toBeGreaterThan(0);

    // Each group has a category and patterns array
    for (const group of res.results) {
      expect(group.category).toBeTruthy();
      expect(Array.isArray(group.patterns)).toBe(true);
      expect(group.patterns.length).toBeGreaterThan(0);
    }
  });

  it('filters by specific stride_category', async () => {
    const res = await getIamStridePatterns(db, {
      component: 'SSO',
      stride_category: 'spoofing',
    });

    expect(res.results.length).toBeLessThanOrEqual(1);
    if (res.results.length > 0) {
      expect(res.results[0].category).toBe('spoofing');
    }
  });

  it('returns empty groups for irrelevant component', async () => {
    const res = await getIamStridePatterns(db, { component: 'xyznonexistent456' });
    expect(res.results).toHaveLength(0);
  });
});
