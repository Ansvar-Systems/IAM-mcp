import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../../scripts/build-db.js';

// Tool handlers
import { handler as getProtocol } from '../../src/tools/get-protocol.js';
import { handler as getAccessModel } from '../../src/tools/get-access-model.js';
import { handler as recommendArchitecture } from '../../src/tools/recommend-architecture.js';
import { handler as getLifecyclePattern } from '../../src/tools/get-lifecycle-pattern.js';
import { handler as getZeroTrustPattern } from '../../src/tools/get-zero-trust-pattern.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = join(__dirname, '..', '..', '.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-architecture-tools.db');

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
// get-protocol
// ---------------------------------------------------------------------------
describe('get-protocol', () => {
  it('returns full flow details with sequence diagram for oauth2-authorization-code-pkce', async () => {
    const res = await getProtocol(db, { id: 'oauth2-authorization-code-pkce' });

    expect(res.results).toHaveLength(1);
    const protocol = res.results[0];
    expect(protocol.id).toBe('oauth2-authorization-code-pkce');
    expect(protocol.protocol).toBe('oauth2');
    expect(protocol.flow_type).toBe('authorization-code-pkce');
    expect(protocol.description).toBeTruthy();
    expect(protocol.security_considerations).toBeTruthy();
    expect(Array.isArray(protocol.recommended_for)).toBe(true);
    expect(protocol.recommended_for.length).toBeGreaterThan(0);
    expect(protocol.deprecated).toBe(false);
    expect(protocol.rfc).toBeTruthy();
    expect(protocol.sequence_diagram).toBeTruthy();
    expect(res._metadata.domain).toBe('iam');
  });

  it('returns empty results for NONEXISTENT', async () => {
    const res = await getProtocol(db, { id: 'NONEXISTENT' });
    expect(res.results).toHaveLength(0);
    expect(res._metadata).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// get-access-model
// ---------------------------------------------------------------------------
describe('get-access-model', () => {
  it('returns RBAC details with when-to-use, compliance mappings', async () => {
    const res = await getAccessModel(db, { id: 'rbac' });

    expect(res.results).toHaveLength(1);
    const model = res.results[0];
    expect(model.id).toBe('rbac');
    expect(model.name).toContain('Role-Based Access Control');
    expect(model.category).toBe('access-model');
    expect(model.description).toBeTruthy();
    expect(model.when_to_use).toBeTruthy();
    expect(Array.isArray(model.components)).toBe(true);
    expect(model.components.length).toBeGreaterThan(0);
    expect(Array.isArray(model.compliance_mappings)).toBe(true);
    expect(model.compliance_mappings.length).toBeGreaterThan(0);
    expect(Array.isArray(model.related_patterns)).toBe(true);
    expect(model.related_patterns.length).toBeGreaterThan(0);
    expect(res._metadata.domain).toBe('iam');
  });

  it('returns empty results for NONEXISTENT', async () => {
    const res = await getAccessModel(db, { id: 'NONEXISTENT' });
    expect(res.results).toHaveLength(0);
    expect(res._metadata).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// recommend-architecture
// ---------------------------------------------------------------------------
describe('recommend-architecture', () => {
  it('returns recommended patterns for scale, compliance, and existing vendor', async () => {
    const res = await recommendArchitecture(db, {
      scale: '10000-users',
      compliance: ['nist-800-53', 'soc2'],
      existing: 'azure-entra',
    });

    expect(res.results.length).toBeGreaterThan(0);
    // Each recommendation should have id, name, category, and a relevance score
    for (const rec of res.results) {
      expect(rec.id).toBeTruthy();
      expect(rec.name).toBeTruthy();
      expect(rec.category).toBeTruthy();
      expect(typeof rec.score).toBe('number');
      expect(rec.score).toBeGreaterThan(0);
    }
    expect(res._metadata.domain).toBe('iam');
  });
});

// ---------------------------------------------------------------------------
// get-lifecycle-pattern
// ---------------------------------------------------------------------------
describe('get-lifecycle-pattern', () => {
  it('returns Joiner-Mover-Leaver pattern by ID "jml-lifecycle"', async () => {
    const res = await getLifecyclePattern(db, { id: 'jml-lifecycle' });

    expect(res.results).toHaveLength(1);
    const pattern = res.results[0];
    expect(pattern.id).toBe('jml-lifecycle');
    expect(pattern.name).toContain('Joiner-Mover-Leaver');
    expect(pattern.category).toBe('lifecycle');
    expect(pattern.description).toBeTruthy();
    expect(pattern.when_to_use).toBeTruthy();
    expect(Array.isArray(pattern.components)).toBe(true);
    expect(pattern.components.length).toBeGreaterThan(0);
    expect(Array.isArray(pattern.compliance_mappings)).toBe(true);
    expect(pattern.compliance_mappings.length).toBeGreaterThan(0);
    expect(Array.isArray(pattern.related_patterns)).toBe(true);
    expect(pattern.related_patterns.length).toBeGreaterThan(0);
    expect(res._metadata.domain).toBe('iam');
  });

  it('returns all lifecycle patterns when category is "lifecycle"', async () => {
    const res = await getLifecyclePattern(db, { category: 'lifecycle' });

    expect(res.results.length).toBeGreaterThan(1);
    for (const pattern of res.results) {
      expect(pattern.category).toBe('lifecycle');
      expect(Array.isArray(pattern.components)).toBe(true);
      expect(Array.isArray(pattern.compliance_mappings)).toBe(true);
      expect(Array.isArray(pattern.related_patterns)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// get-zero-trust-pattern
// ---------------------------------------------------------------------------
describe('get-zero-trust-pattern', () => {
  it('returns ZT guidance for identity pillar at advanced maturity', async () => {
    const res = await getZeroTrustPattern(db, { pillar: 'identity', maturity: 'advanced' });

    expect(res.results.standards.length).toBeGreaterThan(0);
    // All returned standards should be for the identity pillar
    for (const std of res.results.standards) {
      expect(std.zero_trust_pillar).toBe('identity');
      expect(std.maturity_level).toBe('advanced');
    }
    // Should also include ZT architecture patterns
    expect(Array.isArray(res.results.patterns)).toBe(true);
    expect(res._metadata.domain).toBe('iam');
  });

  it('returns all maturity levels for identity pillar when no maturity specified', async () => {
    const res = await getZeroTrustPattern(db, { pillar: 'identity' });

    expect(res.results.standards.length).toBeGreaterThan(0);
    // All standards should be for the identity pillar
    for (const std of res.results.standards) {
      expect(std.zero_trust_pillar).toBe('identity');
    }
    // Should have a mix of maturity levels
    const maturityLevels = new Set(res.results.standards.map((s: { maturity_level: string }) => s.maturity_level));
    expect(maturityLevels.size).toBeGreaterThan(1);
    // Should also include ZT architecture patterns
    expect(Array.isArray(res.results.patterns)).toBe(true);
    expect(res.results.patterns.length).toBeGreaterThan(0);
  });
});
