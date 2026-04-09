/**
 * Golden contract tests for IAM Expert MCP.
 *
 * Loads golden-tests.json and verifies every domain tool handler against
 * its expected assertions. Tests are dynamically generated from the fixture
 * file, covering all 22 domain tools with positive and negative cases.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Database from 'better-sqlite3';
import { readFileSync, existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDatabase } from '../../scripts/build-db.js';

// --- Standards & Compliance ---
import { handler as getIamStandard } from '../../src/tools/get-iam-standard.js';
import { handler as searchIamRequirements } from '../../src/tools/search-iam-requirements.js';
import { handler as checkIamCompliance } from '../../src/tools/check-iam-compliance.js';
import { handler as mapFrameworks } from '../../src/tools/map-frameworks.js';
import { handler as getAssuranceLevels } from '../../src/tools/get-assurance-levels.js';

// --- Threat Intelligence ---
import { handler as getIamAttack } from '../../src/tools/get-iam-attack.js';
import { handler as searchIamThreats } from '../../src/tools/search-iam-threats.js';
import { handler as getIamWeakness } from '../../src/tools/get-iam-weakness.js';
import { handler as assessIamPosture } from '../../src/tools/assess-iam-posture.js';
import { handler as getIamStridePatterns } from '../../src/tools/get-iam-stride-patterns.js';

// --- Protocols & Architecture ---
import { handler as getProtocol } from '../../src/tools/get-protocol.js';
import { handler as getAccessModel } from '../../src/tools/get-access-model.js';
import { handler as recommendArchitecture } from '../../src/tools/recommend-architecture.js';
import { handler as getLifecyclePattern } from '../../src/tools/get-lifecycle-pattern.js';
import { handler as getZeroTrustPattern } from '../../src/tools/get-zero-trust-pattern.js';

// --- Vendor Guidance ---
import { handler as getVendorConfig } from '../../src/tools/get-vendor-config.js';
import { handler as compareVendors } from '../../src/tools/compare-vendors.js';
import { handler as getMisconfigurations } from '../../src/tools/get-misconfigurations.js';
import { handler as getMigrationPath } from '../../src/tools/get-migration-path.js';

// --- Emerging & Advanced ---
import { handler as getEmergingTechnology } from '../../src/tools/get-emerging-technology.js';
import { handler as getMachineIdentity } from '../../src/tools/get-machine-identity.js';
import { handler as assessIamMaturity } from '../../src/tools/assess-iam-maturity.js';

// ────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────

interface GoldenTest {
  id: string;
  category: string;
  description: string;
  tool: string;
  input: Record<string, unknown>;
  assertions: {
    result_not_empty?: boolean;
    result_empty?: boolean;
    fields_present?: string[];
    min_results?: number;
  };
}

interface GoldenFixture {
  version: string;
  mcp_name: string;
  description: string;
  tests: GoldenTest[];
}

// ────────────────────────────────────────────────────────
// Tool dispatch map
// ────────────────────────────────────────────────────────

type ToolHandler = (db: InstanceType<typeof Database>, input: never) => Promise<{ results: unknown; _meta: unknown }>;

const toolHandlers: Record<string, ToolHandler> = {
  get_iam_standard: getIamStandard as ToolHandler,
  search_iam_requirements: searchIamRequirements as ToolHandler,
  check_iam_compliance: checkIamCompliance as ToolHandler,
  map_frameworks: mapFrameworks as ToolHandler,
  get_assurance_levels: getAssuranceLevels as ToolHandler,
  get_iam_attack: getIamAttack as ToolHandler,
  search_iam_threats: searchIamThreats as ToolHandler,
  get_iam_weakness: getIamWeakness as ToolHandler,
  assess_iam_posture: assessIamPosture as ToolHandler,
  get_iam_stride_patterns: getIamStridePatterns as ToolHandler,
  get_protocol: getProtocol as ToolHandler,
  get_access_model: getAccessModel as ToolHandler,
  recommend_architecture: recommendArchitecture as ToolHandler,
  get_lifecycle_pattern: getLifecyclePattern as ToolHandler,
  get_zero_trust_pattern: getZeroTrustPattern as ToolHandler,
  get_vendor_config: getVendorConfig as ToolHandler,
  compare_vendors: compareVendors as ToolHandler,
  get_misconfigurations: getMisconfigurations as ToolHandler,
  get_migration_path: getMigrationPath as ToolHandler,
  get_emerging_technology: getEmergingTechnology as ToolHandler,
  get_machine_identity: getMachineIdentity as ToolHandler,
  assess_iam_maturity: assessIamMaturity as ToolHandler,
};

// ────────────────────────────────────────────────────────
// Setup
// ────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, '../../fixtures/golden-tests.json');
const fixture: GoldenFixture = JSON.parse(readFileSync(fixturesPath, 'utf-8'));

const TEST_DB_DIR = join(__dirname, '../../.tmp-test');
const TEST_DB_PATH = join(TEST_DB_DIR, 'test-golden-contract.db');

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

// ────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────

/**
 * Extract the results data from the handler response.
 *
 * Handlers return either:
 * - { results: SomeObject[], _meta } — array of results
 * - { results: { threats, weaknesses, ... }, _meta } — complex object
 *
 * For assertions that check array length (result_not_empty, min_results),
 * we need to determine what the "results" looks like.
 */
function getResultsArray(results: unknown): unknown[] {
  if (Array.isArray(results)) {
    return results;
  }
  // For complex objects (posture, zero-trust, machine-identity, migration, maturity, compliance),
  // treat "not empty" as having at least one truthy property.
  return [];
}

function isResultsNonEmpty(results: unknown): boolean {
  if (Array.isArray(results)) {
    return results.length > 0;
  }
  if (results !== null && typeof results === 'object') {
    // Complex result objects: check if any property has content
    const obj = results as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      if (Array.isArray(val) && val.length > 0) return true;
      if (typeof val === 'string' && val.length > 0) return true;
      if (typeof val === 'number') return true;
      if (typeof val === 'object' && val !== null && Object.keys(val).length > 0) return true;
    }
    return false;
  }
  return false;
}

function isResultsEmpty(results: unknown): boolean {
  if (Array.isArray(results)) {
    return results.length === 0;
  }
  if (results !== null && typeof results === 'object') {
    const obj = results as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      if (Array.isArray(val) && val.length > 0) return false;
      if (typeof val === 'string' && val.length > 0) return false;
      if (typeof val === 'number' && val > 0) return false;
      if (typeof val === 'object' && val !== null && Object.keys(val).length > 0) return false;
    }
    return true;
  }
  return true;
}

/**
 * Check that specific fields are present on the results.
 *
 * - For array results: check the first element has the fields.
 * - For object results: check the object itself has the fields.
 */
function checkFieldsPresent(results: unknown, fields: string[]): void {
  let target: Record<string, unknown>;

  if (Array.isArray(results)) {
    expect(results.length).toBeGreaterThan(0);
    target = results[0] as Record<string, unknown>;
  } else {
    target = results as Record<string, unknown>;
  }

  for (const field of fields) {
    expect(target).toHaveProperty(field);
  }
}

// ────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────

describe('Golden contract tests', () => {
  it('fixture file is valid', () => {
    expect(fixture.version).toBe('1.0');
    expect(fixture.mcp_name).toBe('IAM Expert MCP');
    expect(fixture.tests.length).toBeGreaterThanOrEqual(44);
  });

  it('all tools in fixture have registered handlers', () => {
    const toolNames = new Set(fixture.tests.map((t) => t.tool));
    for (const tool of toolNames) {
      expect(toolHandlers).toHaveProperty(tool);
    }
  });

  // Group tests by category for organized output
  const categories = [...new Set(fixture.tests.map((t) => t.category))];

  for (const category of categories) {
    const categoryTests = fixture.tests.filter((t) => t.category === category);

    describe(`[${category}]`, () => {
      for (const test of categoryTests) {
        it(`${test.id}: ${test.description}`, async () => {
          const handler = toolHandlers[test.tool];
          expect(handler).toBeDefined();

          const response = await handler(db, test.input as never);
          expect(response).toBeDefined();
          expect(response._meta).toBeDefined();

          const { results } = response;

          // --- result_not_empty ---
          if (test.assertions.result_not_empty === true) {
            expect(
              isResultsNonEmpty(results),
            ).toBe(true);
          }

          // --- result_empty ---
          if (test.assertions.result_empty === true) {
            expect(
              isResultsEmpty(results),
            ).toBe(true);
          }

          // --- fields_present ---
          if (test.assertions.fields_present) {
            checkFieldsPresent(results, test.assertions.fields_present);
          }

          // --- min_results ---
          if (test.assertions.min_results !== undefined) {
            const arr = getResultsArray(results);
            expect(arr.length).toBeGreaterThanOrEqual(test.assertions.min_results);
          }
        });
      }
    });
  }
});

// ────────────────────────────────────────────────────────
// Coverage validation
// ────────────────────────────────────────────────────────

describe('Golden test coverage', () => {
  it('covers all 22 domain tools', () => {
    const testedTools = new Set(fixture.tests.map((t) => t.tool));

    const allDomainTools = [
      'get_iam_standard',
      'search_iam_requirements',
      'check_iam_compliance',
      'map_frameworks',
      'get_assurance_levels',
      'get_iam_attack',
      'search_iam_threats',
      'get_iam_weakness',
      'assess_iam_posture',
      'get_iam_stride_patterns',
      'get_protocol',
      'get_access_model',
      'recommend_architecture',
      'get_lifecycle_pattern',
      'get_zero_trust_pattern',
      'get_vendor_config',
      'compare_vendors',
      'get_misconfigurations',
      'get_migration_path',
      'get_emerging_technology',
      'get_machine_identity',
      'assess_iam_maturity',
    ];

    for (const tool of allDomainTools) {
      expect(testedTools).toContain(tool);
    }
  });

  it('has at least 2 tests per domain tool', () => {
    const toolCounts: Record<string, number> = {};
    for (const test of fixture.tests) {
      toolCounts[test.tool] = (toolCounts[test.tool] || 0) + 1;
    }

    const allDomainTools = Object.keys(toolHandlers);
    for (const tool of allDomainTools) {
      expect(toolCounts[tool] ?? 0).toBeGreaterThanOrEqual(2);
    }
  });

  it('includes negative tests', () => {
    const negativeTests = fixture.tests.filter((t) => t.category === 'negative');
    expect(negativeTests.length).toBeGreaterThanOrEqual(4);
  });

  it('has at least 44 total tests', () => {
    expect(fixture.tests.length).toBeGreaterThanOrEqual(44);
  });
});
