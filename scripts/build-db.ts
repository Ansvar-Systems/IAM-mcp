import Database from 'better-sqlite3';
import { existsSync, unlinkSync, readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_DB_PATH = join(__dirname, '..', 'data', 'database.db');

const SCHEMA = `
-- IAM standards and framework requirements
CREATE TABLE standards (
  id TEXT PRIMARY KEY,
  framework TEXT NOT NULL,
  section TEXT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('authentication','authorization','identity-lifecycle','privileged-access','federation','monitoring','session-management','credential-management')),
  assurance_level TEXT,
  zero_trust_pillar TEXT,
  maturity_level TEXT,
  cross_references TEXT NOT NULL DEFAULT '[]'
);

-- Identity protocols (OAuth, OIDC, SAML, FIDO2, SCIM, etc.)
CREATE TABLE protocols (
  id TEXT PRIMARY KEY,
  protocol TEXT NOT NULL,
  flow_type TEXT,
  description TEXT NOT NULL,
  security_considerations TEXT NOT NULL,
  recommended_for TEXT NOT NULL DEFAULT '[]',
  deprecated INTEGER NOT NULL DEFAULT 0,
  rfc TEXT,
  sequence_diagram TEXT
);

-- MITRE ATT&CK IAM attack patterns
CREATE TABLE attack_patterns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tactic TEXT NOT NULL,
  description TEXT NOT NULL,
  sub_techniques TEXT NOT NULL DEFAULT '[]',
  detection_guidance TEXT,
  mitigation_controls TEXT NOT NULL DEFAULT '[]',
  stride_category TEXT NOT NULL CHECK(stride_category IN ('spoofing','tampering','repudiation','information_disclosure','denial_of_service','elevation_of_privilege')),
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
  real_world_examples TEXT
);

-- CWE identity/access weaknesses
CREATE TABLE iam_weaknesses (
  cwe_id TEXT PRIMARY KEY,
  capec_ids TEXT NOT NULL DEFAULT '[]',
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('authentication','authorization','session-management','privilege-management','credential-storage')),
  affected_protocols TEXT NOT NULL DEFAULT '[]',
  stride_category TEXT NOT NULL CHECK(stride_category IN ('spoofing','tampering','repudiation','information_disclosure','denial_of_service','elevation_of_privilege')),
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
  detection_guidance TEXT,
  remediation TEXT
);

-- IAM architecture / design patterns
CREATE TABLE architecture_patterns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('access-model','federation','privileged-access','lifecycle','zero-trust','directory','ciam')),
  description TEXT NOT NULL,
  when_to_use TEXT NOT NULL,
  when_not_to_use TEXT,
  components TEXT NOT NULL DEFAULT '[]',
  data_flow TEXT,
  strengths TEXT,
  weaknesses TEXT,
  compliance_mappings TEXT NOT NULL DEFAULT '[]',
  related_patterns TEXT NOT NULL DEFAULT '[]'
);

-- Vendor-specific IAM configuration guidance
CREATE TABLE vendor_configurations (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL CHECK(vendor IN ('azure-entra','aws-iam','gcp-iam','okta','auth0','ping','forgerock','cyberark','sailpoint')),
  feature TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('authentication','authorization','privileged-access','governance','federation','monitoring')),
  description TEXT NOT NULL,
  best_practices TEXT,
  common_misconfigurations TEXT NOT NULL DEFAULT '[]',
  compliance_controls TEXT NOT NULL DEFAULT '[]',
  equivalent_in TEXT NOT NULL DEFAULT '{}'
);

-- Cross-framework compliance mappings
CREATE TABLE compliance_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_framework TEXT NOT NULL,
  source_control TEXT NOT NULL,
  target_framework TEXT NOT NULL,
  target_control TEXT NOT NULL,
  relationship TEXT NOT NULL CHECK(relationship IN ('equivalent','partial','superset','subset')),
  notes TEXT
);

-- Emerging IAM technologies
CREATE TABLE emerging_technologies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('passwordless','decentralized-identity','machine-identity','ciam','identity-fabric')),
  description TEXT NOT NULL,
  maturity TEXT NOT NULL CHECK(maturity IN ('experimental','emerging','mainstream','deprecated')),
  standards TEXT NOT NULL DEFAULT '[]',
  adoption_status TEXT,
  use_cases TEXT NOT NULL DEFAULT '[]',
  migration_from TEXT,
  vendor_support TEXT NOT NULL DEFAULT '{}'
);

-- FTS5: full-text search on standards
CREATE VIRTUAL TABLE standards_fts USING fts5(
  title, description, section,
  content='standards',
  content_rowid='rowid',
  tokenize='unicode61'
);
CREATE TRIGGER standards_ai AFTER INSERT ON standards BEGIN
  INSERT INTO standards_fts(rowid, title, description, section) VALUES (new.rowid, new.title, new.description, new.section);
END;

-- FTS5: full-text search on attack patterns
CREATE VIRTUAL TABLE attack_patterns_fts USING fts5(
  name, description, detection_guidance, real_world_examples,
  content='attack_patterns',
  content_rowid='rowid',
  tokenize='unicode61'
);
CREATE TRIGGER attack_patterns_ai AFTER INSERT ON attack_patterns BEGIN
  INSERT INTO attack_patterns_fts(rowid, name, description, detection_guidance, real_world_examples) VALUES (new.rowid, new.name, new.description, new.detection_guidance, new.real_world_examples);
END;

-- FTS5: full-text search on IAM weaknesses
CREATE VIRTUAL TABLE weaknesses_fts USING fts5(
  title, description, detection_guidance, remediation,
  content='iam_weaknesses',
  content_rowid='rowid',
  tokenize='unicode61'
);
CREATE TRIGGER weaknesses_ai AFTER INSERT ON iam_weaknesses BEGIN
  INSERT INTO weaknesses_fts(rowid, title, description, detection_guidance, remediation) VALUES (new.rowid, new.title, new.description, new.detection_guidance, new.remediation);
END;

-- FTS5: full-text search on vendor configurations
CREATE VIRTUAL TABLE vendor_fts USING fts5(
  feature, description, best_practices,
  content='vendor_configurations',
  content_rowid='rowid',
  tokenize='unicode61'
);
CREATE TRIGGER vendor_ai AFTER INSERT ON vendor_configurations BEGIN
  INSERT INTO vendor_fts(rowid, feature, description, best_practices) VALUES (new.rowid, new.feature, new.description, new.best_practices);
END;

-- FTS5: full-text search on architecture patterns
CREATE VIRTUAL TABLE patterns_fts USING fts5(
  name, description, when_to_use, strengths,
  content='architecture_patterns',
  content_rowid='rowid',
  tokenize='unicode61'
);
CREATE TRIGGER patterns_ai AFTER INSERT ON architecture_patterns BEGIN
  INSERT INTO patterns_fts(rowid, name, description, when_to_use, strengths) VALUES (new.rowid, new.name, new.description, new.when_to_use, new.strengths);
END;

-- Metadata key-value store
CREATE TABLE db_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

/**
 * Stringify a value if it is an array or object; pass through strings.
 */
function jsonify(value: unknown): string {
  if (value === null || value === undefined) return '[]';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

/**
 * Stringify a value if it is an object; pass through strings.
 */
function jsonifyObj(value: unknown): string {
  if (value === null || value === undefined) return '{}';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

/**
 * Build the IAM MCP SQLite database from seed JSON files.
 *
 * @param dbPath - Output path (defaults to IAM_DB_PATH env or data/database.db)
 */
export function buildDatabase(dbPath?: string): void {
  const resolvedPath = dbPath ?? process.env.IAM_DB_PATH ?? DEFAULT_DB_PATH;

  if (existsSync(resolvedPath)) unlinkSync(resolvedPath);

  const db = new Database(resolvedPath);
  db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);

  // --- Prepared statements for each table ---
  const insertStandard = db.prepare(`
    INSERT INTO standards (id, framework, section, title, description, category,
      assurance_level, zero_trust_pillar, maturity_level, cross_references)
    VALUES (@id, @framework, @section, @title, @description, @category,
      @assurance_level, @zero_trust_pillar, @maturity_level, @cross_references)
  `);

  const insertProtocol = db.prepare(`
    INSERT INTO protocols (id, protocol, flow_type, description, security_considerations,
      recommended_for, deprecated, rfc, sequence_diagram)
    VALUES (@id, @protocol, @flow_type, @description, @security_considerations,
      @recommended_for, @deprecated, @rfc, @sequence_diagram)
  `);

  const insertAttackPattern = db.prepare(`
    INSERT INTO attack_patterns (id, name, tactic, description, sub_techniques,
      detection_guidance, mitigation_controls, stride_category, severity, real_world_examples)
    VALUES (@id, @name, @tactic, @description, @sub_techniques,
      @detection_guidance, @mitigation_controls, @stride_category, @severity, @real_world_examples)
  `);

  const insertWeakness = db.prepare(`
    INSERT INTO iam_weaknesses (cwe_id, capec_ids, title, description, category,
      affected_protocols, stride_category, severity, detection_guidance, remediation)
    VALUES (@cwe_id, @capec_ids, @title, @description, @category,
      @affected_protocols, @stride_category, @severity, @detection_guidance, @remediation)
  `);

  const insertPattern = db.prepare(`
    INSERT INTO architecture_patterns (id, name, category, description, when_to_use,
      when_not_to_use, components, data_flow, strengths, weaknesses, compliance_mappings, related_patterns)
    VALUES (@id, @name, @category, @description, @when_to_use,
      @when_not_to_use, @components, @data_flow, @strengths, @weaknesses, @compliance_mappings, @related_patterns)
  `);

  const insertVendor = db.prepare(`
    INSERT INTO vendor_configurations (id, vendor, feature, category, description,
      best_practices, common_misconfigurations, compliance_controls, equivalent_in)
    VALUES (@id, @vendor, @feature, @category, @description,
      @best_practices, @common_misconfigurations, @compliance_controls, @equivalent_in)
  `);

  const insertMapping = db.prepare(`
    INSERT INTO compliance_mappings (source_framework, source_control, target_framework,
      target_control, relationship, notes)
    VALUES (@source_framework, @source_control, @target_framework,
      @target_control, @relationship, @notes)
  `);

  const insertEmerging = db.prepare(`
    INSERT INTO emerging_technologies (id, name, category, description, maturity,
      standards, adoption_status, use_cases, migration_from, vendor_support)
    VALUES (@id, @name, @category, @description, @maturity,
      @standards, @adoption_status, @use_cases, @migration_from, @vendor_support)
  `);

  // --- Load and insert seed data ---
  const seedDir = join(__dirname, '..', 'data', 'seed');
  if (existsSync(seedDir)) {
    const seedFiles = readdirSync(seedDir)
      .filter((f) => f.endsWith('.json'))
      .sort();

    db.transaction(() => {
      for (const file of seedFiles) {
        const data = JSON.parse(readFileSync(join(seedDir, file), 'utf-8'));

        if (data.standards) {
          for (const row of data.standards) {
            insertStandard.run({
              id: row.id,
              framework: row.framework,
              section: row.section ?? null,
              title: row.title,
              description: row.description,
              category: row.category,
              assurance_level: row.assurance_level ?? null,
              zero_trust_pillar: row.zero_trust_pillar ?? null,
              maturity_level: row.maturity_level ?? null,
              cross_references: jsonify(row.cross_references),
            });
          }
        }

        if (data.protocols) {
          for (const row of data.protocols) {
            insertProtocol.run({
              id: row.id,
              protocol: row.protocol,
              flow_type: row.flow_type ?? null,
              description: row.description,
              security_considerations: row.security_considerations,
              recommended_for: jsonify(row.recommended_for),
              deprecated: row.deprecated ? 1 : 0,
              rfc: row.rfc ?? null,
              sequence_diagram: row.sequence_diagram ?? null,
            });
          }
        }

        if (data.attack_patterns) {
          for (const row of data.attack_patterns) {
            insertAttackPattern.run({
              id: row.id,
              name: row.name,
              tactic: row.tactic,
              description: row.description,
              sub_techniques: jsonify(row.sub_techniques),
              detection_guidance: row.detection_guidance ?? null,
              mitigation_controls: jsonify(row.mitigation_controls),
              stride_category: row.stride_category,
              severity: row.severity,
              real_world_examples: row.real_world_examples ?? null,
            });
          }
        }

        if (data.weaknesses) {
          for (const row of data.weaknesses) {
            insertWeakness.run({
              cwe_id: row.cwe_id,
              capec_ids: jsonify(row.capec_ids),
              title: row.title,
              description: row.description,
              category: row.category,
              affected_protocols: jsonify(row.affected_protocols),
              stride_category: row.stride_category,
              severity: row.severity,
              detection_guidance: row.detection_guidance ?? null,
              remediation: row.remediation ?? null,
            });
          }
        }

        if (data.architecture_patterns) {
          for (const row of data.architecture_patterns) {
            insertPattern.run({
              id: row.id,
              name: row.name,
              category: row.category,
              description: row.description,
              when_to_use: row.when_to_use,
              when_not_to_use: row.when_not_to_use ?? null,
              components: jsonify(row.components),
              data_flow: row.data_flow ?? null,
              strengths: row.strengths ?? null,
              weaknesses: row.weaknesses ?? null,
              compliance_mappings: jsonify(row.compliance_mappings),
              related_patterns: jsonify(row.related_patterns),
            });
          }
        }

        if (data.vendor_configurations) {
          for (const row of data.vendor_configurations) {
            insertVendor.run({
              id: row.id,
              vendor: row.vendor,
              feature: row.feature,
              category: row.category,
              description: row.description,
              best_practices: row.best_practices ?? null,
              common_misconfigurations: jsonify(row.common_misconfigurations),
              compliance_controls: jsonify(row.compliance_controls),
              equivalent_in: jsonifyObj(row.equivalent_in),
            });
          }
        }

        if (data.compliance_mappings) {
          for (const row of data.compliance_mappings) {
            insertMapping.run({
              source_framework: row.source_framework,
              source_control: row.source_control,
              target_framework: row.target_framework,
              target_control: row.target_control,
              relationship: row.relationship,
              notes: row.notes ?? null,
            });
          }
        }

        if (data.emerging_technologies) {
          for (const row of data.emerging_technologies) {
            insertEmerging.run({
              id: row.id,
              name: row.name,
              category: row.category,
              description: row.description,
              maturity: row.maturity,
              standards: jsonify(row.standards),
              adoption_status: row.adoption_status ?? null,
              use_cases: jsonify(row.use_cases),
              migration_from: row.migration_from ?? null,
              vendor_support: jsonifyObj(row.vendor_support),
            });
          }
        }
      }
    })();
  }

  // --- Metadata ---
  const insertMeta = db.prepare('INSERT INTO db_metadata (key, value) VALUES (?, ?)');
  db.transaction(() => {
    insertMeta.run('tier', 'free');
    insertMeta.run('schema_version', '1');
    insertMeta.run('built_at', new Date().toISOString());
    insertMeta.run('builder', 'build-db.ts');
    insertMeta.run('domain', 'iam');
    insertMeta.run('source', 'NIST SP 800-63/800-53/800-207, MITRE ATT&CK/CWE/CAPEC, OWASP ASVS, CISA Zero Trust, IETF RFCs, OpenID/FIDO/W3C, ISO 27001/27002, SOC 2, Vendor docs');
    insertMeta.run('licence', 'Mixed: Public Domain (NIST/CISA), Apache-2.0 (OIDC), MITRE Terms of Use (ATT&CK/CWE/CAPEC), CC BY-SA 4.0 (OWASP), Fair Use (vendor guidance/ISO/SOC 2)');
  })();

  // --- Finalize for serverless deployment (no WAL) ---
  db.pragma('journal_mode = DELETE');
  db.exec('ANALYZE');
  db.exec('VACUUM');
  db.close();

  console.log(`Database built: ${resolvedPath}`);
}

// CLI entry point
const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && (process.argv[1] === currentFile || process.argv[1] === currentFile.replace(/\.ts$/, '.js'))) {
  buildDatabase();
}
