/**
 * about — Server metadata, dataset statistics, and provenance.
 */

import type Database from '@ansvar/mcp-sqlite';
import { detectCapabilities, readDbMetadata } from '../capabilities.js';
import { SERVER_NAME, SERVER_VERSION, REPOSITORY_URL } from '../constants.js';

export interface AboutContext {
  version: string;
  fingerprint: string;
  dbBuilt: string;
}

function safeCount(db: InstanceType<typeof Database>, sql: string): number {
  try {
    const row = db.prepare(sql).get() as { count: number } | undefined;
    return row ? Number(row.count) : 0;
  } catch {
    return 0;
  }
}

export function getAbout(db: InstanceType<typeof Database>, context: AboutContext) {
  const caps = detectCapabilities(db);
  const meta = readDbMetadata(db);

  return {
    server: SERVER_NAME,
    version: context.version,
    repository: REPOSITORY_URL,
    database: {
      fingerprint: context.fingerprint,
      built_at: context.dbBuilt,
      tier: meta.tier,
      schema_version: meta.schema_version,
      capabilities: [...caps],
    },
    statistics: {
      standards: safeCount(db, 'SELECT COUNT(*) as count FROM standards'),
      protocols: safeCount(db, 'SELECT COUNT(*) as count FROM protocols'),
      attack_patterns: safeCount(db, 'SELECT COUNT(*) as count FROM attack_patterns'),
      iam_weaknesses: safeCount(db, 'SELECT COUNT(*) as count FROM iam_weaknesses'),
      architecture_patterns: safeCount(db, 'SELECT COUNT(*) as count FROM architecture_patterns'),
      vendor_configurations: safeCount(db, 'SELECT COUNT(*) as count FROM vendor_configurations'),
      compliance_mappings: safeCount(db, 'SELECT COUNT(*) as count FROM compliance_mappings'),
      emerging_technologies: safeCount(db, 'SELECT COUNT(*) as count FROM emerging_technologies'),
    },
    data_sources: {
      summary:
        'NIST (800-53/63/207), MITRE (ATT&CK/CWE/CAPEC), OWASP ASVS, ' +
        'CISA ZTMM, IETF RFCs (OAuth/OIDC/SAML/SCIM), W3C (FIDO2/DIDs/VCs), ' +
        'vendor documentation (Azure/AWS/GCP/Okta/Ping/CyberArk/SailPoint), ' +
        'ISO 27001/27002, SOC 2 TSC',
      count: 21,
      details: 'Use list_sources tool for full provenance metadata.',
    },
  };
}
