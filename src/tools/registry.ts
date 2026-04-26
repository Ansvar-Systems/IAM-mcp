/**
 * Tool registry for IAM Expert MCP Server.
 * Shared between stdio (index.ts) and HTTP (api/mcp.ts) entry points.
 *
 * Registers all 24 tools: 22 domain tools + about + list_sources.
 * Tools are conditionally registered based on detected database capabilities.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type Database from '@ansvar/mcp-sqlite';

import type { Capability } from '../capabilities.js';

// --- Standards & Compliance ---
import { handler as getIamStandard, type GetIamStandardInput } from './get-iam-standard.js';
import { handler as searchIamRequirements, type SearchIamRequirementsInput } from './search-iam-requirements.js';
import { handler as checkIamCompliance, type CheckIamComplianceInput } from './check-iam-compliance.js';
import { handler as mapFrameworks, type MapFrameworksInput } from './map-frameworks.js';
import { handler as getAssuranceLevels, type GetAssuranceLevelsInput } from './get-assurance-levels.js';

// --- Threat Intelligence ---
import { handler as getIamAttack, type GetIamAttackInput } from './get-iam-attack.js';
import { handler as searchIamThreats, type SearchIamThreatsInput } from './search-iam-threats.js';
import { handler as getIamWeakness, type GetIamWeaknessInput } from './get-iam-weakness.js';
import { handler as assessIamPosture, type AssessIamPostureInput } from './assess-iam-posture.js';
import { handler as getIamStridePatterns, type GetIamStridePatternsInput } from './get-iam-stride-patterns.js';

// --- Protocols & Architecture ---
import { handler as getProtocol, type GetProtocolInput } from './get-protocol.js';
import { handler as getAccessModel, type GetAccessModelInput } from './get-access-model.js';
import { handler as recommendArchitecture, type RecommendArchitectureInput } from './recommend-architecture.js';
import { handler as getLifecyclePattern, type GetLifecyclePatternInput } from './get-lifecycle-pattern.js';
import { handler as getZeroTrustPattern, type GetZeroTrustPatternInput } from './get-zero-trust-pattern.js';

// --- Vendor Guidance ---
import { handler as getVendorConfig, type GetVendorConfigInput } from './get-vendor-config.js';
import { handler as compareVendors, type CompareVendorsInput } from './compare-vendors.js';
import { handler as getMisconfigurations, type GetMisconfigurationsInput } from './get-misconfigurations.js';
import { handler as getMigrationPath, type GetMigrationPathInput } from './get-migration-path.js';

// --- Emerging & Advanced ---
import { handler as getEmergingTechnology, type GetEmergingTechnologyInput } from './get-emerging-technology.js';
import { handler as getMachineIdentity, type GetMachineIdentityInput } from './get-machine-identity.js';
import { handler as assessIamMaturity, type AssessIamMaturityInput } from './assess-iam-maturity.js';

// --- Meta tools ---
import { listSources } from './list-sources.js';
import { getAbout, type AboutContext } from './about.js';
export type { AboutContext } from './about.js';

// ────────────────────────────────────────────────────────
// Tool definitions
// ────────────────────────────────────────────────────────

const ABOUT_TOOL: Tool = {
  name: 'about',
  description:
    'Server metadata, dataset statistics, freshness, and provenance. ' +
    'Call this to verify data coverage, currency, and content basis before relying on results. ' +
    'Returns server version, database fingerprint, build timestamp, row counts for all 8 tables, ' +
    'and a summary of all 22 data sources.',
  inputSchema: { type: 'object', properties: {} },
};

const LIST_SOURCES_TOOL: Tool = {
  name: 'list_sources',
  description:
    'Returns detailed provenance metadata for all 22 data sources used by this server, ' +
    'including NIST, MITRE, OWASP, IETF, W3C, ISO, AICPA, CISA, FIDO Alliance, and vendor documentation. ' +
    'Each source includes authority, URL, licence, coverage scope, update frequency, and limitations. ' +
    'Also returns dataset statistics (row counts per table) and database build timestamp. ' +
    'Call this FIRST when you need to understand what IAM data this server covers.',
  inputSchema: { type: 'object', properties: {} },
};

// ── Standards & Compliance (5 tools) ──

const GET_IAM_STANDARD_TOOL: Tool = {
  name: 'get_iam_standard',
  description:
    'Retrieve a single IAM standard or control by its exact ID (e.g., "nist-800-53-ac-2", ' +
    '"owasp-asvs-v2.1", "cis-v8-5.1"). Returns the full standard entry including framework, ' +
    'section, description, category, assurance level, zero trust pillar, maturity level, and ' +
    'cross-references to related controls. Use this when you already know the specific standard ID. ' +
    'For discovery by keyword, use search_iam_requirements instead.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'Exact standard/control ID (e.g., "nist-800-53-ac-2", "owasp-asvs-v2.1").',
      },
    },
    required: ['id'],
  },
};

const SEARCH_IAM_REQUIREMENTS_TOOL: Tool = {
  name: 'search_iam_requirements',
  description:
    'Full-text search across IAM standards and controls using FTS5 with BM25 ranking. ' +
    'Search by keyword (e.g., "multi-factor authentication", "least privilege", "session timeout") ' +
    'and optionally filter by framework (e.g., "nist-800-53", "owasp-asvs") or category ' +
    '(e.g., "authentication", "authorization", "session-management"). ' +
    'Supports FTS5 syntax: quoted phrases, AND/OR/NOT operators, prefix wildcards (term*). ' +
    'Use this to discover which standards/controls apply to a given IAM requirement. ' +
    'For looking up a known standard by ID, use get_iam_standard instead.',
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description:
          'Search query in English. Supports FTS5 syntax: ' +
          '"multi-factor authentication" for exact phrase, privilege* for prefix.',
      },
      framework: {
        type: 'string',
        description: 'Optional: filter by framework (e.g., "nist-800-53", "owasp-asvs", "cis-v8").',
      },
      category: {
        type: 'string',
        description: 'Optional: filter by category (e.g., "authentication", "authorization", "access-control").',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 20, max: 50).',
        default: 20,
      },
    },
  },
};

const CHECK_IAM_COMPLIANCE_TOOL: Tool = {
  name: 'check_iam_compliance',
  description:
    'Given a list of implemented control IDs and a target framework, returns a compliance gap analysis: ' +
    'which controls are met, which are missing, and the overall coverage percentage. ' +
    'Use this during compliance assessments to identify IAM control gaps against NIST 800-53, ' +
    'OWASP ASVS, ISO 27001, or CISA ZTMM. ' +
    'Example: check_iam_compliance({implemented: ["nist-800-53-ac-2", "nist-800-53-ac-3"], framework: "nist-800-53"}).',
  inputSchema: {
    type: 'object',
    properties: {
      implemented: {
        type: 'array',
        items: { type: 'string' },
        description: 'List of control IDs already implemented (e.g., ["nist-800-53-ac-2", "nist-800-53-ac-3"]).',
      },
      framework: {
        type: 'string',
        description: 'Target framework to check against (e.g., "nist-800-53", "owasp-asvs", "iso-27001").',
      },
    },
    required: ['implemented', 'framework'],
  },
};

const MAP_FRAMEWORKS_TOOL: Tool = {
  name: 'map_frameworks',
  description:
    'Cross-map a specific control between compliance frameworks. Given a control ID and its source framework, ' +
    'returns equivalent controls in other frameworks (or a specific target framework). ' +
    'Supports bidirectional lookup. Use this to translate requirements between NIST 800-53, ISO 27001, ' +
    'OWASP ASVS, SOC 2, and CISA ZTMM. ' +
    'Example: map_frameworks({control: "AC-2", from: "nist-800-53", to: "iso-27001"}).',
  inputSchema: {
    type: 'object',
    properties: {
      control: {
        type: 'string',
        description: 'Control ID to map (e.g., "AC-2", "A.5.16", "V2.1.1").',
      },
      from: {
        type: 'string',
        description: 'Source framework (e.g., "nist-800-53", "iso-27001", "owasp-asvs").',
      },
      to: {
        type: 'string',
        description: 'Optional: target framework to map to. Omit to get all mappings.',
      },
    },
    required: ['control', 'from'],
  },
};

const GET_ASSURANCE_LEVELS_TOOL: Tool = {
  name: 'get_assurance_levels',
  description:
    'Retrieve NIST 800-63 digital identity assurance levels: AAL (Authenticator Assurance Level), ' +
    'IAL (Identity Assurance Level), or FAL (Federation Assurance Level). ' +
    'Returns all standards grouped by assurance level with their requirements and descriptions. ' +
    'Use this when designing authentication systems or assessing identity proofing requirements. ' +
    'Example: get_assurance_levels({type: "AAL", level: 2}) for AAL2 requirements.',
  inputSchema: {
    type: 'object',
    properties: {
      type: {
        type: 'string',
        enum: ['AAL', 'IAL', 'FAL'],
        description: 'Assurance level type: AAL (authenticator), IAL (identity), or FAL (federation).',
      },
      level: {
        type: 'number',
        enum: [1, 2, 3],
        description: 'Optional: specific level (1, 2, or 3). Omit to get all levels for the type.',
      },
    },
    required: ['type'],
  },
};

// ── Threat Intelligence (5 tools) ──

const GET_IAM_ATTACK_TOOL: Tool = {
  name: 'get_iam_attack',
  description:
    'Retrieve a MITRE ATT&CK IAM attack technique by its technique ID (e.g., "T1110", "T1078", ' +
    '"T1556"). Returns the technique name, tactic, description, sub-techniques, detection guidance, ' +
    'mitigation controls, STRIDE category, severity, and real-world examples. ' +
    'Also returns all tactic variants of the technique (e.g., T1078-IA, T1078-PE for Valid Accounts ' +
    'across Initial Access and Privilege Escalation). ' +
    'Use this during threat modeling to understand specific ATT&CK techniques targeting IAM.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'MITRE ATT&CK technique ID (e.g., "T1110", "T1078", "T1556.001").',
      },
    },
    required: ['id'],
  },
};

const SEARCH_IAM_THREATS_TOOL: Tool = {
  name: 'search_iam_threats',
  description:
    'Full-text search across IAM-related MITRE ATT&CK attack patterns using FTS5 with BM25 ranking. ' +
    'Search by keyword (e.g., "credential stuffing", "session hijack", "privilege escalation") ' +
    'and optionally filter by tactic, STRIDE category, or severity. ' +
    'Use this to discover which ATT&CK techniques are relevant to a specific IAM threat scenario. ' +
    'For looking up a known technique by ID, use get_iam_attack instead.',
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description: 'Search query (e.g., "credential stuffing", "token manipulation", "kerberos").',
      },
      tactic: {
        type: 'string',
        description: 'Optional: filter by ATT&CK tactic (e.g., "credential-access", "privilege-escalation").',
      },
      stride: {
        type: 'string',
        enum: ['spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege'],
        description: 'Optional: filter by STRIDE threat category.',
      },
      severity: {
        type: 'string',
        enum: ['critical', 'high', 'medium', 'low'],
        description: 'Optional: filter by severity level.',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 20, max: 50).',
        default: 20,
      },
    },
  },
};

const GET_IAM_WEAKNESS_TOOL: Tool = {
  name: 'get_iam_weakness',
  description:
    'Retrieve a CWE (Common Weakness Enumeration) IAM weakness by its CWE ID (e.g., "CWE-287", ' +
    '"CWE-798", "CWE-269"). Returns the weakness title, description, category, associated CAPEC IDs, ' +
    'affected protocols, STRIDE category, severity, detection guidance, and remediation steps. ' +
    'Use this during secure design review or code review to understand specific IAM-related software weaknesses.',
  inputSchema: {
    type: 'object',
    properties: {
      cwe_id: {
        type: 'string',
        description: 'CWE identifier (e.g., "CWE-287", "CWE-798", "CWE-269").',
      },
    },
    required: ['cwe_id'],
  },
};

const ASSESS_IAM_POSTURE_TOOL: Tool = {
  name: 'assess_iam_posture',
  description:
    'Given a description of an IAM architecture (e.g., "password auth, no MFA, shared admin accounts, ' +
    'LDAP directory, no PAM"), returns all applicable MITRE ATT&CK techniques, CWE weaknesses, and ' +
    'recommended mitigations. Use this during STRIDE threat enumeration to identify IAM-specific attack ' +
    'surfaces. Returns results mapped to STRIDE categories for direct use in threat models.',
  inputSchema: {
    type: 'object',
    properties: {
      components: {
        type: 'array',
        items: { type: 'string' },
        description:
          'IAM components/characteristics to assess (e.g., ["password-only auth", "LDAP directory", ' +
          '"shared admin accounts", "no session timeout"]).',
      },
      stride_filter: {
        type: 'string',
        enum: ['spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege'],
        description: 'Optional: filter results to a single STRIDE category.',
      },
    },
    required: ['components'],
  },
};

const GET_IAM_STRIDE_PATTERNS_TOOL: Tool = {
  name: 'get_iam_stride_patterns',
  description:
    'Given an IAM component keyword (e.g., "OAuth", "SAML", "Kerberos", "session management"), ' +
    'returns all related MITRE ATT&CK attack patterns grouped by STRIDE category ' +
    '(Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). ' +
    'Use this to enumerate STRIDE threats for a specific IAM component during threat modeling. ' +
    'The output is structured for direct inclusion in STRIDE threat analysis worksheets.',
  inputSchema: {
    type: 'object',
    properties: {
      component: {
        type: 'string',
        description: 'IAM component or technology keyword (e.g., "OAuth", "SAML", "LDAP", "session", "MFA").',
      },
      stride_category: {
        type: 'string',
        enum: ['spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege'],
        description: 'Optional: filter to a single STRIDE category.',
      },
    },
    required: ['component'],
  },
};

// ── Protocols & Architecture (5 tools) ──

const GET_PROTOCOL_TOOL: Tool = {
  name: 'get_protocol',
  description:
    'Retrieve detailed information about an identity/authentication protocol by its exact ID ' +
    '(e.g., "oauth2-authorization-code", "oidc-core", "saml2-web-sso", "fido2-webauthn"). ' +
    'Returns protocol name, flow type, description, security considerations, recommended use-cases, ' +
    'deprecation status, RFC references, and sequence diagrams (where available). ' +
    'Use this when designing authentication flows or comparing protocol options.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'Protocol ID (e.g., "oauth2-authorization-code", "oidc-core", "saml2-web-sso").',
      },
    },
    required: ['id'],
  },
};

const GET_ACCESS_MODEL_TOOL: Tool = {
  name: 'get_access_model',
  description:
    'Retrieve an IAM access model (architecture pattern) by its ID (e.g., "rbac", "abac", "pbac", ' +
    '"rebac"). Returns the model name, category, description, when to use it, when NOT to use it, ' +
    'components, data flow, strengths, weaknesses, compliance mappings, and related patterns. ' +
    'Use this when evaluating access control approaches for a system or comparing authorization models.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'Access model ID (e.g., "rbac", "abac", "pbac", "rebac", "mac").',
      },
    },
    required: ['id'],
  },
};

const RECOMMEND_ARCHITECTURE_TOOL: Tool = {
  name: 'recommend_architecture',
  description:
    'Given IAM architecture requirements (scale, compliance frameworks, existing vendor), returns ' +
    'scored architecture pattern recommendations. Scoring considers: FTS match on scale terms, ' +
    'compliance framework alignment, and vendor compatibility. ' +
    'Use this during architecture design to find suitable IAM patterns. ' +
    'Example: recommend_architecture({scale: "10000 users", compliance: ["nist-800-53", "iso-27001"], existing: "azure-entra"}).',
  inputSchema: {
    type: 'object',
    properties: {
      scale: {
        type: 'string',
        description: 'Scale description (e.g., "enterprise 50000 users", "startup 500 users", "B2C millions").',
      },
      compliance: {
        type: 'array',
        items: { type: 'string' },
        description: 'Required compliance frameworks (e.g., ["nist-800-53", "iso-27001", "soc-2"]).',
      },
      existing: {
        type: 'string',
        description: 'Existing IAM vendor (e.g., "azure-entra", "aws-iam", "okta").',
      },
    },
  },
};

const GET_LIFECYCLE_PATTERN_TOOL: Tool = {
  name: 'get_lifecycle_pattern',
  description:
    'Retrieve identity lifecycle architecture patterns. Lookup by exact pattern ID or list all patterns ' +
    'in a category (e.g., "lifecycle", "federation", "ciam", "directory"). ' +
    'Returns pattern name, description, when to use, components, data flow, strengths, weaknesses, ' +
    'compliance mappings, and related patterns. ' +
    'Use this to understand joiner/mover/leaver workflows, provisioning patterns, or identity governance architecture.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'Optional: exact pattern ID to look up.',
      },
      category: {
        type: 'string',
        description: 'Optional: list all patterns in this category (e.g., "lifecycle", "federation", "ciam").',
      },
    },
  },
};

const GET_ZERO_TRUST_PATTERN_TOOL: Tool = {
  name: 'get_zero_trust_pattern',
  description:
    'Get Zero Trust Architecture guidance for a specific ZT pillar (identity, device, network, application, data). ' +
    'Returns both standards-based ZT requirements (from CISA ZTMM, NIST 800-207) and architecture patterns ' +
    'with the "zero-trust" category. Optionally filter by maturity level (traditional, initial, advanced, optimal). ' +
    'Use this when designing or assessing Zero Trust implementations, particularly the identity pillar.',
  inputSchema: {
    type: 'object',
    properties: {
      pillar: {
        type: 'string',
        enum: ['identity', 'device', 'network', 'application', 'data'],
        description: 'Zero Trust pillar to query.',
      },
      maturity: {
        type: 'string',
        enum: ['traditional', 'initial', 'advanced', 'optimal'],
        description: 'Optional: filter by CISA ZTMM maturity level.',
      },
    },
    required: ['pillar'],
  },
};

// ── Vendor Guidance (4 tools) ──

const GET_VENDOR_CONFIG_TOOL: Tool = {
  name: 'get_vendor_config',
  description:
    'Retrieve vendor-specific IAM configuration guidance for a given platform. ' +
    'Supports Azure Entra ID, AWS IAM, GCP IAM, Okta, Ping Identity, CyberArk, and SailPoint. ' +
    'Returns feature descriptions, best practices, common misconfigurations (with severity/impact), ' +
    'compliance control mappings, and equivalent features in other vendors. ' +
    'Optionally filter by feature name. Use this during implementation reviews or vendor-specific hardening.',
  inputSchema: {
    type: 'object',
    properties: {
      vendor: {
        type: 'string',
        description: 'Vendor name (e.g., "azure-entra", "aws-iam", "gcp-iam", "okta", "ping-identity", "cyberark", "sailpoint").',
      },
      feature: {
        type: 'string',
        description: 'Optional: filter by feature name or keyword (e.g., "Conditional Access", "MFA", "SSO").',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 20, max: 50).',
        default: 20,
      },
    },
    required: ['vendor'],
  },
};

const COMPARE_VENDORS_TOOL: Tool = {
  name: 'compare_vendors',
  description:
    'Side-by-side comparison of how different IAM vendors implement a specific feature. ' +
    'Searches across all vendor configurations using FTS5 for the feature keyword and groups ' +
    'results by vendor. Optionally restrict to specific vendors. ' +
    'Use this when evaluating vendor options or building a feature comparison matrix. ' +
    'Example: compare_vendors({feature: "Conditional Access", vendors: ["azure-entra", "okta"]}).',
  inputSchema: {
    type: 'object',
    properties: {
      feature: {
        type: 'string',
        description: 'Feature to compare (e.g., "Conditional Access", "MFA", "SCIM provisioning", "PAM").',
      },
      vendors: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional: restrict comparison to specific vendors.',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 50, max: 50).',
        default: 50,
      },
    },
    required: ['feature'],
  },
};

const GET_MISCONFIGURATIONS_TOOL: Tool = {
  name: 'get_misconfigurations',
  description:
    'Retrieve common IAM misconfigurations across all vendors or for a specific vendor. ' +
    'Returns each misconfiguration with its parent vendor/feature context, impact description, ' +
    'and severity (critical/high/medium/low). Optionally filter by vendor and/or severity. ' +
    'Use this during security assessments, penetration test planning, or configuration reviews ' +
    'to identify the most common IAM configuration mistakes.',
  inputSchema: {
    type: 'object',
    properties: {
      vendor: {
        type: 'string',
        description: 'Optional: filter by vendor (e.g., "azure-entra", "aws-iam").',
      },
      severity: {
        type: 'string',
        enum: ['critical', 'high', 'medium', 'low'],
        description: 'Optional: filter by severity level.',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 200, max: 500).',
        default: 200,
      },
    },
  },
};

const GET_MIGRATION_PATH_TOOL: Tool = {
  name: 'get_migration_path',
  description:
    'Generate an IAM platform migration mapping from one vendor to another. ' +
    'Returns a feature-by-feature mapping showing source features, their equivalents in the ' +
    'target vendor, and gaps where no equivalent exists. ' +
    'Use this when planning a migration between IAM platforms (e.g., on-prem AD to Azure Entra, ' +
    'Okta to AWS IAM Identity Center). ' +
    'Example: get_migration_path({from: "okta", to: "azure-entra"}).',
  inputSchema: {
    type: 'object',
    properties: {
      from: {
        type: 'string',
        description: 'Source vendor to migrate from (e.g., "okta", "ping-identity", "aws-iam").',
      },
      to: {
        type: 'string',
        description: 'Target vendor to migrate to (e.g., "azure-entra", "gcp-iam", "okta").',
      },
    },
    required: ['from', 'to'],
  },
};

// ── Emerging & Advanced (3 tools) ──

const GET_EMERGING_TECHNOLOGY_TOOL: Tool = {
  name: 'get_emerging_technology',
  description:
    'Look up emerging IAM technologies by ID (e.g., "passkeys", "decentralized-identity", ' +
    '"verifiable-credentials") or by category (e.g., "passwordless", "decentralized", "machine-identity"). ' +
    'Returns technology name, description, maturity level, related standards, adoption status, ' +
    'use-cases, migration path from legacy technology, and vendor support matrix. ' +
    'Use this when evaluating new IAM technologies for adoption or roadmap planning.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'Optional: exact technology ID (e.g., "passkeys", "decentralized-identity").',
      },
      category: {
        type: 'string',
        description: 'Optional: filter by category (e.g., "passwordless", "decentralized", "machine-identity").',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 50, max: 100).',
        default: 50,
      },
    },
  },
};

const GET_MACHINE_IDENTITY_TOOL: Tool = {
  name: 'get_machine_identity',
  description:
    'Get guidance on non-human/machine identity management (service accounts, managed identities, ' +
    'workload identity federation, API keys, certificates). Returns emerging technologies in the ' +
    'machine-identity category plus vendor-specific configuration guidance for the specified platform. ' +
    'Use this when designing service-to-service authentication, managing secrets/certificates, ' +
    'or implementing workload identity federation.',
  inputSchema: {
    type: 'object',
    properties: {
      platform: {
        type: 'string',
        description: 'Optional: cloud platform for vendor-specific guidance ("azure", "aws", "gcp").',
      },
      limit: {
        type: 'number',
        description: 'Maximum technology results (default: 50).',
        default: 50,
      },
    },
  },
};

const ASSESS_IAM_MATURITY_TOOL: Tool = {
  name: 'assess_iam_maturity',
  description:
    'Assess IAM maturity against the CISA Zero Trust Maturity Model. ' +
    'Given a description of current IAM capabilities per area (authentication, authorization, ' +
    'privileged_access, identity_lifecycle, monitoring), maps them to maturity levels ' +
    '(traditional, initial, advanced, optimal) and identifies gaps and recommendations. ' +
    'Returns per-area assessment, overall maturity level, gaps to next level, ' +
    'actionable recommendations, and reference standards. ' +
    'Example: assess_iam_maturity({current: {authentication: "MFA with TOTP", privileged_access: "shared admin accounts"}}).',
  inputSchema: {
    type: 'object',
    properties: {
      current: {
        type: 'object',
        additionalProperties: { type: 'string' },
        description:
          'Current capabilities per area. Keys: authentication, authorization, privileged_access, ' +
          'identity_lifecycle, monitoring. Values: description of current state.',
      },
    },
    required: ['current'],
  },
};

// ────────────────────────────────────────────────────────
// Tool registration
// ────────────────────────────────────────────────────────

/**
 * Build the tool list based on detected capabilities.
 * Tools are conditionally included based on which database tables are available.
 */
export function buildTools(
  capabilities: Set<Capability>,
  context?: AboutContext,
): Tool[] {
  const tools: Tool[] = [];

  // --- Standards & Compliance (requires 'standards' capability) ---
  if (capabilities.has('standards')) {
    tools.push(GET_IAM_STANDARD_TOOL);
    tools.push(SEARCH_IAM_REQUIREMENTS_TOOL);
    tools.push(CHECK_IAM_COMPLIANCE_TOOL);
    tools.push(GET_ASSURANCE_LEVELS_TOOL);
  }

  // --- Compliance Mappings (requires 'compliance_mappings' + 'standards') ---
  if (capabilities.has('compliance_mappings')) {
    tools.push(MAP_FRAMEWORKS_TOOL);
  }

  // --- Threat Intelligence (requires 'attack_patterns') ---
  if (capabilities.has('attack_patterns')) {
    tools.push(GET_IAM_ATTACK_TOOL);
    tools.push(SEARCH_IAM_THREATS_TOOL);
    tools.push(GET_IAM_STRIDE_PATTERNS_TOOL);
  }

  // --- Weaknesses (requires 'weaknesses') ---
  if (capabilities.has('weaknesses')) {
    tools.push(GET_IAM_WEAKNESS_TOOL);
  }

  // --- Posture assessment (requires both attack_patterns + weaknesses) ---
  if (capabilities.has('attack_patterns') && capabilities.has('weaknesses')) {
    tools.push(ASSESS_IAM_POSTURE_TOOL);
  }

  // --- Protocols (requires 'protocols') ---
  if (capabilities.has('protocols')) {
    tools.push(GET_PROTOCOL_TOOL);
  }

  // --- Architecture Patterns (requires 'architecture_patterns') ---
  if (capabilities.has('architecture_patterns')) {
    tools.push(GET_ACCESS_MODEL_TOOL);
    tools.push(GET_LIFECYCLE_PATTERN_TOOL);
  }

  // --- Recommend architecture (requires architecture_patterns, optionally vendor_configurations) ---
  if (capabilities.has('architecture_patterns')) {
    tools.push(RECOMMEND_ARCHITECTURE_TOOL);
  }

  // --- Zero Trust (requires 'standards' + 'architecture_patterns') ---
  if (capabilities.has('standards') && capabilities.has('architecture_patterns')) {
    tools.push(GET_ZERO_TRUST_PATTERN_TOOL);
  }

  // --- Vendor Guidance (requires 'vendor_configurations') ---
  if (capabilities.has('vendor_configurations')) {
    tools.push(GET_VENDOR_CONFIG_TOOL);
    tools.push(COMPARE_VENDORS_TOOL);
    tools.push(GET_MISCONFIGURATIONS_TOOL);
    tools.push(GET_MIGRATION_PATH_TOOL);
  }

  // --- Emerging Technologies (requires 'emerging_technologies') ---
  if (capabilities.has('emerging_technologies')) {
    tools.push(GET_EMERGING_TECHNOLOGY_TOOL);
  }

  // --- Machine Identity (requires 'emerging_technologies', optionally 'vendor_configurations') ---
  if (capabilities.has('emerging_technologies')) {
    tools.push(GET_MACHINE_IDENTITY_TOOL);
  }

  // --- IAM Maturity (requires 'standards') ---
  if (capabilities.has('standards')) {
    tools.push(ASSESS_IAM_MATURITY_TOOL);
  }

  // --- Meta tools (always available) ---
  tools.push(LIST_SOURCES_TOOL);
  if (context) {
    tools.push(ABOUT_TOOL);
  }

  return tools;
}

/**
 * Register all tools with the MCP server.
 */
export function registerTools(
  server: Server,
  db: InstanceType<typeof Database>,
  capabilities: Set<Capability>,
  context?: AboutContext,
): void {
  const allTools = buildTools(capabilities, context);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: allTools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      let result: unknown;

      switch (name) {
        // --- Standards & Compliance ---
        case 'get_iam_standard':
          result = await getIamStandard(db, args as unknown as GetIamStandardInput);
          break;
        case 'search_iam_requirements':
          result = await searchIamRequirements(db, args as unknown as SearchIamRequirementsInput);
          break;
        case 'check_iam_compliance':
          result = await checkIamCompliance(db, args as unknown as CheckIamComplianceInput);
          break;
        case 'map_frameworks':
          result = await mapFrameworks(db, args as unknown as MapFrameworksInput);
          break;
        case 'get_assurance_levels':
          result = await getAssuranceLevels(db, args as unknown as GetAssuranceLevelsInput);
          break;

        // --- Threat Intelligence ---
        case 'get_iam_attack':
          result = await getIamAttack(db, args as unknown as GetIamAttackInput);
          break;
        case 'search_iam_threats':
          result = await searchIamThreats(db, args as unknown as SearchIamThreatsInput);
          break;
        case 'get_iam_weakness':
          result = await getIamWeakness(db, args as unknown as GetIamWeaknessInput);
          break;
        case 'assess_iam_posture':
          result = await assessIamPosture(db, args as unknown as AssessIamPostureInput);
          break;
        case 'get_iam_stride_patterns':
          result = await getIamStridePatterns(db, args as unknown as GetIamStridePatternsInput);
          break;

        // --- Protocols & Architecture ---
        case 'get_protocol':
          result = await getProtocol(db, args as unknown as GetProtocolInput);
          break;
        case 'get_access_model':
          result = await getAccessModel(db, args as unknown as GetAccessModelInput);
          break;
        case 'recommend_architecture':
          result = await recommendArchitecture(db, args as unknown as RecommendArchitectureInput);
          break;
        case 'get_lifecycle_pattern':
          result = await getLifecyclePattern(db, args as unknown as GetLifecyclePatternInput);
          break;
        case 'get_zero_trust_pattern':
          result = await getZeroTrustPattern(db, args as unknown as GetZeroTrustPatternInput);
          break;

        // --- Vendor Guidance ---
        case 'get_vendor_config':
          result = await getVendorConfig(db, args as unknown as GetVendorConfigInput);
          break;
        case 'compare_vendors':
          result = await compareVendors(db, args as unknown as CompareVendorsInput);
          break;
        case 'get_misconfigurations':
          result = await getMisconfigurations(db, args as unknown as GetMisconfigurationsInput);
          break;
        case 'get_migration_path':
          result = await getMigrationPath(db, args as unknown as GetMigrationPathInput);
          break;

        // --- Emerging & Advanced ---
        case 'get_emerging_technology':
          result = await getEmergingTechnology(db, args as unknown as GetEmergingTechnologyInput);
          break;
        case 'get_machine_identity':
          result = await getMachineIdentity(db, args as unknown as GetMachineIdentityInput);
          break;
        case 'assess_iam_maturity':
          result = await assessIamMaturity(db, args as unknown as AssessIamMaturityInput);
          break;

        // --- Meta tools ---
        case 'list_sources':
          result = await listSources(db);
          break;
        case 'about':
          if (context) {
            result = getAbout(db, context);
          } else {
            return {
              content: [{ type: 'text' as const, text: 'About tool not configured.' }],
              isError: true,
            };
          }
          break;

        default:
          return {
            content: [{ type: 'text' as const, text: `Error: Unknown tool "${name}".` }],
            isError: true,
          };
      }

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text' as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });
}
