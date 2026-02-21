/**
 * assess-iam-maturity — IAM maturity assessment against CISA ZTMM.
 *
 * Takes a description of current IAM capabilities per area and maps them
 * to CISA Zero Trust Maturity Model levels, identifying gaps and recommendations.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface AssessIamMaturityInput {
  current: Record<string, string>;
}

export interface AreaAssessment {
  current_level: string;
  description: string;
  next_level: string | null;
}

export interface StandardReference {
  id: string;
  framework: string;
  title: string;
  maturity_level: string | null;
  zero_trust_pillar: string | null;
}

export interface MaturityAssessmentResult {
  areas: Record<string, AreaAssessment>;
  overall_maturity: string;
  gaps: string[];
  recommendations: string[];
  reference_standards: StandardReference[];
}

interface RawStandardRow {
  id: string;
  framework: string;
  section: string | null;
  title: string;
  description: string;
  category: string;
  assurance_level: string | null;
  zero_trust_pillar: string | null;
  maturity_level: string | null;
  cross_references: string;
}

/**
 * Maturity level ordering for comparisons.
 */
const MATURITY_LEVELS = ['traditional', 'initial', 'advanced', 'optimal'] as const;

/**
 * Keyword patterns for mapping input descriptions to maturity levels.
 * Each level has keywords that, when found in the description, indicate that level.
 */
const MATURITY_KEYWORDS: Record<string, string[][]> = {
  authentication: [
    // traditional
    ['password', 'passwords-only', 'single-factor', 'no mfa', 'no-mfa', 'basic-auth', 'static'],
    // initial
    ['mfa', 'multi-factor', 'totp', 'push', 'sms-otp', 'authenticator-app', 'conditional-access'],
    // advanced
    ['fido2', 'webauthn', 'phishing-resistant', 'passkeys', 'passwordless', 'biometric', 'hardware-key', 'continuous-auth'],
    // optimal
    ['adaptive', 'risk-based', 'zero-trust-auth', 'ai-driven-auth', 'decentralized-identity', 'verifiable-credentials'],
  ],
  authorization: [
    // traditional
    ['rbac-basic', 'role-based-basic', 'flat-roles', 'no-authorization', 'network-based', 'implicit-trust'],
    // initial
    ['rbac', 'role-based', 'group-based', 'resource-permissions', 'policy-based-basic'],
    // advanced
    ['abac', 'attribute-based', 'dynamic-policy', 'context-aware', 'fine-grained', 'policy-engine', 'opa', 'cedar'],
    // optimal
    ['continuous-authorization', 'real-time-policy', 'ai-authorization', 'zero-standing-privilege', 'just-in-time-all'],
  ],
  privileged_access: [
    // traditional
    ['shared-admin', 'shared-credentials', 'no-pam', 'direct-admin', 'standing-privileges'],
    // initial
    ['dedicated-admin', 'credential-vault', 'basic-pam', 'admin-accounts-separate'],
    // advanced
    ['jit', 'just-in-time', 'session-recording', 'paw', 'privileged-workstation', 'time-limited'],
    // optimal
    ['zero-standing-privilege', 'ai-anomaly-pam', 'automated-approval', 'self-healing-pam'],
  ],
  identity_lifecycle: [
    // traditional
    ['manual', 'helpdesk-ticket', 'manual-provisioning', 'no-automation', 'ad-hoc'],
    // initial
    ['automated-provisioning', 'hr-integration', 'basic-scim', 'workflow-based'],
    // advanced
    ['full-scim', 'automated-lifecycle', 'joiner-mover-leaver', 'access-reviews', 'certification'],
    // optimal
    ['ai-certification', 'continuous-certification', 'peer-analysis', 'self-service-governance'],
  ],
  monitoring: [
    // traditional
    ['no-monitoring', 'basic-logs', 'siloed-logs', 'no-siem', 'manual-review'],
    // initial
    ['centralized-siem', 'basic-alerts', 'log-aggregation', 'basic-correlation'],
    // advanced
    ['ueba', 'behavior-analytics', 'anomaly-detection', 'cross-pillar', 'identity-analytics'],
    // optimal
    ['ai-ml-detection', 'real-time-correlation', 'itdr', 'identity-threat-detection', 'automated-response'],
  ],
};

/**
 * Maps a description to a CISA ZTMM maturity level using keyword matching.
 */
function mapToMaturityLevel(area: string, description: string): string {
  const normalized = description.toLowerCase().replace(/[\s_]+/g, '-');

  const areaKeywords = MATURITY_KEYWORDS[area] ?? MATURITY_KEYWORDS['authentication'];

  // Check from highest level down so the most advanced match wins
  for (let i = areaKeywords.length - 1; i >= 0; i--) {
    for (const keyword of areaKeywords[i]) {
      if (normalized.includes(keyword.toLowerCase())) {
        return MATURITY_LEVELS[i];
      }
    }
  }

  // Default to traditional if no keywords match
  return 'traditional';
}

/**
 * Get the next maturity level, or null if already at optimal.
 */
function getNextLevel(current: string): string | null {
  const idx = MATURITY_LEVELS.indexOf(current as typeof MATURITY_LEVELS[number]);
  if (idx < 0 || idx >= MATURITY_LEVELS.length - 1) return null;
  return MATURITY_LEVELS[idx + 1];
}

/**
 * Human-readable descriptions for each maturity level per area.
 */
const LEVEL_DESCRIPTIONS: Record<string, Record<string, string>> = {
  authentication: {
    traditional: 'Password-based single-factor authentication with no MFA.',
    initial: 'MFA deployed for privileged users and external applications.',
    advanced: 'Phishing-resistant MFA (FIDO2) for all users with continuous authentication.',
    optimal: 'Passwordless by default with risk-adaptive step-up authentication.',
  },
  authorization: {
    traditional: 'Basic RBAC or implicit trust based on network location.',
    initial: 'Defined RBAC with group-based access control.',
    advanced: 'ABAC with dynamic policy evaluation and context-aware access.',
    optimal: 'Continuous authorization with AI-driven real-time policy adjustment.',
  },
  privileged_access: {
    traditional: 'Shared admin credentials with standing privileges.',
    initial: 'Dedicated admin accounts with basic credential vaulting.',
    advanced: 'Just-in-time access with session recording and privileged workstations.',
    optimal: 'Zero standing privilege with AI-driven anomaly detection.',
  },
  identity_lifecycle: {
    traditional: 'Manual provisioning and deprovisioning via helpdesk tickets.',
    initial: 'Automated provisioning triggered by HR events.',
    advanced: 'Full SCIM-based lifecycle automation with access reviews.',
    optimal: 'AI-assisted continuous certification with peer-based recommendations.',
  },
  monitoring: {
    traditional: 'Basic siloed logs with no centralized analysis.',
    initial: 'Centralized SIEM with basic correlation rules.',
    advanced: 'UEBA with behavioral analytics and cross-pillar integration.',
    optimal: 'AI/ML-driven real-time threat detection with automated response.',
  },
};

/**
 * Generate gaps based on the current vs next maturity level.
 */
function generateGaps(areas: Record<string, AreaAssessment>): string[] {
  const gaps: string[] = [];

  for (const [area, assessment] of Object.entries(areas)) {
    if (assessment.next_level) {
      const areaName = area.replace(/_/g, ' ');
      const nextDesc = LEVEL_DESCRIPTIONS[area]?.[assessment.next_level];
      if (nextDesc) {
        gaps.push(`${areaName}: Currently at ${assessment.current_level} level. To reach ${assessment.next_level}: ${nextDesc}`);
      } else {
        gaps.push(`${areaName}: Currently at ${assessment.current_level} level. Next target: ${assessment.next_level}.`);
      }
    }
  }

  return gaps;
}

/**
 * Generate recommendations based on the assessed areas.
 */
function generateRecommendations(areas: Record<string, AreaAssessment>): string[] {
  const recommendations: string[] = [];

  const recs: Record<string, Record<string, string>> = {
    authentication: {
      traditional: 'Deploy phishing-resistant MFA (FIDO2/WebAuthn) for all privileged users and externally exposed applications as an immediate priority.',
      initial: 'Expand phishing-resistant MFA to all users and begin passwordless pilot with FIDO2 passkeys.',
      advanced: 'Implement risk-adaptive authentication with continuous evaluation and AI-driven anomaly detection.',
    },
    authorization: {
      traditional: 'Implement centralized RBAC with defined roles and access policies. Eliminate implicit network-based trust.',
      initial: 'Transition from static RBAC to attribute-based access control (ABAC) with dynamic policy evaluation.',
      advanced: 'Implement continuous authorization with real-time policy engines (OPA, Cedar) and zero standing privileges.',
    },
    privileged_access: {
      traditional: 'Eliminate shared admin credentials. Implement dedicated admin accounts with credential vaulting.',
      initial: 'Deploy just-in-time privileged access with time-limited elevation and session recording.',
      advanced: 'Achieve zero standing privilege with AI-driven anomaly detection for all privileged sessions.',
    },
    identity_lifecycle: {
      traditional: 'Integrate identity provisioning with HR system for automated joiner/mover/leaver workflows.',
      initial: 'Implement full SCIM-based lifecycle automation with quarterly access reviews and certification campaigns.',
      advanced: 'Deploy AI-assisted continuous access certification with peer-based entitlement recommendations.',
    },
    monitoring: {
      traditional: 'Centralize identity logs in a SIEM with basic authentication failure and privilege escalation alerts.',
      initial: 'Deploy UEBA for behavioral baseline establishment and anomaly detection across authentication events.',
      advanced: 'Implement ITDR (Identity Threat Detection and Response) with AI/ML correlation and automated incident response.',
    },
  };

  for (const [area, assessment] of Object.entries(areas)) {
    const areaRecs = recs[area];
    if (areaRecs && areaRecs[assessment.current_level]) {
      recommendations.push(areaRecs[assessment.current_level]);
    }
  }

  return recommendations;
}

/**
 * Calculate the overall maturity level as the lowest across all areas.
 */
function calculateOverallMaturity(areas: Record<string, AreaAssessment>): string {
  let lowestIdx = MATURITY_LEVELS.length - 1;

  for (const assessment of Object.values(areas)) {
    const idx = MATURITY_LEVELS.indexOf(assessment.current_level as typeof MATURITY_LEVELS[number]);
    if (idx >= 0 && idx < lowestIdx) {
      lowestIdx = idx;
    }
  }

  return MATURITY_LEVELS[lowestIdx];
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: AssessIamMaturityInput,
): Promise<ToolResponse<MaturityAssessmentResult>> {
  // Assess each area
  const areas: Record<string, AreaAssessment> = {};

  for (const [area, description] of Object.entries(params.current)) {
    const normalizedArea = area.replace(/-/g, '_').toLowerCase();
    const level = mapToMaturityLevel(normalizedArea, description);
    const nextLevel = getNextLevel(level);

    areas[normalizedArea] = {
      current_level: level,
      description: LEVEL_DESCRIPTIONS[normalizedArea]?.[level] ?? description,
      next_level: nextLevel,
    };
  }

  // Calculate overall maturity
  const overall_maturity = calculateOverallMaturity(areas);

  // Generate gaps and recommendations
  const gaps = generateGaps(areas);
  const recommendations = generateRecommendations(areas);

  // Get CISA ZTMM reference standards for identity pillar
  const standardRows = db
    .prepare('SELECT id, framework, title, maturity_level, zero_trust_pillar FROM standards WHERE zero_trust_pillar = ?')
    .all('identity') as Array<{ id: string; framework: string; title: string; maturity_level: string | null; zero_trust_pillar: string | null }>;

  const reference_standards: StandardReference[] = standardRows.map((row) => ({
    id: row.id,
    framework: row.framework,
    title: row.title,
    maturity_level: row.maturity_level,
    zero_trust_pillar: row.zero_trust_pillar,
  }));

  return {
    results: {
      areas,
      overall_maturity,
      gaps,
      recommendations,
      reference_standards,
    },
    _metadata: generateResponseMetadata(),
  };
}
