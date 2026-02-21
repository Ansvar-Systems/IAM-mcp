/**
 * Data parsing utilities for IAM Expert MCP ingestion.
 *
 * Provides parsers for upstream data formats:
 * - NIST OSCAL JSON (SP 800-53)
 * - MITRE ATT&CK STIX/TAXII bundles
 * - CWE XML
 * - CAPEC XML
 *
 * Each parser extracts relevant IAM data and normalizes it into the seed JSON
 * format consumed by build-db.ts.
 *
 * NOTE: These are skeleton implementations with the correct interfaces and
 * basic structure. Complex parsing logic is marked with TODO comments for
 * incremental completion.
 */

// ---------------------------------------------------------------------------
// Shared types — mirror the seed JSON shape expected by build-db.ts
// ---------------------------------------------------------------------------

export interface SeedStandard {
  id: string;
  framework: string;
  section: string | null;
  title: string;
  description: string;
  category:
    | 'authentication'
    | 'authorization'
    | 'identity-lifecycle'
    | 'privileged-access'
    | 'federation'
    | 'monitoring'
    | 'session-management'
    | 'credential-management';
  assurance_level: string | null;
  zero_trust_pillar: string | null;
  maturity_level: string | null;
  cross_references: string[];
}

export interface SeedAttackPattern {
  id: string;
  name: string;
  tactic: string;
  description: string;
  sub_techniques: string[];
  detection_guidance: string | null;
  mitigation_controls: string[];
  stride_category:
    | 'spoofing'
    | 'tampering'
    | 'repudiation'
    | 'information_disclosure'
    | 'denial_of_service'
    | 'elevation_of_privilege';
  severity: 'critical' | 'high' | 'medium' | 'low';
  real_world_examples: string | null;
}

export interface SeedWeakness {
  cwe_id: string;
  capec_ids: string[];
  title: string;
  description: string;
  category:
    | 'authentication'
    | 'authorization'
    | 'session-management'
    | 'privilege-management'
    | 'credential-storage';
  affected_protocols: string[];
  stride_category:
    | 'spoofing'
    | 'tampering'
    | 'repudiation'
    | 'information_disclosure'
    | 'denial_of_service'
    | 'elevation_of_privilege';
  severity: 'critical' | 'high' | 'medium' | 'low';
  detection_guidance: string | null;
  remediation: string | null;
}

export interface SeedFile {
  standards?: SeedStandard[];
  attack_patterns?: SeedAttackPattern[];
  weaknesses?: SeedWeakness[];
}

// ---------------------------------------------------------------------------
// OSCAL JSON — NIST SP 800-53
// ---------------------------------------------------------------------------

/**
 * Represents a single control or control enhancement in OSCAL JSON.
 */
interface OscalControl {
  id: string;
  class?: string;
  title: string;
  params?: Array<{ id: string; label?: string; select?: { 'how-many'?: string; choice?: string[] } }>;
  props?: Array<{ name: string; value: string; class?: string }>;
  parts?: Array<{ id?: string; name: string; prose?: string; parts?: OscalControl['parts'] }>;
  controls?: OscalControl[];
}

interface OscalGroup {
  id: string;
  class?: string;
  title: string;
  controls?: OscalControl[];
  groups?: OscalGroup[];
}

interface OscalCatalog {
  catalog: {
    uuid: string;
    metadata: { title: string; version: string };
    groups?: OscalGroup[];
  };
}

/**
 * Map NIST 800-53 control family prefix to an IAM category.
 */
function mapControlCategory(controlId: string): SeedStandard['category'] {
  const id = controlId.toLowerCase();
  if (id.startsWith('ac-')) return 'authorization';
  if (id.startsWith('ia-')) return 'authentication';
  if (id.startsWith('au-')) return 'monitoring';
  if (id.startsWith('sc-')) return 'credential-management';
  return 'authorization';
}

/**
 * Guess a zero-trust pillar based on the control family.
 */
function mapZeroTrustPillar(controlId: string): string {
  const id = controlId.toLowerCase();
  if (id.startsWith('ia-')) return 'identity';
  if (id.startsWith('ac-')) return 'identity';
  if (id.startsWith('au-')) return 'visibility';
  return 'governance';
}

/**
 * Extract prose text from OSCAL control parts recursively.
 */
function extractProse(parts?: OscalControl['parts']): string {
  if (!parts) return '';
  const texts: string[] = [];
  for (const part of parts) {
    if (part.prose) texts.push(part.prose);
    if (part.parts) texts.push(extractProse(part.parts));
  }
  return texts.join(' ').trim();
}

/**
 * Flatten an OSCAL control (and its enhancements) into seed standards.
 */
function flattenControl(control: OscalControl, framework: string): SeedStandard[] {
  const results: SeedStandard[] = [];
  const section = control.id.toUpperCase();
  const description = extractProse(control.parts) || control.title;

  results.push({
    id: `NIST-800-53-${section}`,
    framework,
    section,
    title: control.title,
    description,
    category: mapControlCategory(control.id),
    assurance_level: null,
    zero_trust_pillar: mapZeroTrustPillar(control.id),
    maturity_level: null,
    cross_references: [],
  });

  // Control enhancements are nested controls
  if (control.controls) {
    for (const enhancement of control.controls) {
      const enhSection = enhancement.id.toUpperCase();
      const enhDesc = extractProse(enhancement.parts) || enhancement.title;
      results.push({
        id: `NIST-800-53-${enhSection}`,
        framework,
        section: enhSection,
        title: `${control.title}: ${enhancement.title}`,
        description: enhDesc,
        category: mapControlCategory(enhancement.id),
        assurance_level: null,
        zero_trust_pillar: mapZeroTrustPillar(enhancement.id),
        maturity_level: null,
        cross_references: [],
      });
    }
  }

  return results;
}

/**
 * Parse NIST OSCAL JSON catalog and extract controls from specified families.
 *
 * @param data    Raw JSON string of the OSCAL catalog.
 * @param families  Family IDs to extract (e.g. ['ac', 'ia']). Defaults to ['ac', 'ia'].
 * @returns Array of seed standards.
 */
export function parseOscalJson(data: string, families: string[] = ['ac', 'ia']): SeedStandard[] {
  const catalog: OscalCatalog = JSON.parse(data);
  const standards: SeedStandard[] = [];
  const familySet = new Set(families.map((f) => f.toLowerCase()));

  const groups = catalog.catalog.groups ?? [];
  for (const group of groups) {
    if (!familySet.has(group.id.toLowerCase())) continue;

    const controls = group.controls ?? [];
    for (const control of controls) {
      standards.push(...flattenControl(control, 'nist-800-53'));
    }
  }

  return standards;
}

// ---------------------------------------------------------------------------
// STIX/TAXII — MITRE ATT&CK
// ---------------------------------------------------------------------------

/**
 * Minimal STIX bundle types for ATT&CK extraction.
 */
interface StixObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  external_references?: Array<{ source_name: string; external_id?: string; url?: string }>;
  kill_chain_phases?: Array<{ kill_chain_name: string; phase_name: string }>;
  x_mitre_is_subtechnique?: boolean;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
}

interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

/**
 * Map ATT&CK tactic phase name to a simplified tactic string.
 */
function mapTactic(phaseName: string): string {
  const mapping: Record<string, string> = {
    'credential-access': 'credential-access',
    'privilege-escalation': 'privilege-escalation',
    'lateral-movement': 'lateral-movement',
    'initial-access': 'initial-access',
    persistence: 'persistence',
    'defense-evasion': 'defense-evasion',
    collection: 'collection',
    exfiltration: 'exfiltration',
    impact: 'impact',
    discovery: 'discovery',
    execution: 'execution',
    'command-and-control': 'command-and-control',
    'resource-development': 'resource-development',
    reconnaissance: 'reconnaissance',
  };
  return mapping[phaseName] ?? phaseName;
}

/**
 * Map ATT&CK tactic to a STRIDE category.
 */
function tacticToStride(tactic: string): SeedAttackPattern['stride_category'] {
  const mapping: Record<string, SeedAttackPattern['stride_category']> = {
    'credential-access': 'spoofing',
    'initial-access': 'spoofing',
    'privilege-escalation': 'elevation_of_privilege',
    'lateral-movement': 'spoofing',
    persistence: 'tampering',
    'defense-evasion': 'tampering',
    collection: 'information_disclosure',
    exfiltration: 'information_disclosure',
    impact: 'denial_of_service',
  };
  return mapping[tactic] ?? 'spoofing';
}

/** IAM-relevant ATT&CK tactic names. */
const IAM_TACTICS = new Set([
  'credential-access',
  'privilege-escalation',
  'lateral-movement',
  'initial-access',
  'persistence',
  'defense-evasion',
]);

/**
 * Parse a MITRE ATT&CK STIX bundle and extract IAM-relevant attack patterns.
 *
 * @param data  Raw JSON string of the STIX bundle.
 * @returns Array of seed attack patterns.
 */
export function parseStixBundle(data: string): SeedAttackPattern[] {
  const bundle: StixBundle = JSON.parse(data);
  const patterns: SeedAttackPattern[] = [];

  for (const obj of bundle.objects) {
    // Only process attack-pattern objects
    if (obj.type !== 'attack-pattern') continue;
    if (obj.revoked || obj.x_mitre_deprecated) continue;

    // Get ATT&CK ID
    const attackRef = obj.external_references?.find((r) => r.source_name === 'mitre-attack');
    if (!attackRef?.external_id) continue;

    // Get tactic(s)
    const tactics = (obj.kill_chain_phases ?? [])
      .filter((p) => p.kill_chain_name === 'mitre-attack')
      .map((p) => mapTactic(p.phase_name));

    // Filter to IAM-relevant tactics
    const iamTactics = tactics.filter((t) => IAM_TACTICS.has(t));
    if (iamTactics.length === 0) continue;

    const tactic = iamTactics[0];

    patterns.push({
      id: attackRef.external_id,
      name: obj.name ?? attackRef.external_id,
      tactic,
      description: obj.description ?? '',
      sub_techniques: [], // TODO: correlate sub-techniques from the bundle
      detection_guidance: null, // TODO: extract from x_mitre_detection
      mitigation_controls: [], // TODO: cross-reference mitigations
      stride_category: tacticToStride(tactic),
      severity: 'high', // TODO: derive from ATT&CK data sources / prevalence
      real_world_examples: null, // TODO: extract from campaign references
    });
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// CWE XML
// ---------------------------------------------------------------------------

/**
 * Parse CWE XML content and extract IAM-relevant weakness entries.
 *
 * This is a skeleton implementation. CWE XML is large and deeply nested;
 * a full parser would use a streaming XML parser. For now, this extracts
 * weaknesses by regex matching on well-known CWE IDs relevant to IAM.
 *
 * @param data  Raw XML string of CWE data.
 * @returns Array of seed weaknesses.
 */
export function parseCweXml(data: string): SeedWeakness[] {
  const weaknesses: SeedWeakness[] = [];

  // IAM-relevant CWE IDs and their categories
  const iamCweIds: Record<string, { category: SeedWeakness['category']; stride: SeedWeakness['stride_category'] }> = {
    '284': { category: 'authorization', stride: 'elevation_of_privilege' },
    '285': { category: 'authorization', stride: 'elevation_of_privilege' },
    '287': { category: 'authentication', stride: 'spoofing' },
    '269': { category: 'privilege-management', stride: 'elevation_of_privilege' },
    '306': { category: 'authentication', stride: 'spoofing' },
    '307': { category: 'authentication', stride: 'spoofing' },
    '308': { category: 'authentication', stride: 'spoofing' },
    '384': { category: 'session-management', stride: 'spoofing' },
    '613': { category: 'session-management', stride: 'spoofing' },
    '798': { category: 'credential-storage', stride: 'information_disclosure' },
    '916': { category: 'credential-storage', stride: 'information_disclosure' },
    '521': { category: 'credential-storage', stride: 'spoofing' },
    '522': { category: 'credential-storage', stride: 'information_disclosure' },
    '620': { category: 'credential-storage', stride: 'spoofing' },
    '640': { category: 'authentication', stride: 'spoofing' },
  };

  // TODO: Replace regex extraction with a proper XML parser (e.g., fast-xml-parser)
  // For now, use regex to extract <Weakness> elements with known CWE IDs
  const weaknessPattern = /<Weakness\s+ID="(\d+)"[^>]*Name="([^"]*)"[^>]*>/g;
  let match: RegExpExecArray | null;

  while ((match = weaknessPattern.exec(data)) !== null) {
    const cweId = match[1];
    const name = match[2];

    if (!iamCweIds[cweId]) continue;
    const { category, stride } = iamCweIds[cweId];

    // TODO: Extract full description, detection guidance, and remediation from
    // nested <Description>, <Detection_Methods>, and <Potential_Mitigations> elements
    weaknesses.push({
      cwe_id: `CWE-${cweId}`,
      capec_ids: [], // TODO: extract from <Related_Attack_Patterns>
      title: name,
      description: `${name} (extracted from CWE XML)`, // TODO: extract <Description> prose
      category,
      affected_protocols: [],
      stride_category: stride,
      severity: 'high', // TODO: derive from CVSS or prevalence data
      detection_guidance: null,
      remediation: null,
    });
  }

  return weaknesses;
}

// ---------------------------------------------------------------------------
// CAPEC XML
// ---------------------------------------------------------------------------

/**
 * Parse CAPEC XML content and extract IAM-relevant attack patterns.
 *
 * Skeleton implementation — extracts CAPEC entries by regex.
 * A full parser would use a streaming XML parser.
 *
 * @param data  Raw XML string of CAPEC data.
 * @returns Array of seed attack patterns.
 */
export function parseCapecXml(data: string): SeedAttackPattern[] {
  const patterns: SeedAttackPattern[] = [];

  // IAM-relevant CAPEC IDs
  const iamCapecIds = new Set([
    '49',   // Password Brute Forcing
    '55',   // Rainbow Table Password Cracking
    '56',   // Removing/short-circuiting Validation Logic
    '57',   // Utilizing REST's Trust in the System Resource to Obtain Sensitive Data
    '60',   // Reusing Session IDs
    '70',   // Try Common Usernames and Passwords
    '90',   // Reflection Attack in Authentication Protocol
    '94',   // Adversary in the Middle (AiTM)
    '114',  // Authentication Abuse
    '115',  // Authentication Bypass
    '122',  // Privilege Abuse
    '151',  // Identity Spoofing
    '196',  // Session Credential Falsification through Forging
    '233',  // Privilege Escalation
    '560',  // Use of Known Domain Credentials
    '565',  // Password Spraying
    '600',  // Credential Stuffing
    '633',  // Token Impersonation
    '644',  // Use of Captured Hashes (Pass the Hash)
    '645',  // Use of Captured Tickets (Pass the Ticket)
    '652',  // Use of Known Kerberos Credentials
    '653',  // Use of Known Operating System Credentials
  ]);

  // TODO: Replace regex extraction with a proper XML parser
  const patternRegex = /<Attack_Pattern\s+ID="(\d+)"[^>]*Name="([^"]*)"[^>]*>/g;
  let match: RegExpExecArray | null;

  while ((match = patternRegex.exec(data)) !== null) {
    const capecId = match[1];
    const name = match[2];

    if (!iamCapecIds.has(capecId)) continue;

    // TODO: Extract full description, prerequisites, and mitigations from nested elements
    patterns.push({
      id: `CAPEC-${capecId}`,
      name,
      tactic: 'credential-access', // TODO: derive from <Attack_Motivation> or <Domains_Of_Attack>
      description: `${name} (extracted from CAPEC XML)`, // TODO: extract <Description> prose
      sub_techniques: [],
      detection_guidance: null, // TODO: extract from <Indicators>
      mitigation_controls: [], // TODO: extract from <Mitigations>
      stride_category: 'spoofing', // TODO: derive from attack pattern characteristics
      severity: 'high', // TODO: derive from <Typical_Severity>
      real_world_examples: null, // TODO: extract from <Example_Instances>
    });
  }

  return patterns;
}
