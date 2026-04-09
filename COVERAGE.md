# IAM Expert MCP — Coverage

This document summarises what the IAM Expert MCP server covers across its 8 database tables and 22 domain tools.

## Database Tables

| Table | Description | Key Sources |
|---|---|---|
| `standards` | IAM standards and controls | NIST SP 800-53/63/207/162, OWASP ASVS, CIS Controls v8, CISA ZTMM |
| `protocols` | Identity protocol specifications | OAuth 2.0/2.1, OIDC, SAML 2.0, SCIM, WebAuthn, FIDO2 |
| `attack_patterns` | MITRE ATT&CK IAM techniques | MITRE ATT&CK (STIX/TAXII) |
| `iam_weaknesses` | CWE/CAPEC IAM weakness entries | CWE identity/access families, CAPEC identity attack patterns |
| `architecture_patterns` | Access models and IAM patterns | NIST Zero Trust, RBAC, ABAC, PBAC, PAM |
| `vendor_configurations` | Vendor IAM configuration guidance | Azure Entra, AWS IAM, GCP IAM, Okta, CyberArk, SailPoint |
| `compliance_mappings` | Cross-framework control mappings | ISO 27001/27002, SOC 2 CC6, NIST CSF |
| `emerging_technologies` | Emerging IAM technologies | DIDs, Verifiable Credentials, Passkeys, FIDO2 |

## Tools

### Meta Tools (always available)
- `about` — server metadata, dataset statistics, freshness
- `list_sources` — detailed provenance for all 22 data sources
- `check_data_freshness` — database build timestamp and staleness status

### Standards & Compliance (5 tools)
- `get_iam_standard` — lookup a single standard/control by ID
- `search_iam_requirements` — full-text search across standards
- `check_iam_compliance` — assess controls for a specific framework
- `get_assurance_levels` — NIST 800-63 assurance level guidance
- `map_frameworks` — cross-map controls between frameworks

### Threat Intelligence (5 tools)
- `get_iam_attack` — lookup MITRE ATT&CK technique by ID
- `search_iam_threats` — full-text search across attack patterns
- `get_iam_weakness` — lookup CWE weakness by ID
- `assess_iam_posture` — posture assessment against known threats
- `get_iam_stride_patterns` — STRIDE threat category patterns

### Protocols & Architecture (5 tools)
- `get_protocol` — lookup identity protocol details
- `get_access_model` — lookup access model/architecture pattern
- `recommend_architecture` — recommend architecture for use case
- `get_lifecycle_pattern` — identity lifecycle pattern guidance
- `get_zero_trust_pattern` — Zero Trust architecture patterns

### Vendor Guidance (4 tools)
- `get_vendor_config` — vendor-specific IAM configuration
- `compare_vendors` — side-by-side vendor feature comparison
- `get_misconfigurations` — common IAM misconfigurations by vendor
- `get_migration_path` — migration guidance between platforms

### Emerging & Advanced (3 tools)
- `get_emerging_technology` — emerging IAM technology details
- `get_machine_identity` — machine identity patterns and guidance
- `assess_iam_maturity` — IAM maturity assessment

## Coverage Gaps

- **ISO 27001/27002**: Full control text not included (licensing); control IDs and public summaries only
- **SOC 2**: Fair-use cross-mapping only; authoritative text requires AICPA membership
- **Vendor docs**: Advisory summaries under fair use; not verbatim vendor content
- **MITRE ATT&CK**: IAM-relevant techniques only (not the full ATT&CK matrix)
- **CWE/CAPEC**: Identity and access management categories only

## Freshness

Database is rebuilt periodically from upstream sources. Use `check_data_freshness` to verify currency, or `about` for the build timestamp. See `.github/workflows/ingest.yml` for the scheduled rebuild schedule.
