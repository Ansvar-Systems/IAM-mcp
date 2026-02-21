# IAM Expert MCP

Comprehensive identity and access management intelligence for the [Model Context Protocol](https://modelcontextprotocol.io/), covering standards advisory (NIST/ISO/CIS/Zero Trust), threat patterns (MITRE ATT&CK/CWE/CAPEC), protocol deep-dives (OAuth/OIDC/SAML/FIDO2), architecture patterns (RBAC/ABAC/PAM), vendor configurations (Azure/AWS/GCP/Okta/CyberArk), compliance cross-mapping, and emerging technology tracking (passkeys, decentralized identity).

**MCP Registry:** `eu.ansvar/iam-mcp`
**npm:** `@ansvar/iam-mcp`
**License:** Apache-2.0

---

## Deployment Tier

**MEDIUM** -- dual tier, free database bundled in npm package.

| Tier | Platform | Database | Content |
|------|----------|----------|---------|
| **Free** | Vercel (Hobby) / npm (stdio) | ~80-150 MB bundled | Standards, protocols, attack patterns, CWE/CAPEC, architecture patterns, vendor configs, compliance mappings, emerging tech |

---

## Data Sources

| Source | Authority | Method | Update Frequency | License | Coverage |
|--------|-----------|--------|-----------------|---------|----------|
| [NIST SP 800-63](https://pages.nist.gov/800-63-4/) | NIST | HTML extraction | Monthly | Public Domain | Digital identity assurance levels (IAL/AAL/FAL) |
| [NIST SP 800-53 rev5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) | NIST | OSCAL JSON | Monthly | Public Domain | Access Control (AC) family |
| [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) | NIST | HTML/PDF | Quarterly | Public Domain | Zero Trust Architecture |
| [MITRE ATT&CK](https://attack.mitre.org) | MITRE | STIX/TAXII | Weekly | Apache-2.0 | IAM-related techniques |
| [CWE](https://cwe.mitre.org) | MITRE | XML download | Weekly | CWE ToU | Identity/access weakness families |
| [CAPEC](https://capec.mitre.org) | MITRE | XML download | Weekly | CAPEC ToU | Identity attack patterns |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | OWASP | GitHub markdown | Monthly | CC BY-SA 4.0 | V2 Auth, V3 Session, V4 Access Control |
| [CIS Controls v8](https://www.cisecurity.org/controls) | CIS | CSV/JSON | Monthly | CIS ToU | Controls 5, 6 (identity) |
| [CISA ZTMM](https://www.cisa.gov/zero-trust-maturity-model) | CISA | PDF extraction | Quarterly | Public Domain | Zero Trust maturity pillars |
| OAuth/OIDC/SAML/FIDO2/SCIM | IETF/W3C/OASIS/FIDO | Spec extraction | Monthly-Quarterly | Various | Protocol specifications |
| Azure Entra / AWS IAM / GCP IAM | Microsoft/AWS/Google | Vendor docs | Monthly | Fair use | Platform-specific guidance |
| Okta/Auth0/Ping/ForgeRock | Vendors | Vendor docs | Monthly | Fair use | IdP configurations |
| CyberArk/SailPoint | Vendors | Vendor docs | Quarterly | Fair use | PAM/IGA guidance |
| ISO 27001/27002 | ISO | Manual curation | Quarterly | ISO Copyright | Identity controls (public IDs) |
| SOC 2 TSC | AICPA | Manual curation | Annually | Fair use | CC6 (Logical Access) |
| W3C DIDs/VCs | W3C | Spec extraction | Quarterly | W3C License | Decentralized identity |
| FIDO Alliance | FIDO Alliance | HTML extraction | Monthly | FIDO Terms | Passkey guidance |

> Full provenance metadata: [`sources.yml`](./sources.yml)

---

## Quick Start

### Claude Desktop / Cursor (stdio)

```json
{
  "mcpServers": {
    "iam-expert": {
      "command": "npx",
      "args": ["-y", "@ansvar/iam-mcp"]
    }
  }
}
```

### Vercel Streamable HTTP (ChatGPT / Claude.ai)

Once deployed, the public endpoint will be available at:

```
https://iam-mcp.vercel.app/api/mcp
```

---

## Tools

### Standards & Compliance (5 tools)

| Tool | Description |
|------|-------------|
| `get_iam_standard` | Full details on a specific IAM control/requirement (NIST, ISO, CIS, SOC 2) |
| `search_iam_requirements` | Find IAM requirements by topic, framework, or category |
| `check_iam_compliance` | Given implemented controls, check compliance against a target framework |
| `map_frameworks` | Cross-reference a control between frameworks (e.g., ISO 27001 -> NIST 800-53) |
| `get_assurance_levels` | NIST 800-63 AAL/IAL/FAL details at each assurance level |

### Threat Intelligence (5 tools)

| Tool | Description |
|------|-------------|
| `get_iam_attack` | MITRE ATT&CK technique details for an IAM-related attack |
| `search_iam_threats` | Find threats by tactic, STRIDE category, or target component |
| `get_iam_weakness` | CWE details + CAPEC patterns for an IAM weakness |
| `assess_iam_posture` | Given an architecture, return all applicable threats and weaknesses |
| `get_iam_stride_patterns` | STRIDE-mapped IAM threat patterns for a specific component |

### Protocols & Architecture (5 tools)

| Tool | Description |
|------|-------------|
| `get_protocol` | Deep-dive on identity protocol: flows, security considerations, when to use |
| `get_access_model` | Details on RBAC/ABAC/ReBAC/PBAC: when to use, trade-offs, compliance mappings |
| `recommend_architecture` | Given requirements, recommend IAM architecture with rationale |
| `get_lifecycle_pattern` | Identity lifecycle management: JML, provisioning, deprovisioning patterns |
| `get_zero_trust_pattern` | Zero Trust architecture guidance by CISA maturity level and pillar |

### Vendor Guidance (4 tools)

| Tool | Description |
|------|-------------|
| `get_vendor_config` | Platform-specific IAM configuration guidance (Azure/AWS/GCP/Okta/CyberArk) |
| `compare_vendors` | Side-by-side vendor feature comparison for a specific IAM capability |
| `get_misconfigurations` | Common IAM misconfigurations and their security impact |
| `get_migration_path` | Migration guidance between IAM platforms |

### Emerging & Advanced (3 tools)

| Tool | Description |
|------|-------------|
| `get_emerging_technology` | Passwordless/DID/passkeys/CIAM: maturity, standards, vendor support |
| `get_machine_identity` | Non-human identity: service accounts, managed identities, workload identity |
| `assess_iam_maturity` | IAM maturity assessment against CISA ZTMM |

### Meta (2 tools)

| Tool | Description |
|------|-------------|
| `list_sources` | List all data sources with provenance and freshness metadata |
| `about` | Server version, capabilities, and database statistics |

---

## Database Estimates

| Component | Records | Est. Size |
|-----------|---------|-----------|
| Standards & frameworks | ~300-400 | ~15-25 MB |
| Protocols | ~30 | ~2-5 MB |
| Attack patterns (ATT&CK) | ~150-200 | ~10-20 MB |
| IAM weaknesses (CWE/CAPEC) | ~80-100 | ~5-10 MB |
| Architecture patterns | ~40-50 | ~3-5 MB |
| Vendor configurations | ~200-300 | ~20-40 MB |
| Compliance mappings | ~500+ | ~5-10 MB |
| Emerging technologies | ~30-40 | ~3-5 MB |
| **Total** | **~1,300-1,500+** | **~80-150 MB** |

**Delivery strategy:** DB bundled in npm package (Strategy A -- fits within Vercel 250 MB function limit).

---

## Development

```bash
# Clone the repository
git clone https://github.com/Ansvar-Systems/IAM-mcp.git
cd IAM-mcp

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run contract tests
npm run test:contract

# Build database (requires seed data in data/seed/)
npm run build:db

# Run specific ingestion
npm run ingest:nist
npm run ingest:mitre
npm run ingest:cwe
npm run ingest:capec

# Run drift detection
npm run drift:detect

# Full validation
npm run validate
```

---

## Architecture

```
IAM-mcp/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                    # Test + lint + security scan
│   │   ├── publish.yml               # npm publish on version tags
│   │   └── drift-detect.yml          # Upstream drift detection
│   ├── SECURITY.md
│   └── ISSUE_TEMPLATE/
│       └── data-error.md
├── api/
│   ├── mcp.ts                        # Vercel Streamable HTTP endpoint
│   └── health.ts                     # Health check endpoint
├── data/
│   ├── seed/                         # Seed JSON files (gitignored)
│   └── .gitkeep
├── fixtures/
│   ├── golden-tests.json             # Contract tests
│   └── golden-hashes.json            # Drift detection anchors
├── scripts/
│   ├── lib/                          # Shared ingestion utilities
│   ├── build-db.ts                   # Seed JSON -> SQLite database
│   ├── ingest.ts                     # Orchestrates all ingestion
│   ├── ingest-nist.ts                # NIST SP ingestion
│   ├── ingest-mitre.ts               # MITRE ATT&CK ingestion
│   ├── ingest-cwe.ts                 # CWE identity families
│   ├── ingest-capec.ts               # CAPEC identity patterns
│   └── drift-detect.ts              # Upstream change detection
├── src/
│   ├── constants.ts                  # Server name, version, env vars
│   ├── capabilities.ts               # Runtime table detection
│   ├── index.ts                      # stdio entry point
│   ├── utils/
│   │   ├── fts-query.ts              # FTS5 query builder + sanitizer
│   │   └── metadata.ts               # ToolResponse + metadata helpers
│   └── tools/
│       ├── registry.ts               # Tool registration (shared)
│       ├── get-iam-standard.ts
│       ├── search-iam-requirements.ts
│       ├── check-iam-compliance.ts
│       ├── map-frameworks.ts
│       ├── get-assurance-levels.ts
│       ├── get-iam-attack.ts
│       ├── search-iam-threats.ts
│       ├── get-iam-weakness.ts
│       ├── assess-iam-posture.ts
│       ├── get-iam-stride-patterns.ts
│       ├── get-protocol.ts
│       ├── get-access-model.ts
│       ├── recommend-architecture.ts
│       ├── get-lifecycle-pattern.ts
│       ├── get-zero-trust-pattern.ts
│       ├── get-vendor-config.ts
│       ├── compare-vendors.ts
│       ├── get-misconfigurations.ts
│       ├── get-migration-path.ts
│       ├── get-emerging-technology.ts
│       ├── get-machine-identity.ts
│       ├── assess-iam-maturity.ts
│       ├── list-sources.ts
│       └── about.ts
├── __tests__/
│   └── contract/
│       └── golden.test.ts            # Contract tests against golden data
├── tests/
│   ├── tools/                        # Unit tests for tools
│   └── utils/                        # Unit tests for utilities
├── sources.yml                       # Data provenance metadata
├── server.json                       # MCP server manifest
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── vercel.json
├── CLAUDE.md
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## Related Documents

- [MCP Quality Standard](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/mcp-quality-standard.md) -- quality requirements for all Ansvar MCPs
- [MCP Infrastructure Blueprint](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/mcp-infrastructure-blueprint.md) -- infrastructure implementation templates
- [MCP Deployment Tiers](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/mcp-deployment-tiers.md) -- free vs. professional tier strategy
- [MCP Server Registry](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/mcp-server-registry.md) -- operational registry of all MCPs
- [IAM Expert MCP Design](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/plans/2026-02-20-iam-mcp-design.md) -- design document

---

## Security

Report vulnerabilities to **security@ansvar.eu** (48-hour acknowledgment SLA).

See [SECURITY.md](.github/SECURITY.md) for full disclosure policy.

---

**Maintained by:** Ansvar Systems Engineering
**Contact:** hello@ansvar.eu
