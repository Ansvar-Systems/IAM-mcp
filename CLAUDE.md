# IAM Expert MCP Server -- Developer Guide

## Git Workflow

- **Never commit directly to `main`.** Always create a feature branch and open a Pull Request.
- Branch protection requires: verified signatures, PR review, and status checks to pass.
- Use conventional commit prefixes: `feat:`, `fix:`, `chore:`, `docs:`, etc.

## Project Overview

IAM Expert MCP server providing identity and access management intelligence via Model Context Protocol. Covers standards advisory (NIST/ISO/Zero Trust), threat patterns (MITRE ATT&CK/CWE/CAPEC), protocol deep-dives (OAuth/OIDC/SAML/FIDO2), architecture patterns (RBAC/ABAC/PAM), vendor configurations (Azure/AWS/GCP/Okta/CyberArk), compliance cross-mapping, and emerging technology tracking. Distributed as npm stdio package only (Vercel removed 2026-04-26).

## Architecture

- **Transport:** stdio (npm package only — Vercel removed 2026-04-26)
- **Database:** SQLite + FTS5 via `@ansvar/mcp-sqlite` (WASM-compatible, no WAL mode)
- **Entry point:** `src/index.ts` (stdio)
- **Tool registry:** `src/tools/registry.ts`
- **Capability gating:** `src/capabilities.ts` -- detects available DB tables at runtime
- **Tables:** 8 domain tables (`standards`, `protocols`, `attack_patterns`, `iam_weaknesses`, `architecture_patterns`, `vendor_configurations`, `compliance_mappings`, `emerging_technologies`)
- **Tools:** 22 domain tools + 2 meta tools (`list_sources`, `about`) across 5 categories

## Key Conventions

- All database queries use parameterized statements (never string interpolation)
- FTS5 queries go through `buildFtsQueryVariants()` with primary + fallback strategy
- User input is sanitized via `sanitizeFtsInput()` before FTS5 queries
- Every tool returns `ToolResponse<T>` with `results` + `_metadata` (freshness, disclaimer)
- Tool descriptions are written for LLM agents -- explain WHEN and WHY to use each tool
- Capability-gated tools only appear in `tools/list` when their DB tables exist

## Testing

- Unit tests: `tests/` (vitest, in-memory SQLite fixtures)
- Contract tests: `__tests__/contract/golden.test.ts` with `fixtures/golden-tests.json`
- Nightly mode: `CONTRACT_MODE=nightly` enables network assertions
- Run: `npm test` (unit), `npm run test:contract` (golden), `npm run validate` (both)

## Database

- Schema defined inline in `scripts/build-db.ts`
- Journal mode: DELETE (not WAL)
- Metadata: `db_metadata` table stores tier, schema_version, built_at, builder

## Data Pipeline

1. `scripts/ingest.ts` -- orchestrates all source-specific ingest scripts
2. `scripts/ingest-nist.ts` -- NIST SP 800-63/800-53/800-207 via OSCAL JSON + HTML extraction
3. `scripts/ingest-mitre.ts` -- MITRE ATT&CK techniques via STIX/TAXII API
4. `scripts/ingest-cwe.ts` -- CWE identity/access families via XML download
5. `scripts/ingest-capec.ts` -- CAPEC identity attack patterns via XML download
6. `scripts/build-db.ts` -- seed JSON -> SQLite database in `data/database.db`
7. `scripts/drift-detect.ts` -- verifies upstream content hasn't changed

## Data Sources

- **NIST** (SP 800-63, 800-53 AC family, 800-207, 800-162) -- US Government, public domain
- **MITRE** (ATT&CK, CWE, CAPEC) -- Apache-2.0 / terms of use
- **OWASP** (ASVS V2/V3/V4) -- CC BY-SA 4.0
- **CISA** (Zero Trust Maturity Model) -- US Government, public domain
- **IETF** (OAuth 2.0/2.1 RFCs, SCIM RFCs) -- IETF Trust License
- **OpenID Foundation** (OIDC Core) -- Apache-2.0
- **OASIS** (SAML 2.0) -- OASIS IPR Policy
- **W3C** (WebAuthn, DIDs, Verifiable Credentials) -- W3C Software License
- **FIDO Alliance** (Passkey guidance) -- FIDO Alliance Terms
- **ISO** (27001/27002 identity controls) -- control IDs and public summaries only
- **SOC 2** (CC6 criteria) -- fair use cross-mapping
- **Vendor docs** (Azure Entra, AWS IAM, GCP IAM, Okta/Auth0, Ping/ForgeRock, CyberArk, SailPoint) -- advisory summaries under fair use

**Removed sources:**
- **CIS Controls v8** (Controls 5, 6) -- removed 2026-04-26; non-commercial-only license conflicts with commercial gateway use. Phase 4 backfill candidates: NIST CSF 2.0, CISA guidance (both public domain). Check fleet-overlap with `security-controls` MCP before adding new ingestion.

## Deployment

- npm package: `@ansvar/iam-mcp` with bin entry for stdio
- Estimated DB size: ~80-150 MB (bundled deployment)
