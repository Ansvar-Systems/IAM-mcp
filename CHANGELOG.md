# Changelog

## [2.0.0] - 2026-04-26

### Removed
- CIS Controls v8 (Controls 5 and 6) data from seed files — non-commercial-only license conflicts with commercial gateway use. Removed 14 CIS standards entries and 33 CIS-sourced compliance mappings. Cross-references to CIS control IDs stripped from attack-pattern and standards records.
- Vercel deployment artifacts (`vercel.json`, `api/` directory) — stdio-only distribution going forward.
- `@vercel/node` devDependency.

### Changed
- Renamed `data/seed/standards-cis-owasp.json` to `standards-owasp.json` (OWASP ASVS entries retained, CIS entries removed).
- Renamed `data/seed/mappings-cis-soc2.json` to `mappings-frameworks.json` (CIS-sourced rows removed, 89 non-CIS mappings retained).
- `sources.yml` set to `sources: []` pending Phase 4 backfill. Phase 4 candidates: NIST CSF 2.0, CISA guidance. Fleet-overlap note: verify against `security-controls` MCP before adding new ingestion.
- Version bumped 1.0.0 → 2.0.0 (breaking: CIS data removed).

## [1.0.0] - 2026-02-21

### Added
- Initial release
- 22 IAM tools across 5 categories
- 8 database tables with FTS5 search
- Dual transport: stdio (npm) + Vercel Streamable HTTP
