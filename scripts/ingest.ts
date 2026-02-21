#!/usr/bin/env tsx
/**
 * IAM Expert MCP — Ingestion Orchestrator
 *
 * Runs data ingestion from upstream sources, then rebuilds the SQLite database.
 *
 * Usage:
 *   npm run ingest                       # Run all ingestion scripts
 *   npm run ingest -- --source nist      # Run only NIST ingestion
 *   npm run ingest -- --source mitre     # Run only MITRE ATT&CK ingestion
 *   npm run ingest -- --force            # Force re-download (bypass cache)
 *   npm run ingest -- --skip-build       # Skip database rebuild after ingestion
 */

import { fileURLToPath } from 'node:url';
import { ingestNist, type IngestResult } from './ingest-nist.js';
import { buildDatabase } from './build-db.js';

// ---------------------------------------------------------------------------
// Registry of available ingestion sources
// ---------------------------------------------------------------------------

interface IngestionSource {
  name: string;
  description: string;
  run: (force: boolean) => Promise<IngestResult>;
}

const SOURCES: IngestionSource[] = [
  {
    name: 'nist',
    description: 'NIST SP 800-53 rev5 (AC & IA families)',
    run: ingestNist,
  },
  // Future sources:
  // { name: 'mitre', description: 'MITRE ATT&CK STIX bundle', run: ingestMitre },
  // { name: 'cwe',   description: 'CWE XML (identity/access families)', run: ingestCwe },
  // { name: 'capec', description: 'CAPEC XML (identity attack patterns)', run: ingestCapec },
];

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface CliArgs {
  source: string | null;
  force: boolean;
  skipBuild: boolean;
}

function parseArgs(): CliArgs {
  const args = process.argv.slice(2);
  let source: string | null = null;
  let force = false;
  let skipBuild = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--source' && args[i + 1]) {
      source = args[i + 1];
      i++;
    } else if (args[i] === '--force') {
      force = true;
    } else if (args[i] === '--skip-build') {
      skipBuild = true;
    }
  }

  return { source, force, skipBuild };
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { source, force, skipBuild } = parseArgs();

  console.log('IAM Expert MCP — Ingestion Pipeline');
  console.log('═'.repeat(50));
  console.log();

  if (force) console.log('  --force: bypassing cache for all sources');
  if (skipBuild) console.log('  --skip-build: database rebuild will be skipped');
  console.log();

  // Determine which sources to run
  let toRun: IngestionSource[];
  if (source) {
    const found = SOURCES.find((s) => s.name === source);
    if (!found) {
      console.error(`Unknown source: "${source}". Available sources:`);
      for (const s of SOURCES) {
        console.error(`  ${s.name.padEnd(10)} — ${s.description}`);
      }
      process.exit(1);
    }
    toRun = [found];
  } else {
    toRun = SOURCES;
  }

  // Run ingestion
  const results: IngestResult[] = [];
  const overallStart = Date.now();

  for (const src of toRun) {
    console.log(`\n${'─'.repeat(50)}`);
    console.log(`Source: ${src.name} — ${src.description}`);
    console.log(`${'─'.repeat(50)}\n`);

    try {
      const result = await src.run(force);
      results.push(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`\n  ERROR ingesting ${src.name}: ${msg}\n`);
      results.push({
        source: src.name,
        records: 0,
        cached: false,
        changed: false,
        durationMs: 0,
      });
    }
  }

  // Rebuild database
  if (!skipBuild) {
    console.log(`\n${'─'.repeat(50)}`);
    console.log('Rebuilding database...');
    console.log(`${'─'.repeat(50)}\n`);

    try {
      buildDatabase();
      console.log('  Database rebuilt successfully.');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ERROR rebuilding database: ${msg}`);
    }
  }

  // Summary
  const overallDuration = Date.now() - overallStart;
  const totalRecords = results.reduce((sum, r) => sum + r.records, 0);

  console.log();
  console.log('═'.repeat(50));
  console.log('Ingestion Summary');
  console.log('═'.repeat(50));
  console.log();
  console.log(`  ${'Source'.padEnd(15)} ${'Records'.padEnd(10)} ${'Status'.padEnd(15)} ${'Time'.padEnd(10)}`);
  console.log(`  ${'─'.repeat(15)} ${'─'.repeat(10)} ${'─'.repeat(15)} ${'─'.repeat(10)}`);

  for (const r of results) {
    const status = r.records === 0 ? 'FAILED' : r.cached ? 'cached' : r.changed ? 'updated' : 'fresh';
    const time = `${(r.durationMs / 1000).toFixed(1)}s`;
    console.log(`  ${r.source.padEnd(15)} ${String(r.records).padEnd(10)} ${status.padEnd(15)} ${time}`);
  }

  console.log();
  console.log(`  Total records: ${totalRecords}`);
  console.log(`  Total time:    ${(overallDuration / 1000).toFixed(1)}s`);
  console.log();
}

// CLI entry point
const currentFile = fileURLToPath(import.meta.url);
if (
  process.argv[1] &&
  (process.argv[1] === currentFile || process.argv[1] === currentFile.replace(/\.ts$/, '.js'))
) {
  main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}
