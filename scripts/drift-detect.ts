#!/usr/bin/env tsx
/**
 * IAM Expert MCP — Drift Detection
 *
 * Checks upstream sources for changes by comparing current content hashes
 * against a stored drift state file (data/source/drift-state.json).
 *
 * Exit codes:
 *   0 — No drift detected (all sources unchanged)
 *   1 — Drift detected (one or more sources changed)
 *
 * Usage:
 *   npm run drift:detect                 # Check for drift (read-only)
 *   npm run drift:detect -- --update     # Check and update drift state
 *   npm run drift:detect -- --verbose    # Show detailed per-source info
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchWithCache, sha256 } from './lib/fetcher.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SOURCE_DIR = join(__dirname, '..', 'data', 'source');
const DRIFT_STATE_FILE = join(SOURCE_DIR, 'drift-state.json');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DriftSource {
  /** Human-readable source name. */
  name: string;
  /** Upstream URL to check. */
  url: string;
  /** Cache key for the fetcher. */
  cacheKey: string;
  /** HTTP Accept header. */
  accept?: string;
}

interface DriftStateEntry {
  name: string;
  url: string;
  contentHash: string;
  etag?: string;
  lastChecked: string;
}

interface DriftState {
  version: string;
  lastChecked: string;
  sources: Record<string, DriftStateEntry>;
}

interface DriftResult {
  name: string;
  status: 'unchanged' | 'changed' | 'new' | 'error';
  oldHash?: string;
  newHash?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Sources to check — derived from sources.yml
// ---------------------------------------------------------------------------

const DRIFT_SOURCES: DriftSource[] = [
  {
    name: 'NIST SP 800-53 rev5 (OSCAL JSON)',
    url: 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json',
    cacheKey: 'drift-nist-800-53.json',
    accept: 'application/json',
  },
  // Future sources can be added here as ingestion scripts are built:
  // {
  //   name: 'MITRE ATT&CK Enterprise',
  //   url: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
  //   cacheKey: 'drift-mitre-attack.json',
  //   accept: 'application/json',
  // },
  // {
  //   name: 'CWE Database',
  //   url: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
  //   cacheKey: 'drift-cwe.xml.zip',
  // },
];

// ---------------------------------------------------------------------------
// Drift state persistence
// ---------------------------------------------------------------------------

function loadDriftState(): DriftState {
  if (!existsSync(DRIFT_STATE_FILE)) {
    return { version: '1.0', lastChecked: '', sources: {} };
  }
  try {
    return JSON.parse(readFileSync(DRIFT_STATE_FILE, 'utf-8')) as DriftState;
  } catch {
    return { version: '1.0', lastChecked: '', sources: {} };
  }
}

function saveDriftState(state: DriftState): void {
  if (!existsSync(SOURCE_DIR)) {
    mkdirSync(SOURCE_DIR, { recursive: true });
  }
  state.lastChecked = new Date().toISOString();
  writeFileSync(DRIFT_STATE_FILE, JSON.stringify(state, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface CliArgs {
  update: boolean;
  verbose: boolean;
}

function parseArgs(): CliArgs {
  const args = process.argv.slice(2);
  return {
    update: args.includes('--update'),
    verbose: args.includes('--verbose'),
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { update, verbose } = parseArgs();

  console.log('IAM Expert MCP — Drift Detection');
  console.log('═'.repeat(50));
  console.log();

  if (update) console.log('  --update: drift state will be updated after check');
  if (verbose) console.log('  --verbose: showing detailed per-source info');
  console.log();

  const state = loadDriftState();
  const results: DriftResult[] = [];

  for (const source of DRIFT_SOURCES) {
    process.stdout.write(`  Checking ${source.name}... `);

    try {
      const fetchResult = await fetchWithCache(source.url, source.cacheKey, {
        accept: source.accept,
        force: true, // Always fetch fresh for drift detection
      });

      const newHash = sha256(fetchResult.data);
      const existing = state.sources[source.name];

      if (!existing) {
        console.log('NEW (first check)');
        results.push({
          name: source.name,
          status: 'new',
          newHash,
        });
      } else if (existing.contentHash === newHash) {
        console.log('OK (unchanged)');
        results.push({
          name: source.name,
          status: 'unchanged',
          oldHash: existing.contentHash,
          newHash,
        });
      } else {
        console.log('DRIFT DETECTED');
        results.push({
          name: source.name,
          status: 'changed',
          oldHash: existing.contentHash,
          newHash,
        });
      }

      // Update state entry (only persisted if --update flag is set)
      if (update) {
        state.sources[source.name] = {
          name: source.name,
          url: source.url,
          contentHash: newHash,
          etag: fetchResult.headers['etag'],
          lastChecked: new Date().toISOString(),
        };
      }

      if (verbose) {
        console.log(`    URL:      ${source.url}`);
        console.log(`    Hash:     ${newHash.substring(0, 16)}...`);
        if (existing) {
          console.log(`    Previous: ${existing.contentHash.substring(0, 16)}...`);
          console.log(`    Last:     ${existing.lastChecked}`);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`ERROR: ${msg}`);
      results.push({
        name: source.name,
        status: 'error',
        error: msg,
      });
    }
  }

  // Save updated state if --update
  if (update) {
    saveDriftState(state);
    console.log(`\n  Drift state saved to: ${DRIFT_STATE_FILE}`);
  }

  // Summary
  const changed = results.filter((r) => r.status === 'changed');
  const newSources = results.filter((r) => r.status === 'new');
  const errors = results.filter((r) => r.status === 'error');
  const unchanged = results.filter((r) => r.status === 'unchanged');

  console.log();
  console.log('═'.repeat(50));
  console.log('Drift Detection Summary');
  console.log('═'.repeat(50));
  console.log();
  console.log(`  Unchanged:  ${unchanged.length}`);
  console.log(`  Changed:    ${changed.length}`);
  console.log(`  New:        ${newSources.length}`);
  console.log(`  Errors:     ${errors.length}`);

  if (changed.length > 0) {
    console.log();
    console.log('  Sources with drift:');
    for (const r of changed) {
      console.log(`    - ${r.name}`);
    }
    console.log();
    console.log('  Run "npm run ingest" to re-ingest changed sources.');
  }

  console.log();

  // Exit code: 1 if any drift detected
  if (changed.length > 0) {
    process.exit(1);
  }
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
