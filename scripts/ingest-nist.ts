#!/usr/bin/env tsx
/**
 * NIST SP 800-53 rev5 Ingestion Script
 *
 * Fetches the NIST SP 800-53 rev5 OSCAL JSON catalog from GitHub and extracts
 * Access Control (AC) and Identification & Authentication (IA) family controls.
 *
 * Output is written to data/seed/standards-nist-800-53-ac.json in the seed
 * format consumed by build-db.ts.
 *
 * Source: US Government work — Public Domain (no copyright restrictions).
 *
 * Usage:
 *   npm run ingest:nist
 *   npx tsx scripts/ingest-nist.ts
 */

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchWithCache } from './lib/fetcher.js';
import { parseOscalJson } from './lib/parser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SEED_DIR = join(__dirname, '..', 'data', 'seed');

const NIST_OSCAL_URL =
  'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json';
const CACHE_KEY = 'nist-800-53-rev5-catalog.json';
const OUTPUT_FILE = join(SEED_DIR, 'standards-nist-800-53-ac.json');

/** Families to extract from the OSCAL catalog. */
const TARGET_FAMILIES = ['ac', 'ia'];

export interface IngestResult {
  source: string;
  records: number;
  cached: boolean;
  changed: boolean;
  durationMs: number;
}

/**
 * Run the NIST SP 800-53 ingestion.
 *
 * @param force  If true, bypass cache and re-download.
 * @returns Ingestion result summary.
 */
export async function ingestNist(force = false): Promise<IngestResult> {
  const start = Date.now();

  console.log('NIST SP 800-53 rev5 Ingestion');
  console.log('─'.repeat(40));
  console.log(`  Source:   ${NIST_OSCAL_URL}`);
  console.log(`  Families: ${TARGET_FAMILIES.map((f) => f.toUpperCase()).join(', ')}`);
  console.log(`  Output:   ${OUTPUT_FILE}`);
  console.log();

  // Fetch OSCAL catalog
  process.stdout.write('  Fetching OSCAL catalog... ');
  const result = await fetchWithCache(NIST_OSCAL_URL, CACHE_KEY, {
    accept: 'application/json',
    force,
  });

  if (result.cached) {
    console.log('cached (no change upstream)');
  } else if (result.changed) {
    console.log(`downloaded (${(result.data.length / 1024).toFixed(0)} KB, content changed)`);
  } else {
    console.log(`downloaded (${(result.data.length / 1024).toFixed(0)} KB, first fetch)`);
  }

  // Parse OSCAL JSON
  process.stdout.write('  Parsing OSCAL controls... ');
  const standards = parseOscalJson(result.data, TARGET_FAMILIES);
  console.log(`${standards.length} controls extracted`);

  // Write seed file
  if (!existsSync(SEED_DIR)) {
    mkdirSync(SEED_DIR, { recursive: true });
  }

  const seedData = { standards };
  writeFileSync(OUTPUT_FILE, JSON.stringify(seedData, null, 2) + '\n');
  console.log(`  Written to: ${OUTPUT_FILE}`);

  const durationMs = Date.now() - start;

  // Summary
  console.log();
  console.log('  Summary:');
  console.log(`    AC controls:  ${standards.filter((s) => s.section?.startsWith('AC-')).length}`);
  console.log(`    IA controls:  ${standards.filter((s) => s.section?.startsWith('IA-')).length}`);
  console.log(`    Total:        ${standards.length}`);
  console.log(`    Duration:     ${(durationMs / 1000).toFixed(1)}s`);

  return {
    source: 'nist-800-53',
    records: standards.length,
    cached: result.cached,
    changed: result.changed,
    durationMs,
  };
}

// CLI entry point
const currentFile = fileURLToPath(import.meta.url);
if (
  process.argv[1] &&
  (process.argv[1] === currentFile || process.argv[1] === currentFile.replace(/\.ts$/, '.js'))
) {
  const force = process.argv.includes('--force');
  ingestNist(force).catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}
