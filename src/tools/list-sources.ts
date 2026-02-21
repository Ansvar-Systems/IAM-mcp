/**
 * list_sources — Return provenance metadata for all data sources.
 *
 * Reads sources.yml and returns all data source entries with URLs, licences,
 * and update frequencies, plus database statistics.
 */

import type Database from '@ansvar/mcp-sqlite';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { readDbMetadata } from '../capabilities.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface SourceInfo {
  name: string;
  authority: string;
  url: string;
  license: string;
  coverage: string;
  update_frequency: string;
  languages: string[];
}

export interface ListSourcesResult {
  sources: SourceInfo[];
  database: {
    tier: string;
    schema_version: string;
    built_at?: string;
    table_counts: Record<string, number>;
  };
}

function safeCount(db: InstanceType<typeof Database>, sql: string): number {
  try {
    const row = db.prepare(sql).get() as { count: number } | undefined;
    return row ? Number(row.count) : 0;
  } catch {
    return 0;
  }
}

/**
 * Minimal YAML parser for our sources.yml structure.
 * Avoids adding a YAML dependency for a simple key-value file.
 */
function parseSourcesYml(content: string): SourceInfo[] {
  const sources: SourceInfo[] = [];

  // Split into source blocks using the "  - name:" pattern
  const blocks = content.split(/\n  - name: /);
  // Skip the first block (header before first source)
  for (let i = 1; i < blocks.length; i++) {
    const block = blocks[i];

    const name = extractQuotedValue('', block.split('\n')[0]) || block.split('\n')[0].replace(/^["']|["']$/g, '').trim();
    const authority = extractField(block, 'authority');
    const url = extractField(block, 'official_portal');
    const licenseType = extractNestedField(block, 'license_or_terms', 'type');
    const licenseSummary = extractNestedField(block, 'license_or_terms', 'summary');
    const coverageScope = extractNestedField(block, 'coverage', 'scope');
    const updateFrequency = extractField(block, 'update_frequency');

    // Extract languages array
    const languages: string[] = [];
    const langMatch = block.match(/languages:\s*\n((?:\s+-\s+"[^"]+"\s*\n?)+)/);
    if (langMatch) {
      const langEntries = langMatch[1].matchAll(/-\s+"([^"]+)"/g);
      for (const entry of langEntries) {
        languages.push(entry[1]);
      }
    }

    sources.push({
      name: name || 'Unknown',
      authority: authority || 'Unknown',
      url: url || '',
      license: licenseSummary || licenseType || 'Unknown',
      coverage: coverageScope || '',
      update_frequency: updateFrequency || 'unknown',
      languages: languages.length > 0 ? languages : ['en'],
    });
  }

  return sources;
}

function extractField(block: string, fieldName: string): string {
  const regex = new RegExp(`^\\s*${fieldName}:\\s*"([^"]*)"`, 'm');
  const match = block.match(regex);
  return match ? match[1] : '';
}

function extractNestedField(block: string, parentField: string, childField: string): string {
  const parentIdx = block.indexOf(`${parentField}:`);
  if (parentIdx < 0) return '';
  const subBlock = block.slice(parentIdx);
  const regex = new RegExp(`^\\s*${childField}:\\s*"([^"]*)"`, 'm');
  const match = subBlock.match(regex);
  return match ? match[1] : '';
}

function extractQuotedValue(_field: string, value: string): string {
  const match = value.match(/^"([^"]*)"$/);
  return match ? match[1] : '';
}

export async function listSources(
  db: InstanceType<typeof Database>,
): Promise<ToolResponse<ListSourcesResult>> {
  const meta = readDbMetadata(db);

  // Read sources.yml from project root
  let sources: SourceInfo[] = [];
  try {
    const sourcesPath = join(__dirname, '..', '..', 'sources.yml');
    const content = readFileSync(sourcesPath, 'utf-8');
    sources = parseSourcesYml(content);
  } catch {
    // sources.yml might not be available in all environments
  }

  return {
    results: {
      sources,
      database: {
        tier: meta.tier,
        schema_version: meta.schema_version,
        built_at: meta.built_at,
        table_counts: {
          standards: safeCount(db, 'SELECT COUNT(*) as count FROM standards'),
          protocols: safeCount(db, 'SELECT COUNT(*) as count FROM protocols'),
          attack_patterns: safeCount(db, 'SELECT COUNT(*) as count FROM attack_patterns'),
          iam_weaknesses: safeCount(db, 'SELECT COUNT(*) as count FROM iam_weaknesses'),
          architecture_patterns: safeCount(db, 'SELECT COUNT(*) as count FROM architecture_patterns'),
          vendor_configurations: safeCount(db, 'SELECT COUNT(*) as count FROM vendor_configurations'),
          compliance_mappings: safeCount(db, 'SELECT COUNT(*) as count FROM compliance_mappings'),
          emerging_technologies: safeCount(db, 'SELECT COUNT(*) as count FROM emerging_technologies'),
        },
      },
    },
    _metadata: generateResponseMetadata(),
  };
}
