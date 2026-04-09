/**
 * check-data-freshness — Report database build timestamp and freshness status.
 *
 * Queries the db_metadata table for built_at and computes staleness relative
 * to today. Required meta-tool per the golden standard (alongside about and
 * list_sources).
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface DataFreshnessResult {
  built_at: string | null;
  age_days: number | null;
  status: 'fresh' | 'stale' | 'unknown';
  schema_version: string;
  tier: string;
  message: string;
}

const STALE_THRESHOLD_DAYS = 90;

export async function checkDataFreshness(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
): Promise<ToolResponse<DataFreshnessResult>> {
  const meta: Record<string, string> = {};
  try {
    const rows = db.prepare('SELECT key, value FROM db_metadata').all() as { key: string; value: string }[];
    for (const row of rows) {
      meta[row.key] = row.value;
    }
  } catch {
    // db_metadata table may not exist in older databases
  }

  const builtAt = meta.built_at ?? null;
  const tier = meta.tier ?? 'free';
  const schemaVersion = meta.schema_version ?? '1.0';

  let ageDays: number | null = null;
  let status: DataFreshnessResult['status'] = 'unknown';
  let message: string;

  if (builtAt) {
    try {
      const builtDate = new Date(builtAt);
      const now = new Date();
      ageDays = Math.floor((now.getTime() - builtDate.getTime()) / (1000 * 60 * 60 * 24));
      if (ageDays <= STALE_THRESHOLD_DAYS) {
        status = 'fresh';
        message = `Database is ${ageDays} day(s) old. Data is current.`;
      } else {
        status = 'stale';
        message = `Database is ${ageDays} day(s) old (threshold: ${STALE_THRESHOLD_DAYS} days). Consider updating the database for the most current IAM data.`;
      }
    } catch {
      message = `Database built_at timestamp could not be parsed: ${builtAt}`;
    }
  } else {
    message = 'Database build timestamp is not available. The db_metadata table may be missing or incomplete.';
  }

  return {
    results: {
      built_at: builtAt,
      age_days: ageDays,
      status,
      schema_version: schemaVersion,
      tier,
      message,
    },
    _meta: generateResponseMetadata(builtAt ?? undefined),
  };
}
