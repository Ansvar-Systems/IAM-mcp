/**
 * recommend-architecture — Given requirements (scale, compliance frameworks,
 * existing vendor), search architecture patterns and return scored matches.
 *
 * Scoring:
 * - FTS match on scale-related terms in patterns_fts: +1
 * - Each compliance framework reference found in compliance_mappings JSON: +1
 * - Vendor compatibility (existing vendor found in vendor_configurations): +1
 * - Results sorted by descending score, top 10 returned
 */

import { sanitizeFtsInput, buildFtsQueryVariants } from '../utils/fts-query.js';
import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface RecommendArchitectureInput {
  scale?: string;
  compliance?: string[];
  existing?: string;
}

export interface RecommendationEntry {
  id: string;
  name: string;
  category: string;
  description: string;
  when_to_use: string;
  compliance_mappings: string[];
  related_patterns: string[];
  score: number;
}

interface RawPatternRow {
  id: string;
  name: string;
  category: string;
  description: string;
  when_to_use: string;
  when_not_to_use: string | null;
  components: string;
  data_flow: string | null;
  strengths: string | null;
  weaknesses: string | null;
  compliance_mappings: string;
  related_patterns: string;
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: RecommendArchitectureInput,
): Promise<ToolResponse<RecommendationEntry[]>> {
  // Collect candidate pattern IDs with scores
  const scores = new Map<string, number>();
  const patternCache = new Map<string, RawPatternRow>();

  // --- FTS search for scale-related terms ---
  if (params.scale && params.scale.trim().length > 0) {
    const sanitized = sanitizeFtsInput(params.scale);
    const variants = buildFtsQueryVariants(sanitized);

    for (const variant of variants) {
      try {
        const sql = 'SELECT ap.* FROM architecture_patterns ap JOIN patterns_fts f ON ap.rowid = f.rowid WHERE patterns_fts MATCH ? LIMIT 20';
        const rows = db.prepare(sql).all(variant) as RawPatternRow[];
        for (const row of rows) {
          scores.set(row.id, (scores.get(row.id) ?? 0) + 1);
          patternCache.set(row.id, row);
        }
        if (rows.length > 0) break; // use first successful variant
      } catch {
        continue;
      }
    }
  }

  // --- Compliance framework matching ---
  if (params.compliance && params.compliance.length > 0) {
    // Load all patterns to check compliance_mappings JSON
    const allPatterns = db.prepare('SELECT * FROM architecture_patterns').all() as RawPatternRow[];
    for (const row of allPatterns) {
      const mappings: string[] = JSON.parse(row.compliance_mappings || '[]');
      let complianceScore = 0;

      for (const framework of params.compliance) {
        // Normalize framework to lowercase for comparison
        const fw = framework.toLowerCase();
        const hasMatch = mappings.some((m) => m.toLowerCase().includes(fw));
        if (hasMatch) {
          complianceScore += 1;
        }
      }

      if (complianceScore > 0) {
        scores.set(row.id, (scores.get(row.id) ?? 0) + complianceScore);
        patternCache.set(row.id, row);
      }
    }
  }

  // --- Vendor compatibility ---
  if (params.existing && params.existing.trim().length > 0) {
    // Check vendor_configurations for the specified vendor
    const vendorRows = db
      .prepare('SELECT DISTINCT id FROM vendor_configurations WHERE vendor = ?')
      .all(params.existing) as { id: string }[];

    if (vendorRows.length > 0) {
      // The vendor exists — boost all patterns that are in the score map
      // Also, add patterns that relate to vendor-supported categories
      const vendorCategories = db
        .prepare('SELECT DISTINCT category FROM vendor_configurations WHERE vendor = ?')
        .all(params.existing) as { category: string }[];

      const categories = new Set(vendorCategories.map((c) => c.category));

      // Load all patterns if not already loaded
      const allPatterns = db.prepare('SELECT * FROM architecture_patterns').all() as RawPatternRow[];
      for (const row of allPatterns) {
        // Check if the pattern category maps to a vendor-supported category
        // Map pattern categories to vendor configuration categories
        const categoryMap: Record<string, string[]> = {
          'access-model': ['authorization'],
          'federation': ['federation'],
          'privileged-access': ['privileged-access'],
          'lifecycle': ['governance'],
          'zero-trust': ['authentication', 'authorization'],
          'directory': ['authentication'],
          'ciam': ['authentication', 'federation'],
        };

        const vendorCats = categoryMap[row.category] ?? [];
        const hasVendorSupport = vendorCats.some((vc) => categories.has(vc));

        if (hasVendorSupport) {
          scores.set(row.id, (scores.get(row.id) ?? 0) + 1);
          patternCache.set(row.id, row);
        }
      }
    }
  }

  // --- Build results sorted by score ---
  const entries: RecommendationEntry[] = [];
  for (const [id, score] of scores.entries()) {
    const row = patternCache.get(id);
    if (!row) continue;

    entries.push({
      id: row.id,
      name: row.name,
      category: row.category,
      description: row.description,
      when_to_use: row.when_to_use,
      compliance_mappings: JSON.parse(row.compliance_mappings || '[]'),
      related_patterns: JSON.parse(row.related_patterns || '[]'),
      score,
    });
  }

  // Sort by score descending, then by name ascending
  entries.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  // Return top 10
  const results = entries.slice(0, 10);

  return {
    results,
    _metadata: generateResponseMetadata(),
  };
}
