/**
 * map-frameworks — Cross-map a control between compliance frameworks.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface MapFrameworksInput {
  control: string;
  from: string;
  to?: string;
}

export interface MappingEntry {
  id: number;
  source_framework: string;
  source_control: string;
  target_framework: string;
  target_control: string;
  relationship: string;
  notes: string | null;
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: MapFrameworksInput,
): Promise<ToolResponse<MappingEntry[]>> {
  const results: MappingEntry[] = [];

  // Forward lookup: source_framework=from, source_control=control
  {
    const conditions = ['source_framework = ?', 'source_control = ?'];
    const queryParams: unknown[] = [params.from, params.control];

    if (params.to) {
      conditions.push('target_framework = ?');
      queryParams.push(params.to);
    }

    const sql = `SELECT * FROM compliance_mappings WHERE ${conditions.join(' AND ')}`;
    const rows = db.prepare(sql).all(...queryParams) as MappingEntry[];
    results.push(...rows);
  }

  // Reverse lookup: target_framework=from, target_control=control
  {
    const conditions = ['target_framework = ?', 'target_control = ?'];
    const queryParams: unknown[] = [params.from, params.control];

    if (params.to) {
      conditions.push('source_framework = ?');
      queryParams.push(params.to);
    }

    const sql = `SELECT * FROM compliance_mappings WHERE ${conditions.join(' AND ')}`;
    const rows = db.prepare(sql).all(...queryParams) as MappingEntry[];
    results.push(...rows);
  }

  return {
    results,
    _metadata: generateResponseMetadata(),
  };
}
