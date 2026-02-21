/**
 * get-protocol — Lookup an identity protocol by exact ID.
 *
 * Returns full protocol details including flow type, security considerations,
 * recommended use-cases, RFC references, and sequence diagrams.
 */

import { generateResponseMetadata, type ToolResponse } from '../utils/metadata.js';

export interface GetProtocolInput {
  id: string;
}

export interface ProtocolEntry {
  id: string;
  protocol: string;
  flow_type: string | null;
  description: string;
  security_considerations: string;
  recommended_for: string[];
  deprecated: boolean;
  rfc: string | null;
  sequence_diagram: string | null;
}

interface RawProtocolRow {
  id: string;
  protocol: string;
  flow_type: string | null;
  description: string;
  security_considerations: string;
  recommended_for: string;
  deprecated: number;
  rfc: string | null;
  sequence_diagram: string | null;
}

function parseProtocol(row: RawProtocolRow): ProtocolEntry {
  return {
    ...row,
    recommended_for: JSON.parse(row.recommended_for || '[]'),
    deprecated: row.deprecated === 1,
  };
}

export async function handler(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown; all(...params: unknown[]): unknown[] } },
  params: GetProtocolInput,
): Promise<ToolResponse<ProtocolEntry[]>> {
  const row = db.prepare('SELECT * FROM protocols WHERE id = ?').get(params.id) as RawProtocolRow | undefined;

  const results = row ? [parseProtocol(row)] : [];

  return {
    results,
    _metadata: generateResponseMetadata(),
  };
}
