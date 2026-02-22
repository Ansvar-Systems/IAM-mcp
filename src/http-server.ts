#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer as createHttpServer, IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID, createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import Database from '@ansvar/mcp-sqlite';
import { registerTools, type AboutContext } from './tools/registry.js';
import { detectCapabilities, readDbMetadata } from './capabilities.js';
import { DB_ENV_VAR, SERVER_NAME, SERVER_VERSION } from './constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PORT = parseInt(process.env.PORT || '3000', 10);

function resolveDbPath(): string {
  if (process.env[DB_ENV_VAR]) return process.env[DB_ENV_VAR]!;
  // dist/src/http-server.js → go up 2 levels to project root
  const relative = join(__dirname, '..', '..', 'data', 'database.db');
  if (existsSync(relative)) return relative;
  const alt = join(__dirname, '..', 'data', 'database.db');
  if (existsSync(alt)) return alt;
  throw new Error(`Database not found. Set ${DB_ENV_VAR} or ensure data/database.db exists`);
}

function computeAboutContext(db: InstanceType<typeof Database>): AboutContext {
  const dbPath = resolveDbPath();
  let fingerprint = 'unknown';
  let dbBuilt = 'unknown';

  try {
    const buf = readFileSync(dbPath);
    fingerprint = createHash('sha256').update(buf).digest('hex').slice(0, 12);
  } catch {
    // DB file might not be accessible for hashing
  }

  try {
    const row = db.prepare("SELECT value FROM db_metadata WHERE key = 'built_at'").get() as { value: string } | undefined;
    if (row) dbBuilt = row.value;
  } catch {
    // Ignore — table may not exist
  }

  return { version: SERVER_VERSION, fingerprint, dbBuilt };
}

async function main() {
  const dbPath = resolveDbPath();
  const db = new Database(dbPath, { readonly: true });
  db.pragma('foreign_keys = ON');

  const capabilities = detectCapabilities(db);
  const meta = readDbMetadata(db);
  const aboutContext = computeAboutContext(db);
  console.error(`[${SERVER_NAME}] DB opened: tier=${meta.tier}, caps=[${[...capabilities].join(',')}]`);

  const sessions = new Map<string, StreamableHTTPServerTransport>();

  function createMCPServer(): Server {
    const server = new Server(
      { name: SERVER_NAME, version: SERVER_VERSION },
      { capabilities: { tools: {} } },
    );
    registerTools(server, db, capabilities, aboutContext);
    return server;
  }

  const httpServer = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || '/', `http://localhost:${PORT}`);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');
    res.setHeader('Access-Control-Expose-Headers', 'mcp-session-id');

    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (url.pathname === '/health' && req.method === 'GET') {
        let dbOk = false;
        try {
          db.prepare('SELECT 1').get();
          dbOk = true;
        } catch {
          // DB not healthy
        }
        res.writeHead(dbOk ? 200 : 503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: dbOk ? 'ok' : 'degraded',
          server: SERVER_NAME,
          version: SERVER_VERSION,
          tier: meta.tier,
          capabilities: [...capabilities],
        }));
        return;
      }

      if (url.pathname === '/mcp') {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;

        if (sessionId && sessions.has(sessionId)) {
          await sessions.get(sessionId)!.handleRequest(req, res);
          return;
        }

        if (req.method === 'POST') {
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
          });
          const server = createMCPServer();
          transport.onclose = () => {
            if (transport.sessionId) sessions.delete(transport.sessionId);
          };
          await server.connect(transport);
          if (transport.sessionId) sessions.set(transport.sessionId, transport);
          await transport.handleRequest(req, res);
          return;
        }

        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad request — missing or invalid session' }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    } catch (error) {
      console.error('[HTTP] Unhandled error:', error);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    }
  });

  httpServer.listen(PORT, () => {
    console.log(`${SERVER_NAME} v${SERVER_VERSION} HTTP server listening on port ${PORT}`);
  });

  const shutdown = () => {
    console.log('Shutting down...');
    for (const [, t] of sessions) t.close().catch(() => {});
    sessions.clear();
    try { db.close(); } catch {}
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
