/**
 * HTTP Fetch Utility for IAM Expert MCP ingestion.
 *
 * Provides a rate-limited, retry-capable HTTP client with local file caching
 * and conditional request support (ETag / Last-Modified).
 *
 * Cache files are stored in data/source/ alongside a metadata sidecar (.meta.json)
 * that tracks ETag, Last-Modified, and content hash for drift detection.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SOURCE_DIR = join(__dirname, '..', '..', 'data', 'source');

const USER_AGENT = 'IAM-Expert-MCP/1.0 (https://github.com/Ansvar-Systems/IAM-mcp; hello@ansvar.ai)';
const MIN_DELAY_MS = 1000; // 1 request per second
const MAX_RETRIES = 3;

let lastRequestTime = 0;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface FetchOptions {
  /** HTTP accept header. Defaults to application/json. */
  accept?: string;
  /** Maximum number of retries on 429/5xx. Defaults to 3. */
  maxRetries?: number;
  /** Force re-download even if cache exists. */
  force?: boolean;
}

export interface FetchResult {
  /** Response body as a string. */
  data: string;
  /** Selected response headers (lowercase keys). */
  headers: Record<string, string>;
  /** True when result was served from local cache without a network request. */
  cached: boolean;
  /** True when upstream content differs from the cached version. */
  changed: boolean;
}

export interface CacheMeta {
  url: string;
  etag?: string;
  lastModified?: string;
  contentHash: string;
  fetchedAt: string;
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

async function rateLimit(): Promise<void> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < MIN_DELAY_MS) {
    await new Promise((resolve) => setTimeout(resolve, MIN_DELAY_MS - elapsed));
  }
  lastRequestTime = Date.now();
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

export function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf-8').digest('hex');
}

// ---------------------------------------------------------------------------
// Cache helpers
// ---------------------------------------------------------------------------

function ensureSourceDir(): void {
  if (!existsSync(SOURCE_DIR)) {
    mkdirSync(SOURCE_DIR, { recursive: true });
  }
}

function cachePath(cacheKey: string): string {
  return join(SOURCE_DIR, cacheKey);
}

function metaPath(cacheKey: string): string {
  return join(SOURCE_DIR, `${cacheKey}.meta.json`);
}

function readMeta(cacheKey: string): CacheMeta | null {
  const mp = metaPath(cacheKey);
  if (!existsSync(mp)) return null;
  try {
    return JSON.parse(readFileSync(mp, 'utf-8')) as CacheMeta;
  } catch {
    return null;
  }
}

function writeMeta(cacheKey: string, meta: CacheMeta): void {
  writeFileSync(metaPath(cacheKey), JSON.stringify(meta, null, 2));
}

function readCache(cacheKey: string): string | null {
  const cp = cachePath(cacheKey);
  if (!existsSync(cp)) return null;
  return readFileSync(cp, 'utf-8');
}

function writeCache(cacheKey: string, data: string): void {
  writeFileSync(cachePath(cacheKey), data);
}

// ---------------------------------------------------------------------------
// Core fetch
// ---------------------------------------------------------------------------

/**
 * Fetch a URL with rate limiting, retry, and local file caching.
 *
 * - On first fetch: downloads, caches to `data/source/<cacheKey>`, and stores
 *   metadata (ETag, Last-Modified, content hash) in a `.meta.json` sidecar.
 * - On subsequent fetches: sends conditional headers (If-None-Match /
 *   If-Modified-Since). If the server returns 304, the cached copy is used.
 * - Retries up to `maxRetries` times on 429 and 5xx with exponential backoff.
 *
 * @param url       The upstream URL to fetch.
 * @param cacheKey  Filename used under `data/source/` for caching.
 * @param options   Optional configuration.
 */
export async function fetchWithCache(
  url: string,
  cacheKey: string,
  options?: FetchOptions,
): Promise<FetchResult> {
  const accept = options?.accept ?? 'application/json';
  const maxRetries = options?.maxRetries ?? MAX_RETRIES;
  const force = options?.force ?? false;

  ensureSourceDir();

  const meta = readMeta(cacheKey);
  const cachedData = readCache(cacheKey);

  // If we have a cache and are not forced, try conditional request
  const headers: Record<string, string> = {
    'User-Agent': USER_AGENT,
    Accept: accept,
  };

  if (!force && meta && cachedData) {
    if (meta.etag) headers['If-None-Match'] = meta.etag;
    if (meta.lastModified) headers['If-Modified-Since'] = meta.lastModified;
  }

  await rateLimit();

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let response: Response;
    try {
      response = await fetch(url, { headers });
    } catch (err) {
      if (attempt < maxRetries) {
        const backoff = Math.pow(2, attempt + 1) * 1000;
        console.log(`  Network error for ${url}, retrying in ${backoff}ms...`);
        await new Promise((resolve) => setTimeout(resolve, backoff));
        continue;
      }
      // Last attempt: if we have a cached copy, return it
      if (cachedData && meta) {
        console.log(`  Network error, using cached copy for ${cacheKey}`);
        return { data: cachedData, headers: {}, cached: true, changed: false };
      }
      throw err;
    }

    // 304 Not Modified — cache is still fresh
    if (response.status === 304 && cachedData) {
      return { data: cachedData, headers: {}, cached: true, changed: false };
    }

    // Retry on transient errors
    if (response.status === 429 || response.status >= 500) {
      if (attempt < maxRetries) {
        const backoff = Math.pow(2, attempt + 1) * 1000;
        console.log(`  HTTP ${response.status} for ${url}, retrying in ${backoff}ms...`);
        await new Promise((resolve) => setTimeout(resolve, backoff));
        continue;
      }
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} fetching ${url}`);
    }

    const data = await response.text();
    const contentHash = sha256(data);
    const changed = !meta || meta.contentHash !== contentHash;

    // Update cache
    writeCache(cacheKey, data);
    writeMeta(cacheKey, {
      url,
      etag: response.headers.get('etag') ?? undefined,
      lastModified: response.headers.get('last-modified') ?? undefined,
      contentHash,
      fetchedAt: new Date().toISOString(),
    });

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((v, k) => {
      responseHeaders[k.toLowerCase()] = v;
    });

    return { data, headers: responseHeaders, cached: false, changed };
  }

  throw new Error(`Failed to fetch ${url} after ${maxRetries} retries`);
}
