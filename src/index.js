import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fetchTarget, parseTarget, NotFoundError } from './fetch.js';
import { analyze, score, verdictOf } from './analyze.js';

export { analyze, parseTarget, fetchTarget };

const CACHE_VERSION = 1;
const CACHE_DAYS = 7;

export function cacheDir() {
  if (process.env.BOUNCER_CACHE_DIR) return process.env.BOUNCER_CACHE_DIR;
  const base = process.env.XDG_CACHE_HOME || (process.platform === 'win32' ? process.env.LOCALAPPDATA : null) || join(homedir(), '.cache');
  return join(base, 'agent-bouncer');
}

function cachePath(key) {
  return join(cacheDir(), `${createHash('sha256').update(`${CACHE_VERSION}|${key}`).digest('hex').slice(0, 32)}.json`);
}

function readCache(key) {
  try {
    const p = cachePath(key);
    if (!existsSync(p)) return null;
    const hit = JSON.parse(readFileSync(p, 'utf8'));
    if (Date.now() - hit.cachedAt > CACHE_DAYS * 864e5) return null;
    return { ...hit.report, cached: true };
  } catch {
    return null;
  }
}

function writeCache(key, report) {
  try {
    mkdirSync(cacheDir(), { recursive: true });
    writeFileSync(cachePath(key), JSON.stringify({ cachedAt: Date.now(), report }));
  } catch { /* cache is best effort */ }
}

function notFound(t) {
  const name = t.name ?? t.url ?? t.path;
  const finding = {
    id: 'not-found', severity: 'critical',
    title: `"${name}" does not exist on ${t.type === 'pypi' ? 'PyPI' : 'npm'}`,
    why: 'AI agents hallucinate package names, and attackers register those names with malware (slopsquatting). Check the name before anyone publishes it.',
    file: null, line: null, snippet: null,
  };
  const risk = score([finding]);
  return { target: name, ecosystem: t.type, version: t.version ?? null, files: 0, risk, verdict: verdictOf(risk), findings: [finding] };
}

export async function scan(input, { cache = true } = {}) {
  const t = typeof input === 'string' ? parseTarget(input) : input;
  // Only pinned registry versions are immutable; ranges and local files must be rescanned.
  const pinned = (t.type === 'npm' && /^\d+\.\d+\.\d+/.test(t.version)) || (t.type === 'pypi' && t.version);
  const key = pinned ? `${t.type}:${t.name}@${t.version}` : null;
  if (cache && key) {
    const hit = readCache(key);
    if (hit) return hit;
  }
  let report;
  try {
    report = analyze(await fetchTarget(t));
  } catch (e) {
    if (e instanceof NotFoundError) return notFound(t);
    throw e;
  }
  if (cache && key) writeCache(key, report);
  return report;
}
