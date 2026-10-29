import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, basename } from 'node:path';
import { readArchive, stripRoot, LIMITS } from './archive.js';

// Read at call time so tests and private mirrors can point elsewhere.
const npmBase = () => process.env.BOUNCER_NPM_REGISTRY || 'https://registry.npmjs.org';
const pypiBase = () => process.env.BOUNCER_PYPI || 'https://pypi.org';
const TIMEOUT = Number(process.env.BOUNCER_TIMEOUT_MS || 20000);
const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', 'venv', '__pycache__', '.next', 'dist-types']);

export class NotFoundError extends Error {}

async function get(url, as = 'json') {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(TIMEOUT),
    headers: { 'user-agent': 'agent-bouncer (+https://github.com/burnoutscript/bouncer)' },
  });
  if (res.status === 404) throw new NotFoundError(url);
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  if (as === 'json') return res.json();
  if (as === 'text') return res.text();
  return Buffer.from(await res.arrayBuffer());
}

// "npm:@scope/pkg@1.2.3", "pkg@latest", "pypi:requests==2.31.0", "https://x/install.sh", "./dir"
export function parseTarget(input) {
  const s = input.trim();
  if (/^https?:\/\//i.test(s)) return { type: 'url', url: s };
  if (s.startsWith('npm:')) return { type: 'npm', ...splitNpm(s.slice(4)) };
  if (/^(pypi|pip|py):/.test(s)) return { type: 'pypi', ...splitPypi(s.replace(/^(pypi|pip|py):/, '')) };
  if (existsSync(s)) return { type: 'local', path: resolve(s) };
  if (/[=<>~!]=|==/.test(s)) return { type: 'pypi', ...splitPypi(s) };
  return { type: 'npm', ...splitNpm(s) };
}

export function splitNpm(spec) {
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at).toLowerCase(), version: spec.slice(at + 1) || 'latest' };
  return { name: spec.toLowerCase(), version: 'latest' };
}

export function splitPypi(spec) {
  const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==\s*([^\s,;]+))?/);
  if (!m) return { name: spec, version: null };
  return { name: m[1].toLowerCase().replace(/[._]+/g, '-'), version: m[2] ?? null };
}

const cmp = (a, b) => {
  const pa = a.split(/[.+-]/).map(x => (isNaN(x) ? x : Number(x)));
  const pb = b.split(/[.+-]/).map(x => (isNaN(x) ? x : Number(x)));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === pb[i]) continue;
    if (pa[i] === undefined) return -1;
    if (pb[i] === undefined) return 1;
    return typeof pa[i] === typeof pb[i] ? (pa[i] > pb[i] ? 1 : -1) : typeof pa[i] === 'number' ? 1 : -1;
  }
  return 0;
};

// Small subset of semver ranges: exact, dist-tags, ^x, ~x, x, x.y, >=x.
function pickNpmVersion(doc, wanted) {
  const tags = doc['dist-tags'] || {};
  if (tags[wanted]) return tags[wanted];
  if (doc.versions?.[wanted]) return wanted;
  const stable = Object.keys(doc.versions || {}).filter(v => !v.includes('-')).sort(cmp);
  const m = wanted.match(/^([\^~]|>=)?v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?/);
  if (!m) return tags.latest;
  const [, op, maj, min, pat] = m;
  const fits = v => {
    const [a, b, c] = v.split('.').map(Number);
    if (op === '>=') return cmp(v, [maj, min ?? 0, pat ?? 0].join('.')) >= 0;
    if (a !== Number(maj)) return false;
    if (op === '~' || (!op && min !== undefined && !isNaN(min))) {
      if (min !== undefined && !isNaN(min) && b !== Number(min)) return false;
    }
    if (!op && pat !== undefined && !isNaN(pat)) return c === Number(pat);
    return true;
  };
  return stable.filter(fits).pop() ?? tags.latest;
}

async function fetchNpm({ name, version }) {
  const doc = await get(`${npmBase()}/${name.replace('/', '%2F')}`);
  const resolved = pickNpmVersion(doc, version);
  const manifest = doc.versions?.[resolved];
  if (!manifest) throw new NotFoundError(`${name}@${version}`);
  const tarball = await get(manifest.dist.tarball, 'buffer');
  const { files, skipped } = await readArchive(tarball, manifest.dist.tarball);
  const versions = Object.keys(doc.time || {}).filter(k => k !== 'created' && k !== 'modified');
  return {
    ecosystem: 'npm',
    name,
    version: resolved,
    files: stripRoot(files),
    skipped,
    meta: {
      publishedAt: doc.time?.[resolved] ?? null,
      createdAt: doc.time?.created ?? null,
      versionCount: versions.length,
      maintainers: (manifest.maintainers || doc.maintainers || []).length,
      repository: typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url ?? null,
      description: manifest.description ?? '',
      deprecated: manifest.deprecated ?? null,
      weeklyDownloads: null,
    },
  };
}

async function fetchPypi({ name, version }) {
  const doc = await get(`${pypiBase()}/pypi/${name}/${version ? `${version}/` : ''}json`);
  const urls = doc.urls || [];
  // The sdist matters most: setup.py runs at install time. Fall back to a pure wheel.
  const pick =
    urls.find(u => u.packagetype === 'sdist') ||
    urls.find(u => /py3-none-any\.whl$/.test(u.filename)) ||
    urls.find(u => u.packagetype === 'bdist_wheel');
  if (!pick) throw new NotFoundError(`${name} has no downloadable files`);
  const buf = await get(pick.url, 'buffer');
  const { files, skipped } = await readArchive(buf, pick.filename);
  const releases = doc.releases ? Object.keys(doc.releases) : [];
  const firstUpload = Object.values(doc.releases || {}).flat().map(f => f.upload_time_iso_8601).filter(Boolean).sort()[0];
  return {
    ecosystem: 'pypi',
    name,
    version: doc.info.version,
    artifact: pick.filename,
    files: pick.packagetype === 'sdist' ? stripRoot(files) : files,
    skipped,
    meta: {
      publishedAt: pick.upload_time_iso_8601 ?? null,
      createdAt: firstUpload ?? null,
      versionCount: releases.length,
      maintainers: null,
      repository: doc.info.project_urls?.Source || doc.info.project_urls?.Repository || doc.info.home_page || null,
      description: doc.info.summary ?? '',
      deprecated: doc.info.yanked ? doc.info.yanked_reason || 'yanked' : null,
    },
  };
}

async function fetchUrl({ url }) {
  const text = await get(url, 'text');
  const name = basename(new URL(url).pathname) || 'script';
  return { ecosystem: 'script', name: url, version: null, files: [{ path: name, data: Buffer.from(text) }], skipped: [], meta: {} };
}

function readLocal({ path }) {
  const files = [];
  const skipped = [];
  let total = 0;
  const add = file => {
    const st = statSync(file);
    const rel = relative(statSync(path).isDirectory() ? path : resolve(path, '..'), file).replace(/\\/g, '/');
    if (st.size > LIMITS.fileBytes || total + st.size > LIMITS.totalBytes) return skipped.push({ path: rel, size: st.size });
    total += st.size;
    files.push({ path: rel, data: readFileSync(file) });
  };
  const walk = dir => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(full); }
      else if (e.isFile()) add(full);
    }
  };
  if (statSync(path).isDirectory()) walk(path);
  else add(path);
  let name = basename(path);
  // A single script handed to bouncer is about to be run, like a curl | sh download.
  let ecosystem = statSync(path).isFile() && /\.(sh|bash|zsh|ps1|bat|cmd)$/i.test(path) ? 'script' : 'local';
  const pkg = files.find(f => f.path === 'package.json');
  if (pkg) {
    try { name = JSON.parse(pkg.data.toString()).name || name; ecosystem = 'npm'; } catch { /* not json */ }
  } else if (files.some(f => f.path === 'setup.py' || f.path === 'pyproject.toml')) {
    ecosystem = 'pypi';
  }
  return { ecosystem, name, version: null, local: true, files, skipped, meta: {} };
}

export async function fetchTarget(input) {
  const t = typeof input === 'string' ? parseTarget(input) : input;
  if (t.type === 'npm') return fetchNpm(t);
  if (t.type === 'pypi') return fetchPypi(t);
  if (t.type === 'url') return fetchUrl(t);
  return readLocal(t);
}
