import { FILE_RULES, chainRules, binaryRule, SEVERITY } from './rules.js';
import { lookalike } from './popular.js';

const KINDS = {
  js: 'js', mjs: 'js', cjs: 'js', jsx: 'js', ts: 'js', tsx: 'js', mts: 'js', cts: 'js',
  py: 'py', pyw: 'py', pth: 'py',
  sh: 'sh', bash: 'sh', zsh: 'sh', command: 'sh',
  ps1: 'ps1', psm1: 'ps1', bat: 'bat', cmd: 'bat', rb: 'rb', php: 'php',
  md: 'md', markdown: 'md', mdc: 'mdc', txt: 'txt', json: 'json', yml: 'yaml', yaml: 'yaml', toml: 'toml',
};

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare'];

// Install scripts that are boring and everywhere.
const BENIGN_SCRIPT = /^(node-gyp rebuild|node-gyp-build|prebuild-install( \|\| node-gyp rebuild)?.*|node-pre-gyp install.*|husky( install)?|is-ci \|\| husky.*|patch-package|ngcc.*|opencollective(-postinstall)?.*|node -e "try\{require\('\.\/postinstall'\)\}catch\(e\)\{\}"|npm run build|tsc|lerna bootstrap|echo .*)$/;

function kindOf(path, data) {
  const ext = path.includes('.') ? path.split('.').pop().toLowerCase() : '';
  if (/\.d\.[cm]?ts$/.test(path) || /\.map$/.test(path)) return 'other';
  if (KINDS[ext]) return KINDS[ext];
  if (/(^|\/)\.cursorrules$/.test(path)) return 'md';
  const head = data.subarray(0, 64).toString();
  if (head.startsWith('#!')) return /python/.test(head) ? 'py' : /node/.test(head) ? 'js' : 'sh';
  return 'other';
}

// Never run at install: tests, docs, CI, examples. Browser bundles don't run in Node either.
const AUX = /(^|\/)(tests?|testing|__tests__|spec|examples?|docs?|ci|\.circleci|\.github|benchmarks?|fixtures)\//;
const BROWSER = /(^|\/)(static|public|assets|frontend|templates)\/.*\.[cm]?js$|\.min\.[cm]?js$/;

// Rules run on the first 2 MB and last 1 MB of huge files: payloads sit at the
// edges of bundles, and full scans of 8 MB minified files cost too much.
const HEAD = 2 * 1024 * 1024;
const TAIL = 1024 * 1024;
const textOf = d => (d.length <= HEAD + TAIL ? d.toString('utf8') : `${d.subarray(0, HEAD).toString('utf8')}\n${d.subarray(d.length - TAIL).toString('utf8')}`);

const isBinary = d => d.subarray(0, 8000).includes(0);

function npmRoles(files) {
  const roles = new Map();
  const virtual = [];
  const findings = [];
  const pkgFile = files.find(f => f.path === 'package.json');
  if (!pkgFile) return { roles, virtual, findings, manifest: null };
  let pkg;
  try { pkg = JSON.parse(pkgFile.data.toString('utf8')); } catch { return { roles, virtual, findings, manifest: null }; }

  const scripts = pkg.scripts || {};
  for (const hook of LIFECYCLE) {
    const cmd = scripts[hook];
    if (typeof cmd !== 'string') continue;
    const benign = BENIGN_SCRIPT.test(cmd.trim());
    findings.push({
      id: 'install-script', severity: benign ? 'low' : 'medium',
      title: `Runs a "${hook}" script on install`, why: benign ? 'A common, usually harmless build step.' : 'Code runs on your machine the moment the package is installed, before you ever use it.',
      file: 'package.json', line: null, snippet: `"${hook}": ${JSON.stringify(cmd).slice(0, 140)}`,
    });
    // The script string itself is shell code that runs at install.
    virtual.push({ path: `package.json#scripts.${hook}`, data: Buffer.from(cmd), kind: 'sh', role: 'install' });
    for (const m of cmd.matchAll(/([\w./@-]+\.(?:c|m)?js|[\w./-]+\.(?:sh|py))\b/g)) roles.set(m[1].replace(/^\.\//, ''), 'install');
    const inline = cmd.match(/node\s+(?:-e|--eval)\s+(['"])([\s\S]*)\1/);
    if (inline) virtual.push({ path: `package.json#scripts.${hook}:inline`, data: Buffer.from(inline[2]), kind: 'js', role: 'install' });
  }
  if (!scripts.install && !scripts.preinstall && files.some(f => f.path === 'binding.gyp')) {
    findings.push({ id: 'install-script', severity: 'low', title: 'Builds a native addon on install (binding.gyp)', why: 'npm runs node-gyp automatically.', file: 'binding.gyp', line: null, snippet: null });
  }

  const entries = [pkg.main || 'index.js', pkg.module];
  const collect = e => {
    if (!e) return;
    if (typeof e === 'string') entries.push(e);
    else if (typeof e === 'object') Object.values(e).forEach(collect);
  };
  collect(pkg.exports?.['.'] ?? (typeof pkg.exports === 'string' ? pkg.exports : null));
  for (const e of entries.filter(Boolean)) {
    const p = String(e).replace(/^\.\//, '');
    for (const cand of [p, `${p}.js`, `${p}/index.js`]) if (!roles.has(cand)) roles.set(cand, 'entry');
  }
  return { roles, virtual, findings, manifest: pkg };
}

function pypiRoles(files) {
  const roles = new Map();
  const findings = [];
  for (const f of files) {
    if (f.path === 'setup.py') roles.set(f.path, 'install');
    else if (/^(src\/)?[^/]+\/__init__\.py$/.test(f.path) && !AUX.test(f.path)) roles.set(f.path, 'entry');
    else if (f.path.endsWith('.pth') && !AUX.test(f.path)) {
      const text = f.data.toString('utf8');
      if (/^\s*import\s/m.test(text)) {
        roles.set(f.path, 'entry');
        findings.push({ id: 'pth-exec', severity: 'high', title: 'Ships a .pth file that runs code at every Python startup', why: 'Lines starting with "import" in .pth files execute whenever any Python process starts, even if you never import this package.', file: f.path, line: 1, snippet: text.trim().slice(0, 140) });
      }
    }
  }
  return { roles, virtual: [], findings };
}

function metaFindings(pkg, hasInstallScript) {
  const out = [];
  const m = pkg.meta || {};
  const now = Date.now();
  const hours = t => (t ? (now - Date.parse(t)) / 36e5 : Infinity);
  const age = hours(m.publishedAt);
  if (age < 72) {
    out.push({ id: 'fresh-release', severity: hasInstallScript ? 'medium' : 'low', title: `Version published ${age < 1 ? 'less than an hour' : `${Math.round(age)} hours`} ago`, why: hasInstallScript ? 'Hijacked accounts publish poisoned versions that get pulled before anyone notices. A brand-new release with an install script is the classic pattern.' : 'Most supply-chain attacks are caught within days of publishing.', file: null, line: null, snippet: null });
  }
  const created = hours(m.createdAt);
  if (created < 24 * 30) {
    out.push({ id: 'new-package', severity: created < 24 * 7 ? 'medium' : 'low', title: `Package first published ${Math.round(created / 24)} days ago`, why: 'New packages have no track record. Agents are tricked into installing them by look-alike or hallucinated names.', file: null, line: null, snippet: null });
  }
  if (m.deprecated) out.push({ id: 'deprecated', severity: 'low', title: 'Deprecated or yanked', why: String(m.deprecated).slice(0, 200), file: null, line: null, snippet: null });
  if (!pkg.local && pkg.ecosystem !== 'script' && !m.repository) out.push({ id: 'no-repository', severity: 'low', title: 'No source repository listed', why: "You can't compare the published code with its source.", file: null, line: null, snippet: null });

  if (pkg.ecosystem === 'npm' || pkg.ecosystem === 'pypi') {
    const twin = lookalike(pkg.name, pkg.ecosystem);
    if (twin) {
      const young = created < 24 * 180 || (m.versionCount ?? 99) < 5;
      out.push({ id: 'typosquat', severity: young ? 'high' : 'low', title: `Name looks like "${twin}"`, why: young ? 'A young package with a look-alike name is the textbook typosquat.' : `Probably legitimate, but make sure you meant "${twin}".`, file: null, line: null, snippet: null });
    }
  }
  return out;
}

// Worst finding counts in full, the rest at half. Low findings are context,
// not alarms, so together they can never add more than 10 points.
export function score(findings) {
  const serious = findings.filter(f => f.severity !== 'low').map(f => SEVERITY[f.severity] ?? 0).sort((a, b) => b - a);
  const low = Math.min(10, findings.filter(f => f.severity === 'low').length * SEVERITY.low);
  if (!serious.length) return low;
  return Math.min(100, Math.round(serious[0] + 0.5 * serious.slice(1).reduce((a, b) => a + b, 0) + low));
}

export const verdictOf = risk => (risk >= 60 ? 'BLOCK' : risk >= 25 ? 'REVIEW' : 'SAFE');

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function analyze(pkg) {
  const isNpm = pkg.ecosystem === 'npm' || pkg.files.some(f => f.path === 'package.json');
  const isPy = pkg.ecosystem === 'pypi' || pkg.files.some(f => f.path === 'setup.py' || f.path.endsWith('.pth'));
  const roles = new Map();
  const findings = [];
  const virtual = [];
  for (const r of [isNpm && npmRoles(pkg.files), isPy && pypiRoles(pkg.files)].filter(Boolean)) {
    r.roles.forEach((v, k) => { if (roles.get(k) !== 'install') roles.set(k, v); });
    virtual.push(...r.virtual);
    findings.push(...r.findings);
  }

  // An MCP server depends on an MCP SDK; mentioning one in a string doesn't count.
  const MCP_SIGNS = /"@modelcontextprotocol\/sdk"\s*:|"fastmcp"\s*:|^[ \t]*(from mcp(\.server)?(\.fastmcp)? import|import mcp\b)|from fastmcp\s+import|new McpServer\(|FastMCP\(/m;
  const isMcp = pkg.files.some(f => /\.(json|[cm]?js|ts|py)$/.test(f.path) && MCP_SIGNS.test(f.data.subarray(0, 200000).toString('utf8')));

  const prepared = [
    ...pkg.files.map(f => {
      const binary = isBinary(f.data);
      return {
        ...f,
        kind: binary ? 'binary' : kindOf(f.path, f.data),
        text: binary ? null : textOf(f.data),
        role: pkg.ecosystem === 'script' ? 'install' : roles.get(f.path) ?? (AUX.test(f.path) || BROWSER.test(f.path) || (pkg.ecosystem === 'pypi' && /\.[cm]?js$/.test(f.path)) ? 'aux' : 'runtime'),
      };
    }),
    ...virtual.map(v => ({ ...v, text: v.data.toString('utf8') })),
  ].map(f => ({ ...f, isMcp }));

  const DOWN = { critical: 'medium', high: 'low', medium: 'low', low: 'low' };
  for (const f of prepared) {
    for (const rule of FILE_RULES) {
      for (const x of rule(f)) {
        // Tests, docs and examples don't run on install; count them one level lower.
        findings.push(f.role === 'aux' && x.id !== 'hidden-unicode' ? { ...x, severity: DOWN[x.severity] } : x);
      }
    }
  }
  for (const f of prepared) {
    for (const x of chainRules(f, findings)) findings.push(f.role === 'aux' ? { ...x, severity: DOWN[x.severity] } : x);
  }
  findings.push(...binaryRule(prepared));
  findings.push(...metaFindings(pkg, findings.some(f => f.id === 'install-script' && f.severity !== 'low')));

  // One finding per rule per file; keep the worst.
  const seen = new Map();
  for (const f of findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])) {
    const key = `${f.id}|${f.file}|${f.title}`;
    if (!seen.has(key)) seen.set(key, f);
  }
  const unique = [...seen.values()];
  const risk = score(unique);
  return {
    target: pkg.name,
    ecosystem: pkg.ecosystem,
    version: pkg.version,
    artifact: pkg.artifact ?? null,
    files: pkg.files.length,
    skipped: pkg.skipped?.length ?? 0,
    mcp: isMcp,
    risk,
    verdict: verdictOf(risk),
    findings: unique,
  };
}
