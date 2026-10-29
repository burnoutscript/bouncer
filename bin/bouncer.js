#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/index.js';
import { extractInstalls, toTarget } from '../src/commands.js';
import { pretty, json, markdown } from '../src/report.js';
import { runHook } from '../src/hook.js';
import { detonate, prettyDetonation } from '../src/detonate.js';

const BIN = fileURLToPath(import.meta.url);
const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const WRAPPED = new Set(['npm', 'npx', 'pnpm', 'pnpx', 'yarn', 'bun', 'bunx', 'pip', 'pip3', 'python', 'python3', 'py', 'uv', 'uvx', 'poetry', 'pipx', 'pdm']);

const HELP = `bouncer ${VERSION}: the bouncer for your AI agent's installs

Scan before you install
  bouncer scan express                 npm package (latest)
  bouncer scan npm:lodash@4.17.21      pinned version
  bouncer scan pypi:requests==2.32.3   PyPI package
  bouncer scan https://x.dev/install.sh   a curl | sh script
  bouncer scan ./my-mcp-server         a local folder, skill or MCP server

Guard a command (scans first, runs only if clean)
  bouncer npm install left-pad
  bouncer pip install requests
  bouncer run -- <any command>

Protect your agent automatically
  bouncer setup                Claude Code hook in ~/.claude/settings.json
  bouncer setup --project      ... in ./.claude/settings.json instead
  bouncer setup --print        print the hook config without writing it

Detonate (needs Docker)
  bouncer detonate npm:some-pkg        run install + import in a sandbox full of fake credentials

Options
  --json | --markdown     output format
  -v, --verbose           show every finding with the reasoning
  --fail-on <block|review>  exit 1 at this verdict or worse (default: block)
  -y, --yes               wrapper: run even if the verdict is REVIEW
  --force                 wrapper: run even if the verdict is BLOCK
  --no-cache
  -h, --help · --version
`;

function parse(argv) {
  const o = { rest: [], format: 'pretty', failOn: 'block', cache: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { o.rest.push(...argv.slice(i + 1)); o.dashdash = true; break; }
    else if (a === '--json') o.format = 'json';
    else if (a === '--markdown') o.format = 'markdown';
    else if (a === '-v' || a === '--verbose') o.verbose = true;
    else if (a === '--fail-on') o.failOn = argv[++i];
    else if (a === '-y' || a === '--yes') o.yes = true;
    else if (a === '--force') o.force = true;
    else if (a === '--no-cache') o.cache = false;
    else if (a === '--project') o.project = true;
    else if (a === '--print') o.print = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '--version') o.version = true;
    else o.rest.push(a);
  }
  return o;
}

const out = s => process.stdout.write(s);
const err = s => process.stderr.write(s);
const FORMATS = { pretty, json, markdown };
const failed = (reports, failOn) => reports.some(r => r.verdict === 'BLOCK' || (failOn === 'review' && r.verdict === 'REVIEW'));

async function scanAll(targets, o) {
  const settled = await Promise.allSettled(targets.map(t => scan(t, { cache: o.cache })));
  const reports = [];
  for (const [i, s] of settled.entries()) {
    if (s.status === 'fulfilled') reports.push(s.value);
    else err(`bouncer: could not scan ${targets[i]}: ${s.reason?.message}\n`);
  }
  return { reports, errors: settled.filter(s => s.status === 'rejected').length };
}

async function cmdScan(o) {
  if (!o.rest.length) { err('bouncer: nothing to scan. Try: bouncer scan express\n'); return 2; }
  const { reports, errors } = await scanAll(o.rest, o);
  out(FORMATS[o.format](reports, { verbose: o.verbose }));
  if (failed(reports, o.failOn)) return 1;
  return errors ? 2 : 0;
}

async function cmdWrap(argv, o) {
  const command = argv.join(' ');
  const installs = extractInstalls(command);
  if (installs.length) {
    const { reports } = await scanAll(installs.map(toTarget), o);
    err(pretty(reports.filter(r => r.verdict !== 'SAFE' || o.verbose), { verbose: o.verbose }));
    const block = reports.some(r => r.verdict === 'BLOCK');
    const review = reports.some(r => r.verdict === 'REVIEW');
    if (block && !o.force) { err('⛔ bouncer: not running this. Use --force if you are sure.\n'); return 1; }
    if (review && !o.yes && !o.force) {
      if (!process.stdin.isTTY) { err('⚠️  bouncer: needs review. Re-run with --yes to proceed.\n'); return 1; }
      err('⚠️  Proceed anyway? [y/N] ');
      const answer = await new Promise(r => process.stdin.once('data', d => r(String(d).trim().toLowerCase())));
      process.stdin.pause();
      if (answer !== 'y' && answer !== 'yes') return 1;
    }
    if (!block && !review) err(`✅ bouncer: ${reports.length} package${reports.length === 1 ? '' : 's'} look clean\n`);
  }
  const r = spawnSync(argv[0], argv.slice(1), { stdio: 'inherit', shell: process.platform === 'win32', windowsHide: true });
  return r.status ?? 1;
}

function hookEntry() {
  const cmd = `node "${BIN.replace(/\\/g, '/')}" hook`;
  return { matcher: 'Bash', hooks: [{ type: 'command', command: cmd, timeout: 60 }] };
}

function cmdSetup(o) {
  const entry = hookEntry();
  if (o.print) { out(JSON.stringify({ hooks: { PreToolUse: [entry] } }, null, 2) + '\n'); return 0; }
  const file = o.project ? resolve('.claude', 'settings.json') : join(homedir(), '.claude', 'settings.json');
  let settings = {};
  if (existsSync(file)) {
    try { settings = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { err(`bouncer: ${file} is not valid JSON (${e.message}). Fix it or use --print.\n`); return 2; }
  }
  settings.hooks ??= {};
  settings.hooks.PreToolUse ??= [];
  const existing = settings.hooks.PreToolUse.find(h => h.hooks?.some(x => /bouncer(\.js)?["']?\s+hook\b/.test(x.command ?? '')));
  if (existing) {
    existing.hooks = entry.hooks;
    existing.matcher = 'Bash';
  } else {
    settings.hooks.PreToolUse.push(entry);
  }
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
  out(`✅ bouncer is guarding Claude Code installs (${file})\n`);
  if (/[\\/]_npx[\\/]/.test(BIN)) err('⚠️  You ran setup through npx, so the hook points at a temporary copy. Install it for good with: npm i -g agent-bouncer && bouncer setup\n');
  return 0;
}

async function main() {
  const argv = process.argv.slice(2);
  const first = argv[0];
  if (first && WRAPPED.has(first.toLowerCase())) return cmdWrap(argv, parse([]));
  const o = parse(argv);
  if (o.version) { out(`${VERSION}\n`); return 0; }
  const [cmd, ...rest] = o.rest;
  o.rest = rest;
  if (o.help || !cmd) { out(HELP); return cmd || o.help ? 0 : 0; }
  switch (cmd) {
    case 'scan': return cmdScan(o);
    case 'hook': return runHook();
    case 'setup': return cmdSetup(o);
    case 'run': return o.rest.length ? cmdWrap(o.rest, o) : (err('bouncer: usage: bouncer run -- <command>\n'), 2);
    case 'detonate': {
      if (!o.rest.length) { err('bouncer: usage: bouncer detonate <target>\n'); return 2; }
      const report = await detonate(o.rest[0], { onLog: s => err(s) });
      out(o.format === 'json' ? JSON.stringify(report, null, 2) + '\n' : prettyDetonation(report));
      return report.verdict === 'BLOCK' ? 1 : 0;
    }
    default:
      // "bouncer express" is a scan.
      o.rest = [cmd, ...rest];
      return cmdScan(o);
  }
}

main().then(code => { process.exitCode = code; }, e => { err(`bouncer: ${e.message}\n`); process.exitCode = 2; });
