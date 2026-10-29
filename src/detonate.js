// Dynamic analysis: run a package's install scripts and import it inside a
// network-less Docker container full of fake credentials, then read the
// strace log and the fake-internet log to see what it actually did.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { fetchTarget } from './fetch.js';
import { score, verdictOf } from './analyze.js';

const DOCKER_DIR = fileURLToPath(new URL('../docker/', import.meta.url));
const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const IMAGE = process.env.BOUNCER_IMAGE || `agent-bouncer-sandbox:${VERSION}`;

const BAIT = {
  '.ssh/id_rsa': 'SSH private key',
  '.aws/credentials': 'AWS credentials',
  '.npmrc': 'npm token',
  '.git-credentials': 'git credentials',
  '.config/gh/hosts.yml': 'GitHub CLI token',
  '.docker/config.json': 'Docker registry credentials',
  '.kube/config': 'Kubernetes token',
  '.env': '.env file',
};
const WATCHED_WRITES = {
  '.claude/settings.json': ['ai-config-tamper', 'Rewrote Claude Code settings'],
  '.bashrc': ['persistence', 'Modified ~/.bashrc'],
  '.profile': ['persistence', 'Modified ~/.profile'],
  '.zshrc': ['persistence', 'Modified ~/.zshrc'],
  '.ssh/authorized_keys': ['persistence', 'Added an SSH authorized key'],
};
const LOUD_BINARIES = /\/(curl|wget|nc|ncat|socat|ssh|scp|base64|openssl|powershell|pwsh|python3? -c|perl|crontab|systemctl)$/;
const REGISTRY_HOSTS = /(^|\.)(registry\.npmjs\.org|npmjs\.com|pypi\.org|files\.pythonhosted\.org|github\.com|githubusercontent\.com|objects\.githubusercontent\.com|nodejs\.org)$/;

function docker(args, opts = {}) {
  return spawnSync('docker', args, { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024, ...opts });
}

export function dockerAvailable() {
  const r = docker(['version', '--format', '{{.Server.Version}}']);
  return r.status === 0 ? r.stdout.trim() : null;
}

function ensureImage(onLog) {
  if (docker(['image', 'inspect', IMAGE]).status === 0) return;
  onLog(`bouncer: building sandbox image ${IMAGE} (first run only)...\n`);
  const r = docker(['build', '-t', IMAGE, DOCKER_DIR], { stdio: ['ignore', 'ignore', 'pipe'] });
  if (r.status !== 0) throw new Error(`docker build failed: ${r.stderr?.slice(-500)}`);
}

const unescape = s => s.replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');

export function parseTrace(text, home = '/home/victim') {
  const events = { reads: [], writes: [], connects: [], execs: [], leaks: [] };
  for (const line of text.split('\n')) {
    let m;
    if ((m = line.match(/\b(?:openat|open|creat)\((?:AT_FDCWD, |\d+, )?"([^"]+)"(?:, ([A-Z_|]+))?.*?\)\s+=\s+(-?\d+)/))) {
      const [, path, flags = '', ret] = m;
      if (Number(ret) < 0 || !path.startsWith(home + '/')) continue;
      const rel = path.slice(home.length + 1);
      if (/O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND/.test(flags) || line.includes('creat(')) events.writes.push(rel);
      else events.reads.push(rel);
    } else if ((m = line.match(/\bconnect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), (?:sin_addr=inet_addr\("([^"]+)"\)|sin6_addr[^}]*inet_pton\(AF_INET6, "([^"]+)"\))/))) {
      const port = Number(m[1]);
      const addr = m[2] ?? m[3];
      if (!(port === 53 && addr === '127.0.0.1')) events.connects.push({ addr, port });
    } else if ((m = line.match(/\bexecve\("([^"]+)", \[(.*?)\], /))) {
      const argv = [...m[2].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(x => unescape(x[1]));
      events.execs.push({ bin: m[1], argv });
    }
    if (/\b(sendto|sendmsg|write)\(/.test(line)) events.leaks.push(line);
  }
  return events;
}

export function interpret({ traces, net, canary, phases, claudeAfter }) {
  const findings = [];
  const add = (id, severity, title, why, snippet = null) => findings.push({ id, severity, title, why, file: null, line: null, snippet });
  const all = traces.join('\n');
  const ev = parseTrace(all);

  const dns = net.filter(n => n.kind === 'dns' && n.name && !/^(localhost|.*\.local)$/.test(n.name));
  const tcp = net.filter(n => n.kind === 'tcp');
  const outbound = [...new Set([...dns.map(d => d.name), ...tcp.map(t => t.sni).filter(Boolean)])];
  const suspiciousHosts = outbound.filter(h => !REGISTRY_HOSTS.test(h));

  const baitRead = [...new Set(ev.reads.map(r => BAIT[r]).filter(Boolean))];
  const leakedNet = tcp.filter(t => t.preview?.includes(canary));
  const leakedWrite = ev.leaks.filter(l => l.includes(canary) && /\b(sendto|sendmsg)\(/.test(l));

  if (leakedNet.length || leakedWrite.length) {
    add('exfiltration', 'critical', 'Sent your (fake) secrets over the network', 'Bait credentials planted in the sandbox showed up in outgoing traffic. This package steals credentials.', (leakedNet[0]?.preview ?? leakedWrite[0]).replace(/\s+/g, ' ').slice(0, 200));
  }
  if (baitRead.length) {
    add('secret-read', outbound.length ? 'critical' : 'high', `Read ${baitRead.join(', ')}`, outbound.length ? 'Read credential files and then made network requests.' : 'Install and import code has no reason to open credential files.');
  }
  for (const [path, [id, title]] of Object.entries(WATCHED_WRITES)) {
    if (ev.writes.includes(path)) add(id, 'critical', title, 'Changed a file outside the package that persists or controls your agent.');
  }
  if (claudeAfter && claudeAfter.trim() !== '{"hooks":{}}') {
    add('ai-config-tamper', 'critical', 'Claude Code settings changed during install', 'New hooks or MCP servers in your agent config give an attacker a permanent foothold.', claudeAfter.replace(/\s+/g, ' ').slice(0, 200));
  }
  if (suspiciousHosts.length) {
    add('network', baitRead.length ? 'critical' : 'medium', `Contacted ${suspiciousHosts.slice(0, 5).join(', ')}${suspiciousHosts.length > 5 ? ` and ${suspiciousHosts.length - 5} more` : ''}`, 'Network calls during install or import. Some packages download binaries; check that these hosts make sense.');
  }
  const rawIp = ev.connects.filter(c => c.addr !== '127.0.0.1' && c.addr !== '::1');
  if (rawIp.length) add('network-ip', 'high', `Connected straight to IP ${rawIp[0].addr}:${rawIp[0].port}`, 'Skipping DNS and dialing an IP is typical of malware C2.');
  const loud = [...new Set(ev.execs.filter(e => LOUD_BINARIES.test(e.bin) || /\b(curl|wget)\b.*\|\s*(ba)?sh/.test(e.argv.join(' '))).map(e => e.argv.join(' ').slice(0, 120)))];
  if (loud.length) add('exec', 'medium', `Ran ${loud.length} suspicious command${loud.length > 1 ? 's' : ''}`, 'Process launches during install or import.', loud.slice(0, 3).join(' ; '));

  const risk = score(findings);
  return {
    verdict: verdictOf(risk),
    risk,
    findings,
    observed: {
      phases,
      filesRead: [...new Set(ev.reads)].slice(0, 50),
      filesWritten: [...new Set(ev.writes)].slice(0, 50),
      dns: [...new Set(dns.map(d => d.name))],
      connections: tcp.map(t => ({ port: t.port, sni: t.sni, bytes: t.bytes })),
      processes: ev.execs.map(e => e.argv.join(' ').slice(0, 160)).slice(0, 50),
    },
  };
}

export async function detonate(target, { onLog = () => {}, keep = false } = {}) {
  if (!dockerAvailable()) {
    throw new Error('Docker is not running. Detonation needs Docker (https://docs.docker.com/get-docker/). Static scans with `bouncer scan` work without it.');
  }
  ensureImage(onLog);
  const pkg = await fetchTarget(target);
  const root = mkdtempSync(join(tmpdir(), 'bouncer-'));
  const pkgDir = join(root, 'pkg');
  const outDir = join(root, 'out');
  mkdirSync(outDir);
  for (const f of pkg.files) {
    const dest = join(pkgDir, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.data);
  }
  const kind = pkg.ecosystem === 'script' ? 'script' : pkg.ecosystem === 'pypi' ? 'pypi' : 'npm';
  const entry = kind === 'script' ? pkg.files[0].path : '';
  const canary = `BOUNCERCANARY${randomBytes(8).toString('hex').toUpperCase()}`;

  onLog(`bouncer: detonating ${pkg.name}${pkg.version ? `@${pkg.version}` : ''} in a sandbox (no network, fake credentials)...\n`);
  const r = docker([
    'run', '--rm', '--network', 'none', '--cap-add', 'SYS_PTRACE',
    '--memory', '1g', '--pids-limit', '512', '--cpus', '2',
    '-e', `CANARY=${canary}`,
    '-v', `${pkgDir}:/pkg:ro`, '-v', `${DOCKER_DIR}:/harness:ro`, '-v', `${outDir}:/out`,
    IMAGE, 'bash', '/harness/harness.sh', kind, entry,
  ], { timeout: 6 * 60 * 1000 });
  if (r.error) throw r.error;

  const read = f => (existsSync(join(outDir, f)) ? readFileSync(join(outDir, f), 'utf8') : '');
  const traces = readdirSync(outDir).filter(f => f.startsWith('trace.')).map(read);
  const net = read('net.log').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const phases = read('phases.log').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const result = interpret({ traces, net, canary, phases, claudeAfter: read('claude-settings.after.json') });
  if (!keep) rmSync(root, { recursive: true, force: true });
  return { target: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, ...result, ...(keep && { workdir: root }) };
}

export function prettyDetonation(r) {
  const icon = { BLOCK: '⛔', REVIEW: '⚠️ ', SAFE: '✅' }[r.verdict];
  const out = [`${icon} ${r.verdict}  ${r.target}${r.version ? `@${r.version}` : ''}  (detonated · risk ${r.risk}/100)`];
  for (const f of r.findings) {
    out.push(`   ${f.severity.toUpperCase().padEnd(8)} ${f.title}`);
    if (f.snippet) out.push(`            │ ${f.snippet}`);
  }
  const o = r.observed;
  out.push('', '   Observed:');
  out.push(`     phases     ${o.phases.filter(p => p.cmd).map(p => p.phase).join(', ') || '-'}`);
  out.push(`     dns        ${o.dns.join(', ') || '-'}`);
  out.push(`     processes  ${o.processes.length}`);
  out.push(`     home reads ${o.filesRead.filter(f => !f.startsWith('.cache') && !f.startsWith('.local')).join(', ') || '-'}`);
  out.push('');
  return out.join('\n');
}
