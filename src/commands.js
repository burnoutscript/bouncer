// Works out what a shell command is about to install or execute, so the hook
// and the wrapper know what to scan. Deliberately forgiving: it's better to
// scan something harmless than to miss an install.

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function tokenize(cmd) {
  const tokens = [];
  let cur = '';
  let quote = null;
  let has = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < cmd.length) cur += cmd[++i];
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; has = true; continue; }
    // Only treat \ as an escape before shell-special characters, so Windows
    // paths like C:\Users\me\pkg survive.
    if (c === '\\' && i + 1 < cmd.length && /[\s"'\\$`|&;<>()]/.test(cmd[i + 1])) { cur += cmd[++i]; has = true; continue; }
    if (/\s/.test(c)) { if (cur || has) tokens.push(cur); cur = ''; has = false; continue; }
    cur += c;
    has = true;
  }
  if (cur || has) tokens.push(cur);
  return tokens;
}

// Split on && || ; | & and newlines, outside quotes. Pipes are kept apart so
// "curl ... | sh" can be spotted on the raw segment text.
export function segments(cmd) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) { cur += c; if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'") { quote = c; cur += c; continue; }
    if (c === '\n' || c === ';' || c === '|' || c === '&') {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const VALUE_FLAGS = new Set([
  '--registry', '--prefix', '--cache', '--tag', '--workspace', '--filter', '-C', '--dir', '--cwd', '--userconfig',
  '-i', '--index-url', '--extra-index-url', '-c', '--constraint', '-t', '--target', '--python', '-p', '--package',
  '--platform', '--root', '--src', '--find-links', '-f', '--trusted-host', '--only-binary', '--no-binary',
]);

const isLocalSpec = s => /^(\.{0,2}\/|\/|~|[A-Za-z]:[\\/]|file:|link:|workspace:|portal:)/.test(s) || /\.(tgz|tar\.gz|whl|zip)$/i.test(s) || s === '.';
const isRemoteSpec = s => /^(git\+|git:|github:|gitlab:|bitbucket:|https?:)/.test(s) || /^[\w-]+\/[\w.-]+(#.*)?$/.test(s) && !s.startsWith('@');

function positional(args, { stopAtFirst = false } = {}) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') break;
    if (a.startsWith('-')) {
      if (VALUE_FLAGS.has(a)) i++;
      continue;
    }
    out.push(a);
    if (stopAtFirst) break;
  }
  return out;
}

function npmSpecs(args, single = false) {
  const pkgFlag = args.findIndex(a => a === '--package' || a === '-p' || a.startsWith('--package='));
  if (pkgFlag !== -1) {
    const v = args[pkgFlag].includes('=') ? args[pkgFlag].split('=')[1] : args[pkgFlag + 1];
    return v ? [v] : [];
  }
  return positional(args, { stopAtFirst: single })
    .map(s => s.replace(/^npm:/, '').replace(/^[^@/]+@npm:/, ''))
    .filter(s => !isLocalSpec(s) && !isRemoteSpec(s));
}

function requirementsFile(path, cwd) {
  const p = resolve(cwd, path);
  if (!existsSync(p)) return [];
  return readFileSync(p, 'utf8').split(/\r?\n/)
    .map(l => l.replace(/#.*/, '').trim())
    .filter(l => l && !l.startsWith('-') && !isLocalSpec(l) && !/^(git\+|https?:)/.test(l));
}

function pipSpecs(args, cwd) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-r' || args[i] === '--requirement') out.push(...requirementsFile(args[++i] ?? '', cwd));
    else if (args[i].startsWith('--requirement=')) out.push(...requirementsFile(args[i].split('=')[1], cwd));
  }
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-r' || args[i] === '--requirement' || args[i] === '-e' || args[i] === '--editable') { i++; continue; }
    rest.push(args[i]);
  }
  return [...out, ...positional(rest).filter(s => !isLocalSpec(s) && !/^(git\+|https?:)/.test(s))];
}

const npm = s => ({ type: 'npm', spec: s });
const pypi = s => ({ type: 'pypi', spec: s });

// Returns [{ type: 'npm' | 'pypi' | 'url', spec }]
export function extractInstalls(command, { cwd = process.cwd() } = {}) {
  const found = [];
  const pipeExec = /\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*?(https?:\/\/[^\s'"|)]+)[^|\n]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k)?sh\b|\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*?(https?:\/\/[^\s'"|)]+)[^|\n]*\|\s*(python3?|node|iex|Invoke-Expression)\b/gi;
  for (const m of command.matchAll(pipeExec)) found.push({ type: 'url', spec: m[2] ?? m[7] });

  for (const seg of segments(command)) {
    const t = tokenize(seg);
    for (let i = 0; i < t.length; i++) {
      const w = t[i].replace(/^.*[\\/]/, '').replace(/\.(exe|cmd)$/i, '').toLowerCase();
      const next = (t[i + 1] || '').toLowerCase();
      const rest = t.slice(i + 2);
      let hit = null;

      if (w === 'npm' && ['i', 'install', 'add', 'isntall', 'in', 'ins', 'inst'].includes(next)) hit = npmSpecs(rest).map(npm);
      else if (w === 'npm' && (next === 'exec' || next === 'x')) hit = npmSpecs(rest, true).map(npm);
      else if (w === 'npx' || w === 'bunx') hit = npmSpecs(t.slice(i + 1), true).map(npm);
      else if (w === 'pnpm' && ['add', 'install', 'i'].includes(next)) hit = npmSpecs(rest).map(npm);
      else if ((w === 'pnpm' || w === 'yarn') && next === 'dlx') hit = npmSpecs(rest, true).map(npm);
      else if (w === 'pnpx') hit = npmSpecs(t.slice(i + 1), true).map(npm);
      else if (w === 'yarn' && (next === 'add' || next === 'global')) hit = npmSpecs(next === 'global' ? rest.slice(1) : rest).map(npm);
      else if (w === 'bun' && ['add', 'install', 'i', 'a'].includes(next)) hit = npmSpecs(rest).map(npm);
      else if (w === 'bun' && next === 'x') hit = npmSpecs(rest, true).map(npm);
      else if (/^pip(3(\.\d+)?)?$/.test(w) && next === 'install') hit = pipSpecs(rest, cwd).map(pypi);
      else if (/^python(3(\.\d+)?)?$|^py$/.test(w) && next === '-m' && /^pip3?$/.test((t[i + 2] || '').toLowerCase()) && t[i + 3] === 'install') hit = pipSpecs(t.slice(i + 4), cwd).map(pypi);
      else if (w === 'uv' && next === 'pip' && t[i + 2] === 'install') hit = pipSpecs(t.slice(i + 3), cwd).map(pypi);
      else if (w === 'uv' && next === 'add') hit = pipSpecs(rest, cwd).map(pypi);
      else if (w === 'uv' && next === 'tool' && ['install', 'run'].includes(t[i + 2])) hit = pipSpecs(t.slice(i + 3), cwd).slice(0, 1).map(pypi);
      else if (w === 'uvx') hit = pipSpecs(t.slice(i + 1), cwd).slice(0, 1).map(pypi);
      else if ((w === 'poetry' || w === 'pdm' || w === 'rye') && next === 'add') hit = pipSpecs(rest, cwd).map(pypi);
      else if (w === 'pipx' && ['install', 'run'].includes(next)) hit = pipSpecs(rest, cwd).slice(0, 1).map(pypi);

      if (hit) {
        found.push(...hit);
        break;
      }
    }
  }

  const seen = new Set();
  return found.filter(x => {
    const k = `${x.type}:${x.spec}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function toTarget(x) {
  if (x.type === 'url') return x.spec;
  return `${x.type === 'pypi' ? 'pypi' : 'npm'}:${x.spec}`;
}
