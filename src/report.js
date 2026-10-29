const useColor = process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
const paint = code => s => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { red: paint('31'), yellow: paint('33'), green: paint('32'), blue: paint('34'), gray: paint('90'), bold: paint('1'), magenta: paint('35') };

const SEV = {
  critical: c.magenta('CRIT'),
  high: c.red('HIGH'),
  medium: c.yellow('MED '),
  low: c.blue('LOW '),
  info: c.gray('INFO'),
};

const VERDICT = {
  BLOCK: s => c.bold(c.red(s)),
  REVIEW: s => c.bold(c.yellow(s)),
  SAFE: s => c.bold(c.green(s)),
};
const ICON = { BLOCK: '⛔', REVIEW: '⚠️ ', SAFE: '✅' };

export function label(r) {
  return `${r.ecosystem === 'pypi' ? 'pypi:' : ''}${r.target}${r.version ? `@${r.version}` : ''}`;
}

export function pretty(reports, { verbose = false } = {}) {
  const out = [];
  for (const r of reports) {
    out.push(`${ICON[r.verdict]} ${VERDICT[r.verdict](r.verdict.padEnd(6))} ${c.bold(label(r))}  ${c.gray(`risk ${r.risk}/100 · ${r.files} files${r.mcp ? ' · MCP server' : ''}${r.cached ? ' · cached' : ''}`)}`);
    const shown = verbose ? r.findings : r.findings.filter(f => f.severity !== 'low' && f.severity !== 'info');
    for (const f of shown.slice(0, verbose ? 100 : 8)) {
      const where = f.file ? c.gray(` ${f.file}${f.line ? `:${f.line}` : ''}`) : '';
      out.push(`   ${SEV[f.severity]} ${f.title}${where}`);
      if (f.snippet) out.push(`        ${c.gray('│')} ${c.gray(f.snippet)}`);
      if (verbose) out.push(`        ${c.gray(`└ ${f.why}`)}`);
    }
    const hidden = r.findings.length - Math.min(shown.length, verbose ? 100 : 8);
    if (hidden > 0) out.push(c.gray(`   … ${hidden} more (--verbose)`));
    out.push('');
  }
  return out.join('\n');
}

export function markdown(reports) {
  const out = ['| Target | Verdict | Risk | Top findings |', '| --- | --- | ---: | --- |'];
  for (const r of reports) {
    const top = r.findings.filter(f => f.severity !== 'low').slice(0, 3).map(f => `${f.severity}: ${f.title}`).join('<br>') || '-';
    out.push(`| \`${label(r)}\` | ${ICON[r.verdict]} ${r.verdict} | ${r.risk} | ${top} |`);
  }
  return out.join('\n') + '\n';
}

// Short, plain text for an agent: it reads this as the reason a command was blocked.
export function forAgent(reports) {
  return reports
    .filter(r => r.verdict !== 'SAFE')
    .map(r => {
      const lines = r.findings.filter(f => f.severity === 'critical' || f.severity === 'high' || (r.verdict === 'REVIEW' && f.severity === 'medium')).slice(0, 4);
      return `${r.verdict} ${label(r)} (risk ${r.risk}/100):\n` + lines.map(f => `  - [${f.severity}] ${f.title}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ''})` : ''}`).join('\n');
    })
    .join('\n');
}

export const json = reports => JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2) + '\n';
