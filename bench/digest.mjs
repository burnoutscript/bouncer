// Prints a compact text digest of samples that scanned SAFE, so misses can be
// studied as text in CI logs. Never executes anything.
//   node bench/digest.mjs <samples-dir> <results.json> [perGroup]
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const [root, resultsFile, per = '25'] = process.argv.slice(2);
const { results } = JSON.parse(readFileSync(resultsFile, 'utf8'));
const KEY = /https?:|fetch\(|request|urllib|socket|exec|eval|spawn|system\(|popen|child_process|curl|wget|nslookup|dig |base64|b64|hostname|userInfo|getuser|platform|environ|process\.env|discord|webhook|telegram|\.ssh|token|password|startfile|chmod|powershell|Invoke|atob|fromCharCode|zlib|marshal|pip install|npm install|bash|sh -c/i;

function walk(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

const byGroup = {};
for (const r of results.filter(r => r.verdict === 'SAFE')) (byGroup[r.group] ??= []).push(r);
for (const [group, list] of Object.entries(byGroup)) {
  for (const r of list.slice(0, Number(per))) {
    const dir = join(root, group, r.sample);
    const files = walk(dir);
    console.log(`\n===== ${group}/${r.sample} (${files.length} files)`);
    console.log('files: ' + files.slice(0, 12).map(f => relative(dir, f)).join(', '));
    for (const f of files) {
      if (statSync(f).size > 200000 || !/\.(js|cjs|mjs|py|sh|json|md|ps1|bat|txt|ts|yml|yaml)$|^[^.]+$/i.test(f)) continue;
      const lines = readFileSync(f, 'utf8').split('\n').filter(l => KEY.test(l)).slice(0, 6);
      if (lines.length) console.log(`--- ${relative(dir, f)}\n` + lines.map(l => '  ' + l.trim().slice(0, 220)).join('\n'));
    }
  }
}
