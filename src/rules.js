// Static detectors. Each one looks at a single file (with its role in the
// package) and returns findings. Severity depends on where code runs:
// install-time and import-time code runs the moment an agent installs or
// loads the package, so the same pattern is far worse there.

export const SEVERITY = { critical: 60, high: 30, medium: 12, low: 4, info: 0 };

const CODE = new Set(['js', 'py', 'sh', 'ps1', 'bat', 'rb', 'php']);
const AGENT_TEXT = new Set(['md', 'txt', 'json', 'yaml', 'toml', 'mdc']);

const SECRET_PATHS = [
  ['SSH keys', /\.ssh[\\/]+(id_[a-z0-9]+|authorized_keys|known_hosts)|['"`]id_(rsa|ed25519|ecdsa)['"`]/],
  ['AWS credentials', /\.aws[\\/]+credentials/],
  ['npm token', /['"`/\\]\.npmrc\b/],
  ['PyPI token', /\.pypirc\b/],
  ['git credentials', /\.git-credentials\b/],
  ['Docker credentials', /\.docker[\\/]+config\.json/],
  ['Kubernetes config', /\.kube[\\/]+config/],
  ['GitHub CLI token', /gh[\\/]+hosts\.yml/],
  ['cloud CLI credentials', /\.config[\\/]+gcloud|\.azure[\\/]+(accessTokens|msal_token)/],
  ['browser passwords and cookies', /Login Data|Local State['"`]|[\\/]Cookies['"`]|cookies\.sqlite|logins\.json/],
  ['crypto wallets', /wallet\.dat\b|Exodus[\\/]+exodus\.wallet|Local Extension Settings[\\/]+[a-p]{32}|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|keystore[\\/]UTC--|solana[\\/]+id\.json|\.electrum[\\/]+wallets/],
  ['Discord tokens', /discord(canary|ptb)?[\\/]+Local Storage|discord[\\/]+leveldb/i],
  ['macOS keychain', /login\.keychain|security find-generic-password/],
  ['system password file', /\/etc\/(shadow|passwd)\b/],
];

const AI_CONFIG = /\.claude[\\/]+(settings(\.local)?\.json|commands|skills|agents|hooks)|\.claude\.json|claude_desktop_config\.json|\.cursor[\\/]+(mcp\.json|rules)|\.codex[\\/]+config\.toml|\.gemini[\\/]+settings\.json|\.windsurf|\.vscode[\\/]+(settings|mcp)\.json|\.continue[\\/]+config/;

const PERSISTENCE = [
  ['shell startup files', /(?:~|\$HOME|HOME\)?|['"`/\\])[/\\]?\.(bashrc|bash_profile|zshrc|zprofile|profile)\b(?!\()/],
  ['cron jobs', /crontab\s+-|\/etc\/cron|\/var\/spool\/cron/],
  ['macOS launch agents', /Library[\\/]+Launch(Agents|Daemons)/],
  ['Windows startup', /Start Menu[\\/]+Programs[\\/]+Startup|CurrentVersion[\\/]+Run\b|schtasks\s+\/create/i],
  ['systemd services', /systemd[\\/]+(user|system)[\\/]|systemctl\s+(--user\s+)?enable/],
  ['git hooks', /\.git[\\/]+hooks[\\/]/],
];

const EXFIL = [
  ['Discord webhook', /discord(app)?\.com\/api\/webhooks\//i],
  ['Telegram bot API', /api\.telegram\.org\/bot/i],
  // Host labels are anchored with a lookbehind so a long alphanumeric run is O(n), not O(n^2).
  ['request-capture service', /\b(webhook\.site|requestbin\.(com|net|io)|hookbin\.com|requestcatcher\.com)\b|(?<![a-z0-9-])[a-z0-9-]{1,63}\.(m\.pipedream\.net|free\.beeceptor\.com)\b/i],
  ['tunnel', /(?<![a-z0-9-])[a-z0-9-]{1,63}\.(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net)/i],
  ['OAST callback', /(?<![a-z0-9-])[a-z0-9]{6,63}\.(oast\.(pro|live|site|online|fun|me)|interact\.sh|burpcollaborator\.net)\b|canarytokens\.com\/|https?:\/\/[a-z0-9.-]{0,80}\boast(-[a-z]{2,4})?\.[a-z0-9-]{2,63}\.[a-z]{2,}/i],
  ['paste or file drop', /pastebin\.com\/raw|transfer\.sh|file\.io\/|0x0\.st|bashupload\.com|temp\.sh/i],
  ['raw IP address', /https?:\/\/(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.))(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\//],
];

const NETWORK = /\b(fetch\(|https?\.(request|get)\(|require\(['"](https?|net|dgram|dns|axios|node-fetch|got|undici)['"]\)|from ['"](axios|node-fetch|got|undici)['"]|XMLHttpRequest|WebSocket\(|net\.connect|dgram\.createSocket|dns\.(resolve|lookup)|requests\.(get|post|put)|urllib\.request|urlopen\(|http\.client|socket\.socket|aiohttp|httpx\.|Invoke-WebRequest|Invoke-RestMethod|iwr |curl |wget |nc -)/;
const EXEC = /(\bchild_process\b|\bos\.startfile\(|\bexecSync\(|\bspawnSync\(|\bexecFile(Sync)?\(|\bsubprocess\.(run|call|Popen|check_output|check_call)\(|\bos\.(system|popen)\(|\bRuntime\.getRuntime|\bpowershell(\.exe)?\s+-|\bcmd(\.exe)?\s+\/c)/;
// Serialising the whole environment is the strong signal. Iterating it is
// normal (copying env into a child process), except in install code.
const ENV_HARVEST = /JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(dict\()?os\.environ|str\(\s*os\.environ\s*\)|\benv\s*\|\s*(curl|nc|base64)|printenv\s*\|\s*(curl|nc|base64)|Get-ChildItem\s+env:[^\n]{0,200}\|\s*(ConvertTo-Json|Out-String)/i;
const ENV_ITER = /Object\.(entries|keys|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.(copy|items)\(\)/;
// Who and where the victim is: the payload of dependency-confusion "beacons".
const IDENTITY = /\bos\.(hostname|userInfo|networkInterfaces)\(\)|\bsocket\.gethostname\(\)|\bplatform\.(node|uname)\(\)|\bgetpass\.getuser\(\)|\bos\.getlogin\(\)|\bos\.uname\(\)|\$\((whoami|hostname|id|pwd)\)|`(whoami|hostname)`|api\.ipify\.org|ifconfig\.me|ipinfo\.io\/|icanhazip\.com/;
const DNS_EXFIL = /(^|[;&|(`'"]\s*)(nslookup|dig)\s[^\n]{0,80}(\$\((whoami|hostname|id|pwd|uname)|`(whoami|hostname)`|\$\{?(USER|HOSTNAME|LOGNAME)\b)|\bdns\.(lookup|resolve\w*)\(\s*`[^`]{0,200}\$\{[^}]{0,60}(hostname|userInfo|username|whoami)/m;
const REVERSE_SHELL = /\/dev\/tcp\/\S+\/\d+|\bsocket\b[\s\S]{0,800}\[\s*["']\/bin\/(ba)?sh["']\s*,\s*["']-i["']|\bnc(at)?\s+(-\w+\s+)*-(e|c)\s+\/bin\/|\bpty\.spawn\(\s*["']\/bin\/(ba)?sh|\bos\.dup2\(\s*(s|sock|so|conn|client)\.fileno\(\)\s*,\s*[0-2]\s*\)|\bsocket\.socket\([^)]{0,80}\)[\s\S]{0,600}\b(subprocess\.\w+|os\.system|os\.popen)\([\s\S]{0,300}\brecv\(|\.recv\(\d+\)[\s\S]{0,300}\b(subprocess\.\w+|os\.system|os\.popen)\(|\bnet\.(connect|createConnection)\([\s\S]{0,400}\bspawn\(\s*["'](\/bin\/)?(ba)?sh/;
const ESCAPE = /\\x[0-9a-fA-F]{2}|\\[0-7]{3}/g;
const UPLOAD = /\b(curl|wget)\b[^\n]{0,300}?(--data-binary\s+["']?@|--data(-raw|-urlencode)?\s+["']?@|\s-d\s+["']?@|\s-F\s+["']?[\w-]+=@|--upload-file\s|\s-T\s+\S|--post-file[=\s])/;
const DECODE = /\b(b64decode|base64\.decodebytes|atob)\(|Buffer\.from\([^)]{0,200}["']base64["']\)|codecs\.decode\([^)]{0,200}["'](rot13|hex)["']/g;
const AGENT_DOC = /(^|\/)(SKILL|CLAUDE|AGENTS|GEMINI)\.md$|\.cursorrules$|\.mdc$/i;
const TOKEN_VARS =/\b(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|PYPI_TOKEN|TWINE_PASSWORD|SLACK_TOKEN|STRIPE_SECRET_KEY|DATABASE_URL)\b/;

const REMOTE_EXEC = [
  /\b(curl|wget)\b[^\n|;]{0,400}\|\s*(sudo\s+)?(ba|z|da)?sh\b/,
  /\b(curl|wget)\b[^\n|;]{0,400}\|\s*(python3?|node|perl|ruby)\b/,
  /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,400}\|\s*(iex|Invoke-Expression)\b/i,
  /\bIEX\s*\(\s*(New-Object\s+Net\.WebClient|\(New-Object)/i,
  /powershell(\.exe)?[^\n]{0,200}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i,
  /\bexec\(\s*(requests\.get|urllib\.request\.urlopen|urlopen)\(/,
  /\beval\(\s*(await\s+)?\(?\s*(await\s+)?fetch\(/,
  /new Function\([^)]*\b(responseText|body|data)\b/,
];

const OBFUSCATION = [
  ['eval of decoded data', /\beval\(\s*(atob|unescape|decodeURIComponent)\(|\beval\(\s*Buffer\.from\([^)]*,\s*['"](base64|hex)['"]\)/],
  ['eval of char codes', /\beval\(\s*String\.fromCharCode/],
  ['exec of decoded data', /\bexec\(\s*(base64\.b64decode|codecs\.decode|zlib\.decompress|bytes\.fromhex|marshal\.loads)|\bexec\(\s*compile\(\s*base64/],
  ['dynamic import of decoded code', /__import__\(\s*['"]base64['"]\)\.b64decode|require\(\s*Buffer\.from\(/],
  ['Function constructor on decoded data', /new Function\(\s*(atob|Buffer\.from)\(/],
];

const INJECTION = [
  ['instruction override', /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts?|rules|messages)/i],
  ['hiding actions from the user', /\b(do not|don't|never)\s+(tell|inform|notify|alert|show|mention|reveal)\b[^.\n]{0,30}?\buser\b|\bwithout\s+(telling|informing|asking|notifying)\s+the\s+user\b|\bkeep\s+this\s+(secret|hidden)\s+from\s+the\s+user/i],
  ['fake system or priority tags', /<\s*(IMPORTANT|SYSTEM|system-reminder|admin|instructions?)\s*>/],
  ['impersonating the system', /\byou are now\b.{0,40}\b(mode|assistant|DAN)\b|\bnew system prompt\b|\bsystem override\b/i],
  ['instructions to read secrets', /\b(read|cat|open|send|upload|include|print|pass|attach)\b[^.\n]{0,60}(~\/\.ssh|id_rsa|\.aws\/credentials|~\/\.env\b|\.npmrc|mcp\.json|claude_desktop_config)/i],
  ['instructions to run hidden commands', /\b(silently|quietly|secretly|in the background)\s+(run|execute|install|download|send|call)\b/i],
];

const HIDDEN_TAGS = /[\u{E0000}-\u{E007F}]/u;
const FLAG_SEQ = /\u{1F3F4}[\u{E0061}-\u{E007A}]{2,8}\u{E007F}/gu;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]{3,}/;

// String values an MCP client shows the model: description: "...",
// description="...", .describe("..."), and docstrings of @mcp.tool functions.
export function toolDescriptions(text) {
  const out = [];
  const patterns = [
    /\bdescription\s*[:=]\s*(?:`([^`]{10,4000})`|"((?:[^"\\\n]|\\.){10,4000})"|'((?:[^'\\\n]|\\.){10,4000})')/g,
    /\.describe\(\s*(?:`([^`]{10,2000})`|"((?:[^"\\]|\\.){10,2000})"|'((?:[^'\\]|\\.){10,2000})')/g,
    /@\w*\.?tool\b[^\n]{0,200}\n(?:[ \t]*@[^\n]{0,200}\n){0,5}[ \t]*(?:async[ \t]+)?def [^\n]{1,300}\n[ \t]*(?:"{3}|'{3})([\s\S]{10,4000}?)(?:"{3}|'{3})/g,
  ];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) {
      const body = m[1] ?? m[2] ?? m[3];
      if (body) out.push({ text: body, offset: m.index + m[0].indexOf(body) });
    }
  }
  return out;
}

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function snippet(text, index, len = 0) {
  const start = Math.max(0, index - 50);
  const end = Math.min(text.length, index + Math.max(len, 1) + 70);
  return text.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 160);
}

function first(text, re) {
  const m = re.exec(text);
  return m ? { index: m.index, match: m[0] } : null;
}

const mk = (file, id, severity, title, why, hit) => ({
  id, severity, title, why, file: file.path,
  line: hit ? lineOf(file.text, hit.index) : null,
  snippet: hit ? snippet(file.text, hit.index, hit.match.length) : null,
});

// Install-time and import-time code is "hot": it runs without anyone calling it.
const hot = f => f.role === 'install' || f.role === 'entry';
const bump = (sev, f) => (hot(f) ? { low: 'medium', medium: 'high', high: 'critical' }[sev] ?? sev : sev);

export const FILE_RULES = [
  function remoteExec(f) {
    // Skills and agent rules are instructions the agent carries out, so a
    // command written anywhere in them counts like a shell script.
    const agentDoc = AGENT_DOC.test(f.path);
    if (!CODE.has(f.kind) && f.role !== 'install' && !agentDoc) return [];
    // In shell files the pattern is the command. In JS/Python it is only a
    // command if something nearby executes it; otherwise it's help text, a
    // comment or a regex (like this file).
    const isShell = f.kind === 'sh' || f.kind === 'ps1' || f.kind === 'bat' || agentDoc;
    const out = [];
    const upload = first(f.text, UPLOAD);
    if (upload && (isShell || EXEC.test(f.text.slice(Math.max(0, upload.index - 300), upload.index + 300)))) {
      out.push(mk(f, 'file-upload', hot(f) || agentDoc ? 'high' : 'medium', 'Uploads local files to a server', 'Sending files off the machine is how skills and scripts exfiltrate your code and secrets.', upload));
    }
    for (const re of REMOTE_EXEC) {
      for (const m of f.text.matchAll(new RegExp(re.source, `${re.flags.replace('g', '')}g`))) {
        const around = f.text.slice(Math.max(0, m.index - 300), m.index + m[0].length + 20);
        if (!isShell && !/\bexec\(|\beval\(|new Function/.test(m[0]) && !EXEC.test(around) && !/\b(system|popen|shell_exec|passthru)\(/.test(around)) continue;
        out.push(mk(f, 'remote-code', hot(f) || agentDoc ? 'critical' : 'high', 'Downloads and runs remote code', 'Code fetched at run time can be swapped for malware at any moment, after any review.', { index: m.index, match: m[0] }));
        return out;
      }
    }
    return out;
  },

  function obfuscation(f) {
    if (!CODE.has(f.kind)) return [];
    const out = [];
    for (const [label, re] of OBFUSCATION) {
      const hit = first(f.text, re);
      if (hit) out.push(mk(f, 'obfuscated-exec', bump('high', f), `Obfuscated code execution (${label})`, 'Legitimate packages almost never decode and execute hidden code.', hit));
    }
    // Decode on one line, execute on the next: `p = b64decode(x)` ... `exec(p)`.
    if (!out.length) {
      for (const d of f.text.matchAll(DECODE)) {
        const after = f.text.slice(d.index, d.index + 600);
        // (?<![.\w]) keeps out regex.exec(str) and friends.
        const run = /(?<![.\w$])(exec|eval)\(\s*[A-Za-z_]\w*\s*(\)|,\s*(globals\(\)|\{))|new Function\(\s*[A-Za-z_]\w*\s*\)/.exec(after);
        if (run) {
          out.push(mk(f, 'obfuscated-exec', bump('high', f), 'Decodes data and then executes it', 'Hiding a payload in base64 and running it is the most common malware trick.', { index: d.index + run.index, match: run[0] }));
          break;
        }
      }
    }
    const hexVars = f.text.match(/_0x[a-f0-9]{4,6}/g);
    if (hexVars && hexVars.length > 40 && !/\.min\.(js|mjs|cjs)$/.test(f.path)) {
      const hit = first(f.text, /_0x[a-f0-9]{4,6}/);
      out.push(mk(f, 'obfuscator', bump('medium', f), 'Looks machine-obfuscated (javascript-obfuscator pattern)', `${hexVars.length} _0x… identifiers. Common in malware, rare in honest packages.`, hit));
    }
    const blob = first(f.text, /['"`][A-Za-z0-9+/]{3000,}={0,2}['"`]/);
    if (blob && hot(f)) out.push(mk(f, 'encoded-blob', 'medium', 'Large encoded blob in install or entry code', 'Payloads are often hidden as long base64 strings.', blob));
    return out;
  },

  function backdoor(f) {
    if (!CODE.has(f.kind)) return [];
    const hit = first(f.text, REVERSE_SHELL);
    return hit ? [mk(f, 'reverse-shell', 'critical', 'Reverse shell or remote command backdoor', 'Gives someone else a shell on your machine.', hit)] : [];
  },

  function escapedCode(f) {
    if (!CODE.has(f.kind) || /\.min\.[cm]?js$|_pb2\.py$/.test(f.path)) return [];
    const out = [];
    const evalEsc = first(f.text, /\b(eval|exec)\(\s*["'](\\x[0-9a-fA-F]{2}|\\[0-7]{3}){3}/);
    if (evalEsc) out.push(mk(f, 'obfuscated-exec', bump('high', f), 'Executes code spelled out in escape sequences', 'Hiding function names like eval as \\x65\\x76\\x61\\x6c is what obfuscators such as BlankOBF do.', evalEsc));
    const n = (f.text.match(ESCAPE) || []).length;
    if (n > 300 && (n * 4) / f.text.length > 0.15) {
      const hit = first(f.text, /\\x[0-9a-fA-F]{2}|\\[0-7]{3}/);
      out.push(mk(f, 'obfuscator', bump('medium', f), 'Mostly escape-encoded code', `${n} \\x/octal escapes make up most of this file. Real code is written in plain text.`, hit));
    }
    return out;
  },

  function exfilEndpoint(f) {
    if (!CODE.has(f.kind) && f.role !== 'install') return [];
    const out = [];
    for (const [label, re] of EXFIL) {
      const hit = first(f.text, re);
      // Honest libraries talk to Telegram and Discord too; only install/import code doing it is alarming.
      if (hit) out.push(mk(f, 'exfil-endpoint', hot(f) ? 'critical' : 'medium', `Talks to a ${label}`, 'These endpoints are favourite drop points for stolen data.', hit));
    }
    return out;
  },

  function secrets(f) {
    if (!CODE.has(f.kind)) return [];
    const out = [];
    for (const [label, re] of SECRET_PATHS) {
      const hit = first(f.text, re);
      if (hit) out.push(mk(f, 'secret-access', hot(f) ? 'high' : 'low', `Reads ${label}`, hot(f) ? 'Install and import code has no business touching your credentials.' : 'Fine for tools that manage these files, suspicious anywhere else.', hit));
    }
    const env = first(f.text, ENV_HARVEST);
    if (env) out.push(mk(f, 'env-harvest', bump('medium', f), 'Collects all environment variables', 'Dumping the whole environment grabs every token and API key in it.', env));
    return out;
  },

  function persistence(f) {
    if (!CODE.has(f.kind)) return [];
    const out = [];
    for (const [label, re] of PERSISTENCE) {
      const hit = first(f.text, re);
      if (hit && /(write|append|open\(|>>|copy|cp |echo |mkdir|install)/i.test(snippet(f.text, hit.index, 200))) {
        out.push(mk(f, 'persistence', hot(f) ? 'high' : 'low', `Modifies ${label}`, 'A way to keep running after the package is gone.', hit));
      }
    }
    // Plenty of honest CLIs register themselves with agents; doing it at install time is not honest.
    const ai = first(f.text, AI_CONFIG);
    if (ai) out.push(mk(f, 'ai-config-tamper', f.role === 'install' ? 'critical' : 'low', f.role === 'install' ? 'Modifies AI agent configuration at install time' : 'Can modify AI agent configuration', 'Writing to Claude, Cursor, Codex or VS Code config can plant MCP servers, hooks or rules in your agent.', ai));
    return out;
  },

  function hiddenText(f) {
    if (!f.text) return [];
    const out = [];
    // Subdivision flags (England, Scotland, Wales) are legit tag sequences; anything else is smuggling.
    const tag = first(f.text.replace(FLAG_SEQ, m => ' '.repeat(m.length)), HIDDEN_TAGS);
    if (tag) out.push(mk(f, 'hidden-unicode', 'critical', 'Invisible Unicode tag characters', 'Invisible to humans, readable by models: the classic way to smuggle instructions into an agent.', tag));
    if (CODE.has(f.kind)) {
      // Unicode tables in minified bundles are full of these; Trojan Source hides in readable lines.
      const bidi = [...f.text.matchAll(new RegExp(BIDI.source, 'g'))].map(m => ({ index: m.index, match: m[0] })).find(h => {
        const start = f.text.lastIndexOf('\n', h.index) + 1;
        const end = f.text.indexOf('\n', h.index);
        return (end === -1 ? f.text.length : end) - start < 400;
      });
      if (bidi) out.push(mk(f, 'bidi-control', 'high', 'Bidirectional control characters in code (Trojan Source)', 'Makes code display differently from how it runs.', bidi));
    }
    const zw = AGENT_TEXT.has(f.kind) ? first(f.text, ZERO_WIDTH) : null;
    if (zw) out.push(mk(f, 'zero-width', 'medium', 'Runs of zero-width characters', 'Often used to hide or watermark text meant for models.', zw));
    return out;
  },

  function promptInjection(f) {
    // Agent-facing text is checked as-is. In code, only MCP tool descriptions
    // are checked, because that's where tool poisoning lives; comments that
    // merely discuss injection are not an attack.
    if (!f.text) return [];
    const out = [];
    const agentFile = /(^|\/)(SKILL|CLAUDE|AGENTS|GEMINI)\.md$|\.cursorrules$|\.mdc$|(^|\/)rules\//i.test(f.path);
    const regions = AGENT_TEXT.has(f.kind) ? [{ text: f.text, offset: 0 }] : CODE.has(f.kind) && f.isMcp ? toolDescriptions(f.text) : [];
    for (const [label, re] of INJECTION) {
      for (const r of regions) {
        const m = re.exec(r.text);
        if (!m) continue;
        const where = CODE.has(f.kind) ? 'MCP tool description' : 'text';
        out.push(mk(f, 'prompt-injection', agentFile || CODE.has(f.kind) ? 'critical' : /(^|\/)README(\.md)?$/i.test(f.path) ? 'medium' : 'low', `Prompt injection in ${where}: ${label}`, 'Text an agent will read that tries to change what the agent does.', { index: r.offset + m.index, match: m[0] }));
        break;
      }
    }
    const comment = f.kind === 'md' ? first(f.text, /<!--[\s\S]{0,400}?\b(you must|always|never|assistant|AI|agent|model|instructions?)\b[\s\S]{0,400}?-->/i) : null;
    if (comment && agentFile) out.push(mk(f, 'hidden-instructions', 'high', 'Instructions hidden in an HTML comment', 'Invisible when rendered, fully visible to the agent.', comment));
    return out;
  },

];

export function executableKind(d) {
  if (d.length < 4) return null;
  if (d[0] === 0x7f && d[1] === 0x45 && d[2] === 0x4c && d[3] === 0x46) return 'Linux';
  if (d[0] === 0x4d && d[1] === 0x5a) return 'Windows';
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(d.readUInt32BE(0))) return 'macOS';
  return null;
}

// One finding for all binaries: they're normal in native packages, and only
// matter much when install code runs them.
export function binaryRule(files) {
  const bins = files.filter(f => !f.text && executableKind(f.data));
  if (!bins.length) return [];
  const hot = bins.find(f => f.role === 'install');
  const kinds = [...new Set(bins.map(f => executableKind(f.data)))].join(', ');
  return [{
    id: 'binary', severity: hot ? 'high' : 'low',
    title: hot ? `Install script runs a bundled executable (${hot.path})` : `Ships ${bins.length} prebuilt executable${bins.length > 1 ? 's' : ''} (${kinds})`,
    why: "Binaries can't be reviewed line by line. Normal for native addons and SDKs.",
    file: (hot ?? bins[0]).path, line: null, snippet: bins.slice(0, 4).map(b => b.path).join(', '),
  }];
}

// Combinations matter more than single signals: reading secrets is normal for
// an AWS SDK, reading secrets and sending them out from a postinstall is not.
// Capped: a minified bundle can hold thousands of matches, and pairing them is quadratic.
const indexes = (text, re, cap = 400) => {
  const out = [];
  for (const m of text.matchAll(new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`))) {
    out.push(m.index);
    if (out.length >= cap) break;
  }
  return out;
};
const NEAR = 1500;

export function chainRules(f, findings) {
  if (!CODE.has(f.kind)) return [];
  const mine = findings.filter(x => x.file === f.path);
  const ids = new Set(mine.map(x => x.id));
  const out = [];

  // Secret access and a network call close together, not just somewhere in a
  // 50k-line bundle.
  const secretAt = [
    ...SECRET_PATHS.flatMap(([, re]) => indexes(f.text, re)),
    ...indexes(f.text, ENV_HARVEST),
    ...(hot(f) ? [...indexes(f.text, TOKEN_VARS), ...indexes(f.text, ENV_ITER)] : []),
  ];
  const netAt = [...indexes(f.text, NETWORK), ...EXFIL.flatMap(([, re]) => indexes(f.text, re))];
  let best = null;
  for (const s of secretAt) for (const n of netAt) {
    const d = Math.abs(s - n);
    if (d < NEAR && (!best || d < best.d)) best = { d, at: Math.min(s, n) };
  }
  if (best && (ids.has('secret-access') || ids.has('env-harvest') || hot(f))) {
    out.push({ ...mk(f, 'exfil-chain', hot(f) ? 'critical' : 'high', 'Reads secrets and sends data over the network, side by side', 'The signature of a credential stealer.', { index: best.at, match: '' }) });
  }
  // Beacons: identity (user, host, IP) gathered right next to a network call or DNS lookup.
  const idAt = indexes(f.text, IDENTITY);
  let beacon = null;
  for (const s of idAt) for (const n of netAt) if (Math.abs(s - n) < NEAR && !beacon) beacon = Math.min(s, n);
  if (beacon !== null) {
    out.push(mk(f, 'recon-beacon', f.role === 'install' ? 'critical' : hot(f) ? 'high' : 'low', 'Sends your username, hostname or IP somewhere', 'The payload of dependency-confusion and reconnaissance packages.', { index: beacon, match: '' }));
  }
  const dnsHit = first(f.text, DNS_EXFIL);
  if (dnsHit) out.push(mk(f, 'dns-exfil', hot(f) ? 'critical' : 'high', 'Leaks data through DNS lookups', 'Encoding user or host names into a DNS query sneaks data past firewalls.', dnsHit));
  const net = netAt.length > 0;
  if (hot(f) && EXEC.test(f.text) && net && !ids.has('remote-code')) {
    const hit = first(f.text, EXEC);
    // npm postinstalls download binaries all the time; setup.py almost never needs to.
    out.push(mk(f, 'install-exec-net', /(^|\/)setup\.py$/.test(f.path) || /\bos\.startfile\(/.test(f.text) ? 'high' : 'medium', 'Install or entry code spawns processes and uses the network', 'Often legitimate (downloading a binary), but the most common shape of droppers too.', hit));
  }
  return out;
}

export { CODE, AGENT_TEXT, NETWORK, EXEC };
