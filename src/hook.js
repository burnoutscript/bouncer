// Claude Code PreToolUse hook. Reads the pending tool call on stdin and, when
// a Bash command is about to install something, scans it first.
//
//   BLOCK  -> deny the call and tell the agent why
//   REVIEW -> ask the human (or deny, with BOUNCER_REVIEW=deny)
//   SAFE   -> stay silent so the normal permission flow continues
//
// The hook fails open: a network error never blocks your work.

import { extractInstalls, toTarget } from './commands.js';
import { scan } from './index.js';
import { forAgent } from './report.js';

const HOOK_TIMEOUT = Number(process.env.BOUNCER_HOOK_TIMEOUT_MS || 45000);

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

export async function decide(input) {
  const command = input?.tool_input?.command;
  if (input?.tool_name !== 'Bash' || typeof command !== 'string') return null;
  const installs = extractInstalls(command, { cwd: input.cwd || process.cwd() });
  if (!installs.length) return null;

  const results = await Promise.allSettled(installs.map(x => scan(toTarget(x))));
  const reports = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  const errors = results.filter(r => r.status === 'rejected').map(r => r.reason?.message);

  const worst = reports.some(r => r.verdict === 'BLOCK') ? 'BLOCK' : reports.some(r => r.verdict === 'REVIEW') ? 'REVIEW' : 'SAFE';
  if (worst === 'SAFE') return { decision: null, reports, errors };

  const policy = worst === 'BLOCK' ? 'deny' : (process.env.BOUNCER_REVIEW || 'ask');
  if (policy === 'allow') return { decision: null, reports, errors };
  const reason = `bouncer: ${worst === 'BLOCK' ? 'blocked this install' : 'flagged this install for review'}.\n${forAgent(reports)}\n` +
    (worst === 'BLOCK'
      ? 'Do not retry or work around this. Tell the user what was found and suggest a safer alternative package.'
      : 'Ask the user whether to proceed.');
  return { decision: policy, reason, reports, errors };
}

export async function runHook() {
  let input;
  try {
    input = JSON.parse(await readStdin());
  } catch {
    return 0;
  }
  let timer;
  try {
    const result = await Promise.race([
      decide(input),
      new Promise(resolve => { timer = setTimeout(() => resolve({ timeout: true }), HOOK_TIMEOUT); }),
    ]);
    if (result?.timeout) {
      process.stderr.write('bouncer: scan timed out, letting the command through\n');
      return 0;
    }
    if (result?.errors?.length) process.stderr.write(`bouncer: could not scan: ${result.errors.join('; ')}\n`);
    if (!result?.decision) return 0;
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: result.decision,
        permissionDecisionReason: result.reason,
      },
    }));
    return 0;
  } catch (e) {
    process.stderr.write(`bouncer: ${e.message}\n`);
    return 0;
  } finally {
    clearTimeout(timer);
  }
}
