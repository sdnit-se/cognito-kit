// What each flow in tests/live/registration.ts must have recorded. A run
// fails on any miss and prints the flow and the check. It also checks a
// saved report on its own:
//
//   bun tests/live/outcomes.ts <report.json>
import { readFileSync } from 'node:fs';

type Check = [name: string, ok: (outcome: any) => boolean];

const scripted: Check[] = [
  ['state came back', (f) => f.stateMatches === true],
  ['token 200', (f) => f.token === 200],
  ['MCP 200', (f) => f.mcp === 200],
  ['refresh 200', (f) => f.refresh === 200],
  ['MCP 200 after refresh', (f) => f.mcpAfterRefresh === 200],
  ['reused refresh token refused', (f) => f.reusedRefreshToken === 'invalid_grant'],
];

const codex: Check[] = [
  ['login done', (f) => f.exit === 0],
  ['credentials stored', (f) => f.stored === true],
  ['MCP 200', (f) => f.mcp === 200],
];

const expected: [path: string, checks: Check[]][] = [
  ['discovery', [['MCP 401 without a token', (d) => d.status === 401]]],
  ['claudeCodeByDocument.0', scripted],
  ['claudeCodeByDocument.1', scripted],
  ['claudeCodeByRegistration', [['registered 201', (r) => r.registered === 201]]],
  ['claudeCodeByRegistration.flow', scripted],
  ['codexBycimd', codex],
  ['codexBydcr', codex],
];

/// Each flow and check that the report misses.
export function misses(report: Record<string, any>): string[] {
  const missed = report.failure ? [`run: ${report.failure}`] : [];
  for (const [path, checks] of expected) {
    const outcome = path.split('.').reduce((value, key) => value?.[key], report as any);
    if (outcome === undefined) missed.push(`${path}: no outcome`);
    else if (outcome.failure) missed.push(`${path}: ${outcome.failure}`);
    else missed.push(...checks.filter(([, ok]) => !ok(outcome)).map(([check]) => `${path}: ${check}`));
  }
  return missed;
}

/// Prints each miss and fails the process on any.
export function check(report: Record<string, any>) {
  const missed = misses(report);
  for (const miss of missed) console.error(`missed ${miss}`);
  if (missed.length) process.exitCode = 1;
}

if (import.meta.main) check(JSON.parse(readFileSync(process.argv[2], 'utf8')));
