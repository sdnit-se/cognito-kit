// What each flow in tests/live/registration.ts must have recorded. A run
// fails on any miss and prints the flow and the check. It also checks a
// saved report on its own:
//
//   bun tests/live/outcomes.ts <report.json>
import { createHash } from 'node:crypto';
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

/// The URL of Codex's metadata document for an MCP server, which names the
/// server by the start of its URL's SHA-256, as Codex 0.164 builds it.
const codexDocument = (server: string) =>
  `https://chatgpt.com/oauth/codex/${createHash('sha256').update(server).digest('base64url').slice(0, 12)}/client.json`;

/// Codex logs in by its metadata document, whose URL is then its client_id,
/// or by registering, which returns the client_id it must use.
const codex = (byDocument: boolean): Check[] => [
  ['login done', (f) => f.exit === 0],
  byDocument
    ? ['client_id is Codex\'s document URL', (f) => typeof f.server === 'string' && f.clientId === codexDocument(f.server)]
    : ['client_id is the one its registration returned', (f) => typeof f.clientId === 'string' && f.registered?.includes(f.clientId)],
  ['credentials stored', (f) => f.stored === true],
  ['MCP 200', (f) => f.mcp === 200],
];

const expected: [path: string, checks: Check[]][] = [
  ['discovery', [
    ['MCP 401 without a token', (d) => d.status === 401],
    ['metadata documents advertised', (d) => d.cimd === true],
    ['registration endpoint advertised', (d) => typeof d.registration === 'string' && d.registration.endsWith('/oauth2/register')],
    ['PKCE with S256 alone', (d) => JSON.stringify(d.pkce) === '["S256"]'],
  ]],
  ['claudeCodeByDocument.0', scripted],
  ['claudeCodeByDocument.1', scripted],
  ['claudeCodeAfterChange', [
    ...scripted,
    ['refresh stored the fetched document', (f) => f.refreshed === true],
    ['callbacks back to the relay alone', (f) => f.callbacks?.length === 1 && f.callbacks[0].endsWith('/oauth2/callback')],
  ]],
  ['claudeCodeWhileLeased', [
    ...scripted,
    ['the stored document served while another server held the lease', (f) => f.leaseKept === true && f.refreshed === false],
  ]],
  ['claudeCodeByRegistration', [
    ['registered 201', (r) => r.registered === 201],
    ['registered as a public client', (r) => r.method === 'none'],
  ]],
  ['claudeCodeByRegistration.flow', scripted],
  ['codexBycimd', codex(true)],
  ['codexBydcr', codex(false)],
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
