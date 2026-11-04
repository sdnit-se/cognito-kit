// Connects clients to tests/live/server with no client id configured: Claude
// Code's metadata document and its Dynamic Client Registration, scripted as
// Claude Code does them, then the real Codex CLI by document and by
// registration. Prints what it saw as JSON and never prints a token or the
// password.
//
//   BASE=http://localhost:3000 USER_FILE=<json with email, password> \
//   PLAYWRIGHT=<path to playwright's index.mjs> [CODEX=codex] bun tests/live/registration.ts
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
const BASE = process.env.BASE!;
const MCP = `${BASE}/mcp`;
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const user = JSON.parse(readFileSync(process.env.USER_FILE!, 'utf8'));
const report: Record<string, unknown> = {};
const b64url = (buf: Uint8Array) => Buffer.from(buf).toString('base64url');
const claimsOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
const form = (body: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(body),
});

async function signInIfAsked(page: any) {
  const email = page.locator('input[type=email], input[name=username], input[name=email]').first();
  if (!(await email.isVisible({ timeout: 15_000 }).catch(() => false))) return false;
  await email.fill(user.email);
  const password = page.locator('input[type=password]').first();
  if (!(await password.isVisible().catch(() => false))) {
    await page.getByRole('button', { name: /next|continue|sign in/i }).first().click();
  }
  await password.waitFor({ timeout: 15_000 });
  await password.fill(user.password);
  await page.getByRole('button', { name: /^(sign in|continue|next|log in)$/i }).first().click();
  return true;
}

const mcp = async (token?: string) => {
  const response = await fetch(MCP, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'whoami' } }),
  });
  return { status: response.status, body: response.status === 200 ? await response.json() : await response.text() };
};

const browser = await chromium.launch();
// Every loopback request the browser makes is seen here, redirects included,
// whether or not something listens on the port.
let onCallback = (_: URL) => {};
const context = await browser.newContext();
const page = await context.newPage();
page.on('request', (request: any) => {
  const url = new URL(request.url());
  if (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) && url.port !== new URL(BASE).port) onCallback(url);
});

/// A CLI's loopback listener.
function listen(port: number) {
  return Bun.serve({ port, hostname: '127.0.0.1', fetch: () => new Response('ok') });
}

/// Follows an authorization URL through managed login to the loopback callback.
async function browse(authorize: string): Promise<URL> {
  const arrived = new Promise<URL>((resolve) => (onCallback = resolve));
  await page.goto(authorize).catch(() => {});
  await Promise.race([arrived, signInIfAsked(page)]);
  return Promise.race([
    arrived,
    new Promise<never>((_, r) =>
      setTimeout(() => {
        const at = new URL(page.url());
        r(new Error(`no callback; the browser is at ${at.host}${at.pathname} ${at.searchParams.get('error') ?? ''}`));
      }, 30_000),
    ),
  ]);
}

async function discover() {
  const first = await fetch(MCP, { method: 'POST' });
  const challenge = first.headers.get('www-authenticate') ?? '';
  const prmUrl = /resource_metadata="([^"]+)"/.exec(challenge)![1];
  const prm = await (await fetch(prmUrl)).json();
  const asm = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
  return { status: first.status, prm, asm };
}

/// The authorization code flow as Claude Code runs it, on a port the system picks.
async function claudeCode(clientId: string, redirectUri: string, asm: any, prm: any) {
  const listener = listen(Number(new URL(redirectUri).port));
  try {
    return await authorizeAndUse(clientId, redirectUri, asm, prm);
  } finally {
    listener.stop(true);
  }
}

async function authorizeAndUse(clientId: string, redirectUri: string, asm: any, prm: any) {
  const verifier = b64url(randomBytes(48));
  const state = b64url(randomBytes(16));
  const url = new URL(asm.authorization_endpoint);
  for (const [k, v] of Object.entries({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri, state, resource: prm.resource,
    scope: prm.scopes_supported.join(' '),
    code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256',
  })) url.searchParams.set(k, v);
  // Managed login may refuse a callback URL the front just added; retry the
  // same request and time how long that lasts.
  const started = Date.now();
  let callback: URL | undefined;
  let refusals = 0;
  while (!callback) {
    try {
      callback = await browse(url.toString());
    } catch (e) {
      if (!String(e).includes('redirect_mismatch') || Date.now() - started > 120_000) throw e;
      refusals += 1;
      await new Promise((r) => setTimeout(r, 2_000));
    }
  }
  const mismatch = refusals ? { redirectMismatchFor: `${Math.round((Date.now() - started) / 1000)} s`, refusals } : {};
  const token = await fetch(asm.token_endpoint, form({
    grant_type: 'authorization_code', code: callback.searchParams.get('code')!, redirect_uri: redirectUri,
    client_id: clientId, code_verifier: verifier, resource: prm.resource,
  }));
  const tokens = await token.json();
  const access = claimsOf(tokens.access_token);
  const call = await mcp(tokens.access_token);
  const refresh = { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId, resource: prm.resource };
  const refreshed = await fetch(asm.token_endpoint, form(refresh));
  const refreshedBody = await refreshed.json();
  const reused = await fetch(asm.token_endpoint, form(refresh));
  return {
    ...mismatch,
    callbackHost: callback.host, stateMatches: callback.searchParams.get('state') === state, token: token.status,
    access: { aud: access.aud, client_id: access.client_id, scope: access.scope },
    mcp: call.status, refresh: refreshed.status, mcpAfterRefresh: (await mcp(refreshedBody.access_token)).status,
    reusedRefreshToken: (await reused.json()).error,
  };
}

const port = () => 49152 + Math.floor(Math.random() * 10000);

try {
  const { status, prm, asm } = await discover();
  report.discovery = {
    status, resource: prm.resource, issuer: asm.issuer, authorize: asm.authorization_endpoint,
    cimd: asm.client_id_metadata_document_supported, registration: asm.registration_endpoint, pkce: asm.code_challenge_methods_supported,
  };

  // Claude Code by its metadata document, twice on different ports.
  const attempt = async (run: () => Promise<unknown>) => run().catch((e) => ({ failure: (e as Error).message }));
  report.claudeCodeByDocument = [
    await attempt(() => claudeCode(CLAUDE_CODE, `http://localhost:${port()}/callback`, asm, prm)),
    await attempt(() => claudeCode(CLAUDE_CODE, `http://localhost:${port()}/callback`, asm, prm)),
  ];

  // Claude Code by Dynamic Client Registration, as when a server offers no documents.
  const redirect = `http://localhost:${port()}/callback`;
  const registered = await fetch(asm.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Claude Code (live)', redirect_uris: [redirect], grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'], token_endpoint_auth_method: 'none', scope: prm.scopes_supported.join(' '),
    }),
  });
  const registration = await registered.json();
  report.claudeCodeByRegistration = {
    registered: registered.status, method: registration.token_endpoint_auth_method,
    flow: await attempt(() => claudeCode(registration.client_id, redirect, asm, prm)),
  };

  // The real Codex CLI, by document and by registration.
  const codex = process.env.CODEX ?? 'codex';
  for (const strategy of ['cimd', 'dcr']) report[`codexBy${strategy}`] = await attempt(async () => {
    const home = mkdtempSync(join(tmpdir(), 'codex-live-'));
    writeFileSync(join(home, 'config.toml'), `mcp_oauth_credentials_store = "file"\n[mcp_servers.portal]\nurl = "${MCP}"\n`);
    const child = Bun.spawn([codex, 'mcp', 'login', 'portal', '--no-browser', '--oauth-client-registration', strategy], {
      env: { ...process.env, CODEX_HOME: home }, stdin: 'pipe', stdout: 'pipe', stderr: 'pipe',
    });
    // The home holds Codex's tokens, and a child left running would keep
    // this script from exiting.
    try {
      let printed = '';
      const decoder = new TextDecoder();
      const authorize = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`codex printed no URL: ${printed.slice(0, 300)}`)), 30_000);
        for (const stream of [child.stdout, child.stderr]) {
          (async () => {
            for await (const chunk of stream) {
              printed += decoder.decode(chunk);
              const found = /(http\S+\/oauth2\/authorize\S+)/.exec(printed);
              if (found) { clearTimeout(timer); resolve(found[1]); }
            }
          })();
        }
      });
      const sent = new URL(authorize);
      const callback = await browse(authorize);
      // In --no-browser mode Codex may take the callback URL on stdin too.
      try {
        child.stdin.write(`${callback.toString()}\n`);
        child.stdin.end();
      } catch {}
      const exit = await Promise.race([child.exited, new Promise((r) => setTimeout(() => r('timeout'), 30_000))]);
      const stored = readdirSync(home).filter((f) => f.includes('credential'));
      const credentials = stored.length ? readFileSync(join(home, stored[0]), 'utf8') : '';
      const access = /"access_token"\s*:\s*"([^"]+)"/.exec(credentials)?.[1];
      return {
        exit, clientIdIsUrl: sent.searchParams.get('client_id')?.startsWith('https://'),
        redirect: sent.searchParams.get('redirect_uri')?.replace(/:\d+\//, ':<port>/'),
        resource: sent.searchParams.get('resource'), stored: stored.length > 0,
        access: access ? { aud: claimsOf(access).aud, scope: claimsOf(access).scope } : null,
        mcp: access ? (await mcp(access)).status : null,
      };
    } finally {
      child.kill();
      rmSync(home, { recursive: true, force: true });
    }
  });
} catch (e) {
  report.failure = (e as Error).message;
} finally {
  await browser.close();
}
console.log(JSON.stringify(report, null, 2));
if (JSON.stringify(report).includes('"failure"')) process.exitCode = 1;
