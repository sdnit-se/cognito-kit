// Drives the portal example against a real user pool: web sign-in through
// managed login, then the MCP flow a client such as Claude Code follows.
// Prints what it saw as JSON and never prints a token or the password.
//
//   BASE=http://localhost:3000 CLI_CLIENT=<public client id> USER_FILE=<json with email, password> \
//   PLAYWRIGHT=<path to playwright's index.mjs> bun tests/live/flow.ts
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
const BASE = process.env.BASE!;
const CLIENT = process.env.CLI_CLIENT!;
const REDIRECT = 'http://localhost:8765/callback';
const user = JSON.parse(readFileSync(process.env.USER_FILE!, 'utf8'));
const report: Record<string, unknown> = {};
const b64url = (buf: Uint8Array) => Buffer.from(buf).toString('base64url');
const claimsOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

async function signInIfAsked(page: any) {
  const email = page.locator('input[type=email], input[name=username], input[name=email]').first();
  if (!(await email.isVisible({ timeout: 10_000 }).catch(() => false))) return false;
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

const mcp = (token?: string, id = 1) =>
  fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'whoami' } }),
  });

// The loopback listener a CLI assistant runs for its callback.
let onCallback = (_: Record<string, string>) => {};
const listener = Bun.serve({
  port: 8765,
  fetch(request) {
    onCallback(Object.fromEntries(new URL(request.url).searchParams));
    return new Response('ok');
  },
});

const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  const page = await context.newPage();

  // Web sign-in with the confidential web client.
  await page.goto(`${BASE}/login`);
  report.loginPage = new URL(page.url()).host;
  await signInIfAsked(page);
  await page.waitForURL(`${BASE}/`, { timeout: 20_000 });
  report.web = {
    page: (await page.textContent('body'))?.trim(),
    me: await (await page.request.get(`${BASE}/me`)).json(),
    refresh: await (await page.request.post(`${BASE}/refresh`)).json(),
  };

  // MCP: 401, discovery, then PKCE with `resource` as a public client.
  const first = await mcp();
  const challenge = first.headers.get('www-authenticate') ?? '';
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge)?.[1];
  const prm = await (await fetch(metadataUrl!)).json();
  const asm = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
  report.discovery = { status: first.status, challenge, resource: prm.resource, issuer: asm.issuer, pkce: asm.code_challenge_methods_supported };

  async function authorize(scope: string, resource: boolean) {
    const verifier = b64url(randomBytes(48));
    const state = b64url(randomBytes(16));
    const url = new URL(asm.authorization_endpoint);
    const params: Record<string, string> = {
      response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope, state,
      code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256',
    };
    if (resource) params.resource = prm.resource;
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const arrived = new Promise<Record<string, string>>((resolve) => (onCallback = resolve));
    await page.goto(url.toString());
    const formShown = await Promise.race([arrived.then(() => false), signInIfAsked(page)]);
    const callback = await Promise.race([arrived, new Promise<never>((_, r) => setTimeout(() => r(new Error('no callback')), 20_000))]);
    const body = new URLSearchParams({ grant_type: 'authorization_code', code: callback.code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: verifier });
    if (resource) body.set('resource', prm.resource);
    const response = await fetch(asm.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    return { formShown, stateMatches: callback.state === state, tokens: await response.json(), status: response.status };
  }

  const full = await authorize(['openid', 'email', ...prm.scopes_supported].join(' '), true);
  const access = claimsOf(full.tokens.access_token);
  const call = await mcp(full.tokens.access_token);
  report.mcp = {
    token: full.status, stateMatches: full.stateMatches, formShownAgain: full.formShown,
    access: { aud: access.aud, scope: access.scope, client_id: access.client_id, token_use: access.token_use },
    call: { status: call.status, body: await call.json() },
  };

  const idAsBearer = await mcp(full.tokens.id_token);
  report.idTokenAsBearer = { status: idAsBearer.status, challenge: idAsBearer.headers.get('www-authenticate') };

  const refresh = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: full.tokens.refresh_token, client_id: CLIENT, resource: prm.resource });
  const post = (body: URLSearchParams) => fetch(asm.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  const refreshed = await post(refresh);
  const refreshedBody = await refreshed.json();
  const reused = await post(refresh);
  const afterRefresh = await mcp(refreshedBody.access_token);
  report.refresh = {
    status: refreshed.status, aud: claimsOf(refreshedBody.access_token).aud, newRefreshToken: Boolean(refreshedBody.refresh_token),
    mcpAfterRefresh: afterRefresh.status, oldTokenReused: { status: reused.status, error: (await reused.json()).error },
  };

  const noScope = await authorize('openid email', true);
  const noScopeCall = await mcp(noScope.tokens.access_token);
  report.withoutDraftsScope = {
    aud: claimsOf(noScope.tokens.access_token).aud, status: noScopeCall.status, challenge: noScopeCall.headers.get('www-authenticate'),
  };

  const noResource = await authorize(['openid', ...prm.scopes_supported].join(' '), false);
  const noResourceCall = await mcp(noResource.tokens.access_token);
  report.withoutResource = { aud: claimsOf(noResource.tokens.access_token).aud ?? null, status: noResourceCall.status };

  await page.goto(`${BASE}/logout`);
  await page.waitForURL(`${BASE}/`, { timeout: 20_000 });
  report.signOut = { page: (await page.textContent('body'))?.trim(), me: (await page.request.get(`${BASE}/me`)).status() };
} catch (e) {
  report.failure = (e as Error).message;
} finally {
  await browser.close();
  listener.stop(true);
}
console.log(JSON.stringify(report, null, 2));
