# Security

cognito-kit sits in the authentication path of the services that use it, so
we treat a flaw in it as urgent.

## Reporting a vulnerability

Report it privately through GitHub: on the repository's **Security** tab,
choose **Report a vulnerability**. Please don't open a public issue.

Include what you found, the version, and how to reproduce it. A failing test
against the fake Cognito in `tests/support` is the most useful form.

## What counts

Anything that lets a token through that should be refused, or refuses one
that should pass, is in scope. For example:

- a forged, expired or wrongly scoped token that a verifier accepts;
- a token from another user pool, app client or audience that passes;
- a sign-in callback that completes without its own state, nonce or PKCE
  verifier;
- metadata documents or challenges that send clients somewhere unintended;
- the OpenTofu module creating an app client weaker than it documents.

Flaws in Amazon Cognito itself go to AWS: <https://aws.amazon.com/security/vulnerability-reporting/>.

## Supported versions

Fixes go into the latest 0.x release.
