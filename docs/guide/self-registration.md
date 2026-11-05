Let AI assistants register themselves, so that they connect to your MCP
server from its URL alone.

With [the plain OAuth front](crate::guide::mcp_server), every assistant needs an
app client that you create, and each person types its id into the
assistant. MCP clients have two standard ways to skip that, and the
[`Registrar`] supports both:

- **Client ID Metadata Documents** (CIMD). The client's `client_id` is the
  https URL of a JSON document that it publishes, listing its name and
  redirect URIs. Claude, ChatGPT, Claude Code, Codex and Executor are
  examples.
- **Dynamic Client Registration** (DCR, RFC 7591). The client posts its
  metadata to a registration endpoint and gets a `client_id` back. This is
  for clients without a document.

Cognito supports neither. So the registrar creates a Cognito app client for
each client on its first sign-in, and the front swaps the client's
`client_id` for that app client's id on the way to managed login and the
token endpoint. Cognito still signs people in and issues every token.

# Wire it up

You need the `registration` feature, and `dynamodb` for the store below.
The registrar creates app clients through the AWS SDK with [`CognitoApi`],
and keeps its registrations in a [`RegistrationStore`]. Give it to the
verifier, and the front serves its own endpoints:

```rust
use cognito_kit::registration::{CognitoApi, DynamoStore, Registrar};
use cognito_kit::{OAuthFront, PoolId, UserPool};

fn front(
    cognito: aws_sdk_cognitoidentityprovider::Client,
    dynamodb: aws_sdk_dynamodb::Client,
) -> Result<(OAuthFront, Registrar), Box<dyn std::error::Error>> {
    let pool_id: PoolId = "eu-north-1_AbC123".parse()?;
    let registrar = Registrar::builder(
        // New app clients copy this one's settings.
        CognitoApi::new(cognito, pool_id.clone(), "1example23456789".parse()?),
        DynamoStore::new(dynamodb, "portal-registrations"),
    )
    .metadata_documents()
    .dynamic_registration()
    .client_hosts(["claude.ai", "chatgpt.com"])
    .build()?;

    let verifier = UserPool::new(pool_id)
        .access_tokens()
        .registrar(registrar.clone())
        .resource("https://portal.example.com/mcp".parse()?)
        .scope("https://portal.example.com/mcp/drafts".parse()?)
        .build()?;
    let front = OAuthFront::new(verifier, "https://login.example.com".parse()?)?;
    Ok((front, registrar))
}
```

Build the two AWS clients from `aws-config` in your `main`. This crate
turns off the AWS SDK's default features, so the SDK's HTTP client comes
from your `aws-config`, whose default features include one. `aws-config`
isn't a dependency of this crate, so this part isn't tested here:

```rust,ignore
let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
let (front, registrar) = front(
    aws_sdk_cognitoidentityprovider::Client::new(&aws),
    aws_sdk_dynamodb::Client::new(&aws),
)?;
```

Serve the front as in [the MCP chapter](crate::guide::mcp_server), with
[`OAuthFront::router`](crate::OAuthFront::router) or
[`OAuthFront::handle`](crate::OAuthFront::handle). Besides the metadata, it
now answers these paths, and its metadata points at them:

| Path | What it does |
|------|--------------|
| `GET /oauth2/authorize` | Checks the client and its redirect URI, creates the app client on first use, and sends the browser to managed login |
| `POST /oauth2/token` | Passes the request to Cognito with the app client's id |
| `POST /oauth2/revoke` | The same, for revocation |
| `GET /oauth2/callback` | Passes a code on to a loopback redirect URI (see below) |
| `POST /oauth2/register` | Dynamic Client Registration, when it is on |

App clients you created yourself keep working through these endpoints.
The front passes their requests to Cognito unchanged, and Cognito checks
them as before.

# What each new app client gets

[`CognitoApi`] copies a template app client that you manage: its scopes,
identity providers, token lifetimes, attribute permissions and managed
login style. Every app client it creates is public, without a secret, uses
the authorization code grant, and rotates refresh tokens. Its only
callback URLs are the client's https redirect URIs and, for loopback ones,
the front's `/oauth2/callback`.

The template is usually the app client you made for one assistant, such as
`claude` in [the OpenTofu module](crate::guide::opentofu). Its
`registration_template_client_id` output is the id to pass.

# Decide which hosts get codes

Cognito has no consent step, and its authorize endpoint is public. Anyone
who learns an app client's id can send a signed-in person through it, and
the code goes to one of that app client's callback URLs. So the registrar
only creates app clients whose redirect URIs keep the code on the person's
device, or send it to a host you trust:

- `http` on `localhost`, `127.0.0.1` or `[::1]`, on any port. Command-line
  and desktop assistants such as Claude Code and Codex use these.
- `https` on a host you list with
  [`client_hosts`](crate::registration::RegistrarBuilder::client_hosts).
  Web assistants such as Claude and ChatGPT need this.

Any other scheme is refused, because some can hand a URL to a browser and
send the code off the device. With a list, the registrar also fetches
metadata documents only from the hosts on it. Without one, it fetches them
from any host, and only command-line and desktop assistants can connect.

The front checks the list on every authorization. If you take a host off
it, clients on that host get no more codes through the front at once. Their
app clients still list the host as a callback URL, though, and Cognito's
own authorize endpoint is public. Run [cleanup](#clean-up-unused-clients)
straight after, which deletes them.

Every registered client must use PKCE with `S256`, must not send a client
secret, and must support the `none` token endpoint authentication method.

# Why loopback codes go through the front

A command-line assistant listens for its code on a port the system picks
when it starts (RFC 8252), so its document lists a loopback URI without a
port. Cognito matches callback URLs exactly, and when we measured, managed
login took 140 seconds to accept a callback URL added to an existing app
client.

So for a loopback redirect URI, Cognito's callback is the front's
`/oauth2/callback`. The front puts the client's real redirect URI and
state into the `state` it sends to managed login. When the browser comes
back, the front passes the code on to that redirect URI. It only ever
redirects to a loopback address, so a code sent through it never leaves
the person's device, and `state` needs no signature.

# How documents are fetched

[`metadata_documents`](crate::registration::RegistrarBuilder::metadata_documents)
fetches with [`GuardedFetcher`]: https only, at most 5 KiB within five
seconds, no redirects and no proxy. Every address the host resolves to must
be public, and the connection goes to exactly the addresses checked, so a
DNS answer that changes in between can't reach your private network.

A document must name its own URL as `client_id` and list the redirect URI
the client asked for. The registrar uses a stored document for up to five
minutes before it fetches it again. It fetches sooner, at most once a
minute, when a client asks for a redirect URI that the stored document
doesn't list. If the host is down, a document that was valid before stays
in use.

To fetch through your own egress, implement
[`FetchDocument`](crate::registration::FetchDocument) and pass it to
[`fetcher`](crate::registration::RegistrarBuilder::fetcher). It must refuse
what `GuardedFetcher` refuses.

# Stay inside Cognito's limits

A pool holds 1,000 app clients by default, and AWS Support can raise that.
The registrar stops at
[`max_registrations`](crate::registration::RegistrarBuilder::max_registrations),
500 by default, so the app clients you manage still fit. Past it, or when
Cognito refuses at its own limit, new clients get a 503. A client that
registers through `/oauth2/register` gets it as a JSON OAuth error,
`temporarily_unavailable`. One that arrives at `/oauth2/authorize` with a
metadata document URL gets a plain-text page, since the front can't yet
trust the redirect URI to send an error to. Registered clients keep
working.

Cognito allows five app-client changes per second per pool, shared with
every other caller. Each server process makes at most ten a minute on
behalf of requests, and answers 503 above that. Behind several instances,
that is ten per instance, so also put a rate rule, such as an AWS WAF rule,
in front of `/oauth2/authorize` and `/oauth2/register`.

# Clean up unused clients

Registrations accumulate. People try an assistant once, or stop using it.
[`Registrar::cleanup`](crate::registration::Registrar::cleanup) removes
registrations and their app clients when:

- They never completed a token request within
  [`unused_after`](crate::registration::RegistrarBuilder::unused_after),
  a day by default.
- Their last token request is older than
  [`idle_after`](crate::registration::RegistrarBuilder::idle_after),
  31 days by default.
- A redirect URI is on a host no longer in `client_hosts`.

It also deletes app clients that carry the registrar's
[`name_prefix`](crate::registration::RegistrarBuilder::name_prefix) but have
no registration and are more than an hour old. A server that stops between
creating an app client and storing its registration leaves one behind.
Because of this, two registrars that share a pool need different prefixes.

Keep `idle_after` longer than the refresh tokens last, 30 days by default,
so that cleanup never ends a session that could still refresh. Once a
client is removed, its tokens are refused. A server that checked one of
them in the last minute may accept it until that minute is up.

Run cleanup from one scheduled job, such as a daily one, and at once after
you take a host off `client_hosts`. It lists every registration, and
Cognito allows five app-client changes a second, so a large cleanup takes
a while.

```rust
use cognito_kit::registration::{Registrar, RegistrationError};

async fn nightly(registrar: &Registrar) -> Result<(), RegistrationError> {
    let removed = registrar.cleanup().await?;
    println!(
        "removed {} unused, {} idle, {} untrusted and {} orphaned app clients",
        removed.unused, removed.idle, removed.untrusted, removed.orphans,
    );
    Ok(())
}
```

# Store registrations

Every server instance must share one store, so that a client registered on
one instance is known on all of them.

- [`DynamoStore`] (feature `dynamodb`) keeps them in a DynamoDB table whose
  partition key is a string named `pk`, without a sort key. The OpenTofu
  module's `registration` variable creates it, with an IAM policy that
  allows exactly what the registrar does.
- [`MemoryStore`](crate::test_kit::MemoryStore) (features `test-kit` and
  `registration`) keeps them in memory, for tests.
- For another database, implement [`RegistrationStore`].
  [`Registration`](crate::registration::Registration) serializes to JSON.
  `insert` must keep the first registration for a `client_id` and return
  it to the second writer, because two servers can register one client at
  once.

[`Registrar`]: crate::registration::Registrar
[`CognitoApi`]: crate::registration::CognitoApi
[`RegistrationStore`]: crate::registration::RegistrationStore
[`GuardedFetcher`]: crate::registration::GuardedFetcher
[`DynamoStore`]: crate::registration::DynamoStore
