<!--
SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
SPDX-License-Identifier: MIT
-->

# koh/poppy

A framework-agnostic PHP server for the
[Personal Agent Protocol](https://personalagentprotocol.org/docs/0.2/spec)
(Poppy), draft 0.2: the protocol through which a person's own AI agent works
with a company on their behalf. The agent discovers what the company offers,
starts a Session, browses its website and calls its APIs in that Session, and
signs in to the person's account only when a task needs it — with the person
approving on the company's own page.

This package is the company side. It has no framework dependency and no
global state: it speaks PSR-7, PSR-17, PSR-18 and PSR-20, and leaves storage,
pages and routing to the integration. Integrations exist for
[Sylius](https://github.com/ohartwig/sylius-poppy) and
[TYPO3](https://github.com/ohartwig/typo3-poppy).

## What it covers

| Section of the specification | Here |
|---|---|
| 3 Discovery | `PoppyDocument` (`/.well-known/poppy.json`) and `AuthorizationServerMetadata` (RFC 8414, with `poppy_domains` for the issuer binding) |
| 4.1 Agent identity | `ClientMetadataResolver`, `ClientAuthenticator` — client ID metadata documents, `private_key_jwt`, `aud` pinned to the issuer |
| 4.2 Sessions | `TokenEndpoint`, JWT bearer grant, `session_id`, renewal |
| 4.3 DPoP | `DpopVerifier` (RFC 9449), Bearer tokens only for MCP servers without DPoP |
| 4.5 Direct Sign-In | `DirectSignIn` — authorization code with PKCE S256 and RFC 9207 `iss` |
| 4.6 Device Sign-In | `DeviceAuthorizationEndpoint`, `DeviceVerification` (RFC 8628) |
| 4.8–4.9 Account Tokens, sign-out | `refresh_token` grant, `RevocationEndpoint`, `AccountDisconnector` |
| 5 Web browsing | `BrowserSessions` — browser assertions; the integration sets its own cookie |
| 6 APIs | `ResourceGuard`, `SessionContext`, `Challenge` (`WWW-Authenticate`) |
| 8 Feedback | `FeedbackEndpoint` |

Not covered: Mediated Sign-In (4.7), in which the agent sends the person's
password to the company, and conversations with a Company Agent (section 7).
A company that offers neither is fully conformant; the discovery document only
declares what is wired up.

## The checks that matter

- **Issuer binding, both directions.** `poppy.json` names the issuer, and the
  issuer's metadata lists the domain in `poppy_domains`. The document builder
  refuses a domain the issuer does not list. The metadata also carries the
  same binding as `protected_resources`, the form draft 0.3 uses.
- **Assertions addressed to the issuer.** Client and Session assertions must
  carry the issuer as a single-string `aud` — never the token endpoint, never
  an array — live at most five minutes, and carry a `jti` that is accepted
  once. Browser assertions have their own `typ` and audience, so neither kind
  passes for the other.
- **Every token request proves a key.** Session Tokens are bound to the DPoP
  key of the request that obtained them; proofs are checked for method, URL,
  age, `ath`, key binding and — at the token endpoint — replay. ES256 is always
  accepted. Nonces are optional (`TimeSlotNonceSource`).
- **Bearer only where it cannot be avoided.** A Bearer Session Token exists
  only for an MCP server that does not verify DPoP, and is accepted at that
  server's URL and nowhere else.
- **Sign-out takes effect on the next request.** Whether a request is signed in
  is read from the Session each time, not from the token, so a revoked Account
  Token turns every token issued under it into a signed-out one at once.
- **A Session keeps its account.** Once signed in, a Session can be signed in
  again only to the same account; anything else is `account_mismatch` and no
  tokens.
- **Nothing is fetched that should not be.** Client metadata and key sets are
  fetched over HTTPS on port 443 only, never from loopback, private, link-local
  or other non-public addresses, never following redirects, and only after
  every check that needs no network has passed — a blocked or malformed
  request makes the server send nothing.
- **No token is stored.** Tokens are random strings; storage sees only their
  SHA-256 hash.

## Usage

```php
use Koh\Poppy\Discovery\Api;
use Koh\Poppy\Discovery\PoppyDocument;
use Koh\Poppy\PoppyServer;
use Koh\Poppy\Server\Endpoints;
use Koh\Poppy\Server\ServerConfiguration;

$configuration = new ServerConfiguration(
    issuer: 'https://shop.example/poppy',
    domains: ['shop.example'],
    endpoints: Endpoints::below('https://shop.example/poppy'),
    directScopes: ['poppy:read', 'poppy:write'],
    deviceScopes: ['poppy:read'],
    apis: [Api::openApi('https://shop.example/openapi.json', 'Orders and returns')],
);

$server = new PoppyServer(
    $configuration,
    $storage,        // PoppyStorage — your persistence
    $replayGuard,    // ReplayGuard — atomic set-if-absent, e.g. Redis SET NX or a unique key
    $clientPolicy,   // ClientPolicy — e.g. new ListClientPolicy(block: [...])
    $jsonFetcher,    // JsonFetcher over a PSR-18 client that does not follow redirects
    $clock,          // PSR-20
    $responseFactory,
    $streamFactory,
);

// GET /.well-known/poppy.json
$document = new PoppyDocument('Example Shop', 'shop.example', $configuration, $configuration->apis);

// GET /.well-known/oauth-authorization-server/poppy
$metadata = $server->metadata();

// POST /poppy/token, /poppy/revoke, /poppy/device_authorization
$response = $server->tokenEndpoint()->handle($request);

// An API endpoint
$session = $server->resourceGuard()->authenticate($request, 'https://shop.example/api/orders');
$accountId = $session->requireScopes('poppy:read');
```

The integration provides the pages a person sees — sign-in and consent for
Direct Sign-In, code entry for Device Sign-In, the account page where Personal
Agents are disconnected — and calls `DirectSignIn`, `DeviceVerification` and
`AccountDisconnector` from them.

### What the integration must get right

- **Replay guard: atomic, shared.** `claim()` must be one set-if-absent
  operation across every worker. Two operations ("exists?", then "store") let
  two parallel requests both accept the same assertion.
- **Storage: two single-use operations.** `consumeAuthorizationCode()` and
  `consumeApprovedDeviceAuthorization()` must hand a record out at most once
  under concurrency.
- **HTTP client: no redirects, address pinning.** `PublicAddressGuard` checks
  the resolved addresses before the request; the HTTP client resolves again.
  Use a client that refuses private addresses at connect time (Symfony's
  `NoPrivateNetworkHttpClient`, or cURL with `CURLOPT_RESOLVE`) to close that
  gap.
- **Public URLs.** Pass the public URL of an endpoint to the verifiers rather
  than the URL the request arrived at, which behind a TLS-terminating proxy is
  the internal one.
- **Rate limits.** Implement `RateLimiter`, and rate-limit the device code
  entry page per client address: user codes are short by design.

## Requirements

PHP 8.3 or later with `openssl` and `sodium`, a PSR-18 client and PSR-17
factories.

## Independence

This is an independent implementation, written from the Personal Agent
Protocol specification. It is not affiliated with the authors of the
specification.

## Licence

MIT. See [LICENSE](LICENSE).
