---
lep: 2026-07-20-pluggable-auth-and-repo-acl
title: Pluggable OAuth authentication and per-repository access control
authors:
  - Ben Clarke
status: Draft
created: 2026-07-20
updated: 2026-07-20
discussion: <GitHub Issue link — to be filed before review>
---

# Pluggable OAuth authentication and per-repository access control

## Summary

This proposal makes Lore Server an authentication endpoint in its own right: it implements the auth-session gRPC service the client already speaks, delegates identity verification to a pluggable `AuthProvider` (Google and Amazon Cognito via standard OIDC, plus a static provider for development and CI), and mints its own short-lived JWTs so the rest of the system never depends on identity-provider-specific token shapes. On top of that identity foundation, it adds per-repository access control — `read`, `write`, and `admin` roles granted per user per repository, deny-by-default, persisted in the existing mutable/immutable store, and administered through a new `lore access` CLI backed by a new gRPC service. Deployments that leave auth unconfigured behave exactly as today.

## Motivation

Lore Server validates JWTs against a single remote JWKS endpoint (`lore-server/src/auth/jwt.rs`, `lore-server/src/auth/jwk.rs`), which in practice assumes an Epic-operated auth service that issues tokens with Lore's expected `resources` claims. Open source deployments have no such service, so they run with auth unconfigured — a fully open server (`lore-server/src/grpc/server.rs` registers every service without an interceptor when no verifier exists). Production users compensate with network-level controls such as IP allowlisting on a cloud load balancer, which is operationally brittle, breaks for roaming users, and provides no per-user identity or per-repository isolation.

Two gaps compound the problem:

1. **No way to log in.** The client ships a complete login flow (`lore auth login` → `StartAuthSession` → browser → `GetAuthSession` polling; `lore-revision/src/auth/login.rs`), but the open source server implements no auth service for it to talk to. There is no path to "sign in with Google" or any other standard identity provider.
2. **No per-repository authorization.** Authorization is fragmented: the gRPC interceptor checks only that a repository appears in the token's `resources` claim, not which permissions it carries (`verify_authorization`, `lore-server/src/auth/jwt.rs`); the v1 Repository service runs an authn-only placeholder interceptor (`TODO(UCS-13506)`, `lore-server/src/auth/jwt_interceptor.rs`); and delete/push fall back to creator-string comparison and a blanket `is_service_account` bypass. There is no mechanism to grant or revoke a user's access to a repository.

The access model Lore intends is already specified — `docs/explanation/system-design.md` §17 describes per-partition permission sets (`read`, `write`, `obliterate`, `admin`) with wildcard grants reserved for service accounts — but nothing implements the granting side of it. This proposal implements that section.

## Goals / Non-Goals

### Goals

- Users authenticate to a self-hosted Lore Server with standard OAuth 2.0 / OIDC providers, starting with Google, using the stock `lore auth login` flow with no client changes.
- Identity providers are pluggable behind a server-side trait; adding a provider requires no changes to the wire protocol, token format, or client. A provider's only obligation is "auth succeeded; here is the verified identity" — no Lore-specific JWT claims are required from the IdP.
- Lore Server mints and verifies its own short-lived tokens; only Lore-issued tokens cross the wire protocol.
- Per-repository access control: `read`, `write`, and `admin` roles per user per repository, deny-by-default, with server-level administrators and an automatic `admin` grant for a repository's creator.
- Grants are administered at runtime via `lore access grant|revoke|list`, backed by an authenticated gRPC service, and persisted in the server's existing storage backends.
- A configuration-only static provider enables fully automated authenticated testing (unit and smoke) with no external IdP.
- Refresh tokens keep long-lived sessions working without re-running the browser flow.

### Non-Goals

- Path- or branch-level permissions inside a repository. The access boundary remains the partition, per system-design §17.7.
- Group/team management. Grants are per-user in v1; the token's existing `groups` claim is carried but not evaluated.
- Replacing the external Epic auth-service mode. Servers configured with a remote JWKS endpoint continue to work unchanged.
- SAML, LDAP, or non-OAuth enterprise SSO protocols.
- Multi-node coordination of in-flight login sessions (single-node session affinity is an accepted v1 limitation; see Risks).

## Proposed Design

### Overview

```text
 lore CLI                    Lore Server                        Google / Cognito
    │  StartAuthSession          │                                    │
    ├───────────────────────────►│ create PendingSession,             │
    │   {login_url, session_code}│ build provider auth URL            │
    │◄───────────────────────────┤                                    │
    │  (opens browser)           │                                    │
    │       browser ────────────────────────────────────────────────► │ consent
    │       browser ◄──────────── redirect with code ──────────────── │
    │       browser ────────────►│ GET /auth/callback?code&state      │
    │                            │ code→token exchange, verify        │
    │                            │ ID token, mint Lore JWT ─────────► │ (token endpoint)
    │  GetAuthSession (poll)     │                                    │
    ├───────────────────────────►│                                    │
    │   {lore user token}        │                                    │
    │◄───────────────────────────┤                                    │
```

The client half of this flow already exists and is unchanged: `lore auth login` fetches the environment's `auth_url`, resolves an `Authentication` implementation by URL scheme (`lore-transport/src/auth/mod.rs`), calls `start_auth_session`, opens the browser at the returned URL, and polls `poll_auth_session` (`lore-revision/src/auth/login.rs`). The server advertises `auth_url = ucs-auth://<server-host>:<grpc-port>` so the existing `ucs-auth` client implementation talks to the Lore Server itself.

### Server as auth service

Lore Server implements the subset of the existing `epic_urc.UrcAuthApi` gRPC service (`lore-proto/proto/auth_api.proto`) that the client uses: `StartAuthSession`, `GetAuthSession`, `RefreshAuthSession`, `ExchangeUserTokenForMultiresourceToken`, `GetUserInfo`, and `GetUserId`. Remaining RPCs return `Unimplemented`. Reusing this service is what makes the client zero-change; migrating the surface to a clean `lore.auth.v1` package is proposed as a follow-up (see Unresolved Questions).

`StartAuthSession` creates a `PendingSession` — session code, the client's `client_state`, a CSRF `state` value, a PKCE verifier, an OIDC `nonce`, and a TTL — and returns the provider's authorization URL. The browser redirect lands on the server's existing HTTP endpoint at `GET /auth/callback`; the handler resolves the session by `state`, completes the provider flow, and records the outcome. `GetAuthSession` returns the minted token once the outcome is ready, validates `client_state`, and consumes the session (one-shot).

### The `AuthProvider` trait

```rust
#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    /// Build the URL the user's browser is sent to for this pending session.
    async fn begin_login(&self, session: &PendingSession) -> Result<Url, AuthProviderError>;
    /// Handle the redirect back (code/state) and return the verified identity.
    async fn complete_login(
        &self,
        session: &PendingSession,
        params: CallbackParams,
    ) -> Result<ExternalIdentity, AuthProviderError>;
}

pub struct ExternalIdentity {
    pub subject: String,          // stable IdP subject ("sub")
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub idp: String,              // provider name, e.g. "google"
}
```

Providers:

- **`oidc`** — a generic OIDC Authorization Code + PKCE implementation: discovery-document fetch, authorization-URL construction (`state`, `nonce`, PKCE S256), code exchange at the token endpoint (the `client_secret` never leaves the server), and ID-token validation (signature via the provider's `jwks_uri` using the existing `JwkServiceImpl`, plus `iss`/`aud`/`exp`/`nonce` checks).
- **`google`** — a preset over `oidc`: Google's discovery URL, required `email_verified`, optional `hd` hosted-domain restriction.
- **`cognito`** — a preset over `oidc`: user-pool discovery URL, Cognito's audience conventions, optional group-claim passthrough.
- **`static`** — development/CI only: users and secrets from server configuration; `complete_login` verifies a shared secret posted to a dev-login endpoint. It refuses to construct unless `allow_insecure_dev_login = true` is set explicitly.

The provider contract deliberately stops at `ExternalIdentity`. Everything downstream — token minting, claims, authorization — is provider-independent, which is what keeps "add an IdP" a server-configuration concern rather than a protocol change.

### Token minting and verification

On successful login the server mints a **user token**: a short-lived JWT (default 1 hour) signed with a server-local asymmetric key (ES256 or EdDSA, PEM-configured), carrying the claims the existing verifier already understands (`sub`, `iss`, `aud`, `exp`, `name`, `preferred_username`, `idp`) and **no `resources` claim**. The canonical subject is `<idp>:<subject>` (e.g. `google:118234…`), which is stable even if the user's email changes at the IdP.

Per-repository **authorization tokens** come from the existing `ExchangeUserTokenForMultiresourceToken` exchange, which the client already performs and refreshes every 60 seconds (`lore-transport/src/auth/exchange.rs`, `lore-transport/src/grpc/mod.rs`). The server consults the access store (below) and embeds `resources: [ResourcePermission { resource_id: "urc-<repo>", permission: [...] }]` — the exact claim shape the gRPC interceptor, QUIC session handler, and HTTP middleware already consume (`lore-server/src/auth/jwt.rs`).

Verification of self-minted tokens reuses the existing machinery: a `LocalJwkService` implementing the current single-method `JWKService` trait (`lore-server/src/auth/jwk.rs`) resolves the local public key by `kid`, so `JwtVerifier` and all three transport enforcement paths are unchanged. The service maintains a `kid` accept-list to support key rotation, and the server publishes its public keys at `GET /auth/.well-known/jwks.json` so external services can verify Lore tokens.

Refresh: login also issues an opaque refresh token (random 256-bit value, stored server-side as a hash with rotation-on-use and reuse-detection revocation). The client already stores refresh tokens (`lore-credential/src/token_store.rs`) and the `Authentication` trait already declares `refresh_authentication`; this proposal implements the server side (`RefreshAuthSession`) and wires the dormant client seam into the token-exchange path, falling back to "please run `lore auth login`" — and to today's exact behavior when a server answers `Unimplemented`.

### Per-repository access control

**Model.** Three roles per repository, mapped onto the permission verbs the codebase already checks (`lore-server/src/grpc/mod.rs`; system-design §17.4):

| Role | Permission verbs in minted tokens |
| --- | --- |
| `read` | `read` |
| `write` | `read`, `write` |
| `admin` | `read`, `write`, `admin`, `owner`, `obliterate`, `migrate` |

Server administrators (bootstrapped from a list in server configuration, extendable at runtime) hold every role on every repository. A repository's creator receives an automatic `admin` grant at `RepositoryCreate`. Access is **deny-by-default**: with auth enabled, a user with no grant cannot list, read, or discover a repository. `is_service_account` tokens retain wildcard semantics per system-design §17.4.

**Storage.** Grants follow the established repository-metadata pattern (`lore-revision/src/repository.rs`): the grant set for a repository serializes into a blob in the content-addressed immutable store, with a pointer in the mutable store under a new key type (`mutable_key(salt, ACCESS_CONTROL, repo_id)`), updated via compare-and-swap to make concurrent grant/revoke safe. Server-level admin grants live in a single global blob under the same scheme. No new storage backend is introduced; grants inherit the durability and replication properties of the configured mutable/immutable stores.

**Enforcement.** The primary chokepoint is token exchange: `ExchangeUserTokenForMultiresourceToken` resolves the caller's role for each requested repository and refuses (`PermissionDenied`) when no grant exists. Because every data-plane request already carries an exchanged authorization token, the existing interceptors enforce the result without modification. Additionally:

- `verify_authorization` tightens from presence-checking to verb-checking (read-class vs write-class RPCs), gated by an `enforce_permission_verbs` setting that defaults **on** when the server mints its own tokens and **off** in external-JWKS mode, so externally issued tokens with different verb vocabularies keep working.
- The v1 Repository service replaces its authn-only placeholder (`UCS-13506`): `RepositoryList` filters to granted repositories, `RepositoryGet` requires `read`, `RepositoryDelete` requires `admin`, and the creator-string fallback is replaced by the access store.
- The same verb semantics apply across all three transports (gRPC interceptor, QUIC `AuthorizeStart` session validation, HTTP middleware).

**Administration.** A new `lore.access.v1.AccessService` (new proto package, following the `proto/lore/<domain>/v1` convention) exposes `Grant`, `Revoke`, `List`, `ListServerAdmins`, and `SetServerAdmin`, registered behind the full authn+authz interceptor; callers must hold `admin` on the target repository or be server admins. The CLI gains:

```sh
lore access grant  <repo> <user> --role read|write|admin
lore access revoke <repo> <user>
lore access list   <repo> [--json]
```

Admins may identify users by email; the server resolves and pins the email to the canonical `<idp>:<subject>` at the user's first login.

### Configuration

All new behavior hangs off the existing optional `[server.auth]` settings (`lore-server/src/settings.rs`):

```toml
[server.auth.token]
signing_key_path = "/etc/lore/signing-key.pem"
issuer = "https://lore.example.com"
audience = ["https://lore.example.com"]
user_token_ttl_seconds = 3600

[server.auth.provider]
mode = "google"                     # "google" | "cognito" | "oidc" | "static"
callback_base_url = "https://lore.example.com"

[server.auth.provider.oidc]
client_id = "…"
client_secret_path = "/etc/lore/oauth-client-secret"

[server.auth]
server_admins = ["ben@example.com"]
```

A server with no `[server.auth]` section behaves exactly as today: no verifier, no interceptors, open access.

## Compatibility

- **Wire format** — One additive change: `UserToken` gains an `optional string refresh_token` field (proto3 optional, field 5). Old peers ignore it; new peers treat its absence as "no refresh support". Tokens otherwise remain opaque strings in existing metadata fields and the existing QUIC `AuthorizeStart` payload.
- **Client/server protocols** — No changed RPCs. The server newly *implements* the existing `epic_urc.UrcAuthApi` service that clients already call, and adds one new service (`lore.access.v1.AccessService`). An old client against a new server logs in unchanged (same `ucs-auth` flow) and never sees the new service. A new client against an old server sees exactly today's behavior; the refresh path degrades to current behavior when the server returns `Unimplemented`. Two new unauthenticated HTTP routes are added (`/auth/callback`, `/auth/.well-known/jwks.json`).
- **On-disk format** — Client side: none. Server side: one new mutable-store key type for access-control pointers plus grant blobs in the immutable store, written only when auth is enabled. A downgraded server ignores the unknown keys; repositories remain fully readable.
- **CLI and public API** — Adds the `lore access` subcommand family. No existing subcommand, exit code, or output format changes. `lore-capi` surface is unchanged (login already flows through existing entry points).
- **Configuration** — Extends `[server.auth]` with `token`, `provider`, and `server_admins`; all new fields optional. Existing `jwk`/`jwt_issuer`/`jwt_audience` external-JWKS configuration keeps its current meaning and takes effect exactly as before.

## Non-Functional Considerations

- **Concurrency** — Grant updates use compare-and-swap on the mutable-store pointer, the same discipline as repository metadata; concurrent grant/revoke retries rather than losing writes. Token exchange reads grants through a short-TTL cache sized for the existing 60-second client re-exchange cadence.
- **Memory** — Pending login sessions are small fixed-size records in a TTL-bounded, size-capped in-process map; grant blobs are proportional to the number of principals granted per repository, not to repository size. Streaming behavior of the data plane is untouched.
- **Statelessness** — Two new pieces of server state: (1) in-process pending-session map (seconds-to-minutes lifetime, lost harmlessly on restart — the user retries login); (2) persisted grant and refresh-token records in the existing stores, which are durable state by design.
- **Determinism** — Repository history and content addressing are untouched. Token minting is inherently time- and randomness-dependent, confined to the auth subsystem.

## Migration Plan

N/A — no breaking changes, no migration required. Auth remains opt-in; each phase lands dark for unconfigured servers. The only behavioral change for an *already-authenticated* deployment is verb enforcement, which ships behind `enforce_permission_verbs` defaulting off in external-JWKS mode.

## Security Considerations

This proposal is a security feature and changes the trust model deliberately:

- **Secrets custody.** OAuth `client_secret`s and the token-signing key exist only on the server, read from files (not inline configuration). The client never handles provider credentials.
- **Browser-flow hardening.** The OIDC flow uses single-use `state` (CSRF), `nonce` (ID-token replay), and PKCE S256 (code interception). Sessions are one-shot, TTL-limited, and bound to the CLI's `client_state` so a stolen callback URL alone cannot yield a token. `StartAuthSession` and the callback endpoint are rate-limited.
- **Token integrity.** Lore tokens are asymmetrically signed; verification goes through the existing `JwtVerifier` with mandatory `exp` validation. Rotation uses a `kid` accept-list. Refresh tokens are stored only as hashes, rotate on use, and reuse of a superseded token revokes the whole family.
- **Static provider abuse.** The static provider is the sharpest edge: it accepts shared secrets over HTTP. It requires an explicit `allow_insecure_dev_login = true`, compares secrets in constant time, and its use is prominently logged at startup.
- **Malicious peers.** A crafted repository cannot influence auth: grants are keyed by partition ID and stored server-side; nothing in repository content feeds the auth subsystem. A malicious *server* could always harvest tokens sent to it — unchanged from today, and mitigated by the existing client-side domain-trust check (`verify_jwt_usage_for_remote`, `lore-credential/src/jwt.rs`), which minted tokens must satisfy by carrying server-domain `iss`/`aud`.
- **Deny-by-default.** Repository existence is not revealed to ungranted users (list filtering plus the error-code-precedence discipline of system-design §17.9).

## Privacy Considerations

- The server newly stores identity data: canonical subject (`<idp>:<subject>`), email, and display name, persisted in grant records and embedded (name/username) in minted tokens. Emails appear in `lore access list` output to repository admins and in audit logs.
- Login, grant, and revoke events are audit-logged with user IDs via `tracing`; operators control log retention as they do today.
- The IdP learns that a user authenticated to "the Lore OAuth application" (standard OAuth consent); no repository names or paths are sent to the IdP — the callback carries only opaque `code`/`state`.
- Deleting a repository deletes its grant records. Removing an individual's grants removes their identity from that repository's records; refresh-token records expire and are purgeable by hash.

## Risks and Assumptions

**Assumptions**

- **Assumption:** The client's `ucs-auth` scheme implementation works unmodified against a Lore-Server-hosted `UrcAuthApi` (start/poll/exchange). — *invalidated if:* the client hard-codes Epic-service behaviors beyond the proto contract (e.g. token shapes rejected by `verify_jwt_usage_for_remote` for `host:port` remotes); Phase 1 tests this pairing first.
- **Assumption:** Tonic server codegen for `auth_api.proto` can be enabled where today only the client stubs are used. — *invalidated if:* build constraints prevent server generation, requiring a build-helper change (expected to be minor).
- **Assumption:** The 60-second client re-exchange cadence makes access-store reads cacheable with a short TTL without noticeable grant-propagation lag. — *invalidated if:* deployments need sub-minute revocation, in which case the cache TTL becomes configuration.

**Risks**

- **Risk:** The browser must reach the server's HTTP endpoint over HTTPS; some deployments only expose gRPC/QUIC. — *mitigation:* document the requirement; dev setups use `http://localhost`; the existing HTTP TLS support (`HttpSettings`) covers production. The client-side loopback flow remains a documented future fallback through the existing `exchange_external_token` seam.
- **Risk:** In-process pending sessions break logins behind a non-sticky multi-node load balancer. — *mitigation:* accepted for v1 and documented; the session map can move to the mutable store mechanically if needed.
- **Risk:** Verb-tightening breaks tokens from external issuers whose permission vocabulary differs. — *mitigation:* `enforce_permission_verbs` defaults off in external-JWKS mode; the compatibility matrix is covered by unit tests.
- **Risk:** Email-based granting before first login can pin a grant to the wrong person if an email is re-issued at the IdP. — *mitigation:* canonical identity is `<idp>:<subject>`; email is an alias resolved at first login, and `lore access list` shows whether a grant is pinned.

## Drawbacks

- Lore Server takes on IdP-facing responsibilities (discovery, code exchange, key management) that a dedicated auth service would otherwise own.
- Reusing `epic_urc.UrcAuthApi` perpetuates a legacy namespace in the open source surface until the `lore.auth.v1` migration lands.
- Deny-by-default means enabling auth on an existing populated server requires seeding grants before users regain access.

## Alternatives Considered

### Validate IdP-issued JWTs directly on every request

Configure the verifier with each provider's JWKS and accept Google/Cognito tokens on the data plane.

*Rejected because:* it pushes provider-specific claim shapes (`aud` = client ID, no `resources` claim, provider-specific expiry quirks) into every enforcement path, requires multi-issuer `kid` disambiguation in the hot path, and makes per-repo authorization claims impossible to embed — defeating the "no special JWT claims" goal.

### Client-side loopback redirect with PKCE

The CLI runs a localhost listener, completes the code exchange itself, and presents the IdP token to the server for exchange (`ExchangeExternalTokenForUserToken`).

*Rejected because (for v1):* it requires new client-side OAuth code and per-provider configuration distribution to every client, and Google requires "native app" client registration with loopback redirects, while the server-callback design reuses the entire existing client flow with zero changes and keeps secrets server-side. The seam for this flow already exists and is retained as the documented headless fallback.

### OAuth 2.0 Device Authorization Grant

The CLI prints a code and URL; the user completes login on any device.

*Rejected because:* Cognito does not support the device grant natively, Google restricts its device flow to limited scopes and TV-class clients, and the browser-redirect flow covers the primary workstation use case; device flow can be revisited for headless hosts.

### External identity broker (Dex, Keycloak, oauth2-proxy)

Require operators to deploy a broker that normalizes IdPs and issues Lore-compatible tokens.

*Rejected because:* it leaves the core problem — no open source implementation of the auth-session service and no grant management — unsolved inside Lore, adds a mandatory external dependency to every deployment, and still requires the broker to be taught Lore's `resources` claim contract.

## Prior Art

- **Gerrit** and **GitLab** both act as their own OAuth relying parties with pluggable upstream providers and per-project role tables — the same shape as this proposal (server-brokered login, internal session tokens, repo-scoped roles).
- **GitHub App / installation tokens** demonstrate the exchange pattern: a long-lived identity credential exchanged for short-lived, narrowly-scoped tokens — mirrored here by user-token → per-repository authorization-token exchange, which Lore's client already performs.
- **Perforce** protections tables show the operational cost of fine-grained path-level ACLs; this proposal deliberately stops at repository granularity (Non-Goals), consistent with system-design §17.7's "context is identity, not authorization".

## Unresolved Questions

- Should the auth surface move to a clean `lore.auth.v1` package immediately (adding a client-side scheme implementation to the scope) rather than reusing `epic_urc.UrcAuthApi` with a follow-up migration?
- Signing algorithm: the implementation ships Ed25519 (EdDSA) — the simplest correct choice with the in-tree `ring` backend, published as an RFC 8037 OKP JWK. Should ES256 be offered as an alternative for verifiers without EdDSA support?
- Should `enforce_permission_verbs` eventually default on in external-JWKS mode after a deprecation window, and what telemetry gates that?
- Grant-propagation latency: is a short-TTL access-store cache (bounded by the 60-second exchange cadence) acceptable, or must revocation be immediate (cache-bypass on revoke)?
