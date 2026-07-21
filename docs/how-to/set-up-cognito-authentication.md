# Set up Amazon Cognito authentication

Configure a Lore Server so your team signs in with an Amazon Cognito user pool using `lore auth login`.

The flow matches [Google authentication](set-up-google-authentication.md): the server brokers the OIDC login, mints its own tokens, and enforces per-repository access grants. This guide covers only the Cognito-specific pieces.

## Prerequisites

- A running Lore Server with its HTTP endpoint reachable from your users' browsers over HTTPS (plain HTTP works for `localhost` testing).
- An Amazon Cognito user pool with your users in it.
- The `lore` CLI on your PATH.

## Register an app client with Cognito

1. In the Cognito console, open your user pool and create an **app client** of the confidential type (with a client secret).
2. Under the app client's **hosted UI / login pages** settings, add the allowed callback URL: your server's HTTP base URL plus `/auth/callback` — for example `https://lore.example.com/auth/callback`.
3. Enable the **authorization code grant** with the `openid`, `email`, and `profile` scopes.
4. Note the **client ID**, the **client secret**, the pool's **region**, and the **user pool ID** (like `us-east-1_AbCdEfGhI`).

Save the client secret to a file readable only by the server process:

```sh
install -m 600 /dev/null /etc/lore/cognito-client-secret
echo '…client secret…' > /etc/lore/cognito-client-secret
```

## Configure the server

```toml
[server.auth.token]
signing_key_path = "/etc/lore/signing-key.pem"
generate_signing_key = true
issuer = "https://lore.example.com"
audience = ["lore.example.com"]

[server.auth.provider]
mode = "cognito"
callback_base_url = "https://lore.example.com"

[server.auth.provider.oidc]
client_id = "26q4…app-client-id"
client_secret_path = "/etc/lore/cognito-client-secret"
region = "us-east-1"
user_pool_id = "us-east-1_AbCdEfGhI"

[environment.endpoint]
auth_url = "ucs-auth://lore.example.com:41337"
```

The server derives the pool's OIDC discovery document from `region` and `user_pool_id`; set `discovery_url` explicitly instead to point at a custom endpoint.

Restart `loreserver` and confirm the startup log reports `Server-local authentication enabled` with `provider=cognito`.

## Log in and grant access

```sh
lore auth login https://lore.example.com:41337
lore auth list                # identity appears as cognito:<subject>
```

Access is deny-by-default. Repository creators receive an automatic admin grant; grant teammates with:

```sh
lore access grant teammate@example.com read project1
```

## Verifying Lore tokens externally

The server publishes its token-verification keys at `https://lore.example.com/auth/.well-known/jwks.json` (Ed25519, RFC 8037), so other services can validate Lore-minted tokens.

## Troubleshooting

- **`redirect_uri_mismatch`** — the callback URL registered with the app client doesn't exactly match `callback_base_url` plus `/auth/callback`.
- **"account email is not verified"** — the pool account's email attribute isn't verified; verify it in the Cognito console or at sign-up.
- **`invalid_client` during code exchange** — the app client has no secret (public client) or the secret file contents are wrong; Lore requires a confidential app client.
