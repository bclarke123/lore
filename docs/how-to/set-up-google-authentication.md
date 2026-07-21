# Set up Google authentication

Configure a Lore Server so your team signs in with their Google accounts using `lore auth login` — no external auth service and no IP allowlists.

In this guide you'll register an OAuth client with Google, configure `loreserver` to mint its own tokens backed by Google sign-in, and verify the login flow end to end.

## Prerequisites

- A running Lore Server with its HTTP endpoint reachable from your users' browsers over HTTPS (plain HTTP works for `localhost` testing). See [Deploy a local Lore Server](deploy-local-lore-server.md).
- Access to [Google Cloud Console](https://console.cloud.google.com/) to create an OAuth client.
- The `lore` CLI on your PATH.

## Register an OAuth client with Google

1. In Google Cloud Console, open **APIs & Services → Credentials**.
2. Select **Create Credentials → OAuth client ID** and choose the **Web application** type.
3. Add the authorized redirect URI: your server's HTTP base URL plus `/auth/callback` — for example `https://lore.example.com/auth/callback`, or `http://localhost:41339/auth/callback` for local testing.
4. Note the **Client ID** and download or copy the **Client secret**.

Save the client secret to a file readable only by the server process:

```sh
install -m 600 /dev/null /etc/lore/google-client-secret
echo 'GOCSPX-…' > /etc/lore/google-client-secret
```

## Configure the server

Add the auth sections to your server configuration (for example `lore-server/config/local.toml`):

```toml
[server.auth.token]
# Ed25519 signing key for the tokens the server mints. Generated on first
# start when generate_signing_key is true; keep the file private.
signing_key_path = "/etc/lore/signing-key.pem"
generate_signing_key = true
issuer = "https://lore.example.com"
# Audience entries double as the root domains the client trusts the token
# to; use your server's domain.
audience = ["lore.example.com"]

[server.auth.provider]
mode = "google"
# The externally reachable base of the server's HTTP endpoint; must match
# the redirect URI registered with Google.
callback_base_url = "https://lore.example.com"

[server.auth.provider.oidc]
client_id = "1234567890-abc.apps.googleusercontent.com"
client_secret_path = "/etc/lore/google-client-secret"
# Optional: restrict sign-in to one Google Workspace domain.
# hosted_domain = "example.com"

# Tell clients where to log in: the server's own gRPC endpoint.
[environment.endpoint]
auth_url = "ucs-auth://lore.example.com:41337"
```

Restart `loreserver`. The startup log reports `Server-local authentication enabled` with `provider=google`, and the gRPC log line shows `Auth: enabled`.

Access is deny-by-default: a signed-in user sees only repositories they hold a grant on. Repository creators receive an automatic admin grant; add teammates with `lore access grant <user> <role> <repository>`, and list grants with `lore access list <repository>`. Configure server administrators (who see everything) via `server_admins` under `[server.auth]`.

## Log in

```sh
lore auth login https://lore.example.com:41337
```

The browser opens Google's consent screen. After you approve, the page shows "Login complete", and the CLI stores the minted token. Confirm your identity:

```sh
lore auth list
```

The identity is reported as `google:<subject>` with your Google display name.

## Test the whole flow locally

The full flow — Google consent screen included — runs on a laptop with no TLS. Two differences from the production setup: the redirect URI uses plain `http://localhost` (which Google permits), and the advertised auth endpoint uses the `ucs-auth-insecure://` scheme so the client contacts the auth service without TLS. Never use that scheme outside local development — tokens would travel in the clear.

1. Register the OAuth client as above, with the redirect URI `http://localhost:41339/auth/callback`.

2. Create a sandbox directory for the server:

   ```sh
   mkdir -p ~/lore-dev/lore-server/config && cd ~/lore-dev
   cp <lore-checkout>/lore-server/config/default.toml lore-server/config/

   # Self-signed certificate for the QUIC endpoint
   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
     -days 30 -nodes -subj "/CN=localhost"

   echo 'GOCSPX-…' > google-client-secret
   ```

3. Write `lore-server/config/local.toml` (`local` is the default environment, so it loads automatically):

   ```toml
   [environment.endpoint]
   auth_url = "ucs-auth-insecure://localhost:41337"

   [server.auth]
   server_admins = ["you@example.com"]

   [server.auth.token]
   generate_signing_key = true
   signing_key_path = "signing-key.pem"
   issuer = "http://localhost"
   audience = ["localhost"]

   [server.auth.provider]
   mode = "google"
   callback_base_url = "http://localhost:41339"

   [server.auth.provider.oidc]
   client_id = "1234-abc.apps.googleusercontent.com"
   client_secret_path = "google-client-secret"
   ```

4. Start the server from the sandbox directory and log in:

   ```sh
   cd ~/lore-dev && loreserver          # look for: Server-local authentication enabled
   lore auth login grpc://localhost:41337
   lore auth list                       # identity appears as google:<subject>
   ```

Because your account is in `server_admins`, you hold the admin role everywhere; a second Google account is denied until you grant it:

```sh
lore access grant teammate@gmail.com read myrepo --remote-url grpc://localhost:41337
lore access list myrepo --remote-url grpc://localhost:41337
```

## Troubleshooting

- **`redirect_uri_mismatch` in the browser** — the `callback_base_url` (plus `/auth/callback`) doesn't exactly match the redirect URI registered with Google, including scheme and port.
- **"Login was denied … account is not in the required domain"** — the signed-in Google account isn't in the configured `hosted_domain`.
- **CLI times out polling** — the browser flow wasn't completed within the polling window (about 2.5 minutes); run `lore auth login` again.
- **`JWT 'aud' does not specify remote domain`** — the `audience` entries in `[server.auth.token]` don't cover the host name you connect to; add that domain.
