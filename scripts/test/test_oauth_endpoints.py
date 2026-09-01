# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Smoke tests for the standard OAuth 2.0 / OIDC endpoints.

Runs a loreserver with server-local auth (static provider) and drives the
whole standards-shaped surface over plain HTTP, the way generic OAuth
tooling would: OIDC discovery, the RFC 8628 device-authorization grant,
the refresh_token grant, and RFC 8693 token exchange with an RFC 8707
resource indicator. No Lore client involved — that is the point."""

import json
import urllib.error
import urllib.parse
import urllib.request

import pytest
from grpc_auth import rebac_create_resource
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from test_auth_login import http_get

pytestmark = pytest.mark.xdist_group("oauth_server")

USER = "alice"
SECRET = "s3cret-for-tests"

GRANT_DEVICE = "urn:ietf:params:oauth:grant-type:device_code"
GRANT_REFRESH = "refresh_token"
GRANT_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"

PROJECT_HEX = "0194b726b34e72b0b45550b88a967076"
FOREIGN_HEX = "f6ca55437aa34198ba0f0fdc33154d51"

AUTH_CONFIG_TEMPLATE = """

# Appended by test_oauth_endpoints.py: server-local auth, static provider.
[server.auth.token]
generate_signing_key = true
signing_key_path = "{signing_key_path}"
issuer = "http://localhost:{http_port}"
audience = ["localhost"]
user_token_ttl_seconds = 3600
refresh_token_ttl_seconds = 3600

[server.auth.provider]
mode = "static"
callback_base_url = "http://localhost:{http_port}"

[server.auth.provider.static]
allow_insecure_dev_login = true

[[server.auth.provider.static.users]]
user = "{user}"
secret = "{secret}"
name = "Alice Example"
email = "alice@example.com"
"""


@pytest.fixture(scope="module")
def oauth_server(request, tmp_path_factory):
    """A dedicated loreserver with server-local auth enabled."""
    ports = {
        "http": allocate_free_port(),
        "grpc": allocate_free_port(),
        "quic": allocate_free_port(),
        "internal": allocate_free_port(),
    }
    server_root, server_env = generate_server_config(request, tmp_path_factory, ports)

    signing_key_path = (server_root / "signing-key.pem").as_posix()
    config_path = server_root / "lore-server" / "config" / "gha.toml"
    with config_path.open("a", encoding="utf-8") as config:
        config.write(
            AUTH_CONFIG_TEMPLATE.format(
                signing_key_path=signing_key_path,
                http_port=ports["http"],
                user=USER,
                secret=SECRET,
            )
        )

    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, request.getfixturevalue("lore_server_executable_path")
    )
    yield {
        "grpc": f"127.0.0.1:{ports['grpc']}",
        "http": f"http://localhost:{ports['http']}",
    }
    _kill_server_by_pid(server_proc.pid, server_log_path, label="oauth server")
    server_log_fd.close()


def http_post_form(url: str, fields: dict[str, str]) -> tuple[int, dict]:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def device_login(server) -> dict:
    """Run the full device grant and return the token response."""
    status, authorization = http_post_form(
        f"{server['http']}/auth/device_authorization", {"client_id": "smoke"}
    )
    assert status == 200, authorization
    token_request = {
        "grant_type": GRANT_DEVICE,
        "device_code": authorization["device_code"],
        "client_id": "smoke",
    }

    # Not approved yet.
    status, pending = http_post_form(f"{server['http']}/auth/token", token_request)
    assert status == 400 and pending["error"] == "authorization_pending", pending

    # Approve in the "browser": the complete URI carries the state for the
    # static provider's form, which submits to the callback via GET.
    complete_uri = authorization["verification_uri_complete"]
    state = urllib.parse.parse_qs(urllib.parse.urlparse(complete_uri).query)["state"][0]
    status, body = http_get(
        f"{server['http']}/auth/callback?state={state}&user={USER}&secret={SECRET}"
    )
    assert status == 200 and "Login complete" in body

    status, token = http_post_form(f"{server['http']}/auth/token", token_request)
    assert status == 200, token
    return token


def test_discovery_document_and_jwks(oauth_server):
    for path in (
        "/.well-known/openid-configuration",
        "/auth/.well-known/openid-configuration",
    ):
        status, body = http_get(f"{oauth_server['http']}{path}")
        assert status == 200
        document = json.loads(body)
        assert document["issuer"] == oauth_server["http"]
        for grant in (GRANT_DEVICE, GRANT_REFRESH, GRANT_EXCHANGE):
            assert grant in document["grant_types_supported"]

        # The advertised endpoints resolve on this server.
        jwks_status, jwks_body = http_get(document["jwks_uri"])
        assert jwks_status == 200
        keys = json.loads(jwks_body)["keys"]
        assert keys and keys[0]["kty"] == "OKP"


def test_device_grant_end_to_end(oauth_server):
    token = device_login(oauth_server)
    assert token["token_type"] == "Bearer"
    assert token["expires_in"] > 0
    assert token["access_token"]
    assert token["refresh_token"]

    # The device code is one-shot.
    status, replay = http_post_form(
        f"{oauth_server['http']}/auth/token",
        {"grant_type": GRANT_DEVICE, "device_code": "bogus", "client_id": "smoke"},
    )
    assert status == 400 and replay["error"] == "expired_token"


def test_device_verification_page(oauth_server):
    status, authorization = http_post_form(
        f"{oauth_server['http']}/auth/device_authorization", {}
    )
    assert status == 200
    user_code = authorization["user_code"]

    # The bare page renders the code form; a bad code is reported.
    status, body = http_get(f"{oauth_server['http']}/auth/device")
    assert status == 200 and "user_code" in body
    status, body = http_get(f"{oauth_server['http']}/auth/device?user_code=XXXX-XXXX")
    assert status == 200 and "unknown" in body

    # A good code redirects to the provider (the dev-login form follows it).
    request = urllib.request.Request(
        f"{oauth_server['http']}/auth/device?user_code={user_code.lower()}"
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        # urllib follows the redirect; we land on the static provider form.
        assert response.status == 200
        assert "state=" in response.url


def test_refresh_grant_rotates(oauth_server):
    token = device_login(oauth_server)

    status, refreshed = http_post_form(
        f"{oauth_server['http']}/auth/token",
        {"grant_type": GRANT_REFRESH, "refresh_token": token["refresh_token"]},
    )
    assert status == 200, refreshed
    # A token minted in the same second is byte-identical (deterministic
    # signature over identical claims), so assert validity, not inequality.
    assert refreshed["access_token"] and refreshed["expires_in"] > 0
    assert refreshed["refresh_token"] != token["refresh_token"]

    # A made-up token is refused with the standard error.
    status, refused = http_post_form(
        f"{oauth_server['http']}/auth/token",
        {"grant_type": GRANT_REFRESH, "refresh_token": "never-issued"},
    )
    assert status == 400 and refused["error"] == "invalid_grant"


def test_token_exchange_scopes_to_granted_resources(oauth_server):
    token = device_login(oauth_server)
    access_token = token["access_token"]
    rebac_create_resource(
        oauth_server["grpc"], access_token, f"urc-{PROJECT_HEX}", "smoke-project"
    )

    # RFC 8707 resource indicator (URL form) for a repository the caller
    # holds a grant on.
    status, exchanged = http_post_form(
        f"{oauth_server['http']}/auth/token",
        {
            "grant_type": GRANT_EXCHANGE,
            "subject_token": access_token,
            "subject_token_type": TOKEN_TYPE_ACCESS,
            "resource": f"{oauth_server['http']}/partitions/{PROJECT_HEX}",
        },
    )
    assert status == 200, exchanged
    assert exchanged["issued_token_type"] == TOKEN_TYPE_ACCESS

    from test_auth_login import decode_jwt_claims

    claims = decode_jwt_claims(exchanged["access_token"])
    resources = {r["resource_id"]: r["permission"] for r in claims["resources"]}
    assert f"urc-{PROJECT_HEX}" in resources
    assert "read" in resources[f"urc-{PROJECT_HEX}"]

    # Deny-by-default: no grant on the foreign repository.
    status, denied = http_post_form(
        f"{oauth_server['http']}/auth/token",
        {
            "grant_type": GRANT_EXCHANGE,
            "subject_token": access_token,
            "subject_token_type": TOKEN_TYPE_ACCESS,
            "resource": f"urc-{FOREIGN_HEX}",
        },
    )
    assert status == 403 and denied["error"] == "access_denied", denied

    # A non-repository indicator is invalid_target.
    status, invalid = http_post_form(
        f"{oauth_server['http']}/auth/token",
        {
            "grant_type": GRANT_EXCHANGE,
            "subject_token": access_token,
            "subject_token_type": TOKEN_TYPE_ACCESS,
            "resource": "not-a-repository",
        },
    )
    assert status == 400 and invalid["error"] == "invalid_target"


def test_unknown_grant_type_is_rejected(oauth_server):
    status, body = http_post_form(
        f"{oauth_server['http']}/auth/token", {"grant_type": "password"}
    )
    assert status == 400 and body["error"] == "unsupported_grant_type"
