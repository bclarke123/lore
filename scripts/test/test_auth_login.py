# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Smoke tests for server-local authentication (static provider).

Runs a dedicated loreserver with `[server.auth]` configured: token minting
with a generated signing key plus the static (dev-only) identity provider.
The tests drive the same protocol `lore auth login` uses — StartAuthSession
over gRPC, the browser callback over HTTP, GetAuthSession polling — and then
store the minted token with the real CLI.
"""

import base64
import json
import os
import subprocess
import urllib.error
import urllib.request

import grpc
import pytest
from grpc_auth import (
    exchange_for_resources,
    get_auth_session,
    rebac_create_resource,
    start_auth_session,
)
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)

pytestmark = pytest.mark.xdist_group("auth_server")

USER = "alice"
SECRET = "s3cret-for-tests"
DISPLAY_NAME = "Alice Example"


AUTH_CONFIG_TEMPLATE = """

# Appended by test_auth_login.py: server-local auth with the static provider.
[server.auth.token]
generate_signing_key = true
signing_key_path = "{signing_key_path}"
issuer = "http://localhost"
audience = ["localhost"]
user_token_ttl_seconds = 3600
authz_token_ttl_seconds = 900

[server.auth.provider]
mode = "static"
callback_base_url = "http://localhost:{http_port}"

[server.auth.provider.static]
allow_insecure_dev_login = true

[[server.auth.provider.static.users]]
user = "{user}"
secret = "{secret}"
name = "{display_name}"
email = "alice@example.com"
"""


@pytest.fixture(scope="module")
def auth_server(request, tmp_path_factory):
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
                display_name=DISPLAY_NAME,
            )
        )

    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, request.getfixturevalue("lore_server_executable_path")
    )
    yield {
        "grpc": f"127.0.0.1:{ports['grpc']}",
        "http": f"http://localhost:{ports['http']}",
        "auth_url": f"ucs-auth://localhost:{ports['grpc']}",
    }
    _kill_server_by_pid(server_proc.pid, server_log_path, label="auth server")
    server_log_fd.close()


def http_get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


def decode_jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def browser_login(server, user=USER, secret=SECRET) -> tuple[int, str, str, str]:
    """Start a session and complete the browser flow. Returns
    (callback_status, callback_body, session_code, client_state)."""
    client_state = "smoke-client-state"
    session_code, login_url = start_auth_session(server["grpc"], client_state)
    assert session_code

    # The login URL renders the dev-login form; extract its state parameter.
    assert "/auth/dev-login?state=" in login_url
    state = login_url.split("state=")[1]

    status, body = http_get(
        f"{server['http']}/auth/callback?state={state}&user={user}&secret={secret}"
    )
    return status, body, session_code, client_state


def test_login_flow_end_to_end(auth_server):
    status, body, session_code, client_state = browser_login(auth_server)
    assert status == 200
    assert "Login complete" in body

    token = get_auth_session(auth_server["grpc"], session_code, client_state)
    assert token is not None
    assert token.user_id == f"static:{USER}"
    assert token.user_name == DISPLAY_NAME
    assert token.expires_at > 0

    claims = decode_jwt_claims(token.user_token)
    assert claims["sub"] == f"static:{USER}"
    assert claims["iss"] == "http://localhost"
    assert claims["idp"] == "static"
    assert "resources" not in claims or claims["resources"] is None

    # Sessions are one-shot: a second poll fails.
    with pytest.raises(grpc.RpcError) as error:
        get_auth_session(auth_server["grpc"], session_code, client_state)
    assert error.value.code() == grpc.StatusCode.NOT_FOUND


def test_login_url_renders_form(auth_server):
    _, login_url = start_auth_session(auth_server["grpc"], "smoke-form")
    status, body = http_get(login_url)
    assert status == 200
    assert "form" in body
    assert "/auth/callback" in body


def test_pending_session_polls_empty(auth_server):
    session_code, _ = start_auth_session(auth_server["grpc"], "smoke-pending")
    assert get_auth_session(auth_server["grpc"], session_code, "smoke-pending") is None


def test_wrong_secret_is_denied(auth_server):
    status, body, session_code, client_state = browser_login(
        auth_server, secret="wrong-secret"
    )
    assert status == 403
    assert "denied" in body.lower()

    with pytest.raises(grpc.RpcError) as error:
        get_auth_session(auth_server["grpc"], session_code, client_state)
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED


def test_wrong_client_state_is_denied(auth_server):
    status, _, session_code, _ = browser_login(auth_server)
    assert status == 200
    with pytest.raises(grpc.RpcError) as error:
        get_auth_session(auth_server["grpc"], session_code, "not-my-session")
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED


def test_exchange_mints_authorization_token(auth_server):
    status, _, session_code, client_state = browser_login(auth_server)
    assert status == 200
    user_token = get_auth_session(auth_server["grpc"], session_code, client_state)
    assert user_token is not None

    # Access is deny-by-default: register the resource first (what
    # RepositoryCreate does), granting the caller the admin role.
    resource = "urc-00000000000000000000000000000000"
    rebac_create_resource(
        auth_server["grpc"], user_token.user_token, resource, "smoke-repo"
    )
    authz = exchange_for_resources(
        auth_server["grpc"], user_token.user_token, [resource]
    )
    claims = decode_jwt_claims(authz.user_token)
    assert len(claims["resources"]) == 1
    assert claims["resources"][0]["resource_id"] == resource
    for verb in ("read", "write", "admin"):
        assert verb in claims["resources"][0]["permission"]

    # Exchange without a token is refused.
    with pytest.raises(grpc.RpcError) as error:
        exchange_for_resources(auth_server["grpc"], "garbage-token", [resource])
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_cli_stores_minted_token(auth_server, lore_executable_path, tmp_path):
    status, _, session_code, client_state = browser_login(auth_server)
    assert status == 200
    token = get_auth_session(auth_server["grpc"], session_code, client_state)
    assert token is not None

    # Store the minted token with the real CLI (token-type `lore` validates
    # the recipient domain and stores without a further exchange), then read
    # the identity back.
    auth_env = {
        "LORE_AUTH_PATH": str(tmp_path),
        "LORE_AUTH_STORE": "fallback",
    }
    login = subprocess.run(
        [
            lore_executable_path,
            "auth",
            "login",
            "--token-type",
            "lore",
            "--token",
            token.user_token,
            "--auth-url",
            auth_server["auth_url"],
        ],
        capture_output=True,
        text=True,
        env={**os.environ, **auth_env},
        timeout=60,
    )
    assert login.returncode == 0, login.stderr

    listing = subprocess.run(
        [lore_executable_path, "auth", "list"],
        capture_output=True,
        text=True,
        env={**os.environ, **auth_env},
        timeout=60,
    )
    assert listing.returncode == 0, listing.stderr
    assert f"static:{USER}" in listing.stdout
