# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Smoke tests for refresh tokens (rotation and reuse detection).

Runs a loreserver with a deliberately short user-token TTL so refresh is
the only way to keep a session alive."""

import time

import grpc
import pytest
from grpc_auth import (
    exchange_for_resources,
    get_auth_session,
    rebac_create_resource,
    refresh_auth_session,
    start_auth_session,
)
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from test_auth_login import http_get

pytestmark = pytest.mark.xdist_group("refresh_server")

PROJECT = "urc-0194b726b34e72b0b45550b88a967076"

AUTH_CONFIG_TEMPLATE = """

# Appended by test_auth_refresh.py: short-lived user tokens + refresh.
[server.auth.token]
generate_signing_key = true
signing_key_path = "{signing_key_path}"
issuer = "http://localhost"
audience = ["localhost"]
user_token_ttl_seconds = 2
refresh_token_ttl_seconds = 3600

[server.auth.provider]
mode = "static"
callback_base_url = "http://localhost:{http_port}"

[server.auth.provider.static]
allow_insecure_dev_login = true

[[server.auth.provider.static.users]]
user = "alice"
secret = "alice-secret"
name = "Alice"
email = "alice@example.com"
"""


@pytest.fixture(scope="module")
def refresh_server(request, tmp_path_factory):
    ports = {
        "http": allocate_free_port(),
        "grpc": allocate_free_port(),
        "quic": allocate_free_port(),
        "internal": allocate_free_port(),
    }
    server_root, server_env = generate_server_config(request, tmp_path_factory, ports)
    config_path = server_root / "lore-server" / "config" / "gha.toml"
    with config_path.open("a", encoding="utf-8") as config:
        config.write(
            AUTH_CONFIG_TEMPLATE.format(
                signing_key_path=(server_root / "signing-key.pem").as_posix(),
                http_port=ports["http"],
            )
        )
    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, request.getfixturevalue("lore_server_executable_path")
    )
    yield {
        "grpc": f"127.0.0.1:{ports['grpc']}",
        "http": f"http://localhost:{ports['http']}",
    }
    _kill_server_by_pid(server_proc.pid, server_log_path, label="refresh server")
    server_log_fd.close()


def login(server):
    client_state = "refresh-test"
    session_code, login_url = start_auth_session(server["grpc"], client_state)
    state = login_url.split("state=")[1]
    status, _ = http_get(
        f"{server['http']}/auth/callback?state={state}&user=alice&secret=alice-secret"
    )
    assert status == 200
    token = get_auth_session(server["grpc"], session_code, client_state)
    assert token is not None
    return token


def test_refresh_keeps_session_alive_past_token_expiry(refresh_server):
    token = login(refresh_server)
    assert token.refresh_token, "login should issue a refresh token"

    # Register a resource while the user token is fresh.
    rebac_create_resource(
        refresh_server["grpc"], token.user_token, PROJECT, "project"
    )

    # Let the 2-second user token expire. (Server-side JWT validation
    # applies the standard 60s clock-skew leeway, so the old token is not
    # asserted rejected here; the point is that refresh keeps working.)
    time.sleep(3)

    # A refresh yields a working user token plus a rotated refresh token.
    refreshed = refresh_auth_session(refresh_server["grpc"], token.refresh_token)
    assert refreshed.user_id == "static:alice"
    assert refreshed.refresh_token
    assert refreshed.refresh_token != token.refresh_token
    exchange_for_resources(refresh_server["grpc"], refreshed.user_token, [PROJECT])


def test_refresh_reuse_revokes_the_family(refresh_server):
    token = login(refresh_server)
    first = refresh_auth_session(refresh_server["grpc"], token.refresh_token)

    # Replaying the original (rotated) refresh token is reuse...
    with pytest.raises(grpc.RpcError) as error:
        refresh_auth_session(refresh_server["grpc"], token.refresh_token)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED

    # ...which also kills the successor.
    with pytest.raises(grpc.RpcError) as error:
        refresh_auth_session(refresh_server["grpc"], first.refresh_token)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_garbage_refresh_token_is_refused(refresh_server):
    with pytest.raises(grpc.RpcError) as error:
        refresh_auth_session(refresh_server["grpc"], "never-issued")
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED
