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


def test_refresh_replay_within_grace_converges(refresh_server):
    token = login(refresh_server)
    first = refresh_auth_session(refresh_server["grpc"], token.refresh_token)

    # Replaying the rotated token inside the reuse grace window is a racing
    # legitimate client (several processes share one credential store): it
    # idempotently receives the same successor instead of an error, so every
    # process converges on one token.
    replayed = refresh_auth_session(refresh_server["grpc"], token.refresh_token)
    assert replayed.refresh_token == first.refresh_token

    # The family is intact: the successor still redeems.
    second = refresh_auth_session(refresh_server["grpc"], first.refresh_token)
    assert second.refresh_token != first.refresh_token
    # Replay *past* the grace window revokes the whole family; that branch is
    # covered by the refresh store's unit tests, which zero the grace window
    # (`with_reuse_grace_ms(0)` in lore-server/src/auth/refresh.rs).


def test_garbage_refresh_token_is_refused(refresh_server):
    with pytest.raises(grpc.RpcError) as error:
        refresh_auth_session(refresh_server["grpc"], "never-issued")
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


# --- Client-side refresh on the exchange path (regression) ----------------
#
# A working copy with a configured identity goes through
# `lore-transport::auth::exchange::exchange()`, which historically sent the
# stored (expired) authn token without attempting a refresh — surfacing
# "invalid token: JWT validation failed" on push. This drives the real CLI
# through login → push → token expiry → push.

CLI_CONFIG_TEMPLATE = """

# Appended by test_auth_refresh.py (client-refresh fixture).
[environment.endpoint]
auth_url = "ucs-auth-insecure://localhost:{grpc_port}"

[server.auth]
server_admins = ["root@example.com"]

[server.auth.token]
generate_signing_key = true
signing_key_path = "{signing_key_path}"
issuer = "http://localhost"
audience = ["localhost"]
user_token_ttl_seconds = 2
authz_token_ttl_seconds = 2
refresh_token_ttl_seconds = 3600

[server.auth.provider]
mode = "static"
callback_base_url = "http://localhost:{http_port}"

[server.auth.provider.static]
allow_insecure_dev_login = true

[[server.auth.provider.static.users]]
user = "root"
secret = "root-secret"
name = "Root"
email = "root@example.com"
"""


@pytest.fixture(scope="module")
def cli_refresh_server(request, tmp_path_factory):
    shared = allocate_free_port()
    ports = {
        "http": allocate_free_port(),
        "grpc": shared,
        "quic": shared,
        "internal": allocate_free_port(),
    }
    server_root, server_env = generate_server_config(request, tmp_path_factory, ports)
    config_path = server_root / "lore-server" / "config" / "gha.toml"
    with config_path.open("a", encoding="utf-8") as config:
        config.write(
            CLI_CONFIG_TEMPLATE.format(
                signing_key_path=(server_root / "signing-key.pem").as_posix(),
                http_port=ports["http"],
                grpc_port=ports["grpc"],
            )
        )
    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, request.getfixturevalue("lore_server_executable_path")
    )
    yield {
        "grpc": f"127.0.0.1:{ports['grpc']}",
        "http": f"http://localhost:{ports['http']}",
    }
    _kill_server_by_pid(server_proc.pid, server_log_path, label="cli refresh server")
    server_log_fd.close()


def interactive_cli_login(lore_executable_path, auth_dir, server):
    """Drive `lore auth login --no-browser`: parse the printed login URL,
    complete the static-provider callback, wait for the CLI to store the
    token + refresh token."""
    import os
    import re
    import subprocess
    import time as time_mod

    remote_url = f"grpc://localhost:{server['grpc'].split(':')[1]}"
    proc = subprocess.Popen(
        [lore_executable_path, "auth", "login", "--no-browser", remote_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "LORE_AUTH_PATH": str(auth_dir), "LORE_AUTH_STORE": "fallback"},
    )
    url = None
    deadline = time_mod.time() + 30
    output = []
    while time_mod.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        output.append(line)
        m = re.search(r"(http://\S*state=\S+)", line)
        if m:
            url = m.group(1).rstrip(".,)")
            break
    assert url, f"no login URL printed: {''.join(output)}"
    state = url.split("state=")[1].split("&")[0]
    status, _ = http_get(
        f"{server['http']}/auth/callback?state={state}&user=root&secret=root-secret"
    )
    assert status == 200
    assert proc.wait(timeout=30) == 0, proc.stdout.read()


def test_cli_refreshes_expired_token_on_push(
    cli_refresh_server, lore_executable_path, tmp_path_factory
):
    import time as time_mod

    from lore import Lore

    grpc_port = cli_refresh_server["grpc"].split(":")[1]
    remote = f"grpc://localhost:{grpc_port}/"
    auth_dir = tmp_path_factory.mktemp("cli-refresh-auth")
    interactive_cli_login(lore_executable_path, str(auth_dir), cli_refresh_server)

    src = Lore(
        lore_executable_path=lore_executable_path,
        path=str(tmp_path_factory.mktemp("cli-refresh-src") / "refreshrepo"),
        name="refreshrepo",
        global_dir=str(auth_dir),
        environment_vars={"LORE_AUTH_STORE": "fallback"},
        remote_url=remote,
    )
    with src.open_file("a.txt", "w+") as f:
        f.write("one\n")
    src.stage(scan=True, offline=True)
    src.commit("First", offline=True)
    src.push()

    # Outlive both the authn (2s) and authz (2s) TTLs, then push again: the
    # client must transparently redeem its refresh token instead of erroring
    # with "invalid token".
    time_mod.sleep(4)
    with src.open_file("a.txt", "w+") as f:
        f.write("two\n")
    src.stage(scan=True, offline=True)
    src.commit("Second", offline=True)
    src.push()
