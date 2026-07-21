# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Smoke tests for per-repository access control (deny-by-default).

Runs a dedicated loreserver with server-local auth (static provider) and
three users: alice and bob (regular) plus root (a configured server admin).
Drives the access model over the auth service's gRPC surface: token
exchange embeds granted roles, ungranted repositories are denied, resource
registration grants the creator admin, and deletion requires admin.
"""

import base64
import json

import grpc
import pytest
from grpc_auth import (
    check_user_permission,
    exchange_for_resources,
    get_auth_session,
    lookup_user_permissions,
    rebac_create_resource,
    rebac_delete_resource,
    start_auth_session,
)
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from test_auth_login import http_get

pytestmark = pytest.mark.xdist_group("access_server")

PROJECT1 = "urc-0194b726b34e72b0b45550b88a967076"
PROJECT2 = "urc-f6ca55437aa34198ba0f0fdc33154d51"

AUTH_CONFIG_TEMPLATE = """

# Appended by test_access_control.py: server-local auth + access control.
[environment.endpoint]
auth_url = "ucs-auth://localhost:{grpc_port}"

[server.auth]
server_admins = ["root@example.com"]

[server.auth.token]
generate_signing_key = true
signing_key_path = "{signing_key_path}"
issuer = "http://localhost"
audience = ["localhost"]

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

[[server.auth.provider.static.users]]
user = "bob"
secret = "bob-secret"
name = "Bob"
email = "bob@example.com"

[[server.auth.provider.static.users]]
user = "root"
secret = "root-secret"
name = "Root"
email = "root@example.com"
"""


@pytest.fixture(scope="module")
def access_server(request, tmp_path_factory):
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
    _kill_server_by_pid(server_proc.pid, server_log_path, label="access server")
    server_log_fd.close()


def login(server, user: str, secret: str) -> str:
    """Complete the browser flow for a static user; returns the user token."""
    client_state = f"access-test-{user}"
    session_code, login_url = start_auth_session(server["grpc"], client_state)
    state = login_url.split("state=")[1]
    status, _ = http_get(
        f"{server['http']}/auth/callback?state={state}&user={user}&secret={secret}"
    )
    assert status == 200
    token = get_auth_session(server["grpc"], session_code, client_state)
    assert token is not None
    return token.user_token


@pytest.fixture(scope="module")
def tokens(access_server):
    return {
        "alice": login(access_server, "alice", "alice-secret"),
        "bob": login(access_server, "bob", "bob-secret"),
        "root": login(access_server, "root", "root-secret"),
    }


def decode_jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def test_exchange_denied_without_grant(access_server, tokens):
    with pytest.raises(grpc.RpcError) as error:
        exchange_for_resources(access_server["grpc"], tokens["alice"], [PROJECT1])
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED


def test_creator_grant_scopes_access(access_server, tokens):
    # Registering the resource (what RepositoryCreate does) grants the
    # creator the admin role.
    rebac_create_resource(access_server["grpc"], tokens["alice"], PROJECT1, "project1")

    authz = exchange_for_resources(access_server["grpc"], tokens["alice"], [PROJECT1])
    claims = decode_jwt_claims(authz.user_token)
    resources = {r["resource_id"]: r["permission"] for r in claims["resources"]}
    assert "admin" in resources[PROJECT1]
    assert "read" in resources[PROJECT1]

    # alice can see project1 but not project2.
    with pytest.raises(grpc.RpcError) as error:
        exchange_for_resources(access_server["grpc"], tokens["alice"], [PROJECT2])
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED

    # bob can't see project1 unless somebody adds him.
    with pytest.raises(grpc.RpcError) as error:
        exchange_for_resources(access_server["grpc"], tokens["bob"], [PROJECT1])
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED

    allowed, denied = check_user_permission(
        access_server["grpc"], tokens["bob"], [PROJECT1, PROJECT2]
    )
    assert allowed == {}
    assert set(denied) == {PROJECT1, PROJECT2}


def test_server_admin_sees_everything(access_server, tokens):
    rebac_create_resource(access_server["grpc"], tokens["alice"], PROJECT1, "project1")

    authz = exchange_for_resources(access_server["grpc"], tokens["root"], [PROJECT1])
    claims = decode_jwt_claims(authz.user_token)
    resources = {r["resource_id"]: r["permission"] for r in claims["resources"]}
    assert "admin" in resources[PROJECT1]

    # Even for repositories nobody registered.
    authz = exchange_for_resources(access_server["grpc"], tokens["root"], [PROJECT2])
    claims = decode_jwt_claims(authz.user_token)
    assert claims["resources"][0]["resource_id"] == PROJECT2


def test_delete_requires_admin(access_server, tokens):
    rebac_create_resource(access_server["grpc"], tokens["alice"], PROJECT1, "project1")

    # bob has no role: refused.
    with pytest.raises(grpc.RpcError) as error:
        rebac_delete_resource(access_server["grpc"], tokens["bob"], PROJECT1)
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED

    # alice is admin: allowed, and afterwards her access is gone.
    rebac_delete_resource(access_server["grpc"], tokens["alice"], PROJECT1)
    # Grant reads are cached briefly; retry until the revocation lands.
    import time

    for _ in range(20):
        try:
            exchange_for_resources(access_server["grpc"], tokens["alice"], [PROJECT1])
        except grpc.RpcError as error:
            assert error.code() == grpc.StatusCode.PERMISSION_DENIED
            break
        time.sleep(0.5)
    else:
        pytest.fail("alice retained access after resource deletion")


def test_wildcard_resources_never_granted(access_server, tokens):
    for resource in ("urc-*", "custom-resource", "urc-nothex"):
        with pytest.raises(grpc.RpcError) as error:
            exchange_for_resources(access_server["grpc"], tokens["alice"], [resource])
        assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED


def test_lookup_lists_only_real_granted_repositories(access_server, tokens):
    # PROJECT1/PROJECT2 are auth resources without actual repository
    # records, so an authorized-repository lookup (which walks the
    # repository list) yields nothing for alice...
    assert lookup_user_permissions(access_server["grpc"], tokens["alice"]) == {}
    # ...and nothing for the server admin either, for the same reason.
    assert lookup_user_permissions(access_server["grpc"], tokens["root"]) == {}


def lore_cli(lore_executable_path, auth_dir, *args):
    """Run the lore CLI with an isolated auth store."""
    import os
    import subprocess

    return subprocess.run(
        [lore_executable_path, *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "LORE_AUTH_PATH": str(auth_dir),
            "LORE_AUTH_STORE": "fallback",
        },
    )


def test_cli_grant_revoke_list(
    access_server, tokens, lore_executable_path, tmp_path_factory
):
    remote = f"grpc://localhost:{access_server['grpc'].split(':')[1]}"
    auth_url = f"ucs-auth://localhost:{access_server['grpc'].split(':')[1]}"
    repo_id = PROJECT1.removeprefix("urc-")

    # alice becomes admin of the repository and logs the CLI in.
    rebac_create_resource(access_server["grpc"], tokens["alice"], PROJECT1, "project1")
    alice_dir = tmp_path_factory.mktemp("alice-auth")
    login = lore_cli(
        lore_executable_path,
        alice_dir,
        "auth",
        "login",
        "--token-type",
        "lore",
        "--token",
        tokens["alice"],
        "--auth-url",
        auth_url,
    )
    assert login.returncode == 0, login.stderr

    # Grant bob read access via the CLI.
    grant = lore_cli(
        lore_executable_path,
        alice_dir,
        "access",
        "grant",
        "static:bob",
        "read",
        repo_id,
        "--remote-url",
        remote,
    )
    assert grant.returncode == 0, grant.stderr + grant.stdout

    # bob can now exchange for the repository (read-only verbs).
    authz = exchange_for_resources(access_server["grpc"], tokens["bob"], [PROJECT1])
    claims = decode_jwt_claims(authz.user_token)
    assert claims["resources"][0]["permission"] == ["read"]

    # The listing shows both grants.
    listing = lore_cli(
        lore_executable_path,
        alice_dir,
        "access",
        "list",
        repo_id,
        "--remote-url",
        remote,
        "--json",
    )
    assert listing.returncode == 0, listing.stderr + listing.stdout
    grants = {
        entry["principal"]: entry["role"] for entry in json.loads(listing.stdout)
    }
    assert grants["static:bob"] == "read"
    assert grants["static:alice"] == "admin"

    # bob (read role) may not grant.
    bob_dir = tmp_path_factory.mktemp("bob-auth")
    login = lore_cli(
        lore_executable_path,
        bob_dir,
        "auth",
        "login",
        "--token-type",
        "lore",
        "--token",
        tokens["bob"],
        "--auth-url",
        auth_url,
    )
    assert login.returncode == 0, login.stderr
    denied = lore_cli(
        lore_executable_path,
        bob_dir,
        "access",
        "grant",
        "static:mallory",
        "admin",
        repo_id,
        "--remote-url",
        remote,
    )
    assert denied.returncode != 0

    # Revoke bob; a second revoke reports no grant.
    revoke = lore_cli(
        lore_executable_path,
        alice_dir,
        "access",
        "revoke",
        "static:bob",
        repo_id,
        "--remote-url",
        remote,
    )
    assert revoke.returncode == 0, revoke.stderr + revoke.stdout
    assert "Revoked" in revoke.stdout
    again = lore_cli(
        lore_executable_path,
        alice_dir,
        "access",
        "revoke",
        "static:bob",
        repo_id,
        "--remote-url",
        remote,
    )
    assert again.returncode == 0
    assert "No grant existed" in again.stdout
