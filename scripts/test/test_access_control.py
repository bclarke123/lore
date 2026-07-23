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
auth_url = "ucs-auth-insecure://localhost:{grpc_port}"

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
        # gRPC (TCP) and QUIC (UDP) share a port number, like production:
        # `lore://host:port` reaches the environment endpoint over gRPC on
        # the same port the QUIC data plane listens on.
        "grpc": (shared := allocate_free_port()),
        "quic": shared,
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
        "quic": str(ports["quic"]),
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
    auth_url = f"ucs-auth-insecure://localhost:{access_server['grpc'].split(':')[1]}"
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


# --- Public repositories (the `*` grant + anonymous reads) ---------------

PROJECT3 = "urc-54006a8ca619475881f7083d625a7947"

_BRANCH_LIST = "/urc.rpc.RevisionService/BranchList"
_BRANCH_PUSH = "/urc.rpc.RevisionService/BranchPush"


def _tokenless_call(server, method: str, resource: str) -> grpc.StatusCode:
    """Invoke a data-plane method with no credentials, returning the status
    code (OK when the call succeeds past auth)."""
    repo_hex = resource.removeprefix("urc-")
    with grpc.insecure_channel(server["grpc"]) as channel:
        callable_ = channel.unary_unary(
            method,
            request_serializer=lambda payload: payload,
            response_deserializer=lambda payload: payload,
        )
        try:
            callable_(
                b"", metadata=[("urc-repository-id-bin", bytes.fromhex(repo_hex))]
            )
        except grpc.RpcError as error:
            return error.code()
    return grpc.StatusCode.OK


def test_public_grant_allows_anonymous_reads(
    access_server, tokens, lore_executable_path, tmp_path_factory
):
    remote = f"grpc://localhost:{access_server['grpc'].split(':')[1]}"
    auth_url = f"ucs-auth-insecure://localhost:{access_server['grpc'].split(':')[1]}"
    repo_id = PROJECT3.removeprefix("urc-")

    # alice registers the repository and logs the CLI in.
    rebac_create_resource(access_server["grpc"], tokens["alice"], PROJECT3, "project3")
    alice_dir = tmp_path_factory.mktemp("alice-public-auth")
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

    # Private: anonymous data-plane reads are rejected at the interceptor,
    # and bob cannot exchange.
    assert (
        _tokenless_call(access_server, _BRANCH_LIST, PROJECT3)
        == grpc.StatusCode.UNAUTHENTICATED
    )
    with pytest.raises(grpc.RpcError):
        exchange_for_resources(access_server["grpc"], tokens["bob"], [PROJECT3])

    # The public principal only accepts the read role.
    for role in ("write", "admin"):
        denied = lore_cli(
            lore_executable_path,
            alice_dir,
            "access",
            "grant",
            "*",
            role,
            repo_id,
            "--remote-url",
            remote,
        )
        assert denied.returncode != 0, f"public {role} grant should be refused"

    # Make it public.
    grant = lore_cli(
        lore_executable_path,
        alice_dir,
        "access",
        "grant",
        "*",
        "read",
        repo_id,
        "--remote-url",
        remote,
    )
    assert grant.returncode == 0, grant.stderr + grant.stdout

    # Any authenticated user may now exchange, with read-only verbs.
    authz = exchange_for_resources(access_server["grpc"], tokens["bob"], [PROJECT3])
    claims = decode_jwt_claims(authz.user_token)
    assert claims["resources"][0]["permission"] == ["read"]

    # Anonymous reads pass auth (the call fails later or not at all, but
    # is no longer rejected as unauthenticated)...
    assert _tokenless_call(access_server, _BRANCH_LIST, PROJECT3) not in (
        grpc.StatusCode.UNAUTHENTICATED,
        grpc.StatusCode.PERMISSION_DENIED,
    )
    # ...while anonymous writes stay rejected: mutating methods are not on
    # the anonymous allowlist.
    assert (
        _tokenless_call(access_server, _BRANCH_PUSH, PROJECT3)
        == grpc.StatusCode.UNAUTHENTICATED
    )

    # The listing shows the public grant.
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
    grants = {entry["principal"]: entry["role"] for entry in json.loads(listing.stdout)}
    assert grants["*"] == "read"

    # Revoking `*` restores deny-by-default for bob and anonymous callers.
    revoke = lore_cli(
        lore_executable_path,
        alice_dir,
        "access",
        "revoke",
        "*",
        repo_id,
        "--remote-url",
        remote,
    )
    assert revoke.returncode == 0, revoke.stderr + revoke.stdout
    with pytest.raises(grpc.RpcError) as error:
        exchange_for_resources(access_server["grpc"], tokens["bob"], [PROJECT3])
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED
    assert (
        _tokenless_call(access_server, _BRANCH_LIST, PROJECT3)
        == grpc.StatusCode.UNAUTHENTICATED
    )


def test_anonymous_clone_of_public_repo(
    access_server, tokens, lore_executable_path, tmp_path_factory
):
    """End-to-end: a client that has NEVER logged in can clone a public
    repository, and loses access when the public grant is revoked."""
    from lore import Lore

    grpc_port = access_server["grpc"].split(":")[1]
    remote = f"grpc://localhost:{grpc_port}/"
    remote_flag = f"grpc://localhost:{grpc_port}"
    auth_url = f"ucs-auth-insecure://localhost:{grpc_port}"

    # root (server admin) logs in and publishes a repository with content.
    root_global = str(tmp_path_factory.mktemp("root-global"))
    login = lore_cli(
        lore_executable_path,
        root_global,
        "auth",
        "login",
        "--token-type",
        "lore",
        "--token",
        tokens["root"],
        "--auth-url",
        auth_url,
    )
    assert login.returncode == 0, login.stderr

    src = Lore(
        lore_executable_path=lore_executable_path,
        path=str(tmp_path_factory.mktemp("public-src") / "pubclone"),
        name="pubclone",
        global_dir=root_global,
        environment_vars={"LORE_AUTH_STORE": "fallback"},
        remote_url=remote,
    )
    with src.open_file("hello.txt", "w+") as f:
        f.write("public content\n")
    src.stage(scan=True, offline=True)
    src.commit("Public seed", offline=True)
    src.push()

    grant = lore_cli(
        lore_executable_path,
        root_global,
        "access",
        "grant",
        "*",
        "read",
        "pubclone",
        "--remote-url",
        remote_flag,
    )
    assert grant.returncode == 0, grant.stderr + grant.stdout

    # A brand-new client with an empty auth store clones anonymously.
    anon_global = str(tmp_path_factory.mktemp("anon-global"))
    anon_seed = Lore(
        lore_executable_path=lore_executable_path,
        path=str(tmp_path_factory.mktemp("anon-work") / "seed"),
        name="pubclone",
        global_dir=anon_global,
        environment_vars={"LORE_AUTH_STORE": "fallback"},
        remote_url=remote,
        remote_path=remote + "pubclone",
        create_repo=False,
    )
    cloned = anon_seed.clone(name="anon-clone")
    import os

    assert os.path.isfile(os.path.join(cloned.path, "hello.txt")), (
        "anonymous clone should materialize public content"
    )

    # The same clone over the stock `lore://` scheme (QUIC transport) —
    # the flow a user gets from `lore clone lore://host/repo` with no login.
    quic_remote = f"lore://localhost:{access_server['quic']}/"
    anon_quic = Lore(
        lore_executable_path=lore_executable_path,
        path=str(tmp_path_factory.mktemp("anon-quic") / "seed"),
        name="pubclone",
        global_dir=anon_global,
        environment_vars={"LORE_AUTH_STORE": "fallback"},
        remote_url=quic_remote,
        remote_path=quic_remote + "pubclone",
        create_repo=False,
    )
    quic_cloned = anon_quic.clone(name="anon-quic-clone")
    assert os.path.isfile(os.path.join(quic_cloned.path, "hello.txt")), (
        "anonymous lore:// (QUIC) clone should materialize public content"
    )

    # Revoke the public grant: anonymous access is gone again.
    revoke = lore_cli(
        lore_executable_path,
        root_global,
        "access",
        "revoke",
        "*",
        "pubclone",
        "--remote-url",
        remote_flag,
    )
    assert revoke.returncode == 0, revoke.stderr + revoke.stdout
    denied = anon_seed.clone(name="anon-clone-denied", check=False)
    result = denied.last_output if hasattr(denied, "last_output") else None
    # The clone command must fail; probe by checking no content arrived.
    assert not os.path.isfile(os.path.join(denied.path, "hello.txt")), (
        f"clone of a private repo without credentials must fail: {result}"
    )
