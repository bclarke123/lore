# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""An offline commit pushed onto a divergent remote must land completely.

Reproduces a report where machine B's `lore commit --offline` revision was
pushed after a `sync` with machine A's newer remote commit, the server
fast-forward merged it, and afterwards the offline commit's revision
metadata fragment was missing on the server (DynamoDB and S3) while its
data fragments were present. Machine A could then no longer sync.
"""

import os
import re

import pytest

from lore import Lore

PUSHED_REVISION = re.compile(r"Pushed revision \d+ -> ([0-9a-f]{64})")


def _remote_addresses_with_status(query: str, status: str) -> list[str]:
    """Addresses whose `(remote)` block in a store query reports `status`."""
    found = []
    current = None
    for line in query.splitlines():
        line = line.strip()
        if line.startswith("Address ") and line.endswith("(remote)"):
            current = line.split()[1]
        elif line.startswith("Address "):
            current = None
        elif current and line.startswith("Status:") and status in line:
            found.append(current)
    return found


def _write(repo: Lore, name: str) -> None:
    with repo.open_file(name, "w+b") as output_file:
        output_file.write(os.urandom(4096))


@pytest.mark.smoke
@pytest.mark.parametrize(
    "merge_on",
    ["client_sync", "server_fast_forward"],
    ids=["sync-then-push", "push-with-fast-forward-merge"],
)
def test_offline_commit_push_onto_divergent_remote(new_lore_repo, merge_on):
    # Machine A seeds the repository.
    machine_a: Lore = new_lore_repo()
    _write(machine_a, "a1.uasset")
    machine_a.stage(scan=True)
    machine_a.commit("A: first")
    machine_a.push()

    # Machine B clones, then commits offline.
    machine_b = machine_a.clone()
    _write(machine_b, "b1.uasset")
    machine_b.stage(scan=True, offline=True)
    machine_b.commit("B: offline", offline=True)

    # Meanwhile A pushes again, so the remote diverges from B's parent.
    _write(machine_a, "a2.uasset")
    machine_a.stage(scan=True)
    machine_a.commit("A: second")
    machine_a.push()

    # B lands its offline revision on the divergent remote either by syncing
    # first (client-side merge) or by asking the server to fast-forward merge
    # during the push.
    if merge_on == "client_sync":
        machine_b.sync()
        push_output = machine_b.push()
    else:
        push_output = machine_b.push(fast_forward_merge=True)
    match = PUSHED_REVISION.search(push_output)
    assert match, f"Push did not report a pushed revision: {push_output}"
    pushed = match.group(1)

    # Every fragment the pushed revision references must exist on the
    # remote — this is where the reported case showed the offline
    # commit's revision metadata as "Not found".
    query = machine_b.repository_store_immutable_query(pushed, recurse=True)
    remote_missing = _remote_addresses_with_status(query, "Not found")
    assert not remote_missing, (
        "Pushed revision references fragments missing on the remote:\n"
        + "\n".join(remote_missing)
    )

    # And the user-visible consequence: a fresh clone and A's sync both work
    # and see every commit.
    machine_c = machine_a.clone()
    for name in ("a1.uasset", "a2.uasset", "b1.uasset"):
        assert os.path.exists(os.path.join(machine_c.path, name)), name
    machine_a.sync()
    assert os.path.exists(os.path.join(machine_a.path, "b1.uasset"))
