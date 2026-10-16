# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
import logging

import pytest
from service_util import LORE_SERVICE_ENVIRONMENT

from lore import Lore

logger = logging.getLogger(__name__)

PUSH_COUNT = 3

# Longer than a test may run, so a command that waits on the store the service
# holds fails the test rather than completing once the service lets go.
HOLD_STORE_SECONDS = 3600


def push_revisions(repo: Lore):
    text_file = "text-File.txt"

    for i in range(PUSH_COUNT):
        with repo.open_file(text_file, "w+") as output_file:
            output_file.writelines(
                ["One line\n", "Another line\n", f"Third line\n {i}"]
            )

        repo.stage(scan=True)
        repo.commit()
        repo.push()


def listed_revisions(repo: Lore) -> list[str]:
    return [line for line in repo.branch_latest_list().split("\n") if line.strip()]


@pytest.mark.smoke
def test_latest_list(new_lore_repo):
    repo: Lore = new_lore_repo("LatestList")
    push_revisions(repo)

    hash_lines = listed_revisions(repo)

    assert len(hash_lines) == PUSH_COUNT, (
        f"Expected {PUSH_COUNT} revisions but got {len(hash_lines)}"
    )


@pytest.mark.smoke
def test_latest_list_while_the_service_holds_the_store(
    new_lore_repo, background_lore_service, lore_library_path
):
    """The listing through the C API leaves the service holding the local store,
    as a service serving a mounted instance does, so the listing through the CLI
    completes only when it is relayed to the service as well."""
    repo: Lore = new_lore_repo(environment_vars=LORE_SERVICE_ENVIRONMENT.copy())
    push_revisions(repo)

    assert repo.branch_latest_list_capi(lore_library_path, HOLD_STORE_SECONDS) == 0, (
        "a listing through the C API with the service in use succeeds"
    )
    assert len(listed_revisions(repo)) == PUSH_COUNT

    # A graceful stop waits for the service to let go of the store.
    background_lore_service.kill()
    background_lore_service.wait()
