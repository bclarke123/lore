# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
import logging
import random
import string
from collections.abc import Callable

import pytest
from error_types import BisectDivergentRevisions, NotFound
from service_util import LORE_SERVICE_ENVIRONMENT

from lore import (
    Lore,
)

logger = logging.getLogger(__name__)

# Longer than a test may run, so a command that waits on the store the service
# holds fails the test rather than completing once the service lets go.
HOLD_STORE_SECONDS = 3600


@pytest.mark.smoke
def test_bisect(new_lore_repo):
    rnd = random.Random()

    seed = 3819
    rnd.seed(seed)

    logger.debug(f'Using random seed "{seed}" for bisect test')

    repo: Lore = new_lore_repo()

    def stage_commit_push(repo: Lore, message: str | None = None):
        repo.stage(scan=True)
        repo.commit(message, local=True)
        repo.push()

    def create_branch(repo: Lore, name: str | None = None) -> str:
        if name is None:
            name = "branch_" + random_string()
        repo.branch_create(name)
        return name

    def merge_back_to_main(repo: Lore, target_branch: str):
        repo.branch_switch("main")
        repo.branch_merge(target_branch)
        repo.push()

    def random_string():
        return "".join(
            rnd.choice(string.ascii_uppercase + string.digits) for _ in range(12)
        )

    def random_file_name(name: str | None = None):
        if name is None:
            name = "file_"
        return name + random_string()

    def create_file(
        repo: Lore,
        file_list: list[str],
        name: str | None = None,
        contents: str | None = None,
    ):
        if name is None:
            name = random_file_name()
        if contents is None:
            contents = random_string()
        file_list.append(name)
        with repo.open_file(name, "w+") as output_file:
            output_file.writelines(contents)

    def append_file(repo: Lore, name: str, contents: str | None = None):
        if contents is None:
            contents = random_string()
        with repo.open_file(name, "a+") as output_file:
            output_file.writelines(contents)

    files = []

    # Create some files
    for _ in range(5):
        create_file(repo, files)

    stage_commit_push(repo)

    # Get actions and weights to take random actions for creating branches
    actions: list[Callable[[], None]] = [
        lambda: create_file(repo, files),
        lambda: append_file(repo, rnd.choice(files)),
    ]
    weights = [10, 90]

    # Create some random branches with some random changes and merge them back into main
    for _ in range(3):
        # Randomly add in some commits to main before a branch
        main_commit_count = rnd.choices([0, rnd.randint(1, 3)], [75, 25])[0]
        main_actions = rnd.choices(actions, weights, k=main_commit_count)
        for main_action in main_actions:
            main_action()
            stage_commit_push(repo)

        branch_name = create_branch(repo)
        branch_actions = rnd.choices(actions, weights, k=rnd.randint(1, 3))
        for branch_action in branch_actions:
            branch_action()
            stage_commit_push(repo)
        merge_back_to_main(repo, branch_name)

    # Clone repository
    cloned_repo = repo.clone()

    log_output = cloned_repo.history(oneline=True)
    trunk_revisions = [int(line.revision) for line in log_output]
    logger.debug(trunk_revisions)

    # Use bisect to find a revision
    start_revision_index = rnd.randint(0, int(len(trunk_revisions) / 4))
    end_revision_index = rnd.randint(start_revision_index + 1, len(trunk_revisions) - 1)
    goal_revision_index = rnd.randint(start_revision_index + 1, end_revision_index)

    start_revision = trunk_revisions[start_revision_index]
    end_revision = trunk_revisions[end_revision_index]
    goal_revision = trunk_revisions[goal_revision_index]

    original_start_revision = start_revision
    original_end_revision = end_revision

    for _ in range(end_revision - start_revision):
        result = cloned_repo.revision_bisect(f"@{start_revision}", f"@{end_revision}")

        if result.is_done:
            assert result.current_revision == goal_revision, (
                f"Completed bisect, but not at goal revision. Current: {result.current_revision}, goal: {goal_revision}"
            )
            break

        if result.current_revision >= goal_revision:
            next_path = result.left
        else:
            next_path = result.right
        assert next_path is not None
        (start_revision, end_revision) = (next_path.start, next_path.end)

    # Rerun with reversed inputs
    with pytest.raises(BisectDivergentRevisions):
        cloned_repo.revision_bisect(
            f"@{original_end_revision}", f"@{original_start_revision}"
        )

    # Divergent revisions
    divergent_revisions = [
        rev for rev in range(trunk_revisions[-1]) if rev not in trunk_revisions
    ]
    with pytest.raises(NotFound):
        cloned_repo.revision_bisect("@1", f"@{rnd.choice(divergent_revisions)}")
    with pytest.raises(NotFound):
        cloned_repo.revision_bisect(
            f"@{rnd.choice(divergent_revisions)}", f"@{trunk_revisions[-1]}"
        )


@pytest.mark.smoke
def test_bisect_while_the_service_holds_the_store(
    new_lore_repo, background_lore_service, lore_library_path
):
    """The bisect step through the C API leaves the service holding the local
    store, as a service serving a mounted instance does, so the step through the
    CLI completes only when it is relayed to the service as well."""
    repo: Lore = new_lore_repo(environment_vars=LORE_SERVICE_ENVIRONMENT.copy())
    for i in range(4):
        repo.write_commit_push(None, {"bisected.txt": str(i)})
    revisions = [int(line.revision) for line in repo.history(oneline=True)]
    first, last = min(revisions), max(revisions)

    assert (
        repo.revision_bisect_capi(
            lore_library_path, f"@{first}", f"@{last}", HOLD_STORE_SECONDS
        )
        == 0
    ), "a bisect step through the C API with the service in use succeeds"
    result = repo.revision_bisect(f"@{first}", f"@{last}")
    assert first < result.current_revision < last

    # A graceful stop waits for the service to let go of the store.
    background_lore_service.kill()
    background_lore_service.wait()
