# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
import logging
import os
import re

import pytest

from error_types import InvalidRepositoryPath
from lore import Lore
from lore_parsers import parse_jsonl
from service_util import LORE_SERVICE_ENVIRONMENT

logger = logging.getLogger(__name__)


def get_url(repository_info_output: str) -> str | None:
    match = re.search(".*Remote URL: (.*)", repository_info_output)
    if match is not None:
        return match.group(1)
    return None


def get_instance_id(repository_info_output: str) -> str | None:
    match = re.search(".*Instance: (.*)", repository_info_output)
    if match is not None:
        return match.group(1)
    return None


@pytest.mark.smoke
def test_repository_info_url(new_lore_repo, tmp_path_factory, monkeypatch):
    no_repo_urc: Lore = new_lore_repo(create_repo=False)

    repo = new_lore_repo()

    monkeypatch.chdir(repo.path)

    assert get_url(no_repo_urc.repository_info(use_os_dir=True)) + "/" == repo.remote

    assert get_url(no_repo_urc.repository_info(path=repo.path)) + "/" == repo.remote
    with pytest.raises(InvalidRepositoryPath):
        assert no_repo_urc.repository_info()
    assert (
        get_url(no_repo_urc.repository_info(url=repo.remote_path)) + "/" == repo.remote
    )


@pytest.mark.smoke
@pytest.mark.parametrize("local", [False, True], ids=["remote", "local"])
def test_repository_info_resolves_a_relative_repository_against_the_caller(
    new_lore_repo, lore_service_runner, tmp_path, local
):
    """The service runs in a directory unrelated to the caller's, so it must
    resolve a relative `--repository` where the caller ran, whether the
    information comes from the remote or from the local stores."""
    service_directory = tmp_path / "service_elsewhere"
    service_directory.mkdir()
    lore_service_runner.start(str(service_directory))

    repo: Lore = new_lore_repo(environment_vars=LORE_SERVICE_ENVIRONMENT.copy())

    output = repo.repository_info(
        path=os.path.basename(repo.path), cwd=os.path.dirname(repo.path), local=local
    )
    assert repo.get_id() in output, f"the info must describe the repository: {output}"


@pytest.mark.smoke
def test_repository_create_description(new_lore_repo):
    """repository create --description stores the description and
    repository info returns it in the repositoryData event."""

    description_text = "Automated test repository for description flag"
    repo: Lore = new_lore_repo(create_repo=False)
    repo.repository_create(description=description_text)

    # Plain text output should contain the description
    output = repo.repository_info()
    assert description_text in output

    # JSON output should contain the description in repositoryData event
    json_output = repo.repository_info(json=True)
    events = parse_jsonl(json_output, "repositoryData")
    assert len(events) == 1
    assert events[0]["description"] == description_text


@pytest.mark.smoke
def test_repository_create_no_description(new_lore_repo):
    """repository create without --description should result in an empty
    description field in repositoryData."""

    repo: Lore = new_lore_repo()

    json_output = repo.repository_info(json=True)
    events = parse_jsonl(json_output, "repositoryData")
    assert len(events) == 1
    assert events[0]["description"] == ""
