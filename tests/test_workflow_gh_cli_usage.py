"""Workflow jobs that shell out to `gh` must be able to run it.

`gh` resolves the repository through git even when every call passes --repo, so
a job without a checkout exits 1 with "fatal: not a git repository". A workflow
that fails on every run is invisible: the automation simply never happens.
"""

import io
import pathlib
import re

import pytest
import yaml

WORKFLOWS = sorted(pathlib.Path(".github/workflows").glob("*.yml"))

_GH_CALL = re.compile(r"(?:^|\s|\$\()gh\s", re.M)
# jq compares across types without coercing, so a number is never equal to a
# string. An issue or PR number from the event payload arrives as a string.
_NUMERIC_ENV_COMPARISON = re.compile(
    r"\.(number|id)\s*[!=]=\s*env\.[A-Z_]+(?!\s*\|)"
)


def _jobs():
    for path in WORKFLOWS:
        document = yaml.safe_load(io.open(path, encoding="utf-8").read())
        for name, job in (document.get("jobs") or {}).items():
            yield path, name, job


def test_there_are_workflows_to_check():
    assert WORKFLOWS, "no workflow files were found"


def test_jobs_that_call_gh_check_out_the_repository():
    offenders = []
    for path, name, job in _jobs():
        steps = job.get("steps") or []
        calls_gh = any(_GH_CALL.search(str(step.get("run", ""))) for step in steps)
        if not calls_gh:
            continue
        checks_out = any("checkout" in str(step.get("uses", "")) for step in steps)
        if not checks_out:
            offenders.append((path.name, name))

    assert not offenders, (
        f"These jobs run the gh CLI without checking out the repository: "
        f"{offenders}. gh needs a git repository to resolve against and exits 1 "
        'with "fatal: not a git repository", so the job fails on every run.'
    )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_jq_filters_do_not_compare_a_number_to_an_env_string(path):
    """`.number != env.X` is always true, so such a filter excludes nothing."""
    text = io.open(path, encoding="utf-8").read()
    bad = _NUMERIC_ENV_COMPARISON.findall(text)
    matches = [
        match.group(0).strip()
        for match in _NUMERIC_ENV_COMPARISON.finditer(text)
    ]

    assert not bad, (
        f"{path.name} compares a JSON number against an environment string: "
        f"{matches}. jq never treats those as equal, so the filter matches "
        "everything. Coerce with `env.X | tonumber`."
    )
