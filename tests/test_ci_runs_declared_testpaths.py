"""CI must run every path pytest.ini declares.

A positional path argument on the pytest command line replaces ``testpaths``
rather than adding to it, so ``pytest tests/`` silently drops anything else the
config declares. These tests keep the workflow and the config in agreement.
"""

import ast
import configparser
import io
import re
import shlex

CI_WORKFLOW = ".github/workflows/ci.yml"
PYTEST_INI = "pytest.ini"

_FLAGS_TAKING_A_VALUE = {"-k", "-m", "-p", "-n", "-c", "-o", "--rootdir", "--junitxml"}


def _declared_testpaths():
    parser = configparser.ConfigParser()
    parser.read(PYTEST_INI, encoding="utf-8")
    raw = parser.get("pytest", "testpaths", fallback="")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _pytest_invocations(text):
    """Yield (line, positional arguments) for each pytest command in the text."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not re.search(r"\bpytest\b", stripped):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        if "pytest" not in tokens:
            continue
        rest = tokens[tokens.index("pytest") + 1:]
        positional, skip_next = [], False
        for token in rest:
            if skip_next:
                skip_next = False
                continue
            if token in _FLAGS_TAKING_A_VALUE:
                skip_next = True
                continue
            if token.startswith("-"):
                continue
            positional.append(token)
        yield stripped, positional


def test_declared_testpaths_all_exist():
    """A path in testpaths that does not exist collects nothing, silently."""
    import os

    missing = [path for path in _declared_testpaths() if not os.path.exists(path)]

    assert not missing, f"pytest.ini declares paths that do not exist: {missing}"


def test_ci_does_not_narrow_the_declared_testpaths():
    text = io.open(CI_WORKFLOW, encoding="utf-8").read()
    declared = _declared_testpaths()
    narrowing = [
        (line, positional)
        for line, positional in _pytest_invocations(text)
        if positional and sorted(positional) != sorted(declared)
    ]

    assert not narrowing, (
        "These CI pytest commands pass a positional path, which replaces the "
        f"testpaths in pytest.ini ({declared}) instead of adding to it, so part "
        f"of the declared suite never runs: {narrowing}. Drop the path argument "
        "and let the config decide."
    )


def test_every_declared_testpath_file_carries_tests():
    """A declared file with no test functions would make the check vacuous."""
    empty = []
    for path in _declared_testpaths():
        if not path.endswith(".py"):
            continue
        tree = ast.parse(io.open(path, encoding="utf-8").read())
        functions = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        ]
        if not functions:
            empty.append(path)

    assert not empty, f"testpaths declares files with no test functions: {empty}"
