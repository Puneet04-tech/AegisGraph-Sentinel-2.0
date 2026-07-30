"""Endpoints written in the documentation must exist as documented.

The docs list endpoints as `METHOD /path` lines. Nothing checked them against
the application, so a route that moved left a stale line behind, and a reader
following it gets a 404 or a 405 rather than an answer.
"""

import io
import pathlib
import re

import pytest
from fastapi.routing import APIRoute

from src.api.main import app

DOC_FILES = sorted(pathlib.Path("docs").rglob("*.md")) + [pathlib.Path("README.md")]

_DOC_LINE = re.compile(r"^\s*(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_\-/{}]*)", re.M)

# Registered only when debug honeypot routes are enabled, which is refused in
# production. The docs label it as debug, so it is documented accurately. Any
# addition here should name why the route is absent from a default app.
CONDITIONALLY_REGISTERED = {"/debug/activate_honeypot"}


def _route_table():
    table = {}
    for route in app.routes:
        if isinstance(route, APIRoute):
            table.setdefault(route.path, set()).update(route.methods - {"HEAD", "OPTIONS"})
    return table


def _documented_lines():
    for path in DOC_FILES:
        if not path.exists():
            continue
        text = io.open(path, encoding="utf-8", errors="replace").read()
        for match in _DOC_LINE.finditer(text):
            line_number = text[: match.start()].count("\n") + 1
            yield str(path), line_number, match.group(1), match.group(2)


def test_documentation_lists_at_least_one_endpoint():
    """A regex that matched nothing would make the check below vacuous."""
    assert list(_documented_lines()), "no METHOD /path lines were found in the docs"


def test_every_documented_endpoint_exists_with_the_documented_method():
    table = _route_table()
    broken = []

    for source, line_number, method, documented in _documented_lines():
        path = re.sub(r"\{[^}]*\}", "X", documented.rstrip("/")) or "/"
        if documented in CONDITIONALLY_REGISTERED:
            continue
        matched = [
            (registered, methods)
            for registered, methods in table.items()
            if re.fullmatch(re.sub(r"\{[^}]+\}", "X", registered.rstrip("/")) or "/", path)
        ]
        if not matched:
            broken.append((source, line_number, method, documented, "no such path"))
        elif not any(method in methods for _, methods in matched):
            allowed = sorted({m for _, methods in matched for m in methods})
            broken.append(
                (source, line_number, method, documented, f"registered as {allowed}")
            )

    assert not broken, (
        "The documentation lists endpoints the application does not serve as "
        f"described: {broken}. Following any of these returns 404 or 405."
    )


@pytest.mark.parametrize("path", sorted(CONDITIONALLY_REGISTERED))
def test_conditionally_registered_exemptions_are_still_absent(path):
    """An exemption for a route that is now always present hides a real check."""
    assert path not in _route_table(), (
        f"{path} is registered by default now, so it no longer needs an "
        "exemption in CONDITIONALLY_REGISTERED"
    )
