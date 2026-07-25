"""Tracks which src/api route modules are mounted on the application.

Twelve route modules under src/api are not imported by src/api/main.py, so the
endpoints they define are unreachable. Issues #1495 and #1497 through #1508
tracked exactly these files and were closed as completed while the modules
stayed unmounted, which is possible because nothing failed when they did.

This suite pins the current state. Adding a route module without mounting it,
or mounting one, fails here with instructions, so the decision is recorded
rather than discovered later.
"""

import io
import pathlib
import re

import pytest

API_DIR = pathlib.Path(__file__).resolve().parent.parent / "src" / "api"
MAIN = API_DIR / "main.py"

# Route modules deliberately left unmounted. Entries should only be removed,
# either by mounting the module or by deleting it.
#
# Auth state at the time of writing, which matters because mounting one is a
# single line and three of them would serve unauthenticated traffic:
#   no per-route auth : compliance (14), defense (14), omega (7)
#   verify_api_key    : digital_twin (12), metaverse (15), nexus (11),
#                       research (10), simulation (9), supergraph (14)
#   require_role      : governance (15), knowledge (11)
#   empty stub        : sso (0 routes)
#
# compliance, defense and omega additionally fail to import. They use
# "from ..security import require_api_key", which resolves to src.security
# rather than src.api.security, so mounting one raises ImportError before it can
# serve anything. Those three are also the ones with no per-route auth, so the
# import should not be corrected without adding the missing dependencies.
KNOWN_UNMOUNTED = {
    "compliance_routes.py",
    "defense_routes.py",
    "digital_twin_routes.py",
    "governance_routes.py",
    "knowledge_routes.py",
    "metaverse_routes.py",
    "nexus_routes.py",
    "omega_routes.py",
    "research_routes.py",
    "simulation_routes.py",
    "sso_routes.py",
    "supergraph_routes.py",
}

# Two mounting styles are in use: importing the router directly, and importing a
# register_routes helper that calls include_router itself.
_IMPORT_ROUTER = re.compile(r"^from \.(\w+) import router", re.MULTILINE)
_IMPORT_REGISTER = re.compile(r"^from \.(\w+) import register_routes", re.MULTILINE)


def _route_modules():
    return sorted(p.name for p in API_DIR.glob("*_routes.py"))


def _mounted_modules():
    text = io.open(MAIN, encoding="utf-8").read()
    names = set(_IMPORT_ROUTER.findall(text)) | set(_IMPORT_REGISTER.findall(text))
    return {name + ".py" for name in names}


def test_route_modules_are_discovered():
    assert _route_modules(), "no *_routes.py modules found under src/api"


def test_every_route_module_is_mounted_or_listed():
    unmounted = set(_route_modules()) - _mounted_modules()

    unexpected = sorted(unmounted - KNOWN_UNMOUNTED)
    assert not unexpected, (
        "These route modules are not imported by src/api/main.py, so their "
        f"endpoints are unreachable: {unexpected}. Mount the module, or add it "
        "to KNOWN_UNMOUNTED with a note explaining why it stays unmounted."
    )


def test_known_unmounted_list_has_no_stale_entries():
    unmounted = set(_route_modules()) - _mounted_modules()

    stale = sorted(KNOWN_UNMOUNTED - unmounted)
    assert not stale, (
        f"These modules are listed as unmounted but are no longer: {stale}. "
        "Remove them from KNOWN_UNMOUNTED."
    )


@pytest.mark.parametrize("module", sorted(KNOWN_UNMOUNTED))
def test_unmounted_module_still_exists(module):
    """A listed module that was deleted should be removed from the list."""
    assert (API_DIR / module).exists(), (
        f"{module} is listed in KNOWN_UNMOUNTED but no longer exists. "
        "Remove the entry."
    )
