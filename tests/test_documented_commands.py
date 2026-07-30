"""Commands the documentation tells a contributor to run must exist.

A `python -m` target that does not resolve, or that resolves to a module with
no entry point, fails at the first step of the documented setup.
"""

import ast
import io
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))

_RUN_MODULE = re.compile(r"python -m ([a-zA-Z_][\w\.]*)")

# Modules provided by the interpreter or an installed tool rather than this
# repository, so their presence is not evidence about the source tree.
EXTERNAL = {"venv", "pip", "uvicorn", "pytest", "streamlit", "build", "twine", "flake8"}

# Documented but not yet implemented. src/db/ holds only __init__.py and
# tenant_isolation.py, and the one migration script in the tree,
# database/migration_fix_timestamp.py, is a one-off rather than a CLI. The
# command needs a maintainer decision about whether migrations exist at all,
# so it is recorded here instead of being silently rewritten to something
# that also does not work.
KNOWN_MISSING = {"src.db.migrate"}


def _documented_modules():
    for path in DOCS:
        text = io.open(path, encoding="utf-8", errors="replace").read()
        for module in _RUN_MODULE.findall(text):
            root = module.split(".")[0]
            if root in EXTERNAL:
                continue
            yield path, module


def _module_path(module):
    base = ROOT / pathlib.Path(*module.split("."))
    if base.with_suffix(".py").exists():
        return base.with_suffix(".py")
    if (base / "__init__.py").exists():
        return base / "__init__.py"
    return None


def test_documented_run_module_targets_exist():
    missing = sorted(
        {
            (path.name, module)
            for path, module in _documented_modules()
            if module not in KNOWN_MISSING and _module_path(module) is None
        }
    )

    assert not missing, (
        f"These documents instruct `python -m <module>` for a module that does "
        f"not exist: {missing}"
    )


def test_documented_run_module_targets_are_executable():
    """A `python -m` target needs a __main__ guard or it exits doing nothing."""
    inert = []
    for path, module in _documented_modules():
        if module in KNOWN_MISSING:
            continue
        source_path = _module_path(module)
        if source_path is None:
            continue
        source = io.open(source_path, encoding="utf-8", errors="replace").read()
        if '__name__ == "__main__"' not in source and "__name__ == '__main__'" not in source:
            inert.append((path.name, module))

    assert not inert, (
        "These documented modules have no __main__ guard, so the command exits "
        f"without doing anything: {sorted(set(inert))}"
    )


@pytest.mark.parametrize("module", sorted(KNOWN_MISSING))
def test_known_missing_entry_is_still_missing(module):
    """Remove the allowlist entry once the module is implemented."""
    assert _module_path(module) is None, (
        f"{module} now exists, so remove it from KNOWN_MISSING."
    )


# Documented imports that name code which has never existed. Unlike the
# command fixes, these have no verifiable replacement in the tree, so
# correcting them means either implementing the code or rewriting the
# surrounding prose. Both are maintainer decisions, so they are recorded here
# rather than rewritten to something that also does not resolve.
#   src.data.graph_constructor      no such module, and TemporalGraphConstructor
#                                   appears nowhere in the source
#   src.db.engine                   src/db/__init__.py exports nothing
#   src.models.HTGNN                src/models/__init__.py exports nothing; the
#                                   real class is HTGAT in src/models/htgat.py
KNOWN_BROKEN_IMPORTS = {
    "src.data.graph_constructor.TemporalGraphConstructor",
    "src.data.graph_constructor.create_sample_transactions",
    "src.db.engine",
    "src.models.HTGNN",
}


def test_documented_imports_resolve_to_real_symbols():
    """`from x import Y` in a doc must name a symbol that exists."""
    pattern = re.compile(r"from (src\.[\w\.]+) import ([A-Za-z_][\w]*)")
    broken = []
    for path in DOCS:
        text = io.open(path, encoding="utf-8", errors="replace").read()
        for module, symbol in pattern.findall(text):
            if f"{module}.{symbol}" in KNOWN_BROKEN_IMPORTS:
                continue
            source_path = _module_path(module)
            if source_path is None:
                broken.append((path.name, f"{module}.{symbol}", "module missing"))
                continue
            tree = ast.parse(io.open(source_path, encoding="utf-8", errors="replace").read())
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(node.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            names.add(target.id)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        names.add(alias.asname or alias.name.split(".")[0])
            if symbol not in names:
                broken.append((path.name, f"{module}.{symbol}", "symbol missing"))

    assert not broken, (
        f"These documented imports do not resolve: {sorted(set(broken))}"
    )
