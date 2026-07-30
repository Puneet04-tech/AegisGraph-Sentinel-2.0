"""A file named setup.py at the repository root is reserved by pip.

pip executes it to generate package metadata. A script that instead performs an
interactive environment check runs during the build, prints its findings into
pip's output, produces no metadata, and fails the install with an error that
does not name the real cause.
"""

import ast
import io
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "check_environment.py"


def _calls_setuptools_setup(path):
    tree = ast.parse(io.open(path, encoding="utf-8", errors="replace").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name == "setup":
                return True
    return False


def test_root_setup_py_is_absent_or_a_real_packaging_manifest():
    """setup.py may exist only if it actually declares the package."""
    setup_py = ROOT / "setup.py"
    if not setup_py.exists():
        return

    assert _calls_setuptools_setup(setup_py), (
        "setup.py exists at the repository root but never calls setuptools "
        "setup(), so pip executes it during metadata generation and the "
        "install fails. Either make it a real packaging manifest or give the "
        "script a name pip does not treat as one."
    )


def test_environment_verifier_exists_and_parses():
    assert VERIFIER.exists(), (
        f"{VERIFIER.name} is missing. The environment verification script was "
        "renamed out of setup.py and the documentation points at this name."
    )

    ast.parse(io.open(VERIFIER, encoding="utf-8", errors="replace").read())


def test_environment_verifier_has_a_main_entry_point():
    tree = ast.parse(io.open(VERIFIER, encoding="utf-8", errors="replace").read())
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "main" in functions, "the verifier no longer defines main()"

    source = io.open(VERIFIER, encoding="utf-8", errors="replace").read()
    assert '__name__ == "__main__"' in source, (
        "the verifier is documented as `python check_environment.py`, so it "
        "needs a __main__ guard"
    )


def test_documentation_does_not_reference_the_old_script_name():
    stale = []
    for path in list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md")):
        text = io.open(path, encoding="utf-8", errors="replace").read()
        if "python setup.py" in text:
            stale.append(path.name)

    assert not stale, (
        f"These documents still instruct `python setup.py`: {stale}. "
        "pip owns that filename, so the command no longer refers to anything."
    )
