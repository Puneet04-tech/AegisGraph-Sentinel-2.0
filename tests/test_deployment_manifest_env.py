"""Deployment manifests must inject variables the application actually reads.

A manifest that wires a secret under a name nothing reads produces a service
that starts, passes its health probe, and then refuses real traffic because the
credential it needed was never supplied under the expected name.
"""

import io
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
K8S = ROOT / "infrastructure" / "kubernetes" / "deployment.yaml"
HELM_TEMPLATE = ROOT / "infrastructure" / "helm" / "aegisgraph" / "templates" / "api-deployment.yaml"

# The variable require_role() resolves keys against. Without it every
# role-protected route answers 503.
REQUIRED_ENV = "AEGIS_API_KEY_HASHES"

_ENV_NAME = re.compile(r"- name: ([A-Z][A-Z0-9_]+)")


def _source_files():
    for path in (ROOT / "src").rglob("*.py"):
        yield path
    for name in ("app.py",):
        candidate = ROOT / name
        if candidate.exists():
            yield candidate


def _codebase_text():
    chunks = []
    for path in _source_files():
        try:
            chunks.append(io.open(path, encoding="utf-8", errors="replace").read())
        except OSError:
            continue
    return "\n".join(chunks)


CODE = _codebase_text()


def _env_names(path):
    return sorted(set(_ENV_NAME.findall(io.open(path, encoding="utf-8").read())))


@pytest.mark.parametrize("manifest", [K8S, HELM_TEMPLATE], ids=["kubernetes", "helm"])
def test_manifest_injects_the_api_key_backend(manifest):
    assert manifest.exists(), f"{manifest} is missing"

    names = _env_names(manifest)

    assert REQUIRED_ENV in names, (
        f"{manifest.name} does not inject {REQUIRED_ENV}, so a deployment from "
        "it starts and then answers 503 on every role-protected route. "
        f"Environment variables it does set: {names}"
    )


# Injected deliberately even though no source file reads it today.
# src/data/kafka_consumer.py takes its broker list from its caller rather than
# the environment, so this entry is forward looking. Remove it from here once
# the consumer reads the variable, or drop it from the manifests.
KNOWN_UNREAD = {"KAFKA_BOOTSTRAP_SERVERS"}


@pytest.mark.parametrize("manifest", [K8S, HELM_TEMPLATE], ids=["kubernetes", "helm"])
def test_manifest_env_names_are_read_by_the_application(manifest):
    unread = [
        name
        for name in _env_names(manifest)
        if name not in KNOWN_UNREAD
        and f'"{name}"' not in CODE
        and f"'{name}'" not in CODE
    ]

    assert not unread, (
        f"{manifest.name} injects variables no source file reads: {unread}. "
        "Either the application should read them or the manifest should not "
        "set them, because a secret under an unread name is silently ignored."
    )


def test_kubernetes_manifest_is_valid_yaml():
    documents = list(yaml.safe_load_all(io.open(K8S, encoding="utf-8")))

    assert documents, "no YAML documents parsed"
    assert all(d is None or isinstance(d, dict) for d in documents)


def test_secret_keys_match_the_env_references():
    """Every secretKeyRef key must exist in the Secret this manifest defines."""
    documents = [
        d for d in yaml.safe_load_all(io.open(K8S, encoding="utf-8")) if isinstance(d, dict)
    ]
    secrets = {
        key
        for d in documents
        if d.get("kind") == "Secret"
        for key in (d.get("stringData") or {})
    }
    referenced = set(re.findall(r"secretKeyRef:\s*\n\s*name: [^\n]+\n\s*key: (\S+)",
                                io.open(K8S, encoding="utf-8").read()))

    missing = sorted(referenced - secrets)
    assert not missing, (
        f"These secretKeyRef keys are not defined by the Secret: {missing}. "
        f"Secret defines: {sorted(secrets)}"
    )
