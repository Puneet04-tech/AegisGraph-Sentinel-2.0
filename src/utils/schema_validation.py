"""Lightweight JSON-style schema validation with no external dependencies.

The schema is a dict mapping field names to either a string type name or a
spec dict. ``validate`` returns ``None`` on success and raises
:class:`SchemaError` carrying a list of human-readable messages otherwise.
"""

from __future__ import annotations

_TYPE_NAMES = {"string", "number", "integer", "boolean", "list", "dict", "any"}


class SchemaError(Exception):
    """Raised when validation fails; ``errors`` holds every message."""

    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = list(errors)


def validate(data, schema):
    """Validate ``data`` against ``schema``; raise :class:`SchemaError` on failure."""
    errors = []
    if not isinstance(data, dict):
        errors.append("root value must be an object, got %s" % _type_name(data))
    else:
        _check_object(data, schema, errors, "")
    if errors:
        raise SchemaError(errors)
    return None


def is_valid(data, schema) -> bool:
    """Return True when ``data`` satisfies ``schema`` without raising."""
    try:
        validate(data, schema)
    except SchemaError:
        return False
    return True


def _check_object(data, schema, errors, path):
    for field, spec in schema.items():
        field_path = "%s.%s" % (path, field) if path else field
        if field not in data:
            if _spec_required(spec):
                errors.append("%s: missing required field" % field_path)
            continue
        _check_value(data[field], spec, field_path, errors)


def _check_value(value, spec, path, errors):
    if isinstance(spec, str):
        spec = {"type": spec}
    if not _check_type(value, spec.get("type", "any"), path, errors):
        return
    if "enum" in spec and value not in spec["enum"]:
        errors.append("%s: must be one of %s" % (path, spec["enum"]))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        _check_numeric(value, spec, path, errors)
    if isinstance(value, str):
        _check_length(value, spec, path, errors)
    if isinstance(value, list) and "items" in spec:
        _check_list_items(value, spec["items"], path, errors)
    if isinstance(value, dict) and "properties" in spec:
        _check_object(value, spec["properties"], errors, path)


def _check_type(value, type_name, path, errors):
    if type_name == "any":
        return True
    if type_name not in _TYPE_NAMES:
        return True
    matches = {
        "string": lambda v: isinstance(v, str),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "list": lambda v: isinstance(v, list),
        "dict": lambda v: isinstance(v, dict),
    }
    if matches[type_name](value):
        return True
    errors.append("%s: expected %s, got %s" % (path, type_name, _type_name(value)))
    return False


def _check_numeric(value, spec, path, errors):
    if "min" in spec and value < spec["min"]:
        errors.append("%s: must be >= %s, got %s" % (path, spec["min"], value))
    if "max" in spec and value > spec["max"]:
        errors.append("%s: must be <= %s, got %s" % (path, spec["max"], value))


def _check_length(value, spec, path, errors):
    if "min_length" in spec and len(value) < spec["min_length"]:
        errors.append(
            "%s: length must be >= %s, got %s" % (path, spec["min_length"], len(value))
        )
    if "max_length" in spec and len(value) > spec["max_length"]:
        errors.append(
            "%s: length must be <= %s, got %s" % (path, spec["max_length"], len(value))
        )


def _check_list_items(value, items_spec, path, errors):
    for index, item in enumerate(value):
        _check_value(item, items_spec, "%s[%d]" % (path, index), errors)


def _spec_required(spec) -> bool:
    if isinstance(spec, dict):
        return bool(spec.get("required", False))
    return True


def _type_name(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
