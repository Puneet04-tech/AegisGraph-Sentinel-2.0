"""Record deduplication utilities.

``exact_dedupe`` drops identical records while ``fuzzy_dedupe`` clusters
records whose normalized key values are similar enough to be duplicates.
"""


def normalize_value(value):
    """Return a normalized string form of ``value`` for comparisons.

    Strings are lowercased, stripped, and stripped of internal whitespace.
    ``None`` becomes an empty string and numbers are converted to strings.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return "".join(value.strip().lower().split())
    return str(value)


def jaccard_similarity(a, b):
    """Return the token-level Jaccard similarity of ``a`` and ``b``."""
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def exact_dedupe(records, keys=None):
    """Remove exact duplicate dicts, preserving first occurrence order."""
    seen = set()
    result = []
    for record in records:
        if keys is None:
            identity = tuple(sorted(record.items()))
        else:
            identity = tuple((key, record.get(key)) for key in keys)
        if identity not in seen:
            seen.add(identity)
            result.append(record)
    return result


def fuzzy_dedupe(records, keys, threshold=0.8):
    """Group records whose normalized key-string Jaccard similarity matches."""
    def _text(record):
        return " ".join(normalize_value(record.get(key)) for key in keys)

    groups = []
    for record in records:
        text = _text(record)
        matched = None
        for group in groups:
            for member in group["records"]:
                if jaccard_similarity(text, _text(member)) >= threshold:
                    matched = group
                    break
            if matched is not None:
                break
        if matched is None:
            groups.append({"group": len(groups), "records": [record]})
        else:
            matched["records"].append(record)
    return groups


def merge_group(records):
    """Merge a group of dicts, preferring the first non-null value per key."""
    merged = {}
    for record in records:
        for key, value in record.items():
            if key not in merged and value is not None:
                merged[key] = value
    return merged
