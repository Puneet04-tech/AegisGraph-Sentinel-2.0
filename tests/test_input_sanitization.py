from config.sanitizer import sanitize_query_input


def test_sanitize_html_tags():
    """Verify HTML tags are removed."""
    dirty = "<script>alert('hack')</script>Account123"
    assert sanitize_query_input(dirty) == "alert('hack')Account123"


def test_sanitize_sql_injection():
    """Verify common SQL injection patterns are stripped."""
    dirty = "ACC_VICTIM_3' OR '1'='1"
    assert sanitize_query_input(dirty) == "ACC_VICTIM_3'"

    dirty2 = "ACC_VICTIM_3 UNION SELECT username, password FROM users"
    assert sanitize_query_input(dirty2) == "ACC_VICTIM_3"


def test_sanitize_cypher_injection():
    """Verify common Cypher injection patterns are stripped."""
    dirty = "MATCH (n) DETACH DELETE n"
    assert sanitize_query_input(dirty) == ""


def test_sanitize_ansi_escapes():
    """Verify ANSI escape codes are stripped."""
    dirty = "\x1b[31mACC_VICTIM_3\x1b[0m"
    assert sanitize_query_input(dirty) == "ACC_VICTIM_3"


def test_sanitize_semicolons():
    """Verify semicolons are stripped."""
    dirty = "ACC_VICTIM_3; DROP TABLE transactions"
    assert sanitize_query_input(dirty) == "ACC_VICTIM_3"
