"""Multi-factor authentication token verification helpers."""


def verify_mfa_token(user_id, token, secret=None):
    """Verify a TOTP token for a user-provided MFA secret."""
    if not secret or not token:
        return False

    import pyotp

    return pyotp.TOTP(secret).verify(token, valid_window=1)
