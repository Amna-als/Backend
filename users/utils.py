from django.core import signing
from django.conf import settings

# Utility helpers used to avoid storing Libre passwords as plain text in the DB.
#
# NOTE: django.core.signing provides integrity protection and ties the value to
# the Django SECRET_KEY. This is a convenience for development. For production
# deployments prefer field-level encryption (e.g. using a key in a secrets
# manager) or secure token-based OAuth flows where possible.
SALT = 'users.libre_password'


def encrypt_password(value: str) -> str:
    """Return a signed string representing `value`.

    This uses Django's signing utilities. The output is not encrypted with a
    separate secret key; rather it is signed with `settings.SECRET_KEY` and a
    salt. Treat the result as protected from casual inspection but not as a
    replacement for a secure vault.
    """
    if value is None:
        return None
    return signing.dumps(value, key=settings.SECRET_KEY, salt=SALT)


def decrypt_password(token: str) -> str:
    """Return the original plaintext value from a signed token, or None on failure."""
    if not token:
        return None
    try:
        return signing.loads(token, key=settings.SECRET_KEY, salt=SALT)
    except Exception:
        return None
