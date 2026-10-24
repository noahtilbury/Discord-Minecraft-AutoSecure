import secrets
import string

# Symbol set chosen to survive every consumer the password passes through:
# urlencoded POSTs, RecoverUser / ChangePassword JSON bodies, SQLite storage,
# and Discord markdown (no quotes, backslash, backtick, '+', '&' or '?').
_SYMBOLS = "!@#$%^*()-_=[]{}:;,."


def generate_ms_password(length: int = 16) -> str:
    """Strong Microsoft password: mixed case + digits + symbols, 16 chars.

    Microsoft caps account passwords at 16 characters, so max strength =
    full ~82-char alphabet at length 16, guaranteed to contain lower, upper,
    digit and symbol. Changing these in lower+upper+digit APIs has been
    verified working (RecoverUser / ChangePassword accept symbol passwords).

    Old default (14 alphanumeric, ~62^14) -> 16 complex (~83^16) is several
    hundred thousand times harder to brute-force offline.
    """
    length = max(12, min(int(length), 16))
    alphabet = string.ascii_letters + string.digits + _SYMBOLS
    for _ in range(200):
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in _SYMBOLS for c in pwd)
        ):
            return pwd

    # Unreachable in practice — guaranteed-shape fallback
    return (
        secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.digits)
        + secrets.choice(_SYMBOLS)
        + "".join(secrets.choice(alphabet) for _ in range(max(0, length - 4)))
    )
