"""
Password hashing and JWT session tokens.

Both concerns degrade gracefully:
  * Passwords  -> bcrypt if the `bcrypt` wheel is installed, else PBKDF2-SHA256
                  (Python stdlib, 260k iterations). Verification auto-detects the
                  stored format, so hashes created either way keep working.
  * JWT tokens -> PyJWT if installed, else a small stdlib HS256 implementation.
                  Both produce standard, interoperable HS256 tokens, so swapping
                  libraries never invalidates an already-issued token.

This means the auth layer runs with no extra installs, and silently upgrades to
the industry-standard libraries when they are available.
"""
import os
import hmac
import json
import time
import base64
import hashlib
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from . import database

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
# Override in production:  set JWT_SECRET_KEY in the environment.
SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY",
    "cpeds-x-dev-secret-change-me-in-production-0f3a9c1e7b",
)
ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 60 * 60 * 12  # 12 hours

# ------------------------------------------------------------------
# Optional strong crypto (used automatically when present)
# ------------------------------------------------------------------
try:
    import bcrypt  # type: ignore
    _HAS_BCRYPT = True
except Exception:  # pragma: no cover - depends on environment
    _HAS_BCRYPT = False

try:
    import jwt as _pyjwt  # PyJWT
    _HAS_PYJWT = True
except Exception:  # pragma: no cover - depends on environment
    _HAS_PYJWT = False


# ==================================================================
# Password hashing
# ==================================================================
def _bcrypt_hash(password: str) -> str:
    # bcrypt caps input at 72 bytes; slice defensively.
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def _bcrypt_verify(password: str, stored: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], stored.encode("utf-8"))
    except Exception:
        return False


def _pbkdf2_hash(password: str) -> str:
    salt = os.urandom(16)
    iterations = 260_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def _pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def hash_password(password: str) -> str:
    """Hash a plaintext password with the strongest available algorithm."""
    if _HAS_BCRYPT:
        return _bcrypt_hash(password)
    return _pbkdf2_hash(password)


def verify_password(password: str, stored: str) -> bool:
    """Verify a plaintext password against a stored hash of either format."""
    if stored.startswith("$2"):  # bcrypt hash prefix ($2a$/$2b$/$2y$)
        return _bcrypt_verify(password, stored) if _HAS_BCRYPT else False
    return _pbkdf2_verify(password, stored)


# ==================================================================
# JWT session tokens
# ==================================================================
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_access_token(user_id: int, email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "uid": user_id,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    if _HAS_PYJWT:
        token = _pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        # PyJWT >= 2 returns str; older returns bytes
        return token.decode("utf-8") if isinstance(token, bytes) else token

    header = {"alg": ALGORITHM, "typ": "JWT"}
    segments = [
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    segments.append(_b64url_encode(signature))
    return ".".join(segments)


def decode_access_token(token: str) -> dict:
    """Return the token payload, or raise ValueError if invalid/expired."""
    if _HAS_PYJWT:
        try:
            return _pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception as e:
            raise ValueError(str(e))

    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise ValueError("Malformed token")
    signing_input = "{}.{}".format(header_b64, payload_b64).encode("ascii")
    expected = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
        raise ValueError("Invalid signature")
    payload = json.loads(_b64url_decode(payload_b64))
    if payload.get("exp") and int(time.time()) > int(payload["exp"]):
        raise ValueError("Token expired")
    return payload


# ==================================================================
# FastAPI dependency: resolve the current user from the Bearer token
# ==================================================================
_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated. Please sign in.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None or not creds.credentials:
        raise unauthorized
    try:
        payload = decode_access_token(creds.credentials)
    except ValueError:
        raise unauthorized

    user = database.get_user_by_id(payload.get("uid"))
    if user is None:
        raise unauthorized
    return {"id": user["id"], "email": user["email"], "full_name": user["full_name"]}
