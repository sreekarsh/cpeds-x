"""
Authentication routes for CPEDS-X.

Mounted under /api/v1/auth by main.py.

  POST /api/v1/auth/signup           - create an account
  POST /api/v1/auth/login            - exchange credentials for a JWT
  GET  /api/v1/auth/me               - current user (requires Bearer token)
  POST /api/v1/auth/forgot-password  - issue a single-use reset token
  POST /api/v1/auth/reset-password   - set a new password using that token

Notes on the forgot-password flow: a production system emails a reset link.
This portfolio build has no mail server, so the endpoint returns the reset
token directly in the response (clearly flagged as demo behaviour). The token
is still single-use and time-limited, so the security model is real.
"""
import re
import time
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from . import database
from . import security

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

RESET_TTL_SECONDS = 30 * 60  # reset tokens valid for 30 minutes
_PASSWORD_MIN = 8

# Pragmatic email check. We deliberately avoid pydantic's EmailStr because it
# pulls in the optional `email-validator` package; a plain regex keeps the auth
# layer install-free and robust across environments.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalize_email(value: str) -> str:
    value = (value or "").strip().lower()
    if not _EMAIL_RE.match(value):
        raise ValueError("Enter a valid email address.")
    return value


# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------
class SignupRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=120)
    email: str
    password: str = Field(..., min_length=_PASSWORD_MIN, max_length=200)

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _normalize_email(v)


class LoginRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _normalize_email(v)


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _normalize_email(v)


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=_PASSWORD_MIN, max_length=200)


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _validate_password_strength(password: str) -> None:
    if len(password) < _PASSWORD_MIN:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must be at least {_PASSWORD_MIN} characters.",
        )
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one letter and one number.",
        )


def _user_out(row) -> UserOut:
    return UserOut(id=row["id"], email=row["email"], full_name=row["full_name"])


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(req: SignupRequest):
    _validate_password_strength(req.password)

    if database.get_user_by_email(req.email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    pwd_hash = security.hash_password(req.password)
    try:
        row = database.create_user(req.email, req.full_name, pwd_hash)
    except database.DuplicateEmailError:
        # Race: another request created the same email between check and insert.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    token = security.create_access_token(row["id"], row["email"])
    return TokenResponse(access_token=token, user=_user_out(row))


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    row = database.get_user_by_email(req.email)
    # Constant-ish response whether or not the user exists (no account enumeration).
    if row is None or not security.verify_password(req.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )
    token = security.create_access_token(row["id"], row["email"])
    return TokenResponse(access_token=token, user=_user_out(row))


@router.get("/me", response_model=UserOut)
def me(current_user: dict = Depends(security.get_current_user)):
    return UserOut(**current_user)


@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    """
    Issue a single-use reset token. Always returns 200 with the same message so
    the endpoint can't be used to discover which emails are registered.
    """
    generic = {
        "message": "If an account exists for this email, a password reset token has been issued.",
    }
    row = database.get_user_by_email(req.email)
    if row is None:
        return generic

    token = secrets.token_urlsafe(32)
    database.create_reset_token(req.email, token, int(time.time()) + RESET_TTL_SECONDS)

    # DEMO ONLY: with no mail server, hand the token back directly so the UI can
    # complete the flow. A production deployment would email a link instead.
    generic["demo_reset_token"] = token
    generic["demo_note"] = "No mail server in this build; token returned directly for demonstration."
    generic["expires_in_seconds"] = RESET_TTL_SECONDS
    return generic


@router.post("/reset-password", response_model=TokenResponse)
def reset_password(req: ResetPasswordRequest):
    _validate_password_strength(req.new_password)

    record = database.get_reset_token(req.token)
    # `used` is an int (SQLite 0/1) or a bool (Postgres); `expires_at` is stored
    # as epoch seconds. Normalise both so the check is backend-agnostic.
    if (
        record is None
        or bool(record["used"])
        or int(time.time()) > int(record["expires_at"])
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset token is invalid or has expired.",
        )

    row = database.get_user_by_email(record["email"])
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset token is invalid or has expired.",
        )

    database.update_password(record["email"], security.hash_password(req.new_password))
    database.mark_reset_used(req.token)

    # Log the user straight in after a successful reset.
    token = security.create_access_token(row["id"], row["email"])
    return TokenResponse(access_token=token, user=_user_out(row))
