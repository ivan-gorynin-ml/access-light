"""Pydantic models for request/response validation matching OpenAPI spec."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserRole(str, Enum):
    """User roles for authorization."""

    MEMBER = "member"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class AuditMode(str, Enum):
    """Audit mode for login attempt tracking."""

    STANDARD = "standard"
    NONE = "none"


class Error(BaseModel):
    """Standard error response."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., description="Error code", examples=["invalid_request"])
    message: str = Field(..., description="Human readable error message")


class UserCreateRequest(BaseModel):
    """Request to create a new user."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="Username (3-64 chars)",
        examples=["john_doe"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=256,
        description="Password (8-256 chars)",
        examples=["CorrectHorseBatteryStaple!"],
    )
    email: Optional[EmailStr] = Field(
        default=None,
        description="Optional email address",
        examples=["john@example.com"],
    )
    role: Optional[str] = Field(
        default=None,
        description="User role (member or admin). Defaults to member if not specified. superadmin cannot be assigned via API.",
        examples=["member"],
    )
    auditMode: Optional[str] = Field(
        default="standard",
        description=(
            "Controls login audit persistence for this user. "
            "'standard' (default) preserves normal behaviour – all login attempts "
            "are recorded in the login_attempts collection. "
            "'none' disables all login-related and activity audit persistence "
            "for this user; no audit documents are created on login (success or "
            "failure) and GET /auth/login-attempts returns 403 when querying "
            "this user."
        ),
        examples=["standard"],
    )


class UserResponse(BaseModel):
    """User response (public fields only)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="User ID", examples=["usr_01HXYZ..."])
    username: str = Field(..., examples=["john_doe"])
    email: Optional[str] = Field(default=None, examples=["john@example.com"])
    role: str = Field(
        ...,
        description="User role",
        examples=["member"],
    )
    createdAt: str = Field(
        ...,
        description="ISO-8601 UTC timestamp with Z",
        examples=["2026-01-15T21:00:00Z"],
    )


class CreatedUserItem(BaseModel):
    """Single item in the createdUsers list for admin/superadmin /me response."""

    model_config = ConfigDict(extra="forbid")

    user: "UserResponse" = Field(
        ...,
        description="Full user object for the created user",
    )


class UserMeResponse(UserResponse):
    """Extended user response for GET /users/me.

    For **admin/superadmin** users, includes ``createdUsers`` — a list
    of objects representing users they created.
    """

    model_config = ConfigDict(extra="forbid")

    createdUsers: Optional[list[CreatedUserItem]] = Field(
        default=None,
        description=(
            "List of users created by this admin/superadmin. Populated only when "
            "the user role is admin or superadmin; null or omitted for member."
        ),
    )


class LoginRequest(BaseModel):
    """Login request.

    The ``password`` field accepts either the user's normal account password or the
    plaintext secret of a login credential created for that user (same JSON shape).
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "username": "john_doe",
                    "password": "CorrectHorseBatteryStaple!",
                },
                {
                    "username": "john_doe",
                    "password": "k7x9Qm2pL4vN8wR1sT3uV5yZ6aB0cD2eF4gH6jK8",
                },
            ]
        },
    )

    username: str = Field(
        ...,
        description="Account username",
        examples=["john_doe"],
    )
    password: str = Field(
        ...,
        description=(
            "Account password **or** the plaintext secret of a login credential "
            "belonging to this user (submitted in the same field)."
        ),
        examples=["CorrectHorseBatteryStaple!"],
    )


class TokenResponse(BaseModel):
    """JWT token response."""

    model_config = ConfigDict(extra="forbid")

    accessToken: str = Field(
        ...,
        description="JWT access token",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )
    tokenType: Literal["Bearer"] = Field(
        default="Bearer",
        description="Token type",
        examples=["Bearer"],
    )
    expiresIn: int = Field(
        ...,
        description="Seconds until expiry (fixed to 2592000 = 30 days)",
        examples=[2592000],
    )
    issuedAt: str = Field(
        ...,
        description="ISO-8601 UTC timestamp when token was issued",
        examples=["2026-01-15T21:05:00Z"],
    )


class PasswordChangeRequest(BaseModel):
    """Password change request."""

    model_config = ConfigDict(extra="forbid")

    oldPassword: str = Field(
        ...,
        description="Current password",
        examples=["OldPassword123!"],
    )
    newPassword: str = Field(
        ...,
        min_length=8,
        max_length=256,
        description="New password (8-256 chars)",
        examples=["NewStrongPassword123!"],
    )


class AdminPasswordResetResponse(BaseModel):
    """Response when an admin resets a member user's password.

    The plaintext ``password`` is returned **only** in this response and is
    never stored or logged server-side.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        ...,
        description="Username of the member whose password was reset",
        examples=["alice"],
    )
    password: str = Field(
        ...,
        description=(
            "Newly generated plaintext password shown **only** in this response. "
            "Share it securely with the member; it cannot be retrieved again."
        ),
        examples=["xK9mP2vN4wQ7rT1sU3yZ5a"],
    )


class VerifyRequest(BaseModel):
    """JWT verification request."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(
        ...,
        description="JWT to verify",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )


class VerifyResponse(BaseModel):
    """JWT verification response."""

    model_config = ConfigDict(extra="forbid")

    valid: bool = Field(..., description="Whether token is valid", examples=[True])
    subject: Optional[str] = Field(
        default=None,
        description="sub claim (user ID) if valid",
        examples=["usr_01HXYZ..."],
    )
    username: Optional[str] = Field(
        default=None,
        examples=["john_doe"],
    )
    issuedAt: Optional[int] = Field(
        default=None,
        description="iat claim as UNIX seconds",
        examples=[1768511100],
    )
    expiresAt: Optional[int] = Field(
        default=None,
        description="exp claim as UNIX seconds",
        examples=[1771103100],
    )


# ── Login attempt enums & models ──────────────────────────────────────


class LoginAttemptResult(str, Enum):
    """Outcome of a login attempt."""

    SUCCESS = "success"
    FAILURE = "failure"


class LoginAttemptFailureReason(str, Enum):
    """Internal-only reason for a failed login attempt."""

    INVALID_PASSWORD = "invalid_password"
    USER_NOT_FOUND = "user_not_found"
    ACCOUNT_DISABLED = "account_disabled"
    RATE_LIMITED = "rate_limited"
    OTHER = "other"


class LoginAttemptItem(BaseModel):
    """Single login-attempt record returned to the caller."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., description="The username that was submitted in the login request")
    result: LoginAttemptResult = Field(..., description="success or failure")
    failureReason: Optional[LoginAttemptFailureReason] = Field(
        default=None,
        description="Reason for failure (null when result=success)",
    )
    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of the attempt",
        examples=["2026-01-15T21:00:00Z"],
    )
    ipAddress: str = Field(..., description="Client IP address")
    locale: Optional[str] = Field(
        default=None,
        description="Locale derived from Accept-Language header",
    )
    origin: Optional[str] = Field(
        default=None,
        description=(
            "Optional request origin identifier used for analytics, audit "
            "correlation, and operational visibility; typical values include "
            "'app UI', 'mobile', or other client identifiers."
        ),
    )


class LoginAttemptsResponse(BaseModel):
    """Paginated response for GET /auth/login-attempts."""

    model_config = ConfigDict(extra="forbid")

    items: list[LoginAttemptItem] = Field(default_factory=list)
    limit: int = Field(..., description="Page size used")
    nextCursor: Optional[str] = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results",
    )


# ── Activity attempt enums & models ───────────────────────────────────


class ActivityAttemptResult(str, Enum):
    """Outcome of an activity attempt."""

    SUCCESS = "success"
    FAILURE = "failure"


class ActivityAttemptFailureReason(str, Enum):
    """Internal reason for a failed activity attempt."""

    INVALID_TOKEN = "invalid_token"
    EXPIRED_TOKEN = "expired_token"
    INVALID_CREDENTIALS = "invalid_credentials"
    WRONG_OLD_PASSWORD = "wrong_old_password"
    VALIDATION_ERROR = "validation_error"
    FORBIDDEN = "forbidden"
    USER_NOT_FOUND = "user_not_found"
    AUDIT_NOT_AVAILABLE = "audit_not_available"
    OTHER = "other"


class ActivityAttemptItem(BaseModel):
    """Single activity-attempt record returned to the caller."""

    model_config = ConfigDict(extra="forbid")

    username: Optional[str] = Field(
        default=None,
        description="Resolved authenticated username; null if auth failed before identity resolution",
    )
    endpoint: str = Field(
        ...,
        description='Canonical endpoint string, e.g. "POST /access-light/v1/auth/logout"',
    )
    result: ActivityAttemptResult = Field(..., description="success or failure")
    failureReason: Optional[str] = Field(
        default=None,
        description="Reason for failure (null when result=success)",
    )
    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp",
        examples=["2026-01-15T21:00:00Z"],
    )
    ipAddress: str = Field(..., description="Client IP address")
    locale: Optional[str] = Field(
        default=None,
        description="Locale derived from Accept-Language header",
    )
    origin: Optional[str] = Field(
        default=None,
        description=(
            "Optional request origin identifier used for analytics, audit "
            "correlation, and operational visibility; typical values include "
            "'app UI', 'mobile', or other client identifiers."
        ),
    )
    targetUsername: Optional[str] = Field(
        default=None,
        description=(
            "For operations targeting another user (e.g. password reset), "
            "the username that was the target of the action."
        ),
    )
    operation: Optional[str] = Field(
        default=None,
        description=(
            "For bulk operations, the type of operation performed "
            "(e.g. 'assign', 'reassign', 'unassign')."
        ),
    )
    itemsCount: Optional[int] = Field(
        default=None,
        description="For bulk operations, the total number of items in the request.",
    )


class ActivityAttemptsResponse(BaseModel):
    """Paginated response for GET /auth/activity-attempts."""

    model_config = ConfigDict(extra="forbid")

    items: list[ActivityAttemptItem] = Field(default_factory=list)
    limit: int = Field(..., description="Page size used")
    nextCursor: Optional[str] = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results",
    )


# Internal user document model (for DB operations)
class UserDocument(BaseModel):
    """Internal user document structure in MongoDB."""

    model_config = ConfigDict(extra="allow")

    _id: str  # String user ID (usr_* prefix)
    username: str
    email: Optional[str] = None
    password_hash: str
    role: str = "member"
    created_at: datetime
    password_changed_at: Optional[datetime] = None
    created_usernames: Optional[list[str]] = None
    revoke_before: Optional[datetime] = None
    audit_disabled: Optional[bool] = None


# ── Login credential models ───────────────────────────────────────────


class LoginCredentialCreateRequest(BaseModel):
    """Request to create (or replace) a login credential.

    The server generates the secret; clients must not send one. If ``name`` already
    exists for the user, the existing credential is replaced and ``lastLoginAt`` is reset.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"name": "mobile-app", "description": "iOS client"},
                {"name": "ci-bot"},
            ]
        },
    )

    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description=(
            "Required credential name, trimmed; unique per user. "
            "Non-empty after trimming."
        ),
        examples=["mobile-app"],
    )
    description: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Optional description (trimmed; empty string becomes null)",
        examples=["Automation account for CI"],
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("name must be non-empty after trimming")
        return trimmed

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        return trimmed if trimmed else None


class LoginCredentialUpdateRequest(BaseModel):
    """Request to update a login credential (description only)."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"description": "Updated label"}]},
    )

    description: Optional[str] = Field(
        default=None,
        max_length=512,
        description="New description, or null to clear",
        examples=["Updated label"],
    )

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        return trimmed if trimmed else None


class LoginCredentialResponse(BaseModel):
    """Login credential returned by list/get/update (no secret or hash)."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "name": "mobile-app",
                    "description": "iOS client",
                    "createdAt": "2026-05-25T12:00:00Z",
                    "updatedAt": "2026-05-25T12:00:00Z",
                    "lastLoginAt": None,
                }
            ]
        },
    )

    name: str = Field(..., description="Credential name (unique per user)")
    description: Optional[str] = Field(
        default=None,
        description="Optional description",
    )
    createdAt: str = Field(
        ...,
        description="ISO-8601 UTC timestamp when the credential was first created",
        examples=["2026-05-25T12:00:00Z"],
    )
    updatedAt: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of last metadata or secret rotation",
        examples=["2026-05-25T12:00:00Z"],
    )
    lastLoginAt: Optional[str] = Field(
        default=None,
        description=(
            "ISO-8601 UTC timestamp of the last successful login using this "
            "credential's secret; null until first use"
        ),
        examples=["2026-05-25T14:30:00Z"],
    )


class LoginCredentialCreatedResponse(LoginCredentialResponse):
    """Response when a credential is created or replaced; includes one-time plaintext secret."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "name": "mobile-app",
                    "description": "iOS client",
                    "createdAt": "2026-05-25T12:00:00Z",
                    "updatedAt": "2026-05-25T12:00:00Z",
                    "lastLoginAt": None,
                    "secret": "k7x9Qm2pL4vN8wR1sT3uV5yZ6aB0cD2eF4gH6jK8mN0pQ2rS4tU6vW8xY0z",
                }
            ]
        },
    )

    secret: str = Field(
        ...,
        description=(
            "Plaintext credential secret shown **only** in this create/replace response. "
            "Use it as the ``password`` value in ``POST /auth/login``. Never logged server-side."
        ),
        examples=["k7x9Qm2pL4vN8wR1sT3uV5yZ6aB0cD2eF4gH6jK8mN0pQ2rS4tU6vW8xY0z"],
    )


class LoginCredentialsListResponse(BaseModel):
    """List of login credentials for the authenticated user."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "items": [
                        {
                            "name": "mobile-app",
                            "description": "iOS client",
                            "createdAt": "2026-05-25T12:00:00Z",
                            "updatedAt": "2026-05-25T12:00:00Z",
                            "lastLoginAt": "2026-05-25T14:30:00Z",
                        }
                    ]
                }
            ]
        },
    )

    items: list[LoginCredentialResponse] = Field(
        default_factory=list,
        description="Credentials owned by the authenticated user, sorted by name",
    )
