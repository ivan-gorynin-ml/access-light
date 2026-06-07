"""Authentication routes: login, token verification, logout, and login-attempt audit."""

import base64
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.db import get_collection, get_login_attempts_collection, get_revoked_tokens_collection, get_activity_attempts_collection
from app.deps import get_current_user
from app.models import (
    ActivityAttemptFailureReason,
    ActivityAttemptItem,
    ActivityAttemptResult,
    ActivityAttemptsResponse,
    AuditMode,
    LoginAttemptFailureReason,
    LoginAttemptItem,
    LoginAttemptResult,
    LoginAttemptsResponse,
    LoginRequest,
    TokenResponse,
    UserRole,
    VerifyRequest,
    VerifyResponse,
)
from app.rate_limit import limiter
from app.security import (
    create_access_token,
    datetime_to_iso_string,
    get_utc_now,
    verify_password,
    verify_token,
    verify_token_with_revocation,
)
from app.services import login_credentials as lc_service
from app.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/access-light/v1/auth", tags=["Auth"])


# ── helpers ──────────────────────────────────────────────────────────────

def _extract_client_ip(request: Request) -> str:
    """Derive client IP from X-Forwarded-For → X-Real-IP → connection remote."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First entry is the original client
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return "unknown"


def _extract_locale(request: Request) -> Optional[str]:
    """Return the primary locale from Accept-Language, or None."""
    header = request.headers.get("accept-language")
    if not header:
        return None
    # Take the first tag, e.g. "en-US,en;q=0.9" → "en-US"
    first = header.split(",")[0].split(";")[0].strip()
    return first or None


async def _record_login_attempt(
    *,
    attempted_username: str,
    result: LoginAttemptResult,
    failure_reason: Optional[LoginAttemptFailureReason],
    subject_user_id: Optional[str],
    owner_user_id: Optional[str],
    creator_user_id: Optional[str],
    ip_address: str,
    locale: Optional[str],
    origin: Optional[str] = None,
) -> None:
    """Persist a login-attempt document.  Fire-and-forget – never raises."""
    try:
        col = get_login_attempts_collection()
        now = datetime.now(timezone.utc)
        doc = {
            "_id": str(uuid.uuid4()),
            "timestamp": now,
            "attempted_username": attempted_username,
            "result": result.value,
            "failure_reason": failure_reason.value if failure_reason else None,
            "subject_user_id": subject_user_id,
            "owner_user_id": owner_user_id,
            "creator_user_id": creator_user_id,
            "ip_address": ip_address,
            "locale": locale,
            "origin": origin if origin is not None else "app UI",
        }
        await col.insert_one(doc)
    except Exception as exc:
        logger.error(f"Failed to persist login attempt: {exc}")


async def _record_activity_attempt(
    *,
    username: Optional[str],
    endpoint: str,
    result: ActivityAttemptResult,
    failure_reason: Optional[str],
    owner_user_id: Optional[str],
    creator_user_id: Optional[str],
    ip_address: str,
    locale: Optional[str],
    origin: Optional[str] = None,
    target_username: Optional[str] = None,
    operation: Optional[str] = None,
    items_count: Optional[int] = None,
) -> None:
    """Persist an activity-attempt document.  Fire-and-forget – never raises."""
    try:
        col = get_activity_attempts_collection()
        now = datetime.now(timezone.utc)
        doc = {
            "_id": str(uuid.uuid4()),
            "timestamp": now,
            "username": username,
            "endpoint": endpoint,
            "result": result.value,
            "failure_reason": failure_reason,
            "owner_user_id": owner_user_id,
            "creator_user_id": creator_user_id,
            "ip_address": ip_address,
            "locale": locale,
            "origin": origin if origin is not None else "app UI",
        }
        if target_username is not None:
            doc["target_username"] = target_username
        if operation is not None:
            doc["operation"] = operation
        if items_count is not None:
            doc["items_count"] = items_count
        await col.insert_one(doc)
    except Exception as exc:
        logger.error(f"Failed to persist activity attempt: {exc}")


# ── POST /login ──────────────────────────────────────────────────────────


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and issue JWT",
    description=(
        "Authenticates a user and issues a signed JWT (30-day expiry).\n\n"
        "**Password field:** The request body ``password`` may be either:\n"
        "1. The user's normal account password (verified against ``password_hash``), or\n"
        "2. The plaintext **login credential secret** for a credential owned by that user "
        "(created via ``POST /v1/users/me/login-credentials``). The same JSON field is used; "
        "the server tries the account password first, then login credentials.\n\n"
        "On successful login with a login credential, the matching credential's "
        "``lastLoginAt`` timestamp is updated. The response is identical for both methods "
        "(``TokenResponse``).\n\n"
        "**Errors:** Returns generic ``401 invalid_credentials`` without revealing whether "
        "the username exists or which authentication method failed.\n\n"
        "**Rate limiting:** Requests are limited per client IP (see ``login_rate_limit`` "
        "setting); excess requests receive ``429``.\n\n"
        "**Audit:** Each attempt is recorded in ``login_attempts`` (unless the user's "
        "``auditMode`` is ``none``). Query via ``GET /v1/auth/login-attempts``."
    ),
    responses={
        200: {
            "description": "JWT issued (account password or login credential)",
            "model": TokenResponse,
        },
        401: {
            "description": "Invalid credentials (username, password, or credential secret)",
            "content": {
                "application/json": {
                    "example": {
                        "code": "invalid_credentials",
                        "message": "Invalid username or password",
                    }
                }
            },
        },
        429: {
            "description": "Too many login attempts from this client IP",
            "content": {
                "application/json": {
                    "example": {
                        "error": "Rate limit exceeded: 30 per 1 minute",
                    }
                }
            },
        },
    },
)
@limiter.limit(settings.login_rate_limit)
async def login(
    request: Request,
    body: LoginRequest,
    origin: Optional[str] = Query(
        default="app UI",
        description=(
            "Optional request origin identifier used for analytics, audit "
            "correlation, and operational visibility; typical values include "
            "'app UI', 'mobile', or other client identifiers. If not provided, "
            "the server treats the value as 'app UI'. This parameter is used "
            "only for server-side logging/analytics/audit context and does not "
            "influence authorization, business logic, or response content."
        ),
    ),
) -> TokenResponse:
    """
    Authenticate user and issue JWT access token.

    Security notes:
    - Returns generic 401 error without revealing if username exists
    - Accepts normal password or a login credential secret in the password field
    - Uses constant-time secret comparison; secrets never logged or exposed
    - Every call is audit-logged to login_attempts collection
    - Rate limited per client IP (see settings.login_rate_limit)
    """
    collection = get_collection()
    ip = _extract_client_ip(request)
    locale = _extract_locale(request)
    _origin = origin if origin is not None else "app UI"

    # Find user by username
    user = await collection.find_one({"username": body.username})

    # ── user not found ──────────────────────────────────────────
    if not user:
        logger.warning(f"Login attempt for non-existent user: {body.username}")
        await _record_login_attempt(
            attempted_username=body.username,
            result=LoginAttemptResult.FAILURE,
            failure_reason=LoginAttemptFailureReason.USER_NOT_FOUND,
            subject_user_id=None,
            owner_user_id=None,
            creator_user_id=None,
            ip_address=ip,
            locale=locale,
            origin=_origin,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_credentials",
                "message": "Invalid username or password",
            },
        )

    # Resolve creator id for hierarchical access by finding the user
    # whose created_usernames list contains this username.
    creator_id: Optional[str] = None
    try:
        creator = await collection.find_one(
            {"created_usernames": user["username"]},
            {"_id": 1},
        )
        if creator:
            creator_id = creator["_id"]
    except Exception:
        pass  # non-critical – proceed without creator info

    # Determine whether audit logging is disabled for this user
    _audit_disabled = user.get("audit_disabled", False)

    # ── authenticate: normal password or login credential secret ─
    password_valid = verify_password(body.password, user["password_hash"])
    matched_credential = None
    if not password_valid:
        matched_credential = await lc_service.verify_login_credential_secret(
            user["_id"],
            body.password,
        )

    if not password_valid and not matched_credential:
        logger.warning(f"Failed login attempt for user: {body.username}")
        if not _audit_disabled:
            await _record_login_attempt(
                attempted_username=body.username,
                result=LoginAttemptResult.FAILURE,
                failure_reason=LoginAttemptFailureReason.INVALID_PASSWORD,
                subject_user_id=user["_id"],
                owner_user_id=user["_id"],
                creator_user_id=creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_credentials",
                "message": "Invalid username or password",
            },
        )

    # ── success ─────────────────────────────────────────────────
    try:
        token = create_access_token(user["_id"], user["username"], user.get("role", "member"))
    except Exception as e:
        logger.error(f"Failed to create token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "token_creation_failed",
                "message": "Failed to create access token",
            },
        )

    issued_at = get_utc_now()

    if matched_credential:
        try:
            await lc_service.touch_login_credential_last_login(
                matched_credential["_id"],
                login_time=issued_at,
            )
        except Exception as exc:
            logger.error(
                "Failed to update last_login_at for credential %s: %s",
                matched_credential.get("name"),
                exc,
            )

    if not _audit_disabled:
        await _record_login_attempt(
            attempted_username=body.username,
            result=LoginAttemptResult.SUCCESS,
            failure_reason=None,
            subject_user_id=user["_id"],
            owner_user_id=user["_id"],
            creator_user_id=creator_id,
            ip_address=ip,
            locale=locale,
            origin=_origin,
        )

    logger.info(f"Successful login for user: {body.username}")

    return TokenResponse(
        accessToken=token,
        tokenType="Bearer",
        expiresIn=settings.jwt_expires_seconds,
        issuedAt=datetime_to_iso_string(issued_at),
    )


# ── GET /login-attempts ─────────────────────────────────────────────────


def _encode_cursor(ts: datetime, doc_id: str) -> str:
    """Encode an opaque pagination cursor."""
    raw = f"{ts.isoformat()}|{doc_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str):
    """Decode an opaque cursor → (datetime, doc_id)."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_str, doc_id = raw.rsplit("|", 1)
        ts = datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts, doc_id
    except Exception:
        return None, None


@router.get(
    "/login-attempts",
    response_model=LoginAttemptsResponse,
    status_code=status.HTTP_200_OK,
    summary="Query login audit log",
    description=(
        "Returns login-attempt audit records sorted by timestamp DESC with "
        "cursor-based pagination.  Access-control rules:\n\n"
        "- **member**: own attempts only (`ownerUserId = caller`).\n"
        "- **admin / superadmin**: own attempts **plus** attempts of users in "
        "their `createdUsernames` set.  May also request `includeUserNotFound=true` "
        "to include attempts where the username did not resolve to any user.\n\n"
        "Optional filters: `username`, `from` (inclusive), `to` (exclusive), "
        "`includeUserNotFound` (default false, admin/superadmin only)."
    ),
    responses={
        200: {"description": "Paginated login attempts", "model": LoginAttemptsResponse},
        401: {
            "description": "Missing/invalid token",
            "content": {
                "application/json": {
                    "example": {"code": "invalid_token", "message": "Invalid or expired token"}
                }
            },
        },
        403: {
            "description": (
                "Forbidden – caller tried to access data outside their scope, "
                "or the targeted user was created with `auditMode=\"none\"` and "
                "has no audit data available."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "access_denied": {
                            "summary": "Scope violation",
                            "value": {"code": "forbidden", "message": "Access denied"},
                        },
                        "audit_not_available": {
                            "summary": "Audit disabled for user",
                            "value": {
                                "code": "audit_not_available",
                                "message": "Login audit data is not available for this user",
                            },
                        },
                    }
                }
            },
        },
    },
)
async def get_login_attempts(
    current_user: Dict = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200, description="Page size"),
    cursor: Optional[str] = Query(default=None, description="Opaque pagination cursor"),
    username: Optional[str] = Query(default=None, description="Filter by attempted username"),
    includeUserNotFound: bool = Query(
        default=False,
        description="Include user_not_found attempts (admin/superadmin only)",
    ),
    date_from: Optional[str] = Query(
        default=None, alias="from", description="Inclusive ISO-8601 start date"
    ),
    date_to: Optional[str] = Query(
        default=None, alias="to", description="Exclusive ISO-8601 end date"
    ),
) -> LoginAttemptsResponse:
    """Return paginated login-attempt audit records respecting access control."""

    role = current_user.get("role", "member")
    caller_id = current_user["_id"]
    is_privileged = role in (UserRole.ADMIN.value, UserRole.SUPERADMIN.value)

    # ── audit-disabled check for the caller themselves ───────────
    caller_audit_disabled = current_user.get("audit_disabled", False)

    # ── access-control: determine allowed scope ──────────────────
    created_usernames: list[str] = []
    if is_privileged:
        created_usernames = current_user.get("created_usernames") or []

    # If member asks for includeUserNotFound → 403
    if includeUserNotFound and not is_privileged:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "forbidden",
                "message": "Only admin or superadmin can include user-not-found attempts",
            },
        )

    # ── validate username filter against scope ───────────────────
    if username:
        own_username = current_user["username"]
        if username != own_username:
            if not is_privileged:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "forbidden",
                        "message": "Members can only query their own login attempts",
                    },
                )
            if username not in created_usernames:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "forbidden",
                        "message": "You can only query attempts for users you created or yourself",
                    },
                )

    # ── audit-disabled checks ────────────────────────────────────
    # If a specific username is requested, check that user's audit flag.
    # If no username is given (scope-based), check the caller's own flag
    # for members; for privileged users the broad query is allowed as long
    # as the caller themselves is not audit-disabled.
    collection = get_collection()

    if username:
        # Querying a specific user – look up their audit_disabled flag
        if username == current_user["username"]:
            target_audit_disabled = caller_audit_disabled
        else:
            target_user = await collection.find_one(
                {"username": username}, {"audit_disabled": 1}
            )
            target_audit_disabled = (
                target_user.get("audit_disabled", False) if target_user else False
            )
        if target_audit_disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "audit_not_available",
                    "message": "Login audit data is not available for this user",
                },
            )
    else:
        # Scope-based query – for members this is "own data only"
        if not is_privileged and caller_audit_disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "audit_not_available",
                    "message": "Login audit data is not available for this user",
                },
            )

    # ── build MongoDB filter ─────────────────────────────────────
    query_filter: dict = {}

    if username:
        # Specific username requested (already validated above)
        query_filter["attempted_username"] = username
    else:
        # Scope-based filter
        if is_privileged:
            # Own + created users' attempts
            allowed_usernames = [current_user["username"]] + list(created_usernames)
            or_clauses = [{"attempted_username": {"$in": allowed_usernames}}]
            if includeUserNotFound:
                or_clauses.append({"failure_reason": LoginAttemptFailureReason.USER_NOT_FOUND.value})
            query_filter["$or"] = or_clauses
        else:
            # Members – own attempts only (by owner_user_id)
            query_filter["owner_user_id"] = caller_id

    # Exclude user_not_found by default unless explicitly requested
    if not includeUserNotFound:
        # For non-privileged this is already handled by owner_user_id filter
        # (user_not_found records have no owner_user_id).
        # For privileged, explicitly exclude them when not requested.
        if is_privileged and not username:
            # Already handled by $or clauses above – user_not_found only appears
            # when includeUserNotFound is True.
            pass
        elif is_privileged and username:
            query_filter["failure_reason"] = {"$ne": LoginAttemptFailureReason.USER_NOT_FOUND.value}

    # ── date-range filters ───────────────────────────────────────
    ts_filter: dict = {}
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
            ts_filter["$gte"] = dt_from
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_request", "message": "Invalid 'from' date format"},
            )
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
            ts_filter["$lt"] = dt_to
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_request", "message": "Invalid 'to' date format"},
            )
    if ts_filter:
        query_filter["timestamp"] = ts_filter

    # ── cursor ───────────────────────────────────────────────────
    if cursor:
        cursor_ts, cursor_id = _decode_cursor(cursor)
        if cursor_ts is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_request", "message": "Invalid cursor"},
            )
        # Records strictly before cursor (since DESC order)
        cursor_cond = {
            "$or": [
                {"timestamp": {"$lt": cursor_ts}},
                {"timestamp": cursor_ts, "_id": {"$lt": cursor_id}},
            ]
        }
        # Always use $and to combine with existing filter to avoid key conflicts
        query_filter = {"$and": [query_filter, cursor_cond]}

    # ── execute query ────────────────────────────────────────────
    col = get_login_attempts_collection()
    docs = (
        await col.find(query_filter)
        .sort([("timestamp", -1), ("_id", -1)])
        .limit(limit + 1)  # fetch one extra to check for next page
        .to_list(length=limit + 1)
    )

    has_next = len(docs) > limit
    if has_next:
        docs = docs[:limit]

    next_cursor: Optional[str] = None
    if has_next and docs:
        last = docs[-1]
        next_cursor = _encode_cursor(last["timestamp"], last["_id"])

    items = [
        LoginAttemptItem(
            username=d["attempted_username"],
            result=d["result"],
            failureReason=d.get("failure_reason"),
            timestamp=datetime_to_iso_string(d["timestamp"]),
            ipAddress=d["ip_address"],
            locale=d.get("locale"),
            origin=d.get("origin"),
        )
        for d in docs
    ]

    return LoginAttemptsResponse(items=items, limit=limit, nextCursor=next_cursor)


# ── POST /logout ─────────────────────────────────────────────────────────

# Standalone bearer scheme for logout (does not auto-error so we can
# return our own 401 body).
_bearer = HTTPBearer(auto_error=False)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke current JWT",
    description=(
        "Revokes the currently presented JWT access token by inserting its `jti` "
        "into the `revoked_tokens` collection.  Subsequent requests using the "
        "same token will receive 401.  The endpoint is idempotent: calling it "
        "multiple times with the same token always returns 204.  "
        "Clients should discard the token locally after calling this endpoint."
    ),
    responses={
        204: {"description": "Token revoked (no content)"},
        401: {
            "description": "Missing/invalid/expired token",
            "content": {
                "application/json": {
                    "example": {
                        "code": "invalid_token",
                        "message": "Invalid or expired token",
                    }
                }
            },
        },
    },
)
async def logout(
    raw_request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    origin: Optional[str] = Query(
        default="app UI",
        description=(
            "Optional request origin identifier used for analytics, audit "
            "correlation, and operational visibility; typical values include "
            "'app UI', 'mobile', or other client identifiers. If not provided, "
            "the server treats the value as 'app UI'. This parameter is used "
            "only for server-side logging/analytics/audit context and does not "
            "influence authorization, business logic, or response content."
        ),
    ),
) -> None:
    """
    Revoke the presented JWT so it cannot be used again.

    - Validates Bearer token (signature, exp, iat, iss, aud).
    - Inserts a revocation record keyed by jti (idempotent upsert).
    - Records an activity_attempts audit entry.
    - Returns 204 on success (even if the token was already revoked).
    """
    ip = _extract_client_ip(raw_request)
    locale = _extract_locale(raw_request)
    endpoint_name = "POST /access-light/v1/auth/logout"
    _origin = origin if origin is not None else "app UI"

    if not credentials:
        # No identity resolved – record activity with username=null
        # We cannot determine audit_disabled without identity, so skip recording
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "missing_token",
                "message": "Authorization header with Bearer token is required",
            },
        )

    token = credentials.credentials

    # Validate signature & standard claims (without revocation check –
    # we need the payload to *create* the revocation record).
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_token",
                "message": "Invalid or expired token",
            },
        )

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_token",
                "message": "Invalid or expired token",
            },
        )

    user_id = payload.get("sub", "")
    username = payload.get("username", "")
    exp = payload.get("exp")
    now_utc = get_utc_now()

    # Derive expiresAt from the exp claim
    expires_at = (
        datetime.fromtimestamp(exp, tz=timezone.utc) if exp else now_utc
    )

    # Idempotent upsert into revoked_tokens (setOnInsert guarantees safe retries)
    revoked_col = get_revoked_tokens_collection()
    await revoked_col.update_one(
        {"jti": jti},
        {
            "$setOnInsert": {
                "jti": jti,
                "userId": user_id,
                "revokedAt": datetime_to_iso_string(now_utc),
                "expiresAt": expires_at,
                "reason": "logout",
            }
        },
        upsert=True,
    )

    # Audit: record activity attempt (only if user’s auditMode is not "none")
    collection = get_collection()
    user_doc = await collection.find_one({"_id": user_id}, {"audit_disabled": 1, "created_usernames": 1, "username": 1})
    audit_disabled = user_doc.get("audit_disabled", False) if user_doc else False

    if not audit_disabled:
        creator_id: Optional[str] = None
        try:
            creator = await collection.find_one(
                {"created_usernames": username},
                {"_id": 1},
            )
            if creator:
                creator_id = creator["_id"]
        except Exception:
            pass
        await _record_activity_attempt(
            username=username,
            endpoint=endpoint_name,
            result=ActivityAttemptResult.SUCCESS,
            failure_reason=None,
            owner_user_id=user_id,
            creator_user_id=creator_id,
            ip_address=ip,
            locale=locale,
            origin=_origin,
        )

    logger.info(f"Token revoked for user {username} (jti={jti})")
    # 204 No Content – FastAPI returns empty body automatically.


@router.post(
    "/verify",
    response_model=VerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify JWT signature/validity",
    description=(
        "Verifies a provided JWT: checks signature, algorithm, exp/iat, "
        "and any configured iss/aud. Returns valid=true plus selected claims if valid; "
        "otherwise valid=false with null claim fields."
    ),
    responses={
        200: {
            "description": "Verification result",
            "model": VerifyResponse,
        },
        400: {
            "description": "Bad request",
            "content": {
                "application/json": {
                    "example": {
                        "code": "invalid_request",
                        "message": "Token is required",
                    }
                }
            },
        },
    },
)
async def verify(
    request: VerifyRequest,
    raw_request: Request,
    origin: Optional[str] = Query(
        default="app UI",
        description=(
            "Optional request origin identifier used for analytics, audit "
            "correlation, and operational visibility; typical values include "
            "'app UI', 'mobile', or other client identifiers. If not provided, "
            "the server treats the value as 'app UI'. This parameter is used "
            "only for server-side logging/analytics/audit context and does not "
            "influence authorization, business logic, or response content."
        ),
    ),
) -> VerifyResponse:
    """
    Verify JWT token and return claims if valid.
    
    Returns valid=false with null claims if token is invalid/expired.
    This approach allows the caller to distinguish between invalid tokens
    and malformed requests (400).
    """
    if not request.token or not request.token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_request",
                "message": "Token is required",
            },
        )

    ip = _extract_client_ip(raw_request)
    locale = _extract_locale(raw_request)
    endpoint_name = "POST /access-light/v1/auth/verify"
    _origin = origin if origin is not None else "app UI"

    # Verify token (includes revocation checks)
    payload = await verify_token_with_revocation(request.token)
    
    if not payload:
        # Invalid/expired token - return valid=false
        # Try to extract username from token payload for audit
        # (even if expired/invalid signature, we can still try to parse)
        _username: Optional[str] = None
        try:
            # Try to decode without verification to get username
            import jose.jwt as jose_jwt
            unverified = jose_jwt.get_unverified_claims(request.token)
            _username = unverified.get("username")
            _sub = unverified.get("sub")
        except Exception:
            _sub = None

        # Record activity for invalid token if we can resolve a user
        if _username and _sub:
            collection = get_collection()
            user_doc = await collection.find_one({"_id": _sub}, {"audit_disabled": 1})
            audit_disabled = user_doc.get("audit_disabled", False) if user_doc else False
            if not audit_disabled:
                creator_id: Optional[str] = None
                try:
                    creator = await collection.find_one(
                        {"created_usernames": _username}, {"_id": 1}
                    )
                    if creator:
                        creator_id = creator["_id"]
                except Exception:
                    pass
                await _record_activity_attempt(
                    username=_username,
                    endpoint=endpoint_name,
                    result=ActivityAttemptResult.FAILURE,
                    failure_reason=ActivityAttemptFailureReason.INVALID_TOKEN.value,
                    owner_user_id=_sub,
                    creator_user_id=creator_id,
                    ip_address=ip,
                    locale=locale,
                    origin=_origin,
                )

        return VerifyResponse(
            valid=False,
            subject=None,
            username=None,
            issuedAt=None,
            expiresAt=None,
        )
    
    # Valid token - extract claims and record success
    username = payload.get("username")
    user_id = payload.get("sub")

    if username and user_id:
        collection = get_collection()
        user_doc = await collection.find_one({"_id": user_id}, {"audit_disabled": 1})
        audit_disabled = user_doc.get("audit_disabled", False) if user_doc else False
        if not audit_disabled:
            creator_id_s: Optional[str] = None
            try:
                creator = await collection.find_one(
                    {"created_usernames": username}, {"_id": 1}
                )
                if creator:
                    creator_id_s = creator["_id"]
            except Exception:
                pass
            await _record_activity_attempt(
                username=username,
                endpoint=endpoint_name,
                result=ActivityAttemptResult.SUCCESS,
                failure_reason=None,
                owner_user_id=user_id,
                creator_user_id=creator_id_s,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )

    return VerifyResponse(
        valid=True,
        subject=payload.get("sub"),
        username=payload.get("username"),
        issuedAt=payload.get("iat"),
        expiresAt=payload.get("exp"),
    )


# ── GET /activity-attempts ──────────────────────────────────────────────


@router.get(
    "/activity-attempts",
    response_model=ActivityAttemptsResponse,
    status_code=status.HTTP_200_OK,
    summary="Query activity audit log",
    description=(
        "Returns activity-attempt audit records sorted by timestamp DESC with "
        "cursor-based pagination.  Access-control rules:\n\n"
        "- **member**: own activity only.\n"
        "- **admin / superadmin**: own activity **plus** activity of users in "
        "their `createdUsernames` set.\n\n"
        "Optional filters: `username` (actor), `endpoint` (exact match), "
        "`result`, `from` (inclusive), `to` (exclusive)."
    ),
    responses={
        200: {"description": "Paginated activity attempts", "model": ActivityAttemptsResponse},
        401: {
            "description": "Missing/invalid token",
            "content": {
                "application/json": {
                    "example": {"code": "invalid_token", "message": "Invalid or expired token"}
                }
            },
        },
        403: {
            "description": "Forbidden or audit not available",
            "content": {
                "application/json": {
                    "examples": {
                        "access_denied": {
                            "summary": "Scope violation",
                            "value": {"code": "forbidden", "message": "Access denied"},
                        },
                        "audit_not_available": {
                            "summary": "Audit disabled for user",
                            "value": {
                                "code": "audit_not_available",
                                "message": "Activity audit data is not available for this user",
                            },
                        },
                    }
                }
            },
        },
    },
)
async def get_activity_attempts(
    current_user: Dict = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200, description="Page size"),
    cursor: Optional[str] = Query(default=None, description="Opaque pagination cursor"),
    username: Optional[str] = Query(default=None, description="Filter by actor username"),
    endpoint: Optional[str] = Query(default=None, description="Filter by endpoint (exact match, e.g. 'POST /access-light/v1/auth/logout')"),
    result: Optional[str] = Query(default=None, description="Filter by result (success or failure)"),
    date_from: Optional[str] = Query(
        default=None, alias="from", description="Inclusive ISO-8601 start date"
    ),
    date_to: Optional[str] = Query(
        default=None, alias="to", description="Exclusive ISO-8601 end date"
    ),
) -> ActivityAttemptsResponse:
    """Return paginated activity-attempt audit records respecting access control."""

    role = current_user.get("role", "member")
    caller_id = current_user["_id"]
    is_privileged = role in (UserRole.ADMIN.value, UserRole.SUPERADMIN.value)

    caller_audit_disabled = current_user.get("audit_disabled", False)

    created_usernames: list[str] = []
    if is_privileged:
        created_usernames = current_user.get("created_usernames") or []

    # ── validate username filter against scope ───────────────────
    if username:
        own_username = current_user["username"]
        if username != own_username:
            if not is_privileged:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "forbidden",
                        "message": "Members can only query their own activity",
                    },
                )
            if username not in created_usernames:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "forbidden",
                        "message": "You can only query activity for users you created or yourself",
                    },
                )

    # ── validate result filter ───────────────────────────────────
    if result and result not in (ActivityAttemptResult.SUCCESS.value, ActivityAttemptResult.FAILURE.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_request",
                "message": f"Invalid result filter '{result}'. Allowed: success, failure",
            },
        )

    # ── audit-disabled checks ────────────────────────────────────
    collection = get_collection()

    if username:
        if username == current_user["username"]:
            target_audit_disabled = caller_audit_disabled
        else:
            target_user = await collection.find_one(
                {"username": username}, {"audit_disabled": 1}
            )
            target_audit_disabled = (
                target_user.get("audit_disabled", False) if target_user else False
            )
        if target_audit_disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "audit_not_available",
                    "message": "Activity audit data is not available for this user",
                },
            )
    else:
        if not is_privileged and caller_audit_disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "audit_not_available",
                    "message": "Activity audit data is not available for this user",
                },
            )

    # ── build MongoDB filter ─────────────────────────────────────
    query_filter: dict = {}

    if username:
        query_filter["username"] = username
    else:
        if is_privileged:
            allowed_usernames = [current_user["username"]] + list(created_usernames)
            query_filter["username"] = {"$in": allowed_usernames}
        else:
            query_filter["owner_user_id"] = caller_id

    if endpoint:
        query_filter["endpoint"] = endpoint

    if result:
        query_filter["result"] = result

    # ── date-range filters ───────────────────────────────────────
    ts_filter: dict = {}
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
            ts_filter["$gte"] = dt_from
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_request", "message": "Invalid 'from' date format"},
            )
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
            ts_filter["$lt"] = dt_to
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_request", "message": "Invalid 'to' date format"},
            )
    if ts_filter:
        query_filter["timestamp"] = ts_filter

    # ── cursor ───────────────────────────────────────────────────
    if cursor:
        cursor_ts, cursor_id = _decode_cursor(cursor)
        if cursor_ts is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_request", "message": "Invalid cursor"},
            )
        cursor_cond = {
            "$or": [
                {"timestamp": {"$lt": cursor_ts}},
                {"timestamp": cursor_ts, "_id": {"$lt": cursor_id}},
            ]
        }
        query_filter = {"$and": [query_filter, cursor_cond]}

    # ── execute query ────────────────────────────────────────────
    col = get_activity_attempts_collection()
    docs = (
        await col.find(query_filter)
        .sort([("timestamp", -1), ("_id", -1)])
        .limit(limit + 1)
        .to_list(length=limit + 1)
    )

    has_next = len(docs) > limit
    if has_next:
        docs = docs[:limit]

    next_cursor: Optional[str] = None
    if has_next and docs:
        last = docs[-1]
        next_cursor = _encode_cursor(last["timestamp"], last["_id"])

    items = [
        ActivityAttemptItem(
            username=d.get("username"),
            endpoint=d["endpoint"],
            result=d["result"],
            failureReason=d.get("failure_reason"),
            timestamp=datetime_to_iso_string(d["timestamp"]),
            ipAddress=d["ip_address"],
            locale=d.get("locale"),
            origin=d.get("origin"),
            targetUsername=d.get("target_username"),
            operation=d.get("operation"),
            itemsCount=d.get("items_count"),
        )
        for d in docs
    ]

    return ActivityAttemptsResponse(items=items, limit=limit, nextCursor=next_cursor)
