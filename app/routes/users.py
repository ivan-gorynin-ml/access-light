"""User management routes: create, get current user, change password."""

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pymongo.errors import DuplicateKeyError

from app.db import get_collection
from app.deps import get_current_user, require_admin_or_superadmin
from app.models import (
    AdminPasswordResetResponse,
    AuditMode,
    CreatedUserItem,
    PasswordChangeRequest,
    UserCreateRequest,
    UserMeResponse,
    UserResponse,
    UserRole,
)
from app.routes.auth import (
    ActivityAttemptResult,
    _extract_client_ip,
    _extract_locale,
    _record_activity_attempt,
)
from app.security import (
    datetime_to_iso_string,
    generate_random_password,
    generate_user_id,
    get_utc_now,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/access-light/v1/users", tags=["Users"])


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user (admin/superadmin only)",
    description=(
        "Creates a new user with a securely hashed password "
        "(using Argon2id; never store plaintext). "
        "Only admin or superadmin users can create other users. "
        "The superadmin role cannot be assigned via this endpoint. "
        "Returns the created user. On username conflict return 409.\n\n"
        "**Server-side behaviour (no request changes):** When an authenticated "
        "user with role admin or superadmin successfully creates a new user "
        "(HTTP 201), the system automatically appends the newly created "
        "username to a persistent per-creator list `createdUsernames` "
        "associated with the creator account (usernames only, append-only, "
        "deduplicated for idempotency and retry safety). This list is "
        "returned exclusively via `GET /users/me` inside the "
        "`UserMeResponse` schema and is **not** included in the "
        "`UserResponse` returned by this endpoint. The feature does not "
        "alter authentication, authorization, JWT contents, validation "
        "rules, existing field requirements, or introduce any new "
        "required fields, endpoints, security schemes, or breaking "
        "changes to existing clients, SDKs, or schema consumers."
    ),
    responses={
        201: {
            "description": "User created",
            "model": UserResponse,
        },
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
        403: {
            "description": "Insufficient permissions",
            "content": {
                "application/json": {
                    "example": {
                        "code": "forbidden",
                        "message": "Only admin or superadmin users can perform this action",
                    }
                }
            },
        },
        409: {
            "description": "Username already exists",
            "content": {
                "application/json": {
                    "example": {
                        "code": "username_exists",
                        "message": "Username already exists",
                    }
                }
            },
        },
        400: {
            "description": "Validation error",
            "content": {
                "application/json": {
                    "example": {
                        "code": "validation_error",
                        "message": "Invalid request data",
                    }
                }
            },
        },
    },
)
async def create_user(
    request: UserCreateRequest,
    raw_request: Request,
    current_user: Dict = Depends(require_admin_or_superadmin),
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
) -> UserResponse:
    """
    Create a new user with hashed password.
    
    Security notes:
    - Only admin or superadmin users can create other users
    - The superadmin role cannot be assigned via REST API
    - Password is hashed using Argon2id before storage
    - Password never logged or stored in plaintext
    - Username uniqueness enforced by MongoDB unique index
    """
    ip = _extract_client_ip(raw_request)
    locale = _extract_locale(raw_request)
    endpoint_name = "POST /access-light/v1/users"
    caller_audit_disabled = current_user.get("audit_disabled", False)
    _origin = origin if origin is not None else "app UI"

    # Resolve creator_id for activity audit (the creator's own creator)
    caller_creator_id: Optional[str] = None
    if not caller_audit_disabled:
        try:
            _col = get_collection()
            _creator = await _col.find_one(
                {"created_usernames": current_user["username"]},
                {"_id": 1},
            )
            if _creator:
                caller_creator_id = _creator["_id"]
        except Exception:
            pass

    # Determine role: default to "member" if not specified
    role = request.role if request.role else UserRole.MEMBER.value

    # Block superadmin creation via REST
    if role == UserRole.SUPERADMIN.value:
        if not caller_audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="forbidden",
                owner_user_id=current_user["_id"],
                creator_user_id=caller_creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "forbidden",
                "message": "Cannot create users with superadmin role via API",
            },
        )

    # Validate that role is a known value
    if role not in (UserRole.MEMBER.value, UserRole.ADMIN.value):
        if not caller_audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="validation_error",
                owner_user_id=current_user["_id"],
                creator_user_id=caller_creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "validation_error",
                "message": f"Invalid role '{role}'. Allowed roles: member, admin",
            },
        )

    # Resolve audit mode (default: standard)
    audit_mode = request.auditMode if request.auditMode else AuditMode.STANDARD.value
    if audit_mode not in (AuditMode.STANDARD.value, AuditMode.NONE.value):
        if not caller_audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="validation_error",
                owner_user_id=current_user["_id"],
                creator_user_id=caller_creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "validation_error",
                "message": f"Invalid auditMode '{audit_mode}'. Allowed values: standard, none",
            },
        )
    audit_disabled = audit_mode == AuditMode.NONE.value

    collection = get_collection()
    
    # Generate unique user ID
    user_id = generate_user_id()
    
    # Hash password (NEVER store plaintext)
    password_hash = hash_password(request.password)
    
    # Prepare user document
    now = get_utc_now()
    user_doc = {
        "_id": user_id,
        "username": request.username,
        "email": request.email,
        "password_hash": password_hash,
        "role": role,
        "created_at": now,
    }
    if audit_disabled:
        user_doc["audit_disabled"] = True
    
    # Insert user
    try:
        await collection.insert_one(user_doc)
        logger.info(f"Created user: {request.username} (ID: {user_id})")
    except DuplicateKeyError:
        logger.warning(f"Username already exists: {request.username}")
        if not caller_audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="username_exists",
                owner_user_id=current_user["_id"],
                creator_user_id=caller_creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "username_exists",
                "message": "Username already exists",
            },
        )
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        if not caller_audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="other",
                owner_user_id=current_user["_id"],
                creator_user_id=caller_creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "database_error",
                "message": "Failed to create user",
            },
        )

    # Append newly created username to the creator's createdUsernames list.
    # Uses $addToSet for deduplication (idempotency / retry safety).
    try:
        await collection.update_one(
            {"_id": current_user["_id"]},
            {"$addToSet": {"created_usernames": request.username}},
        )
        logger.info(
            f"Appended '{request.username}' to created_usernames of "
            f"user '{current_user['username']}'"
        )
    except Exception as e:
        # Non-fatal: the user was already created; log and continue.
        logger.error(
            f"Failed to update created_usernames for "
            f"'{current_user['username']}': {e}"
        )

    # Record successful user creation activity
    if not caller_audit_disabled:
        await _record_activity_attempt(
            username=current_user["username"],
            endpoint=endpoint_name,
            result=ActivityAttemptResult.SUCCESS,
            failure_reason=None,
            owner_user_id=current_user["_id"],
            creator_user_id=caller_creator_id,
            ip_address=ip,
            locale=locale,
            origin=_origin,
        )

    # Return user response (no password_hash)
    return UserResponse(
        id=user_id,
        username=request.username,
        email=request.email,
        role=role,
        createdAt=datetime_to_iso_string(now),
    )


@router.get(
    "/me",
    response_model=UserMeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user",
    description=(
        "Returns the currently authenticated user based on the verified JWT "
        "in Authorization header. Server verifies signature, exp, and any iss/aud "
        "before trusting claims.\n\n"
        "The response uses the `UserMeResponse` schema which extends "
        "`UserResponse` with **createdUsers** (admin/superadmin only): an array "
        "of objects, each containing `user` (full UserResponse)."
    ),
    responses={
        200: {
            "description": "Current user",
            "model": UserMeResponse,
        },
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
async def get_me(
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
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
) -> UserMeResponse:
    """
    Get current authenticated user.

    Requires valid JWT in Authorization header.
    Returns UserMeResponse which includes createdUsers for admin/superadmin.
    """
    role = current_user.get("role", "member")
    _origin = origin if origin is not None else "app UI"

    # ── Admin/Superadmin: build createdUsers ─────────────────────
    created_users_list: Optional[list[CreatedUserItem]] = None
    if role in (UserRole.ADMIN.value, UserRole.SUPERADMIN.value):
        created_usernames = current_user.get("created_usernames") or []

        created_user_docs: list[Dict] = []
        if created_usernames:
            try:
                collection = get_collection()
                async for udoc in collection.find(
                    {"username": {"$in": created_usernames}}
                ):
                    created_user_docs.append(udoc)
            except Exception as e:
                logger.warning(f"Failed to fetch created users for '{current_user['username']}': {e}")

        created_users_list = []
        for udoc in created_user_docs:
            user_resp = UserResponse(
                id=udoc["_id"],
                username=udoc["username"],
                email=udoc.get("email"),
                role=udoc.get("role", "member"),
                createdAt=datetime_to_iso_string(udoc["created_at"]),
            )
            created_users_list.append(CreatedUserItem(user=user_resp))

    # Record activity attempt (only if audit is not disabled)
    audit_disabled = current_user.get("audit_disabled", False)
    if not audit_disabled:
        ip = _extract_client_ip(raw_request)
        locale = _extract_locale(raw_request)
        creator_id: Optional[str] = None
        try:
            collection = get_collection()
            creator = await collection.find_one(
                {"created_usernames": current_user["username"]},
                {"_id": 1},
            )
            if creator:
                creator_id = creator["_id"]
        except Exception:
            pass
        await _record_activity_attempt(
            username=current_user["username"],
            endpoint="GET /access-light/v1/users/me",
            result=ActivityAttemptResult.SUCCESS,
            failure_reason=None,
            owner_user_id=current_user["_id"],
            creator_user_id=creator_id,
            ip_address=ip,
            locale=locale,
            origin=_origin,
        )

    return UserMeResponse(
        id=current_user["_id"],
        username=current_user["username"],
        email=current_user.get("email"),
        role=role,
        createdAt=datetime_to_iso_string(current_user["created_at"]),
        createdUsers=created_users_list,
    )


@router.post(
    "/me/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change password",
    description=(
        "Authenticated endpoint to change the current user password. "
        "Requires valid JWT plus correct oldPassword; server verifies oldPassword "
        "against stored hash, then replaces with hash(newPassword). "
        "Returns 204 on success."
    ),
    responses={
        204: {
            "description": "Password changed (no content)",
        },
        400: {
            "description": "Validation error",
            "content": {
                "application/json": {
                    "example": {
                        "code": "validation_error",
                        "message": "Invalid request data",
                    }
                }
            },
        },
        401: {
            "description": "Missing/invalid token or wrong oldPassword",
            "content": {
                "application/json": {
                    "example": {
                        "code": "invalid_credentials",
                        "message": "Invalid old password",
                    }
                }
            },
        },
    },
)
async def change_password(
    request: PasswordChangeRequest,
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
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
    Change current user's password.
    
    Security notes:
    - Requires valid JWT authentication
    - Verifies old password with constant-time comparison
    - Hashes new password with Argon2id
    - Updates password_changed_at timestamp
    - Invalidates all active sessions by setting revoke_before
    """
    collection = get_collection()
    ip = _extract_client_ip(raw_request)
    locale = _extract_locale(raw_request)
    endpoint_name = "POST /access-light/v1/users/me/password"
    audit_disabled = current_user.get("audit_disabled", False)
    _origin = origin if origin is not None else "app UI"

    # Resolve creator_id for activity audit
    creator_id: Optional[str] = None
    if not audit_disabled:
        try:
            creator = await collection.find_one(
                {"created_usernames": current_user["username"]},
                {"_id": 1},
            )
            if creator:
                creator_id = creator["_id"]
        except Exception:
            pass
    
    # Verify old password
    if not verify_password(request.oldPassword, current_user["password_hash"]):
        logger.warning(f"Failed password change for user: {current_user['username']}")
        if not audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="wrong_old_password",
                owner_user_id=current_user["_id"],
                creator_user_id=creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_credentials",
                "message": "Invalid old password",
            },
        )
    
    # Hash new password
    new_password_hash = hash_password(request.newPassword)
    
    # Update password in database and set revoke_before to invalidate
    # all tokens issued before this moment.
    try:
        now = get_utc_now()
        result = await collection.update_one(
            {"_id": current_user["_id"]},
            {
                "$set": {
                    "password_hash": new_password_hash,
                    "password_changed_at": now,
                    "revoke_before": now,
                }
            },
        )
        
        if result.modified_count == 0:
            logger.error(f"Password update failed for user: {current_user['username']}")
            if not audit_disabled:
                await _record_activity_attempt(
                    username=current_user["username"],
                    endpoint=endpoint_name,
                    result=ActivityAttemptResult.FAILURE,
                    failure_reason="other",
                    owner_user_id=current_user["_id"],
                    creator_user_id=creator_id,
                    ip_address=ip,
                    locale=locale,
                    origin=_origin,
                )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": "update_failed",
                    "message": "Failed to update password",
                },
            )
        
        logger.info(f"Password changed for user: {current_user['username']}")

        # Record success activity
        if not audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.SUCCESS,
                failure_reason=None,
                owner_user_id=current_user["_id"],
                creator_user_id=creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during password change: {e}")
        if not audit_disabled:
            await _record_activity_attempt(
                username=current_user["username"],
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason="other",
                owner_user_id=current_user["_id"],
                creator_user_id=creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "database_error",
                "message": "Failed to update password",
            },
        )


@router.post(
    "/{username}/password-reset",
    response_model=AdminPasswordResetResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset password for a created member user (admin/superadmin only)",
    description=(
        "Generates a new secure password on the server, sets it for the target "
        "member user, and returns the plaintext password **once** in the response. "
        "The caller must be admin or superadmin and must have created the target "
        "user (username in caller's createdUsernames). The target user must have "
        "role **member**. All existing sessions for the target user are invalidated."
    ),
    responses={
        200: {
            "description": "Password reset; new password returned once",
            "model": AdminPasswordResetResponse,
        },
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
        403: {
            "description": "Insufficient permissions",
            "content": {
                "application/json": {
                    "example": {
                        "code": "forbidden",
                        "message": "Only admin or superadmin users can perform this action",
                    }
                }
            },
        },
        404: {
            "description": "Target user not found or not created by caller",
            "content": {
                "application/json": {
                    "example": {
                        "code": "user_not_found",
                        "message": "User 'alice' not found",
                    }
                }
            },
        },
        400: {
            "description": "Target user is not a member",
            "content": {
                "application/json": {
                    "example": {
                        "code": "user_not_member",
                        "message": "User 'alice' is not a member user",
                    }
                }
            },
        },
    },
)
async def reset_member_password(
    username: str,
    raw_request: Request,
    current_user: Dict = Depends(require_admin_or_superadmin),
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
) -> AdminPasswordResetResponse:
    """Reset password for a member user created by the caller."""
    caller_id = current_user["_id"]
    caller_username = current_user["username"]
    created_usernames_set = set(current_user.get("created_usernames") or [])
    collection = get_collection()

    endpoint_name = f"POST /access-light/v1/users/{username}/password-reset"
    _origin = origin if origin is not None else "app UI"
    ip = _extract_client_ip(raw_request)
    locale = _extract_locale(raw_request)
    caller_audit_disabled = current_user.get("audit_disabled", False)

    caller_creator_id: Optional[str] = None
    if not caller_audit_disabled:
        try:
            _creator = await collection.find_one(
                {"created_usernames": caller_username},
                {"_id": 1},
            )
            if _creator:
                caller_creator_id = _creator["_id"]
        except Exception:
            pass

    async def _audit_failure(failure_reason: str) -> None:
        if not caller_audit_disabled:
            await _record_activity_attempt(
                username=caller_username,
                endpoint=endpoint_name,
                result=ActivityAttemptResult.FAILURE,
                failure_reason=failure_reason,
                owner_user_id=caller_id,
                creator_user_id=caller_creator_id,
                ip_address=ip,
                locale=locale,
                origin=_origin,
                target_username=username,
                operation="password_reset",
            )

    if username not in created_usernames_set:
        await _audit_failure("user_not_found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "user_not_found",
                "message": f"User '{username}' not found",
            },
        )

    target_user = await collection.find_one({"username": username})
    if not target_user:
        await _audit_failure("user_not_found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "user_not_found",
                "message": f"User '{username}' not found",
            },
        )

    if target_user.get("role", "member") != UserRole.MEMBER.value:
        await _audit_failure("user_not_member")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "user_not_member",
                "message": f"User '{username}' is not a member user",
            },
        )

    new_password = generate_random_password()
    new_password_hash = hash_password(new_password)
    now = get_utc_now()

    try:
        result = await collection.update_one(
            {"_id": target_user["_id"]},
            {
                "$set": {
                    "password_hash": new_password_hash,
                    "password_changed_at": now,
                    "revoke_before": now,
                }
            },
        )
        if result.modified_count == 0:
            logger.error(f"Password reset update failed for user: {username}")
            await _audit_failure("other")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": "update_failed",
                    "message": "Failed to reset password",
                },
            )
        logger.info(
            f"Password reset by '{caller_username}' for member user '{username}'"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during password reset for '{username}': {e}")
        await _audit_failure("other")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "database_error",
                "message": "Failed to reset password",
            },
        )

    if not caller_audit_disabled:
        await _record_activity_attempt(
            username=caller_username,
            endpoint=endpoint_name,
            result=ActivityAttemptResult.SUCCESS,
            failure_reason=None,
            owner_user_id=caller_id,
            creator_user_id=caller_creator_id,
            ip_address=ip,
            locale=locale,
            origin=_origin,
            target_username=username,
            operation="password_reset",
        )

    return AdminPasswordResetResponse(username=username, password=new_password)
