"""Login credential CRUD routes (scoped to the authenticated user)."""

import logging
from typing import Annotated, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.deps import get_current_user
from app.models import (
    LoginCredentialCreateRequest,
    LoginCredentialCreatedResponse,
    LoginCredentialResponse,
    LoginCredentialUpdateRequest,
    LoginCredentialsListResponse,
)
from app.routes.auth import (
    ActivityAttemptResult,
    _extract_client_ip,
    _extract_locale,
    _record_activity_attempt,
)
from app.services import login_credentials as lc_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/access-light/v1/users/me/login-credentials",
    tags=["Login credentials"],
)

_BASE = "/access-light/v1/users/me/login-credentials"

_ORIGIN_QUERY = Query(
    default="app UI",
    description=(
        "Optional request origin identifier for activity audit correlation "
        "(e.g. 'app UI', 'mobile'). Does not affect authorization or responses."
    ),
)

_CREDENTIAL_NAME_PATH = Path(
    ...,
    min_length=1,
    max_length=128,
    description=(
        "Login credential name (URL-encoded if needed). Matched after trimming; "
        "must belong to the authenticated user."
    ),
    examples=["mobile-app"],
)

_RESPONSES_AUTH = {
    401: {
        "description": "Missing or invalid Bearer token",
        "content": {
            "application/json": {
                "example": {
                    "code": "invalid_token",
                    "message": "Invalid or expired token",
                }
            }
        },
    },
}

_RESPONSES_VALIDATION = {
    400: {
        "description": "Validation error (e.g. empty name)",
        "content": {
            "application/json": {
                "example": {
                    "code": "validation_error",
                    "message": "Validation error: name: name must be non-empty after trimming",
                }
            }
        },
    },
}

_RESPONSES_NOT_FOUND = {
    404: {
        "description": "Login credential not found for this user",
        "content": {
            "application/json": {
                "example": {
                    "code": "not_found",
                    "message": "Login credential not found",
                }
            }
        },
    },
}


async def _resolve_creator_id(username: str) -> Optional[str]:
    from app.db import get_collection

    try:
        creator = await get_collection().find_one(
            {"created_usernames": username},
            {"_id": 1},
        )
        if creator:
            return creator["_id"]
    except Exception:
        pass
    return None


async def _audit_activity(
    *,
    current_user: Dict,
    endpoint: str,
    result: ActivityAttemptResult,
    failure_reason: Optional[str],
    raw_request: Request,
    origin: str,
) -> None:
    if current_user.get("audit_disabled", False):
        return
    creator_id = await _resolve_creator_id(current_user["username"])
    await _record_activity_attempt(
        username=current_user["username"],
        endpoint=endpoint,
        result=result,
        failure_reason=failure_reason,
        owner_user_id=current_user["_id"],
        creator_user_id=creator_id,
        ip_address=_extract_client_ip(raw_request),
        locale=_extract_locale(raw_request),
        origin=origin,
    )


@router.post(
    "",
    response_model=LoginCredentialCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or replace a login credential",
    description=(
        "Creates an app-generated login credential for the authenticated user.\n\n"
        "- **Secret generation:** The server generates a cryptographically secure secret; "
        "clients must not supply one. Only a hash is persisted.\n"
        "- **One-time disclosure:** The plaintext ``secret`` is returned **only** in this "
        "response (and never in list/get/update).\n"
        "- **Replace by name:** If ``name`` already exists for this user, the previous "
        "credential is replaced: new secret, ``lastLoginAt`` reset to null, "
        "``updatedAt`` refreshed.\n"
        "- **Naming:** ``name`` is required, trimmed, non-empty, and unique per user.\n\n"
        "Use the returned secret as the ``password`` field in ``POST /v1/auth/login`` "
        "together with the account ``username``."
    ),
    responses={
        201: {
            "description": "Credential created or replaced",
            "model": LoginCredentialCreatedResponse,
        },
        **_RESPONSES_AUTH,
        **_RESPONSES_VALIDATION,
        500: {
            "description": "Failed to persist credential",
            "content": {
                "application/json": {
                    "example": {
                        "code": "internal_error",
                        "message": "Failed to create login credential",
                    }
                }
            },
        },
    },
)
async def create_login_credential(
    request: LoginCredentialCreateRequest,
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
    origin: Optional[str] = _ORIGIN_QUERY,
) -> LoginCredentialCreatedResponse:
    _origin = origin if origin is not None else "app UI"
    endpoint = f"POST {_BASE}"

    try:
        response, _replaced = await lc_service.create_login_credential(
            user_id=current_user["_id"],
            name=request.name,
            description=request.description,
        )
    except Exception as exc:
        logger.error("Failed to create login credential: %s", exc)
        await _audit_activity(
            current_user=current_user,
            endpoint=endpoint,
            result=ActivityAttemptResult.FAILURE,
            failure_reason="other",
            raw_request=raw_request,
            origin=_origin,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "internal_error",
                "message": "Failed to create login credential",
            },
        ) from exc

    await _audit_activity(
        current_user=current_user,
        endpoint=endpoint,
        result=ActivityAttemptResult.SUCCESS,
        failure_reason=None,
        raw_request=raw_request,
        origin=_origin,
    )
    return response


@router.get(
    "",
    response_model=LoginCredentialsListResponse,
    status_code=status.HTTP_200_OK,
    summary="List login credentials",
    description=(
        "Returns all login credentials owned by the authenticated user, sorted by name. "
        "Secrets and hashes are never included."
    ),
    responses={
        200: {
            "description": "Credential list",
            "model": LoginCredentialsListResponse,
        },
        **_RESPONSES_AUTH,
    },
)
async def list_login_credentials(
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
    origin: Optional[str] = _ORIGIN_QUERY,
) -> LoginCredentialsListResponse:
    _origin = origin if origin is not None else "app UI"
    endpoint = f"GET {_BASE}"

    items = await lc_service.list_login_credentials(current_user["_id"])
    await _audit_activity(
        current_user=current_user,
        endpoint=endpoint,
        result=ActivityAttemptResult.SUCCESS,
        failure_reason=None,
        raw_request=raw_request,
        origin=_origin,
    )
    return LoginCredentialsListResponse(items=items)


@router.get(
    "/{name}",
    response_model=LoginCredentialResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a login credential",
    description=(
        "Returns a single login credential by name for the authenticated user. "
        "The secret and stored hash are never returned."
    ),
    responses={
        200: {
            "description": "Credential metadata",
            "model": LoginCredentialResponse,
        },
        **_RESPONSES_AUTH,
        **_RESPONSES_VALIDATION,
        **_RESPONSES_NOT_FOUND,
    },
)
async def get_login_credential(
    name: Annotated[str, _CREDENTIAL_NAME_PATH],
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
    origin: Optional[str] = _ORIGIN_QUERY,
) -> LoginCredentialResponse:
    _origin = origin if origin is not None else "app UI"
    endpoint = f"GET {_BASE}/{{name}}"
    trimmed = name.strip()
    if not trimmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "validation_error", "message": "name must be non-empty"},
        )

    cred = await lc_service.get_login_credential(current_user["_id"], trimmed)
    if not cred:
        await _audit_activity(
            current_user=current_user,
            endpoint=endpoint,
            result=ActivityAttemptResult.FAILURE,
            failure_reason="not_found",
            raw_request=raw_request,
            origin=_origin,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "not_found",
                "message": "Login credential not found",
            },
        )

    await _audit_activity(
        current_user=current_user,
        endpoint=endpoint,
        result=ActivityAttemptResult.SUCCESS,
        failure_reason=None,
        raw_request=raw_request,
        origin=_origin,
    )
    return cred


@router.patch(
    "/{name}",
    response_model=LoginCredentialResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a login credential",
    description=(
        "Updates the optional ``description`` of a login credential. "
        "The name and secret cannot be changed via this endpoint; use "
        "``POST /login-credentials`` with the same name to rotate the secret."
    ),
    responses={
        200: {
            "description": "Updated credential metadata",
            "model": LoginCredentialResponse,
        },
        **_RESPONSES_AUTH,
        **_RESPONSES_VALIDATION,
        **_RESPONSES_NOT_FOUND,
    },
)
async def update_login_credential(
    name: Annotated[str, _CREDENTIAL_NAME_PATH],
    request: LoginCredentialUpdateRequest,
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
    origin: Optional[str] = _ORIGIN_QUERY,
) -> LoginCredentialResponse:
    _origin = origin if origin is not None else "app UI"
    endpoint = f"PATCH {_BASE}/{{name}}"
    trimmed = name.strip()
    if not trimmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "validation_error", "message": "name must be non-empty"},
        )

    cred = await lc_service.update_login_credential(
        current_user["_id"],
        trimmed,
        request.description,
    )
    if not cred:
        await _audit_activity(
            current_user=current_user,
            endpoint=endpoint,
            result=ActivityAttemptResult.FAILURE,
            failure_reason="not_found",
            raw_request=raw_request,
            origin=_origin,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "not_found",
                "message": "Login credential not found",
            },
        )

    await _audit_activity(
        current_user=current_user,
        endpoint=endpoint,
        result=ActivityAttemptResult.SUCCESS,
        failure_reason=None,
        raw_request=raw_request,
        origin=_origin,
    )
    return cred


@router.delete(
    "/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a login credential",
    description=(
        "Permanently deletes a login credential by name for the authenticated user. "
        "The secret immediately stops working for login."
    ),
    responses={
        204: {"description": "Credential deleted (no content)"},
        **_RESPONSES_AUTH,
        **_RESPONSES_VALIDATION,
        **_RESPONSES_NOT_FOUND,
    },
)
async def delete_login_credential(
    name: Annotated[str, _CREDENTIAL_NAME_PATH],
    raw_request: Request,
    current_user: Dict = Depends(get_current_user),
    origin: Optional[str] = _ORIGIN_QUERY,
) -> None:
    _origin = origin if origin is not None else "app UI"
    endpoint = f"DELETE {_BASE}/{{name}}"
    trimmed = name.strip()
    if not trimmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "validation_error", "message": "name must be non-empty"},
        )

    deleted = await lc_service.delete_login_credential(current_user["_id"], trimmed)
    if not deleted:
        await _audit_activity(
            current_user=current_user,
            endpoint=endpoint,
            result=ActivityAttemptResult.FAILURE,
            failure_reason="not_found",
            raw_request=raw_request,
            origin=_origin,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "not_found",
                "message": "Login credential not found",
            },
        )

    await _audit_activity(
        current_user=current_user,
        endpoint=endpoint,
        result=ActivityAttemptResult.SUCCESS,
        failure_reason=None,
        raw_request=raw_request,
        origin=_origin,
    )
