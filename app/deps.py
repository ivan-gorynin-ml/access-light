"""FastAPI dependencies for authentication and authorization."""

from typing import Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.db import get_collection
from app.models import UserDocument, UserRole
from app.security import verify_token_with_revocation

# Bearer token security scheme
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict:
    """
    Dependency to get the current authenticated user from JWT.
    
    Validates the Authorization header, verifies the JWT token,
    and fetches the user from the database.
    
    Args:
        credentials: HTTP Bearer token from Authorization header.
        
    Returns:
        Dict: User document from database.
        
    Raises:
        HTTPException: 401 if token is missing, invalid, expired, or user not found.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "missing_token",
                "message": "Authorization header with Bearer token is required",
            },
        )
    
    token = credentials.credentials
    
    # Verify token (includes revocation checks)
    payload = await verify_token_with_revocation(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_token",
                "message": "Invalid or expired token",
            },
        )
    
    # Extract user ID from sub claim
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_token",
                "message": "Token missing required sub claim",
            },
        )
    
    # Fetch user from database
    collection = get_collection()
    user = await collection.find_one({"_id": user_id})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "user_not_found",
                "message": "User associated with token not found",
            },
        )
    
    return user


async def require_admin_or_superadmin(
    current_user: Dict = Depends(get_current_user),
) -> Dict:
    """
    Dependency that ensures the current user has admin or superadmin role.

    Args:
        current_user: The authenticated user from get_current_user.

    Returns:
        Dict: User document if authorized.

    Raises:
        HTTPException: 403 if user does not have admin or superadmin role.
    """
    user_role = current_user.get("role", "member")
    if user_role not in (UserRole.ADMIN.value, UserRole.SUPERADMIN.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "forbidden",
                "message": "Only admin or superadmin users can perform this action",
            },
        )
    return current_user
