"""Security utilities: password hashing, JWT creation/verification, user ID generation."""

import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.settings import settings

# Password hashing context using Argon2id (preferred) with bcrypt fallback
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,  # 3 iterations
    argon2__parallelism=4,  # 4 parallel threads
)


def generate_user_id() -> str:
    """
    Generate a unique user ID with usr_ prefix.
    
    Uses a ULID-like format: usr_ + timestamp + random.
    This is a simplified version that's monotonically increasing and collision-resistant.
    
    Returns:
        str: User ID like "usr_01HXYZ123ABC..."
    """
    # Get current timestamp in milliseconds
    timestamp = int(time.time() * 1000)
    
    # Generate random component (80 bits = 16 hex chars)
    random_part = secrets.token_hex(8)
    
    # Combine: timestamp (13 digits) + random (16 hex chars)
    # Format as base36-like string for compactness
    user_id = f"usr_{timestamp:013x}{random_part}"
    
    return user_id


def generate_login_credential_secret() -> str:
    """
    Generate a cryptographically secure login credential secret.

    Returns:
        str: URL-safe random secret (never logged).
    """
    return secrets.token_urlsafe(32)


def generate_random_password() -> str:
    """
    Generate a cryptographically secure random password for admin-initiated resets.

    Returns:
        str: URL-safe random password (22+ chars; never logged).
    """
    return secrets.token_urlsafe(16)


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.
    
    Args:
        password: Plain text password (never logged or stored).
        
    Returns:
        str: Hashed password with salt.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash using constant-time comparison.
    
    Args:
        plain_password: Plain text password to verify.
        hashed_password: Stored password hash.
        
    Returns:
        bool: True if password matches, False otherwise.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Handle invalid hash format gracefully
        return False


def create_access_token(user_id: str, username: str, role: str = "member") -> str:
    """
    Create a JWT access token with required claims.
    
    Args:
        user_id: User ID (sub claim).
        username: Username.
        role: User role.
        
    Returns:
        str: Encoded JWT token.
        
    Raises:
        ValueError: If JWT configuration is invalid.
    """
    now = int(time.time())
    expires_at = now + settings.jwt_expires_seconds
    
    # Build payload with required claims
    payload: Dict[str, Any] = {
        "jti": uuid.uuid4().hex,
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": now,
        "exp": expires_at,
    }
    
    # Add optional issuer/audience
    if settings.jwt_issuer:
        payload["iss"] = settings.jwt_issuer
    if settings.jwt_audience:
        payload["aud"] = settings.jwt_audience
    
    # Encode JWT
    if settings.jwt_algorithm.startswith("HS"):
        if not settings.jwt_secret:
            raise ValueError("JWT_SECRET is required for HMAC algorithms")
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    else:
        # For RS256/ES256, jwt_secret would contain the private key
        if not settings.jwt_secret:
            raise ValueError(f"JWT_SECRET (private key) is required for {settings.jwt_algorithm}")
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    
    return token


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token.
    
    Validates:
    - Signature
    - Algorithm (no alg=none)
    - Expiration
    - Issuer (if configured)
    - Audience (if configured)
    - Required claims: sub, username, iat, exp
    
    Args:
        token: JWT token to verify.
        
    Returns:
        Optional[Dict[str, Any]]: Decoded payload if valid, None otherwise.
    """
    try:
        # Build verification options
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "require_exp": True,
            "require_iat": True,
        }
        
        # Decode and verify
        if settings.jwt_algorithm.startswith("HS"):
            if not settings.jwt_secret:
                return None
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm],
                options=options,
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
            )
        else:
            # For RS256/ES256, jwt_secret contains the public key
            if not settings.jwt_secret:
                return None
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm],
                options=options,
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
            )
        
        # Verify required claims
        required_claims = ["sub", "username", "iat", "exp"]
        for claim in required_claims:
            if claim not in payload:
                return None
        
        # Reject alg=none
        if payload.get("alg") == "none":
            return None
        
        return payload
        
    except JWTError:
        return None
    except Exception:
        return None


async def verify_token_with_revocation(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify a JWT token including revocation checks.

    After standard signature/algorithm/exp/iat/iss/aud validation,
    performs two additional checks:
    1. jti blacklist – rejects the token if its jti appears in revoked_tokens.
    2. Per-user revokeBefore – rejects the token if iat < user.revoke_before.

    Returns:
        Optional[Dict[str, Any]]: Decoded payload if valid and not revoked, None otherwise.
    """
    payload = verify_token(token)
    if not payload:
        return None

    from app.db import get_revoked_tokens_collection, get_collection

    jti = payload.get("jti")
    if jti:
        revoked_col = get_revoked_tokens_collection()
        revoked = await revoked_col.find_one({"jti": jti}, {"_id": 1})
        if revoked:
            return None

    # Per-user revokeBefore check
    user_id = payload.get("sub")
    iat = payload.get("iat")
    if user_id and iat:
        users_col = get_collection()
        user_doc = await users_col.find_one({"_id": user_id}, {"revoke_before": 1})
        if user_doc:
            revoke_before = user_doc.get("revoke_before")
            if revoke_before is not None:
                # revoke_before is stored as a datetime; compare against iat (unix ts)
                revoke_ts = int(revoke_before.timestamp())
                if iat < revoke_ts:
                    return None

    return payload


def get_utc_now() -> datetime:
    """
    Get current UTC datetime.
    
    Returns:
        datetime: Current UTC time with timezone info.
    """
    return datetime.now(timezone.utc)


def datetime_to_iso_string(dt: datetime) -> str:
    """
    Convert datetime to ISO-8601 string with Z suffix.
    
    Args:
        dt: Datetime object (should be UTC).
        
    Returns:
        str: ISO string like "2026-01-15T21:00:00Z"
    """
    # Ensure UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    
    # Format as ISO with Z
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
