"""Login credential persistence and business logic."""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pymongo import ReturnDocument

from app.db import get_login_credentials_collection
from app.models import (
    LoginCredentialCreatedResponse,
    LoginCredentialResponse,
)
from app.security import (
    datetime_to_iso_string,
    generate_login_credential_secret,
    get_utc_now,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)


def _doc_to_response(doc: Dict[str, Any]) -> LoginCredentialResponse:
    last_login = doc.get("last_login_at")
    return LoginCredentialResponse(
        name=doc["name"],
        description=doc.get("description"),
        createdAt=datetime_to_iso_string(doc["created_at"]),
        updatedAt=datetime_to_iso_string(doc["updated_at"]),
        lastLoginAt=datetime_to_iso_string(last_login) if last_login else None,
    )


async def create_login_credential(
    user_id: str,
    name: str,
    description: Optional[str],
) -> Tuple[LoginCredentialCreatedResponse, bool]:
    """
    Create or replace a login credential for the user.

    If a credential with the same name exists, it is replaced with a new secret
    and last_login_at is reset.

    Returns:
        Tuple of (response with one-time secret, replaced_existing flag).
    """
    col = get_login_credentials_collection()
    now = get_utc_now()
    plaintext_secret = generate_login_credential_secret()
    secret_hash = hash_password(plaintext_secret)

    existing = await col.find_one({"user_id": user_id, "name": name})
    replaced = existing is not None

    doc = {
        "_id": existing["_id"] if existing else str(uuid.uuid4()),
        "user_id": user_id,
        "name": name,
        "description": description,
        "secret_hash": secret_hash,
        "created_at": existing["created_at"] if existing else now,
        "updated_at": now,
        "last_login_at": None,
    }

    if existing:
        await col.replace_one({"_id": existing["_id"]}, doc)
        logger.info("Replaced login credential '%s' for user %s", name, user_id)
    else:
        doc["created_at"] = now
        await col.insert_one(doc)
        logger.info("Created login credential '%s' for user %s", name, user_id)

    base = _doc_to_response(doc)
    return (
        LoginCredentialCreatedResponse(
            **base.model_dump(),
            secret=plaintext_secret,
        ),
        replaced,
    )


async def list_login_credentials(user_id: str) -> List[LoginCredentialResponse]:
    """List all login credentials for a user, sorted by name."""
    col = get_login_credentials_collection()
    cursor = col.find({"user_id": user_id}).sort("name", 1)
    docs = await cursor.to_list(length=500)
    return [_doc_to_response(d) for d in docs]


async def get_login_credential(
    user_id: str,
    name: str,
) -> Optional[LoginCredentialResponse]:
    """Retrieve a single login credential by name for the user."""
    col = get_login_credentials_collection()
    doc = await col.find_one({"user_id": user_id, "name": name})
    if not doc:
        return None
    return _doc_to_response(doc)


async def update_login_credential(
    user_id: str,
    name: str,
    description: Optional[str],
) -> Optional[LoginCredentialResponse]:
    """Update description on an existing login credential."""
    col = get_login_credentials_collection()
    now = get_utc_now()
    result = await col.find_one_and_update(
        {"user_id": user_id, "name": name},
        {"$set": {"description": description, "updated_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    if not result:
        return None
    return _doc_to_response(result)


async def delete_login_credential(user_id: str, name: str) -> bool:
    """Delete a login credential. Returns True if a document was deleted."""
    col = get_login_credentials_collection()
    result = await col.delete_one({"user_id": user_id, "name": name})
    if result.deleted_count:
        logger.info("Deleted login credential '%s' for user %s", name, user_id)
    return result.deleted_count > 0


async def verify_login_credential_secret(
    user_id: str,
    secret: str,
) -> Optional[Dict[str, Any]]:
    """
    Find a login credential for the user whose secret matches.

    Returns:
        The matching credential document, or None.
    """
    col = get_login_credentials_collection()
    cursor = col.find({"user_id": user_id})
    async for doc in cursor:
        if verify_password(secret, doc["secret_hash"]):
            return doc
    return None


async def touch_login_credential_last_login(
    credential_id: str,
    login_time: Optional[datetime] = None,
) -> None:
    """Set last_login_at after a successful login with this credential."""
    col = get_login_credentials_collection()
    now = login_time or get_utc_now()
    await col.update_one(
        {"_id": credential_id},
        {"$set": {"last_login_at": now, "updated_at": now}},
    )
