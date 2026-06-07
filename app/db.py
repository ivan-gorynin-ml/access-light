"""MongoDB connection and initialization using Motor (async driver)."""

import logging
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError, OperationFailure

from app.settings import settings

logger = logging.getLogger(__name__)

# Global client instance
_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None
_collection: Optional[AsyncIOMotorCollection] = None
_login_attempts_collection: Optional[AsyncIOMotorCollection] = None
_revoked_tokens_collection: Optional[AsyncIOMotorCollection] = None
_activity_attempts_collection: Optional[AsyncIOMotorCollection] = None
_login_credentials_collection: Optional[AsyncIOMotorCollection] = None


async def connect_db() -> None:
    """
    Connect to MongoDB and create required indexes.
    
    Raises:
        Exception: If connection or index creation fails.
    """
    global _client, _db, _collection, _login_attempts_collection, _revoked_tokens_collection, _activity_attempts_collection, _login_credentials_collection

    try:
        logger.info(f"Connecting to MongoDB: {settings.mongodb_url}")
        _client = AsyncIOMotorClient(
            settings.mongodb_url,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )

        # Verify connection
        await _client.admin.command("ping")
        logger.info("MongoDB connection successful")

        _db = _client[settings.database_name]
        _collection = _db[settings.collection_name]

        # Create unique index on username
        logger.info(f"Creating unique index on username in {settings.collection_name}")
        await _collection.create_index("username", unique=True)
        logger.info("Index creation successful")

        # Initialise login_attempts collection and indexes
        _login_attempts_collection = _db[settings.login_attempts_collection_name]
        await _login_attempts_collection.create_index(
            [("timestamp", -1)],
            name="idx_timestamp_desc",
        )
        await _login_attempts_collection.create_index(
            [("owner_user_id", 1), ("timestamp", -1)],
            name="idx_owner_ts",
        )
        await _login_attempts_collection.create_index(
            [("attempted_username", 1), ("timestamp", -1)],
            name="idx_username_ts",
        )
        logger.info("login_attempts collection indexes created")

        # Initialise revoked_tokens collection and indexes
        _revoked_tokens_collection = _db[settings.revoked_tokens_collection_name]
        await _revoked_tokens_collection.create_index(
            "jti",
            unique=True,
            name="idx_jti_unique",
        )
        # TTL index: MongoDB automatically deletes documents once expiresAt passes
        await _revoked_tokens_collection.create_index(
            "expiresAt",
            expireAfterSeconds=0,
            name="idx_expires_ttl",
        )
        logger.info("revoked_tokens collection indexes created")

        # Initialise activity_attempts collection and indexes
        _activity_attempts_collection = _db[settings.activity_attempts_collection_name]
        await _activity_attempts_collection.create_index(
            [("timestamp", -1)],
            name="idx_activity_ts_desc",
        )
        await _activity_attempts_collection.create_index(
            [("username", 1), ("timestamp", -1)],
            name="idx_activity_username_ts",
        )
        await _activity_attempts_collection.create_index(
            [("owner_user_id", 1), ("timestamp", -1)],
            name="idx_activity_owner_ts",
        )
        await _activity_attempts_collection.create_index(
            [("endpoint", 1), ("timestamp", -1)],
            name="idx_activity_endpoint_ts",
        )
        logger.info("activity_attempts collection indexes created")

        # Initialise login_credentials collection and indexes
        _login_credentials_collection = _db[settings.login_credentials_collection_name]
        await _login_credentials_collection.create_index(
            [("user_id", 1), ("name", 1)],
            unique=True,
            name="idx_login_cred_user_name_unique",
        )
        await _login_credentials_collection.create_index(
            [("user_id", 1), ("created_at", -1)],
            name="idx_login_cred_user_created",
        )
        logger.info("login_credentials collection indexes created")

    except Exception as e:
        logger.error(f"Failed to connect to MongoDB or create indexes: {e}")
        if _client:
            _client.close()
            _client = None
        raise


async def init_root_user() -> None:
    """
    Create or update the root superadmin user based on ROOT_LOGIN and ROOT_PASSWORD.

    If the user does not exist, creates it with role 'superadmin'.
    If the user exists, updates the password hash and ensures role is 'superadmin'.
    """
    from app.security import generate_user_id, get_utc_now, hash_password

    if _collection is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")

    root_login = settings.root_login
    root_password = settings.root_password

    password_hash = hash_password(root_password)

    existing = await _collection.find_one({"username": root_login})
    if existing:
        # Update password and ensure role is superadmin
        await _collection.update_one(
            {"_id": existing["_id"]},
            {"$set": {"password_hash": password_hash, "role": "superadmin"}},
        )
        logger.info(f"Root user '{root_login}' password and role updated")
    else:
        # Create root user
        user_id = generate_user_id()
        now = get_utc_now()
        root_doc = {
            "_id": user_id,
            "username": root_login,
            "email": None,
            "password_hash": password_hash,
            "role": "superadmin",
            "created_at": now,
        }
        await _collection.insert_one(root_doc)
        logger.info(f"Root user '{root_login}' created with superadmin role (ID: {user_id})")


async def close_db() -> None:
    """Close MongoDB connection."""
    global _client, _db, _collection, _login_attempts_collection, _revoked_tokens_collection, _activity_attempts_collection, _login_credentials_collection

    if _client:
        logger.info("Closing MongoDB connection")
        _client.close()
        _client = None
        _db = None
        _collection = None
        _login_attempts_collection = None
        _revoked_tokens_collection = None
        _activity_attempts_collection = None
        _login_credentials_collection = None


def get_collection() -> AsyncIOMotorCollection:
    """
    Get the users collection.
    
    Returns:
        AsyncIOMotorCollection: The users collection.
        
    Raises:
        RuntimeError: If database is not connected.
    """
    if _collection is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _collection


def get_database() -> AsyncIOMotorDatabase:
    """
    Get the database instance.
    
    Returns:
        AsyncIOMotorDatabase: The database instance.
        
    Raises:
        RuntimeError: If database is not connected.
    """
    if _db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _db


def get_login_attempts_collection() -> AsyncIOMotorCollection:
    """
    Get the login_attempts collection.

    Returns:
        AsyncIOMotorCollection: The login_attempts collection.

    Raises:
        RuntimeError: If database is not connected.
    """
    if _login_attempts_collection is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _login_attempts_collection


def get_revoked_tokens_collection() -> AsyncIOMotorCollection:
    """
    Get the revoked_tokens collection.

    Returns:
        AsyncIOMotorCollection: The revoked_tokens collection.

    Raises:
        RuntimeError: If database is not connected.
    """
    if _revoked_tokens_collection is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _revoked_tokens_collection


def get_activity_attempts_collection() -> AsyncIOMotorCollection:
    """
    Get the activity_attempts collection.

    Returns:
        AsyncIOMotorCollection: The activity_attempts collection.

    Raises:
        RuntimeError: If database is not connected.
    """
    if _activity_attempts_collection is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _activity_attempts_collection


def get_login_credentials_collection() -> AsyncIOMotorCollection:
    """
    Get the login_credentials collection.

    Returns:
        AsyncIOMotorCollection: The login_credentials collection.

    Raises:
        RuntimeError: If database is not connected.
    """
    if _login_credentials_collection is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _login_credentials_collection
