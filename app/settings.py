"""Application settings loaded from environment variables."""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from .env file and environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application metadata
    app_name: str = Field(default="access-light", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    log_level: str = Field(default="INFO", description="Logging level")

    # MongoDB configuration
    mongodb_url: str = Field(
        ...,
        description="MongoDB connection URL (required)",
    )
    database_name: str = Field(
        ...,
        description="MongoDB database name (required)",
    )

    # Root user configuration
    root_login: str = Field(
        ...,
        description="Root superadmin username (required)",
    )
    root_password: str = Field(
        ...,
        description="Root superadmin password (required)",
    )
    collection_name: str = Field(
        default="users",
        description="MongoDB collection name for users",
    )
    login_attempts_collection_name: str = Field(
        default="login_attempts",
        description="MongoDB collection name for login audit records",
    )
    revoked_tokens_collection_name: str = Field(
        default="revoked_tokens",
        description="MongoDB collection name for revoked JWT tokens",
    )
    activity_attempts_collection_name: str = Field(
        default="activity_attempts",
        description="MongoDB collection name for activity audit events",
    )
    login_credentials_collection_name: str = Field(
        default="login_credentials",
        description="MongoDB collection name for per-user login credential documents",
    )

    login_rate_limit: str = Field(
        default="30/minute",
        description="Rate limit for POST /auth/login (slowapi format)",
    )

    # JWT configuration
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256 or RS256)",
    )
    jwt_secret: Optional[str] = Field(
        default=None,
        description="JWT secret key (required for HS256)",
    )
    jwt_issuer: Optional[str] = Field(
        default=None,
        description="JWT issuer claim (optional)",
    )
    jwt_audience: Optional[str] = Field(
        default=None,
        description="JWT audience claim (optional)",
    )
    jwt_expires_seconds: int = Field(
        default=2592000,
        description="JWT expiry in seconds (default 30 days)",
    )

    # CORS configuration
    cors_origins: str = Field(
        default="*",
        description="Comma-separated list of allowed origins, or '*' for all",
    )
    cors_allow_methods: str = Field(
        default="*",
        description="Comma-separated list of allowed HTTP methods, or '*' for all",
    )
    cors_allow_headers: str = Field(
        default="*",
        description="Comma-separated list of allowed headers, or '*' for all",
    )
    cors_allow_credentials: bool = Field(
        default=False,
        description="Whether to allow credentials (cookies, auth headers)",
    )
    cors_max_age: int = Field(
        default=600,
        description="Max age in seconds for CORS preflight cache",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse comma-separated origins into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def cors_allow_methods_list(self) -> list[str]:
        """Parse comma-separated methods into a list."""
        return [m.strip() for m in self.cors_allow_methods.split(",") if m.strip()]

    @property
    def cors_allow_headers_list(self) -> list[str]:
        """Parse comma-separated headers into a list."""
        return [h.strip() for h in self.cors_allow_headers.split(",") if h.strip()]

    def validate_jwt_config(self) -> None:
        """Validate JWT configuration based on algorithm."""
        if self.jwt_algorithm in ("HS256", "HS384", "HS512"):
            if not self.jwt_secret:
                raise ValueError(
                    f"JWT_SECRET is required when using {self.jwt_algorithm} algorithm"
                )
        elif self.jwt_algorithm not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            raise ValueError(
                f"Unsupported JWT algorithm: {self.jwt_algorithm}. "
                "Supported: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512"
            )


# Global settings instance
settings = Settings()
