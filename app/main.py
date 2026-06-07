"""FastAPI main application with startup/shutdown lifecycle and error handling."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.db import close_db, connect_db, init_root_user
from app.models import Error
from app.rate_limit import limiter
from app.routes import auth, login_credentials, users
from app.settings import settings

# Configure logging
logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events.
    
    Startup:
    - Validate JWT configuration
    - Connect to MongoDB
    - Create required indexes
    
    Shutdown:
    - Close MongoDB connection
    """
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    try:
        # Validate JWT configuration
        settings.validate_jwt_config()
        logger.info(f"JWT algorithm: {settings.jwt_algorithm}")
        
        # Connect to MongoDB and create indexes
        await connect_db()

        # Create or update root superadmin user
        await init_root_user()
        
        logger.info("Application startup complete")
        
    except Exception as e:
        logger.critical(f"Application startup failed: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    await close_db()
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "access-light: user management service with role-based access control.\n\n"
        "**Authentication:** `POST /v1/auth/login` accepts a username and password. "
        "The password field may be either the user's account password or the plaintext "
        "secret of an app-generated **login credential** owned by that user. On success "
        "the service returns a JWT (30-day expiry). Login is rate-limited per client IP.\n\n"
        "**Login credentials:** Authenticated users manage per-user alternative passwords "
        "via `GET|POST|PATCH|DELETE /v1/users/me/login-credentials`. Secrets are generated "
        "server-side, stored hashed only, and returned in plaintext solely in the create "
        "(or replace-by-name) response. List and retrieve never include secrets.\n\n"
        "Also supports user creation (admin/superadmin), password change, JWT verify/logout, "
        "and audit endpoints."
    ),
    lifespan=lifespan,
    docs_url="/access-light/docs",
    redoc_url="/access-light/redoc",
    openapi_url="/access-light/openapi.json",
)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods_list,
    allow_headers=settings.cors_allow_headers_list,
    max_age=settings.cors_max_age,
)

# Include routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(login_credentials.router)


# Exception handlers for consistent error responses


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Handle HTTPException and return standardized Error response.
    
    Transforms FastAPI HTTPException into {code, message} format.
    """
    # Check if detail is already in Error format
    if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
        )
    
    # Convert string detail to Error format
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": "http_error",
            "message": str(exc.detail) if exc.detail else "An error occurred",
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Handle Pydantic validation errors and return standardized Error response.
    
    Returns 400 Bad Request with validation error details.
    """
    # Extract first error message for simplicity
    errors = exc.errors()
    if errors:
        first_error = errors[0]
        field = ".".join(str(loc) for loc in first_error["loc"] if loc != "body")
        message = f"Validation error: {field}: {first_error['msg']}"
    else:
        message = "Validation error"
    
    logger.warning(f"Validation error: {message}")
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "code": "validation_error",
            "message": message,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions and return standardized Error response.
    
    Returns 500 Internal Server Error.
    """
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": "internal_error",
            "message": "An internal server error occurred",
        },
    )


# Health check endpoint (not in spec, but useful)
@app.get(
    "/access-light/health",
    tags=["System"],
    summary="Health check",
    include_in_schema=False,  # Don't include in OpenAPI spec
)
async def health_check() -> Dict[str, Any]:
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
    }


# Root endpoint
@app.get(
    "/access-light",
    tags=["System"],
    summary="Service information",
    include_in_schema=False,
)
async def root() -> Dict[str, Any]:
    """Service information endpoint."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "description": (
            "Authentication/authorization microservice. "
            "See /docs for API documentation."
        ),
    }


# Admin dashboard – serves the single-page admin dashboard
_ADMIN_HTML = Path(__file__).resolve().parent.parent / "index.html"


@app.get(
    "/access-light/admin",
    tags=["System"],
    summary="Admin dashboard",
    include_in_schema=False,
)
async def admin_ui():
    """Serve the single-page admin dashboard."""
    if not _ADMIN_HTML.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "not_found", "message": "Admin dashboard file not found"},
        )
    return FileResponse(_ADMIN_HTML, media_type="text/html")


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=settings.log_level.lower(),
    )
