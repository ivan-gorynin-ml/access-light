# Features

A complete reference of everything access-light provides: authentication, authorization, audit, security primitives, and operational tooling.

---

## Overview

access-light is an **authentication and user-management microservice**. It stores users in MongoDB, issues signed JWT access tokens, enforces role-based access control, and records security-relevant events for compliance and debugging.

**Design principles:**

- Passwords and credential secrets are **never** stored or logged in plaintext
- Login failures return **generic** `401` messages (no username enumeration)
- JWTs can be **revoked** individually (logout) or **bulk-invalidated** (password change)
- Admins have **scoped visibility** — they see audit data for themselves and users they created

---

## Authentication

### JWT-based sessions

| Aspect | Detail |
|--------|--------|
| Token format | Signed JWT (`Bearer`) |
| Default algorithm | HS256 (configurable) |
| Default lifetime | 30 days (`JWT_EXPIRES_SECONDS=2592000`) |
| Claims | `jti`, `sub` (user ID), `username`, `role`, `iat`, `exp`; optional `iss`, `aud` |
| User ID format | `usr_<timestamp><random>` — opaque, collision-resistant |

### Login (`POST /v1/auth/login`)

- Accepts `username` + `password`
- The `password` field accepts **either**:
  1. The user's account password (Argon2id hash verified), or
  2. A **login credential secret** belonging to that user
- Server tries account password first, then credential secrets
- On credential login, updates the credential's `lastLoginAt`
- Rate-limited per client IP (`LOGIN_RATE_LIMIT`, default `30/minute`)
- Returns `TokenResponse` with `accessToken`, `tokenType`, `expiresIn`, `issuedAt`

### Logout (`POST /v1/auth/logout`)

- Requires valid Bearer token
- Inserts `jti` into `revoked_tokens` collection (idempotent)
- TTL index auto-deletes expired revocation records
- Returns `204 No Content`

### Token verification (`POST /v1/auth/verify`)

- Public endpoint (no Bearer required)
- Validates signature, algorithm, expiration, optional iss/aud
- Checks revocation blacklist and per-user `revoke_before`
- Returns `valid: true/false` with selected claims

### Dual revocation model

1. **Per-token (jti):** Logout blacklists the specific token
2. **Per-user (revoke_before):** Password change or admin reset sets a timestamp; any token with `iat` before that moment is rejected

---

## Authorization & roles

### Role hierarchy

| Role | Assigned via | Notes |
|------|--------------|-------|
| `member` | Default on user creation | Standard user |
| `admin` | API (`POST /users`) | Can create users, reset passwords |
| `superadmin` | `.env` root bootstrap only | Cannot be assigned via REST API |

### Permission matrix

| Action | member | admin | superadmin |
|--------|:------:|:-----:|:----------:|
| Login / logout / verify | ✓ | ✓ | ✓ |
| GET `/users/me` | ✓ | ✓ (+ createdUsers) | ✓ (+ createdUsers) |
| Change own password | ✓ | ✓ | ✓ |
| Create users | | ✓ | ✓ |
| Reset member password (created users) | | ✓ | ✓ |
| Manage own login credentials | ✓ | ✓ | ✓ |
| View own login attempts | ✓* | ✓* | ✓* |
| View created users' login attempts | | ✓ | ✓ |
| View own activity attempts | ✓* | ✓* | ✓* |
| View created users' activity | | ✓ | ✓ |
| `includeUserNotFound` on login audit | | ✓ | ✓ |

\*Not available when user's `auditMode` is `none`

### Creator tracking

When an admin creates a user, the new username is appended to the creator's `created_usernames` list (deduplicated). This powers:

- `GET /users/me` → `createdUsers` array for admins
- Scoped audit log access
- Password reset eligibility (`POST /users/{username}/password-reset`)

---

## User management

### Create user (`POST /v1/users`)

- Admin / superadmin only
- Fields: `username` (3–64 chars), `password` (8–256 chars), optional `email`, optional `role`, optional `auditMode`
- Username uniqueness enforced by MongoDB unique index → `409 username_exists`
- Password hashed with Argon2id before storage

### Get current user (`GET /v1/users/me`)

- Returns `UserMeResponse`
- Admins/superadmins additionally receive `createdUsers` — full `UserResponse` objects for each user they created

### Change password (`POST /v1/users/me/password`)

- Requires `oldPassword` + `newPassword`
- Sets `password_changed_at` and `revoke_before` → invalidates all existing sessions
- Returns `204`

### Admin password reset (`POST /v1/users/{username}/password-reset`)

- Admin / superadmin only
- Target must be a **member** the caller created
- Server generates a random password, returns it once in plaintext
- Invalidates all target user sessions

---

## Login credentials

Alternative authentication tokens for scripts, CI, mobile apps, or per-integration access — without sharing the account password.

| Property | Behavior |
|----------|----------|
| Secret generation | Server-side (`secrets.token_urlsafe(32)`) |
| Storage | Argon2id hash only; plaintext shown once on create/replace |
| Naming | Unique per user; trimmed; 1–128 chars |
| Login | Use secret as `password` in `POST /auth/login` |
| Rotation | `POST` with same `name` replaces secret and resets `lastLoginAt` |
| Metadata | `description`, `createdAt`, `updatedAt`, `lastLoginAt` |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/users/me/login-credentials` | Create or replace by name |
| `GET` | `/users/me/login-credentials` | List (no secrets) |
| `GET` | `/users/me/login-credentials/{name}` | Get one |
| `PATCH` | `/users/me/login-credentials/{name}` | Update description |
| `DELETE` | `/users/me/login-credentials/{name}` | Delete (immediate invalidation) |

---

## Audit & compliance

### Login attempts (`login_attempts` collection)

Recorded on every `POST /auth/login` unless the user's `auditMode` is `none`.

| Field | Description |
|-------|-------------|
| `attempted_username` | Submitted username |
| `result` | `success` or `failure` |
| `failure_reason` | `invalid_password`, `user_not_found`, etc. (internal) |
| `subject_user_id` | Resolved user ID (null if not found) |
| `owner_user_id` | Same as subject for successful logins |
| `creator_user_id` | Admin who created the subject user |
| `ip_address` | From `X-Forwarded-For` → `X-Real-IP` → socket |
| `locale` | From `Accept-Language` |
| `origin` | Query param (default `app UI`) for client attribution |
| `timestamp` | UTC |

**Query:** `GET /v1/auth/login-attempts` with cursor pagination, date range, username filter.

### Activity attempts (`activity_attempts` collection)

Recorded on authenticated and some unauthenticated operations (verify failures, etc.) unless audit is disabled.

Captures: endpoint, result, failure reason, actor username, target username (for password resets), operation type, bulk item counts, IP, locale, origin.

**Query:** `GET /v1/auth/activity-attempts` with filters for username, endpoint, result, date range.

### Audit modes

| `auditMode` | Effect |
|-------------|--------|
| `standard` | Full login and activity audit (default) |
| `none` | No audit documents written; audit GET endpoints return `403 audit_not_available` for that user |

Set at user creation time only (via `auditMode` field).

---

## Security

### Password hashing

- **Primary:** Argon2id (64 MB memory, 3 iterations, 4 parallelism)
- **Fallback:** bcrypt (passlib `CryptContext`)
- Constant-time verification; invalid hashes handled gracefully

### JWT security

- Rejects `alg=none`
- Validates required claims: `sub`, `username`, `iat`, `exp`
- Optional issuer and audience enforcement
- Revocation checked on every authenticated request

### Rate limiting

- `POST /auth/login` limited by client IP via slowapi
- Configurable: `LOGIN_RATE_LIMIT` (e.g. `30/minute`, `10/hour`)
- Excess requests → HTTP `429`

### Information disclosure controls

- Login: always `401 invalid_credentials` regardless of failure reason
- Credential secrets: never in list/get responses or logs
- Admin password reset: plaintext returned only in the single success response
- Internal errors: generic `500 internal_error` to clients; details in server logs

### CORS

Fully configurable via environment:

- `CORS_ORIGINS`, `CORS_ALLOW_METHODS`, `CORS_ALLOW_HEADERS`
- `CORS_ALLOW_CREDENTIALS`, `CORS_MAX_AGE`

---

## Database (MongoDB)

### Collections

| Collection | Purpose | Key indexes |
|------------|---------|-------------|
| `users` | User accounts | Unique `username` |
| `login_attempts` | Login audit | `timestamp`, `owner_user_id+timestamp`, `attempted_username+timestamp` |
| `activity_attempts` | Activity audit | `timestamp`, `username+timestamp`, `endpoint+timestamp` |
| `revoked_tokens` | JWT blacklist | Unique `jti`, TTL on `expiresAt` |
| `login_credentials` | Per-user credentials | Unique `user_id+name` |

Collection names are overridable via `.env`.

### Startup lifecycle

1. Connect and ping MongoDB
2. Create indexes (idempotent)
3. Bootstrap/update root superadmin from `ROOT_LOGIN` / `ROOT_PASSWORD`

---

## API & developer experience

### OpenAPI

- Interactive Swagger UI at `/access-light/docs`
- ReDoc at `/access-light/redoc`
- Machine-readable spec at `/access-light/openapi.json`
- Rich endpoint descriptions with examples and error schemas

### Standardized errors

All HTTP errors return `{ "code": "...", "message": "..." }`.

Validation errors → `400 validation_error`.

### Health & metadata

| Endpoint | Purpose |
|----------|---------|
| `GET /access-light/health` | Liveness probe |
| `GET /access-light` | Service name, version, description |

### Origin query parameter

Many endpoints accept `?origin=app UI|mobile|...` for audit attribution. Does not affect authorization or response content.

---

## Built-in admin dashboard

Single-page HTML application served at `/access-light/admin` — no npm, no build pipeline.

**Capabilities:**

- JWT login/logout with localStorage persistence
- Configurable API base URL
- Dashboard with role badge and profile details
- User creation form (admin) with role and audit mode
- User management table with password reset modal
- Login credential CRUD with one-time secret display
- Password change form
- Interactive audit viewers with filters and pagination
- Quick links to Swagger and OpenAPI download

Dark-themed, responsive layout suitable for local development and manual QA.

---

## Configuration

All settings load from `.env` and environment variables via Pydantic Settings. See [Start guide — Configure `.env`](START_GUIDE.md#3-configure-env) for the full variable list.

Required: `MONGODB_URL`, `DATABASE_NAME`, `ROOT_LOGIN`, `ROOT_PASSWORD`, `JWT_SECRET` (for HS256).

---

## Technology stack

| Layer | Technology |
|-------|------------|
| Framework | FastAPI |
| ASGI server | Uvicorn |
| Database driver | Motor (async MongoDB) |
| Validation | Pydantic v2 |
| Password hashing | passlib (Argon2id, bcrypt) |
| JWT | python-jose |
| Rate limiting | slowapi |
| Packaging | uv, hatchling |

**Python:** 3.11+

**License:** MIT
