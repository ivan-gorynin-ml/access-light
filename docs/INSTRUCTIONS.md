# Instructions

How to use access-light day-to-day: authentication, user management, the built-in admin dashboard, and deployment notes.

## Service URLs

When running via `start-dev.bat` (port **55079**):

| Resource | URL |
|----------|-----|
| Admin dashboard | `http://localhost:55079/access-light/admin` |
| Swagger docs | `http://localhost:55079/access-light/docs` |
| ReDoc | `http://localhost:55079/access-light/redoc` |
| OpenAPI JSON | `http://localhost:55079/access-light/openapi.json` |
| Health | `http://localhost:55079/access-light/health` |
| Service info | `http://localhost:55079/access-light` |

All API routes live under `/access-light/v1/...`.

---

## Roles

| Role | Capabilities |
|------|--------------|
| **member** | Own profile, password change, login credentials, own audit logs |
| **admin** | Everything a member can do, plus create users (member/admin), reset passwords for users they created, view audit logs for created users |
| **superadmin** | Full admin powers; bootstrapped from `ROOT_LOGIN` / `ROOT_PASSWORD` on startup; cannot be assigned via API |

The root account from `.env` is always ensured to exist with `superadmin` role.

---

## Authentication flow

### 1. Login

```http
POST /access-light/v1/auth/login
Content-Type: application/json

{
  "username": "root",
  "password": "your-password"
}
```

Response:

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "tokenType": "Bearer",
  "expiresIn": 2592000,
  "issuedAt": "2026-06-07T12:00:00Z"
}
```

The `password` field also accepts a **login credential secret** (see [Features — Login credentials](FEATURES.md#login-credentials)).

### 2. Use the token

```http
GET /access-light/v1/users/me
Authorization: Bearer <accessToken>
```

### 3. Logout (revoke token)

```http
POST /access-light/v1/auth/logout
Authorization: Bearer <accessToken>
```

Returns `204 No Content`. The token's `jti` is blacklisted; further requests with that token receive `401`.

### 4. Verify a token (no auth required)

```http
POST /access-light/v1/auth/verify
Content-Type: application/json

{ "token": "<accessToken>" }
```

Returns `valid: true` with claims, or `valid: false` with null fields.

---

## User management

### Create a user (admin / superadmin)

```http
POST /access-light/v1/users
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "username": "alice",
  "password": "AliceSecurePass123!",
  "email": "alice@example.com",
  "role": "member",
  "auditMode": "standard"
}
```

- `role`: `member` (default) or `admin` — not `superadmin`
- `auditMode`: `standard` (default) or `none` — `none` disables audit persistence for that user

### Change your own password

```http
POST /access-light/v1/users/me/password
Authorization: Bearer <token>
Content-Type: application/json

{
  "oldPassword": "AliceSecurePass123!",
  "newPassword": "NewAlicePass456!"
}
```

Returns `204`. All previously issued JWTs for that user are invalidated via `revoke_before`.

### Admin password reset (member only)

```http
POST /access-light/v1/users/alice/password-reset
Authorization: Bearer <admin-token>
```

Returns the new plaintext password **once**. Only works for member users the admin created.

---

## Login credentials

Server-generated alternative passwords for automation or per-app access.

```http
POST /access-light/v1/users/me/login-credentials
Authorization: Bearer <token>
Content-Type: application/json

{ "name": "ci-bot", "description": "GitHub Actions deploy" }
```

The response includes a one-time `secret`. Use it as the `password` in `POST /auth/login` with the same `username`.

List, get, patch (description only), and delete via `/users/me/login-credentials` and `/users/me/login-credentials/{name}`.

---

## Audit logs

### Login attempts

```http
GET /access-light/v1/auth/login-attempts?limit=50
Authorization: Bearer <token>
```

Query parameters: `cursor`, `username`, `from`, `to`, `includeUserNotFound` (admin only).

### Activity attempts

```http
GET /access-light/v1/auth/activity-attempts?limit=50&endpoint=POST%20/access-light/v1/auth/logout
Authorization: Bearer <token>
```

Query parameters: `cursor`, `username`, `endpoint`, `result`, `from`, `to`.

Both endpoints use cursor-based pagination (`nextCursor` in the response).

---

## Built-in admin dashboard

Open `/access-light/admin` in a browser. No build step required.

### Top bar

- **API base URL** — defaults to the current origin; change if the API runs elsewhere
- **API Docs** — opens Swagger in a new tab
- **OpenAPI** — downloads the JSON spec
- **Logout** — calls `POST /auth/logout` and clears local token storage

### Pages

| Page | Who | Purpose |
|------|-----|---------|
| **Sign In** | Everyone | Username/password login |
| **Dashboard** | Authenticated | Profile info; admins see created users |
| **Create User** | Admin / superadmin | Provision new accounts |
| **Manage Users** | Admin / superadmin | List created users, reset member passwords |
| **Login Credentials** | Authenticated | Create, list, test, delete credentials |
| **Change Password** | Authenticated | Self-service password change |
| **Activity Attempts** | Authenticated | Filterable activity audit viewer |
| **Login Attempts** | Authenticated | Filterable login audit viewer |

The UI stores the JWT in `localStorage` and attaches it as `Authorization: Bearer` on API calls.

---

## Error responses

All errors use a consistent JSON shape:

```json
{
  "code": "invalid_credentials",
  "message": "Invalid username or password"
}
```

Common codes: `invalid_credentials`, `invalid_token`, `forbidden`, `username_exists`, `validation_error`, `audit_not_available`.

Login rate limiting returns `429` when `LOGIN_RATE_LIMIT` is exceeded.

---

## Production deployment

### Run without reload

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Use a reverse proxy (nginx, Caddy, Traefik) for TLS termination.

### Environment

- Store secrets in a secrets manager, not in the image or repo
- Set restrictive `CORS_ORIGINS` instead of `*`
- Use a strong `JWT_SECRET` (or RS256 with key rotation)
- Lower `JWT_EXPIRES_SECONDS` if 30 days is too long for your threat model
- Tighten `LOGIN_RATE_LIMIT` (e.g. `10/minute`)

### MongoDB

- Use a replica set for production
- Enable authentication and TLS on the connection string
- Back up `users`, audit collections, and `revoked_tokens`

### Reverse proxy path

The app expects to be served at the root or with `/access-light` prefix as documented. Configure your proxy to forward:

```
/access-light/*  →  uvicorn:8000/access-light/*
```

### Health checks

Point your orchestrator at `GET /access-light/health`.

---

## Development commands

```bash
# Install with dev dependencies
uv sync --extra dev

# Run tests (when tests/ exists)
uv run pytest

# Lint
uv run ruff check app/

# Format
uv run black app/
```

---

## Further reading

- [Start guide](START_GUIDE.md) — `uv`, `.env`, `start-dev.bat`
- [Features](FEATURES.md) — complete feature reference
