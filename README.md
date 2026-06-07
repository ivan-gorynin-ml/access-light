# access-light

**Lightweight auth & user management — FastAPI, MongoDB, JWT, zero ceremony.**

access-light is a self-hosted authentication and authorization microservice. It issues long-lived JWTs, manages users with role-based access control, supports app-generated login credentials for automation, and ships with a built-in admin dashboard for local development — all backed by MongoDB and a small, readable Python codebase.

```
  Client ──► POST /auth/login ──► JWT (30 days)
                │
                ▼
         MongoDB (users, audit, revoked tokens)
```

## Why access-light?

| | |
|---|---|
| **Small surface area** | One FastAPI app, one HTML admin dashboard, no frontend build step |
| **Production-minded security** | Argon2id passwords, JWT revocation, per-user session invalidation, rate-limited login |
| **Operator-friendly** | OpenAPI docs, cursor-paginated audit logs, hierarchical admin visibility |
| **Dev-friendly** | [`uv`](https://docs.astral.sh/uv/) for deps, `start-dev.bat` for one-click local server |

## Quick start

**Prerequisites:** Python 3.11+, [uv](https://docs.astral.sh/uv/getting-started/installation/), MongoDB running locally or remotely.

```bash
# 1. Clone and enter the project
git clone git@github.com:ivan-gorynin-ml/access-light.git
cd access-light

# 2. Configure environment
cp .env.example .env
# Edit .env — at minimum set MONGODB_URL, DATABASE_NAME, ROOT_LOGIN, ROOT_PASSWORD, JWT_SECRET

# 3. Install dependencies
uv sync

# 4. Start the dev server (Windows)
start-dev.bat
```

Then open:

| URL | What |
|-----|------|
| [http://localhost:55079/access-light/admin](http://localhost:55079/access-light/admin) | Admin dashboard |
| [http://localhost:55079/access-light/docs](http://localhost:55079/access-light/docs) | Swagger API docs |
| [http://localhost:55079/access-light/health](http://localhost:55079/access-light/health) | Health check |

Sign in with your `ROOT_LOGIN` / `ROOT_PASSWORD` from `.env`.

> **Full setup guide:** [docs/START_GUIDE.md](docs/START_GUIDE.md) — `uv`, `start-dev.bat`, and every `.env` variable explained with examples.

## Documentation

| Guide | Description |
|-------|-------------|
| [Start guide](docs/START_GUIDE.md) | Install `uv`, configure `.env`, run `start-dev.bat` |
| [Instructions](docs/INSTRUCTIONS.md) | API usage, roles, admin dashboard, production deployment |
| [Features](docs/FEATURES.md) | Complete feature reference |

## API at a glance

All routes are prefixed with `/access-light/v1`.

| Area | Endpoints |
|------|-----------|
| **Auth** | `POST /auth/login`, `POST /auth/logout`, `POST /auth/verify`, `GET /auth/login-attempts`, `GET /auth/activity-attempts` |
| **Users** | `POST /users`, `GET /users/me`, `POST /users/me/password`, `POST /users/{username}/password-reset` |
| **Login credentials** | `GET\|POST /users/me/login-credentials`, `GET\|PATCH\|DELETE /users/me/login-credentials/{name}` |

Authenticate with `Authorization: Bearer <accessToken>`.

## Tech stack

- **Runtime:** Python 3.11+, FastAPI, Uvicorn
- **Database:** MongoDB via Motor (async)
- **Security:** Argon2id / bcrypt (passlib), python-jose JWT, slowapi rate limiting
- **Packaging:** uv + `pyproject.toml`

## Project layout

```
access-light/
├── app/
│   ├── main.py          # FastAPI app, CORS, lifespan
│   ├── settings.py      # .env configuration
│   ├── security.py      # Hashing, JWT, user IDs
│   ├── db.py            # MongoDB connection & indexes
│   ├── routes/          # auth, users, login_credentials
│   └── services/        # login credential business logic
├── index.html           # Built-in admin dashboard
├── start-dev.bat        # Windows dev server launcher
├── pyproject.toml
└── docs/
```

## License

[MIT](LICENSE)
