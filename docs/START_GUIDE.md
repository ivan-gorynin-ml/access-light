# Start Guide

Get access-light running locally in a few minutes. This guide focuses on **[uv](https://docs.astral.sh/uv/)** for dependency management, **`start-dev.bat`** for launching the dev server, and configuring your **`.env`** file.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Python 3.11+** | Check with `python --version` or `py --version` |
| **[uv](https://docs.astral.sh/uv/getting-started/installation/)** | Fast Python package & project manager |
| **MongoDB** | Local install, Docker, or [MongoDB Atlas](https://www.mongodb.com/atlas) |

### Install uv

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Verify:

```bash
uv --version
```

### Start MongoDB

**Docker (quickest for local dev):**

```bash
docker run -d --name access-light-mongo -p 27017:27017 mongo:7
```

**Connection string for local Docker:** `mongodb://localhost:27017`

For MongoDB Atlas, copy the connection string from the Atlas dashboard and replace `<password>` with your database user password.

---

## 1. Clone the repository

```bash
git clone git@github.com:ivan-gorynin-ml/access-light.git
cd access-light
```

---

## 2. Install dependencies with uv

`uv sync` reads `pyproject.toml` and `uv.lock`, creates a virtual environment (`.venv`), and installs all dependencies.

```bash
uv sync
```

To include dev tools (pytest, ruff, black, mypy):

```bash
uv sync --extra dev
```

You do **not** need to activate the virtual environment manually — `uv run` uses it automatically.

---

## 3. Configure `.env`

Copy the example file:

```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Edit `.env` in the project root. The application loads it automatically via `pydantic-settings`.

### Required variables

These **must** be set or the server will fail on startup.

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGODB_URL` | MongoDB connection URI | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Database name (created if missing) | `access_light` |
| `ROOT_LOGIN` | Superadmin username (created/updated on startup) | `root` |
| `ROOT_PASSWORD` | Superadmin password | `MyStr0ng!RootPass` |
| `JWT_SECRET` | Secret for signing JWTs (HS256) | `a1b2c3d4e5f6...` (32+ random chars) |

#### Minimal working `.env`

```dotenv
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=access_light_dev
ROOT_LOGIN=root
ROOT_PASSWORD=DevRootPassword123!
JWT_SECRET=dev-only-change-me-use-openssl-rand-hex-32-in-prod
```

#### MongoDB Atlas example

```dotenv
MONGODB_URL=mongodb+srv://myuser:MyDbPassword@cluster0.abc123.mongodb.net/?retryWrites=true&w=majority
DATABASE_NAME=access_light
ROOT_LOGIN=admin
ROOT_PASSWORD=SuperSecureAdminPass2026!
JWT_SECRET=8f3c2a1b9e7d6c5a4b3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b
```

Generate a strong `JWT_SECRET`:

```bash
# OpenSSL
openssl rand -hex 32

# Python
python -c "import secrets; print(secrets.token_hex(32))"
```

### Optional variables

All optional settings have defaults in `app/settings.py`. Uncomment and set only when you need to override.

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `access-light` | Service name in logs and OpenAPI |
| `APP_VERSION` | `1.0.0` | Version string |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `COLLECTION_NAME` | `users` | Users collection |
| `LOGIN_ATTEMPTS_COLLECTION_NAME` | `login_attempts` | Login audit collection |
| `REVOKED_TOKENS_COLLECTION_NAME` | `revoked_tokens` | JWT blacklist collection |
| `ACTIVITY_ATTEMPTS_COLLECTION_NAME` | `activity_attempts` | Activity audit collection |
| `LOGIN_CREDENTIALS_COLLECTION_NAME` | `login_credentials` | Per-user credential collection |
| `LOGIN_RATE_LIMIT` | `30/minute` | slowapi rate limit for `POST /auth/login` |
| `JWT_ALGORITHM` | `HS256` | `HS256`, `HS384`, `HS512`, or asymmetric (`RS256`, etc.) |
| `JWT_ISSUER` | *(empty)* | Optional `iss` claim validation |
| `JWT_AUDIENCE` | *(empty)* | Optional `aud` claim validation |
| `JWT_EXPIRES_SECONDS` | `2592000` | Token lifetime (30 days) |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `CORS_ALLOW_METHODS` | `*` | Comma-separated HTTP methods |
| `CORS_ALLOW_HEADERS` | `*` | Comma-separated headers |
| `CORS_ALLOW_CREDENTIALS` | `false` | Allow cookies / credentials |
| `CORS_MAX_AGE` | `600` | CORS preflight cache (seconds) |

#### Production-oriented `.env` example

```dotenv
MONGODB_URL=mongodb://db.internal:27017
DATABASE_NAME=access_light_prod
ROOT_LOGIN=ops-admin
ROOT_PASSWORD=<stored-in-secrets-manager>
JWT_SECRET=<stored-in-secrets-manager>
JWT_ISSUER=access-light
JWT_AUDIENCE=my-app
JWT_EXPIRES_SECONDS=86400
LOGIN_RATE_LIMIT=10/minute
LOG_LEVEL=WARNING
CORS_ORIGINS=https://app.example.com,https://admin.example.com
CORS_ALLOW_CREDENTIALS=true
```

> **Security:** Never commit `.env` to git. It is listed in `.gitignore`. Use `.env.example` as the public template only.

---

## 4. Start the dev server

### Windows — `start-dev.bat`

Double-click `start-dev.bat` or run from the project root:

```bat
start-dev.bat
```

The batch file runs:

```bat
uv run uvicorn app.main:app --port 55079 --reload
```

| Flag | Effect |
|------|--------|
| `uv run` | Executes inside the uv-managed virtual environment |
| `--port 55079` | Binds to port **55079** (not the default 8000) |
| `--reload` | Auto-restarts on Python file changes |

### macOS / Linux equivalent

```bash
uv run uvicorn app.main:app --port 55079 --reload
```

To bind on all interfaces (e.g. for LAN testing):

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 55079 --reload
```

---

## 5. Verify it works

1. **Health check**

   ```bash
   curl http://localhost:55079/access-light/health
   ```

   Expected: `{"status":"healthy","service":"access-light","version":"1.0.0"}`

2. **Admin dashboard** — open [http://localhost:55079/access-light/admin](http://localhost:55079/access-light/admin)

3. **Sign in** with `ROOT_LOGIN` / `ROOT_PASSWORD` from your `.env`

4. **API docs** — [http://localhost:55079/access-light/docs](http://localhost:55079/access-light/docs)

---

## Startup behavior

On first launch the service will:

1. Validate JWT configuration (`JWT_SECRET` required for HS256)
2. Connect to MongoDB and create indexes
3. Create or update the root superadmin user from `ROOT_LOGIN` / `ROOT_PASSWORD`

If MongoDB is unreachable, startup fails with a clear error in the console.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `JWT_SECRET is required` | Set `JWT_SECRET` in `.env` |
| MongoDB connection timeout | Check `MONGODB_URL`, firewall, and that MongoDB is running |
| Port 55079 in use | Change the port in `start-dev.bat` or pass `--port <other>` |
| `uv: command not found` | Reinstall uv and restart your terminal |
| Login returns 401 for root | Restart server after changing `ROOT_PASSWORD` — password is synced on startup |

---

## Next steps

- [Instructions](INSTRUCTIONS.md) — use the API and admin dashboard
- [Features](FEATURES.md) — full capability reference
