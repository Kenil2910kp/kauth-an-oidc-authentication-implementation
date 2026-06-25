# KAuth — OAuth & OIDC Provider

A full-stack **OAuth2/OIDC authentication server** with a **developer console** (similar to Google Cloud Console) for registering and managing OAuth applications.

Built with **Express (TypeScript)**, **Postgres**, and **Drizzle ORM**.

---

## Features

| Area | Description |
|------|-------------|
| **Developer Console** | Sign up, sign in, create apps, view all projects, copy credentials, test login flow |
| **OAuth 2.0** | Authorization code flow with `client_id` / `client_secret` |
| **Tokens** | 60-second access tokens (JWT) + 30-day refresh tokens |
| **Userinfo** | `GET /oauth/userinfo` with Bearer access token |
| **OIDC Discovery** | `/.well-known/openid-configuration` + JWKS |
| **End-user login** | Branded sign-in page showing which app the user is signing into |

---

## Architecture

```
Developer                          End user
    │                                  │
    ▼                                  ▼
/console (dashboard)          /oauth/authorize
    │                                  │
    ├─ Create app ──► DB              ├─ /o/authenticate (login)
    ├─ client_id/secret               ├─ redirect with ?code=
    └─ Test login flow                │
                                      ▼
                              App backend calls /oauth/token
                                      │
                                      ▼
                              /oauth/userinfo
```

---

## Local setup

### 1. Environment

Create `.env`:

```bash
DATABASE_URL=postgresql://admin:admin@localhost:5432/oidc_auth
PORT=9000
SESSION_SECRET=change-me-in-production
```

### 2. Database

```bash
docker compose up -d   # if using included Postgres
npm install
npm run db:migrate
```

If OAuth tables are missing, apply migrations manually:

```bash
node -e "const fs=require('fs');const {Client}=require('pg');(async()=>{const c=new Client({connectionString:process.env.DATABASE_URL||'postgresql://admin:admin@localhost:5432/oidc_auth'});await c.connect();for(const f of['drizzle/0001_oauth.sql','drizzle/0002_owner_id.sql']){await c.query(fs.readFileSync(f,'utf8'));console.log('applied',f)}await c.end()})()"
```

### 3. Run

```bash
npm run dev
```

Server: **http://localhost:9000**

---

## End-to-end walkthrough

### Step 1 — Developer account

1. Open **http://localhost:9000**
2. Click **Get started** → create a developer account
3. You land on the **Applications dashboard**

### Step 2 — Register an application

1. Click **Create application**
2. Fill in:
   - **Name**: `My App`
   - **Application URL**: `http://localhost:5173`
   - **Redirect URI**: `http://localhost:9000/callback` (for local testing)
3. Copy **client_id** and **client_secret** (secret shown once)

### Step 3 — View existing projects

All apps appear on the dashboard. Click any app to see:
- Client ID
- Redirect URI
- Pre-built authorize URL
- **Test login flow** button
- **Regenerate secret**

### Step 4 — OAuth login (end user)

From app detail, click **Test login flow**, or open:

```
http://localhost:9000/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&state=abc
```

User signs in → redirected to callback with `?code=...`

### Step 5 — Exchange code for tokens

```bash
curl -sS -X POST "http://localhost:9000/oauth/token" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"PASTE_CODE\",\"redirect_uri\":\"http://localhost:9000/callback\"}"
```

### Step 6 — Userinfo

```bash
curl -sS "http://localhost:9000/oauth/userinfo" \
  -H "Authorization: Bearer PASTE_ACCESS_TOKEN"
```

---

## API reference

### Developer Console (session cookie)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/console/auth/sign-up` | Create developer account |
| POST | `/console/auth/sign-in` | Sign in (sets session cookie) |
| POST | `/console/auth/sign-out` | Sign out |
| GET | `/console/auth/me` | Current user |
| GET | `/console/apps` | List your applications |
| POST | `/console/apps` | Create application |
| GET | `/console/apps/:id` | Application details |
| POST | `/console/apps/:id/regenerate-secret` | New client secret |

### OAuth / OIDC

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/oauth/authorize` | Start authorization (`response_type=code`) |
| POST | `/oauth/token` | Exchange code or refresh token |
| GET | `/oauth/userinfo` | User profile (Bearer token) |
| GET | `/oauth/clients/:clientId/info` | Public app name (for login branding) |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/jwks.json` | Public keys |

### End-user auth pages

| Path | Description |
|------|-------------|
| `/o/authenticate` | OAuth sign-in (shows app name when `client_id` present) |
| `/signup.html` | End-user registration |
| `/callback` | Local test callback page |

---

## Database tables

- `users` — developer accounts + end-user accounts
- `oauth_clients` — registered apps (`owner_id` → developer)
- `oauth_auth_codes` — short-lived authorization codes
- `oauth_tokens` — access token `jti` + refresh token hashes

---

## Pages

| URL | Purpose |
|-----|---------|
| `/` | Landing page |
| `/console/login.html` | Developer sign in |
| `/console/signup.html` | Developer sign up |
| `/console/dashboard.html` | All applications (Google Console style) |
| `/console/create-app.html` | Register new OAuth client |
| `/console/app-detail.html?id=...` | Single app credentials & integration |

---

## Scripts

```bash
npm run dev          # Watch + compile + run
npm run db:migrate   # Apply migrations
npm run db:studio    # Drizzle Studio
```

---

## Notes

- Default port is **9000** (avoids conflict with Django on 8000).
- Access tokens expire in **60 seconds**.
- Client secrets are hashed in the database; only shown once at creation or regeneration.
- This is a dev-focused implementation — add PKCE, consent screens, and rate limiting before production use.
