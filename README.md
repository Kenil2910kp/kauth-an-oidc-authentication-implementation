# OIDC / OAuth2 Auth Server (Express + Postgres)

An **OAuth2/OIDC-style authentication server** implemented with **Express (TypeScript)** and **Postgres** (via **Drizzle ORM**).

It provides:
- **Client registration** (creates `client_id` + `client_secret`)
- **Authorization Code flow** (`/oauth/authorize` → login → `code` → `/oauth/token`)
- **Short-lived access tokens** (**60 seconds**) and **refresh tokens**
- **`/oauth/userinfo`** protected endpoint
- OIDC discovery + JWKS:
  - `/.well-known/openid-configuration`
  - `/.well-known/jwks.json`

> This is a learning/dev-focused implementation. It is not a hardened production IdP yet (no PKCE, no consent screen, limited redirect validation, minimal auditing).

---

## Tech stack
- **Node.js + Express**
- **TypeScript** (compiled to `dist/`)
- **Postgres**
- **Drizzle ORM** + SQL migrations
- **RS256 JWTs** (public key exposed via JWKS)

---

## Local setup

### 1) Configure environment
Create `.env` in the repo root:

```bash
DATABASE_URL=postgresql://admin:admin@localhost:5432/oidc_auth
PORT=9000
```

### 2) Start Postgres
If you’re using Docker, you can use the included `docker-compose.yml` (if present/compatible):

```bash
docker compose up -d
```

Or run Postgres locally and ensure the database exists:

```sql
CREATE DATABASE oidc_auth;
```

### 3) Install dependencies

```bash
npm install
```

### 4) Run DB migrations

```bash
npm run db:migrate
```

If you suspect migrations didn’t apply (tables missing), you can apply the SQL directly:

```bash
node -e "const fs=require('fs'); const {Client}=require('pg'); (async()=>{ const c=new Client({connectionString:process.env.DATABASE_URL}); await c.connect(); await c.query(fs.readFileSync('drizzle/0001_oauth.sql','utf8')); console.log('applied'); await c.end(); })().catch(e=>{ console.error(e); process.exit(1); });"
```

### 5) Run the server

```bash
npm run dev
```

Server will be available at:
- `http://localhost:9000`

---

## What’s implemented

### UI pages (static)
- **Sign in**: `GET /o/authenticate`
- **Sign up**: `GET /signup.html`
- **Register OAuth client**: `GET /oauth/clients/new`
- **Local callback viewer** (for testing): `GET /callback`

### OAuth / OIDC endpoints

#### Discovery / Keys
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

#### OAuth
- `GET /oauth/authorize`
  - Supports: `response_type=code`
  - Validates: `client_id`, `redirect_uri`
  - Redirects to login page with the same query params.

- `POST /oauth/token`
  - Auth: HTTP Basic (`client_id:client_secret`) or JSON body credentials
  - `grant_type=authorization_code`
    - Input: `code`, `redirect_uri`
    - Output: `access_token` (**60s**), `refresh_token`
  - `grant_type=refresh_token`
    - Input: `refresh_token`
    - Output: new `access_token` (**60s**)

- `GET /oauth/userinfo`
  - Auth: `Authorization: Bearer <access_token>`
  - Verifies:
    - JWT signature (RS256)
    - expiry
    - `jti` exists in DB and is not revoked

---

## Data model (Postgres)
Tables:
- `users` (existing)
- `oauth_clients`
  - `client_id` (public)
  - `client_secret_hash` + `client_secret_salt` (server-side only)
  - `redirect_uri` (single allowed redirect for now)
- `oauth_auth_codes`
  - Authorization codes stored as **salted hash** + expiry + `used_at`
- `oauth_tokens`
  - Access token tracked via `jti` + expiry (access token itself is a JWT)
  - Refresh token stored as **salted hash** + expiry

---

## End-to-end test (no frontend app required)

### 1) Create a user
Open:
- `http://localhost:9000/signup.html`

### 2) Register a client
Open:
- `http://localhost:9000/oauth/clients/new`

Use redirect URI:
- `http://localhost:9000/callback`

Copy:
- `client_id`
- `client_secret` (shown once)

### 3) Start authorization
Open in browser (replace `YOUR_CLIENT_ID`):

`http://localhost:9000/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&state=abc`

After login you’ll land on:
- `http://localhost:9000/callback?code=...&state=abc`

Copy the `code`.

### 4) Exchange code for tokens
Replace placeholders and run:

```bash
curl -sS -X POST "http://localhost:9000/oauth/token" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"PASTE_CODE_HERE\",\"redirect_uri\":\"http://localhost:9000/callback\"}"
```

### 5) Call userinfo

```bash
curl -sS "http://localhost:9000/oauth/userinfo" \
  -H "Authorization: Bearer PASTE_ACCESS_TOKEN_HERE"
```

### 6) Refresh token

```bash
curl -sS -X POST "http://localhost:9000/oauth/token" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"PASTE_REFRESH_TOKEN_HERE\"}"
```

---

## Notes / limitations
- **Access tokens expire in 60 seconds** (as requested).
- No PKCE yet (recommended before any real-world usage).
- Redirect URI validation is currently **exact match** against one stored `redirect_uri`.
- No consent screen / scopes enforcement (scope is accepted/stored but not enforced).

---

## Repo scripts
- `npm run dev`: watch + compile + run server
- `npm run db:migrate`: apply Drizzle migrations
- `npm run db:studio`: open Drizzle Studio

