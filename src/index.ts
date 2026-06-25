import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import { and, desc, eq, isNull } from "drizzle-orm";
import JWT from "jsonwebtoken";
import jose from "node-jose";
import { db } from "./db";
import {
  oauthAuthCodesTable,
  oauthClientsTable,
  oauthTokensTable,
  usersTable,
} from "./db/schema";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert";
import {
  clearSessionCookie,
  getSessionUserId,
  setSessionCookie,
} from "./utils/session";
import type { JWTClaims } from "./utils/user-token";

const app = express();
const PORT = process.env.PORT ?? 9000;

app.use(express.json());
app.use(express.static(path.resolve("public")));

app.get("/", (req, res) => res.sendFile(path.resolve("public", "index.html")));

app.get("/health", (req, res) =>
  res.json({ message: "Server is healthy", healthy: true }),
);

function issuer() {
  return `http://localhost:${PORT}`;
}

function randomBase64Url(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function sha256Hex(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hashPassword(password: string, salt: string) {
  return sha256Hex(password + salt);
}

async function findUserByEmail(email: string) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);
  return user ?? null;
}

function publicUser(user: typeof usersTable.$inferSelect) {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
  };
}

function publicApp(app: typeof oauthClientsTable.$inferSelect) {
  return {
    id: app.id,
    name: app.name,
    appURL: app.appURL,
    redirectURI: app.redirectURI,
    clientId: app.clientId,
    createdAt: app.createdAt,
    updatedAt: app.updatedAt,
  };
}

async function createOAuthClient(
  ownerId: string,
  name: string,
  appURL: string,
  redirectURI: string,
) {
  const client_id = `cli_${randomBase64Url(24)}`;
  const client_secret = `sec_${randomBase64Url(32)}`;
  const salt = crypto.randomBytes(16).toString("hex");
  const secretHash = sha256Hex(client_secret + salt);

  const [created] = await db
    .insert(oauthClientsTable)
    .values({
      ownerId,
      name,
      appURL,
      redirectURI,
      clientId: client_id,
      clientSecretHash: secretHash,
      clientSecretSalt: salt,
    })
    .returning();

  return { app: created, client_id, client_secret };
}

function parseBasicAuth(authHeader?: string) {
  if (!authHeader?.startsWith("Basic ")) return null;
  const raw = authHeader.slice(6);
  let decoded: string;
  try {
    decoded = Buffer.from(raw, "base64").toString("utf8");
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx === -1) return null;
  return {
    username: decoded.slice(0, idx),
    password: decoded.slice(idx + 1),
  };
}

// OIDC Endpoints
app.get("/.well-known/openid-configuration", (req, res) => {
  const ISSUER = issuer();
  return res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
});

app.get("/.well-known/jwks.json", async (_, res) => {
  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
  return res.json({ keys: [key.toJSON()] });
});

// ─── Developer Console ───────────────────────────────────────────────────────

app.get("/console", (req, res) => res.redirect("/console/dashboard.html"));
app.get("/oauth/clients/new", (req, res) =>
  res.redirect("/console/create-app.html"),
);

app.post("/console/auth/sign-up", async (req, res) => {
  const { firstName, lastName, email, password } = req.body ?? {};

  if (!email || !password || !firstName) {
    res
      .status(400)
      .json({ message: "First name, email, and password are required." });
    return;
  }
  if (String(password).length < 8) {
    res.status(400).json({ message: "Password must be at least 8 characters." });
    return;
  }

  const existing = await findUserByEmail(email);
  if (existing) {
    res.status(409).json({ message: "An account with this email already exists." });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const [user] = await db
    .insert(usersTable)
    .values({
      firstName,
      lastName: lastName ?? null,
      email,
      password: hashPassword(password, salt),
      salt,
    })
    .returning();

  setSessionCookie(res, user.id);
  res.status(201).json({ user: publicUser(user) });
});

app.post("/console/auth/sign-in", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required." });
    return;
  }

  const user = await findUserByEmail(email);
  if (!user?.password || !user.salt) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }
  if (hashPassword(password, user.salt) !== user.password) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  setSessionCookie(res, user.id);
  res.json({ user: publicUser(user) });
});

app.post("/console/auth/sign-out", (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get("/console/auth/me", async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) {
    res.status(401).json({ message: "Not authenticated." });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);

  if (!user) {
    clearSessionCookie(res);
    res.status(401).json({ message: "Not authenticated." });
    return;
  }

  res.json({ user: publicUser(user) });
});

app.get("/console/apps", async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) {
    res.status(401).json({ message: "Not authenticated." });
    return;
  }

  const apps = await db
    .select()
    .from(oauthClientsTable)
    .where(eq(oauthClientsTable.ownerId, userId))
    .orderBy(desc(oauthClientsTable.createdAt));

  res.json({ apps: apps.map(publicApp) });
});

app.post("/console/apps", async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) {
    res.status(401).json({ message: "Not authenticated." });
    return;
  }

  const { name, appURL, redirectURI } = req.body ?? {};
  if (!name || !appURL || !redirectURI) {
    res.status(400).json({ message: "name, appURL, and redirectURI are required." });
    return;
  }

  let appURLParsed: URL;
  let redirectParsed: URL;
  try {
    appURLParsed = new URL(appURL);
    redirectParsed = new URL(redirectURI);
  } catch {
    res.status(400).json({ message: "appURL and redirectURI must be valid URLs." });
    return;
  }

  if (!["http:", "https:"].includes(appURLParsed.protocol)) {
    res.status(400).json({ message: "appURL must be http(s)." });
    return;
  }
  if (!["http:", "https:"].includes(redirectParsed.protocol)) {
    res.status(400).json({ message: "redirectURI must be http(s)." });
    return;
  }

  try {
    const { app, client_id, client_secret } = await createOAuthClient(
      userId,
      name,
      appURLParsed.toString(),
      redirectParsed.toString(),
    );
    res.status(201).json({
      app: publicApp(app),
      client_id,
      client_secret,
    });
  } catch (err: any) {
    const message =
      err?.cause?.message ?? err?.message ?? "Failed to create application.";
    res.status(500).json({ message });
  }
});

app.get("/console/apps/:id", async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) {
    res.status(401).json({ message: "Not authenticated." });
    return;
  }

  const [app] = await db
    .select()
    .from(oauthClientsTable)
    .where(
      and(
        eq(oauthClientsTable.id, req.params.id),
        eq(oauthClientsTable.ownerId, userId),
      ),
    )
    .limit(1);

  if (!app) {
    res.status(404).json({ message: "Application not found." });
    return;
  }

  res.json({ app: publicApp(app) });
});

app.post("/console/apps/:id/regenerate-secret", async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) {
    res.status(401).json({ message: "Not authenticated." });
    return;
  }

  const [app] = await db
    .select()
    .from(oauthClientsTable)
    .where(
      and(
        eq(oauthClientsTable.id, req.params.id),
        eq(oauthClientsTable.ownerId, userId),
      ),
    )
    .limit(1);

  if (!app) {
    res.status(404).json({ message: "Application not found." });
    return;
  }

  const client_secret = `sec_${randomBase64Url(32)}`;
  const salt = crypto.randomBytes(16).toString("hex");
  const secretHash = sha256Hex(client_secret + salt);

  await db
    .update(oauthClientsTable)
    .set({
      clientSecretHash: secretHash,
      clientSecretSalt: salt,
      updatedAt: new Date(),
    })
    .where(eq(oauthClientsTable.id, app.id));

  res.json({ client_secret });
});

// Public client info for OAuth login page branding
app.get("/oauth/clients/:clientId/info", async (req, res) => {
  const [client] = await db
    .select({
      name: oauthClientsTable.name,
      appURL: oauthClientsTable.appURL,
    })
    .from(oauthClientsTable)
    .where(eq(oauthClientsTable.clientId, req.params.clientId))
    .limit(1);

  if (!client) {
    res.status(404).json({ message: "Client not found." });
    return;
  }

  res.json(client);
});

// Legacy unauthenticated client registration (redirects to console)
app.post("/oauth/clients", async (req, res) => {
  res.status(401).json({
    message: "Sign in to the developer console to create applications.",
  });
});

app.get("/callback", (req, res) => {
  return res.sendFile(path.resolve("public", "callback.html"));
});

// ─── OAuth / OIDC ───────────────────────────────────────────────────────────

app.get("/oauth/authorize", async (req, res) => {
  const response_type = String(req.query.response_type ?? "");
  const client_id = String(req.query.client_id ?? "");
  const redirect_uri = String(req.query.redirect_uri ?? "");
  const scope = typeof req.query.scope === "string" ? req.query.scope : undefined;
  const state = typeof req.query.state === "string" ? req.query.state : undefined;
  const nonce = typeof req.query.nonce === "string" ? req.query.nonce : undefined;

  if (response_type !== "code") {
    res.status(400).json({ message: "Only response_type=code is supported." });
    return;
  }
  if (!client_id || !redirect_uri) {
    res.status(400).json({ message: "client_id and redirect_uri are required." });
    return;
  }

  const [client] = await db
    .select()
    .from(oauthClientsTable)
    .where(eq(oauthClientsTable.clientId, client_id))
    .limit(1);

  if (!client) {
    res.status(400).json({ message: "Invalid client_id." });
    return;
  }

  if (client.redirectURI !== redirect_uri) {
    res.status(400).json({ message: "redirect_uri is not allowed for this client." });
    return;
  }

  const q = new URLSearchParams();
  q.set("client_id", client_id);
  q.set("redirect_uri", redirect_uri);
  if (scope) q.set("scope", scope);
  if (state) q.set("state", state);
  if (nonce) q.set("nonce", nonce);

  res.redirect(`/o/authenticate?${q.toString()}`);
});

app.get("/o/authenticate", (req, res) => {
  const client_id = typeof req.query.client_id === "string" ? req.query.client_id : "";
  const redirect_uri =
    typeof req.query.redirect_uri === "string" ? req.query.redirect_uri : "";

  // End-user login only happens as part of OAuth authorize (not standalone).
  if (!client_id || !redirect_uri) {
    res.redirect("/console/login.html");
    return;
  }

  return res.sendFile(path.resolve("public", "authenticate.html"));
});

app.post("/o/authenticate/sign-in", async (req, res) => {
  const { email, password } = req.body;
  const client_id = typeof req.body?.client_id === "string" ? req.body.client_id : undefined;
  const redirect_uri =
    typeof req.body?.redirect_uri === "string" ? req.body.redirect_uri : undefined;
  const state = typeof req.body?.state === "string" ? req.body.state : undefined;
  const nonce = typeof req.body?.nonce === "string" ? req.body.nonce : undefined;
  const scope = typeof req.body?.scope === "string" ? req.body.scope : undefined;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required." });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (!user || !user.password || !user.salt) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  const hash = crypto
    .createHash("sha256")
    .update(password + user.salt)
    .digest("hex");

  if (hash !== user.password) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  if (client_id && redirect_uri) {
    const [client] = await db
      .select()
      .from(oauthClientsTable)
      .where(eq(oauthClientsTable.clientId, client_id))
      .limit(1);

    if (!client) {
      res.status(400).json({ message: "Invalid client_id." });
      return;
    }
    if (client.redirectURI !== redirect_uri) {
      res.status(400).json({ message: "redirect_uri is not allowed for this client." });
      return;
    }

    const code = `c_${randomBase64Url(32)}`;
    const codeSalt = crypto.randomBytes(16).toString("hex");
    const codeHash = sha256Hex(code + codeSalt);
    const expiresAt = new Date(Date.now() + 2 * 60 * 1000); 

    await db.insert(oauthAuthCodesTable).values({
      codeHash,
      codeSalt,
      clientId: client_id,
      userId: user.id,
      redirectURI: redirect_uri,
      scope: scope ?? null,
      nonce: nonce ?? null,
      expiresAt,
    });

    const u = new URL(redirect_uri);
    u.searchParams.set("code", code);
    if (state) u.searchParams.set("state", state);

    res.json({ redirect: u.toString() });
    return;
  }

  // Sign-in without OAuth context is not allowed here — use the developer console.
  res.status(400).json({
    message:
      "This page is for signing into third-party apps. Developers should use /console/login.html",
  });
});

app.post("/o/authenticate/sign-up", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  const client_id = typeof req.body?.client_id === "string" ? req.body.client_id : undefined;
  const redirect_uri =
    typeof req.body?.redirect_uri === "string" ? req.body.redirect_uri : undefined;
  const state = typeof req.body?.state === "string" ? req.body.state : undefined;
  const nonce = typeof req.body?.nonce === "string" ? req.body.nonce : undefined;
  const scope = typeof req.body?.scope === "string" ? req.body.scope : undefined;

  if (!email || !password || !firstName) {
    res
      .status(400)
      .json({ message: "First name, email, and password are required." });
    return;
  }

  const [existing] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing) {
    res
      .status(409)
      .json({ message: "An account with this email already exists." });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest("hex");

  await db.insert(usersTable).values({
    firstName,
    lastName: lastName ?? null,
    email,
    password: hash,
    salt,
  });

  if (client_id && redirect_uri) {
    const [client] = await db
      .select()
      .from(oauthClientsTable)
      .where(eq(oauthClientsTable.clientId, client_id))
      .limit(1);

    if (!client) {
      res.status(400).json({ message: "Invalid client_id." });
      return;
    }
    if (client.redirectURI !== redirect_uri) {
      res.status(400).json({ message: "redirect_uri is not allowed for this client." });
      return;
    }

    const [createdUser] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.email, email))
      .limit(1);

    if (!createdUser) {
      res.status(500).json({ message: "Unable to create account." });
      return;
    }

    const code = `c_${randomBase64Url(32)}`;
    const codeSalt = crypto.randomBytes(16).toString("hex");
    const codeHash = sha256Hex(code + codeSalt);
    const expiresAt = new Date(Date.now() + 2 * 60 * 1000);

    await db.insert(oauthAuthCodesTable).values({
      codeHash,
      codeSalt,
      clientId: client_id,
      userId: createdUser.id,
      redirectURI: redirect_uri,
      scope: scope ?? null,
      nonce: nonce ?? null,
      expiresAt,
    });

    const u = new URL(redirect_uri);
    u.searchParams.set("code", code);
    if (state) u.searchParams.set("state", state);

    res.status(201).json({ redirect: u.toString() });
    return;
  }

  res.status(201).json({ ok: true, redirect: "/console/login.html" });
});

app.post("/oauth/token", async (req, res) => {
  const grant_type = String(req.body?.grant_type ?? "");

  const basic = parseBasicAuth(req.headers.authorization);
  const client_id =
    (basic?.username ?? (typeof req.body?.client_id === "string" ? req.body.client_id : "")) ||
    "";
  const client_secret =
    (basic?.password ??
      (typeof req.body?.client_secret === "string" ? req.body.client_secret : "")) ||
    "";

  if (!client_id || !client_secret) {
    res.status(401).json({ message: "Missing client credentials." });
    return;
  }

  const [client] = await db
    .select()
    .from(oauthClientsTable)
    .where(eq(oauthClientsTable.clientId, client_id))
    .limit(1);

  if (!client) {
    res.status(401).json({ message: "Invalid client credentials." });
    return;
  }

  const expected = sha256Hex(client_secret + client.clientSecretSalt);
  if (expected !== client.clientSecretHash) {
    res.status(401).json({ message: "Invalid client credentials." });
    return;
  }

  const ISSUER = issuer();
  const now = Math.floor(Date.now() / 1000);

  if (grant_type === "authorization_code") {
    const code = typeof req.body?.code === "string" ? req.body.code : "";
    const redirect_uri = typeof req.body?.redirect_uri === "string" ? req.body.redirect_uri : "";
    if (!code || !redirect_uri) {
      res.status(400).json({ message: "code and redirect_uri are required." });
      return;
    }
    if (redirect_uri !== client.redirectURI) {
      res.status(400).json({ message: "redirect_uri mismatch." });
      return;
    }

    // Find the specific code: we store only a salted hash, so we check candidates.
    const candidates = await db
      .select()
      .from(oauthAuthCodesTable)
      .where(
        and(
          eq(oauthAuthCodesTable.clientId, client_id),
          eq(oauthAuthCodesTable.redirectURI, redirect_uri),
          isNull(oauthAuthCodesTable.usedAt),
        ),
      )
      .orderBy(oauthAuthCodesTable.createdAt)
      .limit(100);

    const nowMs = Date.now();
    const match = candidates.find((row) => {
      if (row.expiresAt.getTime() < nowMs) return false;
      const computed = sha256Hex(code + row.codeSalt);
      return computed === row.codeHash;
    });

    if (!match) {
      const expiredMatch = candidates.find((row) => {
        const computed = sha256Hex(code + row.codeSalt);
        return computed === row.codeHash;
      });
      res
        .status(400)
        .json({ message: expiredMatch ? "Code expired." : "Invalid code." });
      return;
    }

    await db
      .update(oauthAuthCodesTable)
      .set({ usedAt: new Date() })
      .where(eq(oauthAuthCodesTable.id, match.id));

    const jti = `atk_${randomBase64Url(24)}`;
    const accessExp = now + 600; 
    const accessExpiresAt = new Date(accessExp * 1000);

    const refresh = `rt_${randomBase64Url(48)}`;
    const refreshSalt = crypto.randomBytes(16).toString("hex");
    const refreshHash = sha256Hex(refresh + refreshSalt);
    const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); 

    const claims: JWTClaims & { jti: string; aud: string } = {
      iss: ISSUER,
      sub: match.userId,
      aud: client_id,
      jti,
      email: "",
      email_verified: "false",
      exp: accessExp,
      given_name: "",
      name: "",
    };

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, match.userId))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    claims.email = user.email;
    claims.email_verified = String(user.emailVerified);
    claims.given_name = user.firstName ?? "";
    claims.family_name = user.lastName ?? undefined;
    claims.name = [user.firstName, user.lastName].filter(Boolean).join(" ");
    claims.picture = user.profileImageURL ?? undefined;

    const access_token = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

    await db.insert(oauthTokensTable).values({
      jti,
      clientId: client_id,
      userId: user.id,
      scope: match.scope ?? null,
      accessExpiresAt,
      refreshTokenHash: refreshHash,
      refreshTokenSalt: refreshSalt,
      refreshExpiresAt,
    });

    res.json({
      token_type: "Bearer",
      access_token,
      expires_in: 60,
      refresh_token: refresh,
    });
    return;
  }

  if (grant_type === "refresh_token") {
    const refresh_token =
      typeof req.body?.refresh_token === "string" ? req.body.refresh_token : "";
    if (!refresh_token) {
      res.status(400).json({ message: "refresh_token is required." });
      return;
    }

    const refreshHashCandidates = await db
      .select()
      .from(oauthTokensTable)
      .where(and(eq(oauthTokensTable.clientId, client_id), isNull(oauthTokensTable.revokedAt)))
      .limit(50);

    const matching = refreshHashCandidates.find((row) => {
      const computed = sha256Hex(refresh_token + row.refreshTokenSalt);
      return computed === row.refreshTokenHash;
    });

    if (!matching) {
      res.status(400).json({ message: "Invalid refresh_token." });
      return;
    }

    if (matching.refreshExpiresAt.getTime() < Date.now()) {
      res.status(400).json({ message: "Refresh token expired." });
      return;
    }

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, matching.userId))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    const jti = `atk_${randomBase64Url(24)}`;
    const accessExp = now + 60;
    const accessExpiresAt = new Date(accessExp * 1000);

    const claims: JWTClaims & { jti: string; aud: string } = {
      iss: ISSUER,
      sub: user.id,
      aud: client_id,
      jti,
      email: user.email,
      email_verified: String(user.emailVerified),
      exp: accessExp,
      given_name: user.firstName ?? "",
      family_name: user.lastName ?? undefined,
      name: [user.firstName, user.lastName].filter(Boolean).join(" "),
      picture: user.profileImageURL ?? undefined,
    };

    const access_token = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

    // rotate access token jti in DB (keep same refresh token)
    await db
      .update(oauthTokensTable)
      .set({ jti, accessExpiresAt })
      .where(eq(oauthTokensTable.id, matching.id));

    res.json({
      token_type: "Bearer",
      access_token,
      expires_in: 60,
      refresh_token,
    });
    return;
  }

  res.status(400).json({ message: "Unsupported grant_type." });
});

// OAuth / OIDC userinfo endpoint
app.get("/oauth/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    res
      .status(401)
      .json({ message: "Missing or invalid Authorization header." });
    return;
  }

  const token = authHeader.slice(7);

  let claims: (JWTClaims & { jti?: string }) | null = null;
  try {
    claims = JWT.verify(token, PUBLIC_KEY, {
      algorithms: ["RS256"],
    }) as JWTClaims & { jti?: string };
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  if (!claims?.jti) {
    res.status(401).json({ message: "Invalid token." });
    return;
  }

  const [stored] = await db
    .select()
    .from(oauthTokensTable)
    .where(and(eq(oauthTokensTable.jti, claims.jti), isNull(oauthTokensTable.revokedAt)))
    .limit(1);

  if (!stored) {
    res.status(401).json({ message: "Token revoked or unknown." });
    return;
  }
  if (stored.accessExpiresAt.getTime() < Date.now()) {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, claims.sub))
    .limit(1);

  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({
    sub: user.id,
    user_id: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    given_name: user.firstName,
    family_name: user.lastName,
    first_name: user.firstName,
    last_name: user.lastName,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL,
  });
});

app.listen(PORT, () => {
  console.log(`AuthServer is running on PORT ${PORT}`);
});
