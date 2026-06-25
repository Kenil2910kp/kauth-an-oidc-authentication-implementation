import JWT from "jsonwebtoken";
import type { Request, Response } from "express";

const SESSION_SECRET =
  process.env.SESSION_SECRET ?? "kauth-dev-session-secret-change-in-production";

const COOKIE_NAME = "kauth_session";
const SESSION_DAYS = 7;

export interface SessionClaims {
  sub: string;
  exp: number;
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  if (!cookieHeader) return {};
  const out: Record<string, string> = {};
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    out[key] = decodeURIComponent(val);
  }
  return out;
}

export function createSessionToken(userId: string): string {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  return JWT.sign({ sub: userId, exp }, SESSION_SECRET);
}

export function verifySessionToken(token: string): SessionClaims | null {
  try {
    return JWT.verify(token, SESSION_SECRET) as SessionClaims;
  } catch {
    return null;
  }
}

export function setSessionCookie(res: Response, userId: string) {
  const token = createSessionToken(userId);
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`,
  );
}

export function clearSessionCookie(res: Response) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
  );
}

export function getSessionUserId(req: Request): string | null {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const claims = verifySessionToken(token);
  return claims?.sub ?? null;
}

export { COOKIE_NAME };
