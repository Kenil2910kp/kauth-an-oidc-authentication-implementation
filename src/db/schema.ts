import {
  uuid,
  pgTable,
  varchar,
  text,
  boolean,
  timestamp,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),

  firstName: varchar("first_name", { length: 25 }),
  lastName: varchar("last_name", { length: 25 }),

  profileImageURL: text("profile_image_url"),

  email: varchar("email", { length: 322 }).notNull(),
  emailVerified: boolean("email_verified").default(false).notNull(),

  password: varchar("password", { length: 66 }),
  salt: text("salt"),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const oauthClientsTable = pgTable("oauth_clients", {
  id: uuid("id").primaryKey().defaultRandom(),

  ownerId: uuid("owner_id").references(() => usersTable.id),

  name: varchar("name", { length: 120 }).notNull(),
  appURL: text("app_url").notNull(),
  redirectURI: text("redirect_uri").notNull(),

  clientId: varchar("client_id", { length: 64 }).notNull().unique(),
  clientSecretHash: varchar("client_secret_hash", { length: 64 }).notNull(),
  clientSecretSalt: varchar("client_secret_salt", { length: 32 }).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const oauthAuthCodesTable = pgTable("oauth_auth_codes", {
  id: uuid("id").primaryKey().defaultRandom(),

  codeHash: varchar("code_hash", { length: 64 }).notNull(),
  codeSalt: varchar("code_salt", { length: 32 }).notNull(),

  clientId: varchar("client_id", { length: 64 }).notNull(),
  userId: uuid("user_id").notNull(),

  redirectURI: text("redirect_uri").notNull(),
  scope: text("scope"),
  nonce: text("nonce"),

  expiresAt: timestamp("expires_at").notNull(),
  usedAt: timestamp("used_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const oauthTokensTable = pgTable("oauth_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),

  jti: varchar("jti", { length: 64 }).notNull().unique(),
  clientId: varchar("client_id", { length: 64 }).notNull(),
  userId: uuid("user_id").notNull(),

  scope: text("scope"),

  accessExpiresAt: timestamp("access_expires_at").notNull(),

  refreshTokenHash: varchar("refresh_token_hash", { length: 64 }).notNull(),
  refreshTokenSalt: varchar("refresh_token_salt", { length: 32 }).notNull(),
  refreshExpiresAt: timestamp("refresh_expires_at").notNull(),

  revokedAt: timestamp("revoked_at"),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});
