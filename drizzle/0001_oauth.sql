CREATE TABLE "oauth_clients" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(120) NOT NULL,
	"app_url" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"client_id" varchar(64) NOT NULL,
	"client_secret_hash" varchar(64) NOT NULL,
	"client_secret_salt" varchar(32) NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "oauth_clients_client_id_unique" UNIQUE("client_id")
);

CREATE TABLE "oauth_auth_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code_hash" varchar(64) NOT NULL,
	"code_salt" varchar(32) NOT NULL,
	"client_id" varchar(64) NOT NULL,
	"user_id" uuid NOT NULL,
	"redirect_uri" text NOT NULL,
	"scope" text,
	"nonce" text,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);

CREATE TABLE "oauth_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"jti" varchar(64) NOT NULL,
	"client_id" varchar(64) NOT NULL,
	"user_id" uuid NOT NULL,
	"scope" text,
	"access_expires_at" timestamp NOT NULL,
	"refresh_token_hash" varchar(64) NOT NULL,
	"refresh_token_salt" varchar(32) NOT NULL,
	"refresh_expires_at" timestamp NOT NULL,
	"revoked_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "oauth_tokens_jti_unique" UNIQUE("jti")
);
