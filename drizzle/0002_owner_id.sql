ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "owner_id" uuid;
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "updated_at" timestamp;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'oauth_clients_owner_id_users_id_fk'
  ) THEN
    ALTER TABLE "oauth_clients"
      ADD CONSTRAINT "oauth_clients_owner_id_users_id_fk"
      FOREIGN KEY ("owner_id") REFERENCES "users"("id");
  END IF;
END $$;
