package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migrate runs all database migrations and seeds data.
// It is idempotent — safe to run multiple times.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	slog.Info("starting database migration")

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				slog.Error("failed to rollback migration", "error", rbErr)
			}
		}
	}()

	// --- Trigger function for auto-updating updated_at ---
	slog.Info("creating updated_at trigger function")
	_, err = tx.Exec(ctx, `
		CREATE OR REPLACE FUNCTION trigger_set_updated_at()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = NOW();
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
	`)
	if err != nil {
		return fmt.Errorf("create trigger function: %w", err)
	}

	// --- vpn_tunnels table ---
	slog.Info("creating vpn_tunnels table")
	_, err = tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS vpn_tunnels (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tunnel_id    TEXT NOT NULL UNIQUE,
			name         TEXT NOT NULL,
			peer_ip      INET NOT NULL,
			local_subnet CIDR NOT NULL DEFAULT '10.10.10.0/24',
			psk          TEXT,
			status       TEXT NOT NULL DEFAULT 'active',
			metadata     JSONB DEFAULT '{}',
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return fmt.Errorf("create vpn_tunnels table: %w", err)
	}

	// --- vpn_ip_pool table ---
	slog.Info("creating vpn_ip_pool table")
	_, err = tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS vpn_ip_pool (
			id           SERIAL PRIMARY KEY,
			ip_address   INET NOT NULL UNIQUE,
			is_allocated BOOLEAN NOT NULL DEFAULT FALSE,
			allocated_to TEXT REFERENCES vpn_tunnels(tunnel_id) ON DELETE SET NULL,
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return fmt.Errorf("create vpn_ip_pool table: %w", err)
	}

	// --- Add auth columns for EAP/L2TP multi-tenant support ---
	slog.Info("adding auth_type, username, password columns to vpn_tunnels")
	alterColumns := []string{
		`ALTER TABLE vpn_tunnels ADD COLUMN IF NOT EXISTS auth_type TEXT NOT NULL DEFAULT 'eap' CHECK (auth_type IN ('eap', 'l2tp'))`,
		`ALTER TABLE vpn_tunnels ADD COLUMN IF NOT EXISTS username TEXT`,
		`ALTER TABLE vpn_tunnels ADD COLUMN IF NOT EXISTS password_hash TEXT`,
		`ALTER TABLE vpn_tunnels ADD COLUMN IF NOT EXISTS password_encrypted TEXT`,
	}
	for _, col := range alterColumns {
		if _, err = tx.Exec(ctx, col); err != nil {
			return fmt.Errorf("alter vpn_tunnels add column: %w", err)
		}
	}

	// --- Migrate password_plain → password_encrypted (security fix #46) ---
	// Previous versions stored plaintext passwords. New versions encrypt at rest.
	// If password_plain still exists, encrypt existing values and drop the column.
	slog.Info("migrating password_plain to password_encrypted if needed")
	var hasPlainColumn bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_name='vpn_tunnels' AND column_name='password_plain'
	)`).Scan(&hasPlainColumn)
	if err != nil {
		return fmt.Errorf("check password_plain column: %w", err)
	}
	if hasPlainColumn {
		// Copy plaintext to encrypted (will be encrypted by the app layer on next access).
		// For now, just move the value as-is — the app will re-encrypt on next write.
		_, err = tx.Exec(ctx,
			`UPDATE vpn_tunnels SET password_encrypted = password_plain WHERE password_plain IS NOT NULL AND password_plain != ''`)
		if err != nil {
			return fmt.Errorf("migrate password_plain to password_encrypted: %w", err)
		}
		if _, err = tx.Exec(ctx, `ALTER TABLE vpn_tunnels DROP COLUMN IF EXISTS password_plain`); err != nil {
			return fmt.Errorf("drop password_plain column: %w", err)
		}
		slog.Info("migrated password_plain → password_encrypted, dropped old column")
	}

	// --- Indexes ---
	slog.Info("creating indexes")
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_vpn_tunnels_status ON vpn_tunnels(status)`,
		`CREATE INDEX IF NOT EXISTS idx_vpn_tunnels_tunnel_id ON vpn_tunnels(tunnel_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_tunnels_username ON vpn_tunnels(username) WHERE username IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_vpn_ip_pool_allocated ON vpn_ip_pool(is_allocated)`,
	}
	for _, idx := range indexes {
		if _, err = tx.Exec(ctx, idx); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}

	// --- Updated_at triggers ---
	slog.Info("attaching updated_at triggers")

	_, err = tx.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger WHERE tgname = 'trg_vpn_tunnels_updated_at'
			) THEN
				CREATE TRIGGER trg_vpn_tunnels_updated_at
					BEFORE UPDATE ON vpn_tunnels
					FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();
			END IF;
		END;
		$$;
	`)
	if err != nil {
		return fmt.Errorf("create vpn_tunnels trigger: %w", err)
	}

	_, err = tx.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger WHERE tgname = 'trg_vpn_ip_pool_updated_at'
			) THEN
				CREATE TRIGGER trg_vpn_ip_pool_updated_at
					BEFORE UPDATE ON vpn_ip_pool
					FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();
			END IF;
		END;
		$$;
	`)
	if err != nil {
		return fmt.Errorf("create vpn_ip_pool trigger: %w", err)
	}

	// --- Seed IP pool ---
	slog.Info("seeding vpn_ip_pool with 10.10.10.2–10.10.10.254")
	_, err = tx.Exec(ctx, `
		INSERT INTO vpn_ip_pool (ip_address)
		SELECT (10 || '.10.10.' || i)::INET
		FROM generate_series(2, 254) AS i
		ON CONFLICT (ip_address) DO NOTHING;
	`)
	if err != nil {
		return fmt.Errorf("seed ip pool: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}

	slog.Info("database migration completed successfully")
	return nil
}
