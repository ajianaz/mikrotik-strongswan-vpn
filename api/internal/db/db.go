package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool creates a new PostgreSQL connection pool from dbURL.
func NewPool(ctx context.Context, dbURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

// Close gracefully shuts down the connection pool.
func Close(pool *pgxpool.Pool) {
	if pool != nil {
		pool.Close()
	}
}
