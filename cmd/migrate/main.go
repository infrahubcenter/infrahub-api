// Command migrate applies or rolls back SQL migrations in backend/migrations
// against DATABASE_URL. Usage:
//
//	go run ./cmd/migrate up
//	go run ./cmd/migrate down
//	go run ./cmd/migrate status
//	go run ./cmd/migrate redo
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"vmcontrolcenter/backend/internal/config"
)

const migrationsDir = "migrations"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := config.LoadEnv(); err != nil {
		return err
	}

	if len(os.Args) < 2 {
		return fmt.Errorf("usage: migrate <up|down|status|redo|version> [args]")
	}
	command := os.Args[1]
	args := os.Args[2:]

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	return goose.RunContext(context.Background(), command, db, migrationsDir, args...)
}
