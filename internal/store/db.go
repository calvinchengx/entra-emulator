package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/clock"
	_ "modernc.org/sqlite"
)

// Store owns the SQLite connection and exposes the repositories.
type Store struct {
	db *sql.DB
	// Clock is the controllable time source (roadmap #6). Now delegates to
	// it, so admin clock control affects every timestamp the emulator stamps.
	Clock *clock.Clock
	// Now returns the current epoch seconds. Defaults to Clock.Now; tests may
	// override it directly for fully deterministic time.
	Now func() int64
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
  id           TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  issuer       TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id                  TEXT PRIMARY KEY,
  tenant_id           TEXT NOT NULL REFERENCES tenants(id),
  user_principal_name TEXT NOT NULL UNIQUE,
  display_name        TEXT NOT NULL,
  given_name          TEXT,
  surname             TEXT,
  mail                TEXT,
  password_hash       TEXT,
  account_enabled     INTEGER NOT NULL DEFAULT 1,
  created_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_mail ON users(mail);
CREATE TABLE IF NOT EXISTS groups (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  display_name TEXT NOT NULL,
  description  TEXT,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
CREATE TABLE IF NOT EXISTS app_registrations (
  app_id                  TEXT PRIMARY KEY,
  tenant_id               TEXT NOT NULL REFERENCES tenants(id),
  display_name            TEXT NOT NULL,
  is_confidential         INTEGER NOT NULL DEFAULT 0,
  app_id_uri              TEXT,
  optional_claims         TEXT,
  group_membership_claims TEXT NOT NULL DEFAULT 'None',
  group_overage_limit     INTEGER,
  created_at              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apps_tenant ON app_registrations(tenant_id);
CREATE TABLE IF NOT EXISTS app_redirect_uris (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  uri    TEXT NOT NULL,
  type   TEXT NOT NULL DEFAULT 'web',
  UNIQUE(app_id, uri)
);
CREATE TABLE IF NOT EXISTS app_secrets (
  id           TEXT PRIMARY KEY,
  app_id       TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  display_name TEXT,
  secret_hash  TEXT NOT NULL,
  hint         TEXT,
  expires_at   INTEGER,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS app_scopes (
  id                         TEXT PRIMARY KEY,
  app_id                     TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  value                      TEXT NOT NULL,
  admin_consent_display_name TEXT,
  is_enabled                 INTEGER NOT NULL DEFAULT 1,
  UNIQUE(app_id, value)
);
CREATE TABLE IF NOT EXISTS app_roles (
  id                   TEXT PRIMARY KEY,
  app_id               TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  value                TEXT NOT NULL,
  display_name         TEXT,
  allowed_member_types TEXT NOT NULL DEFAULT 'Application',
  is_enabled           INTEGER NOT NULL DEFAULT 1,
  UNIQUE(app_id, value)
);
CREATE TABLE IF NOT EXISTS signing_keys (
  kid           TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  alg           TEXT NOT NULL DEFAULT 'RS256',
  public_jwk    TEXT NOT NULL,
  private_pkcs8 TEXT NOT NULL,
  is_active     INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  not_after     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_signing_keys_active ON signing_keys(tenant_id, is_active);
CREATE TABLE IF NOT EXISTS authorization_codes (
  code                  TEXT PRIMARY KEY,
  app_id                TEXT NOT NULL REFERENCES app_registrations(app_id),
  user_id               TEXT NOT NULL REFERENCES users(id),
  redirect_uri          TEXT NOT NULL,
  scopes                TEXT NOT NULL,
  resource              TEXT,
  code_challenge        TEXT,
  code_challenge_method TEXT,
  nonce                 TEXT,
  expires_at            INTEGER NOT NULL,
  consumed              INTEGER NOT NULL DEFAULT 0,
  created_at            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expiry ON authorization_codes(expires_at);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token        TEXT PRIMARY KEY,
  app_id       TEXT NOT NULL REFERENCES app_registrations(app_id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  scopes       TEXT NOT NULL,
  resource     TEXT,
  expires_at   INTEGER NOT NULL,
  rotated_from TEXT,
  revoked      INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_app_user ON refresh_tokens(app_id, user_id);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS device_codes (
  device_code TEXT PRIMARY KEY,
  user_code   TEXT NOT NULL UNIQUE,
  app_id      TEXT NOT NULL REFERENCES app_registrations(app_id),
  user_id     TEXT,
  scopes      TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  interval    INTEGER NOT NULL DEFAULT 5,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);
`

// Open opens (creating if needed) the SQLite store and applies migrations.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("store: create data dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// The emulator serializes writes through a single connection; SQLite's
	// serialized mode plus WAL keeps concurrent handler reads safe.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	clk := clock.New()
	s := &Store{db: db, Clock: clk, Now: clk.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?)`,
		time.Now().Unix())
	return err
}

// tx runs fn inside a transaction.
func (s *Store) tx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
