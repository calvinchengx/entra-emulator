package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
  id             TEXT PRIMARY KEY,
  display_name   TEXT NOT NULL,
  issuer         TEXT NOT NULL,
  initial_domain TEXT,
  created_at     INTEGER NOT NULL
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
  user_type           TEXT NOT NULL DEFAULT 'Member',   -- Member | Guest
  external_user_state TEXT,                             -- guests: PendingAcceptance | Accepted
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER
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
  created_at              INTEGER NOT NULL,
  frontchannel_logout_uri TEXT
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
  amr                   TEXT,
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
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_method TEXT NOT NULL DEFAULT 'pwd',
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
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
CREATE TABLE IF NOT EXISTS token_lifetime_policies (
  id                     TEXT PRIMARY KEY,
  display_name           TEXT NOT NULL,
  definition             TEXT NOT NULL,          -- Entra's JSON-string definition
  is_organization_default INTEGER NOT NULL DEFAULT 0,
  created_at             INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_token_lifetime_policies (
  app_id    TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  policy_id TEXT NOT NULL REFERENCES token_lifetime_policies(id) ON DELETE CASCADE,
  PRIMARY KEY (app_id, policy_id)
);

CREATE TABLE IF NOT EXISTS attribute_sets (
  id                    TEXT PRIMARY KEY,          -- the set name, e.g. "Engineering"
  description           TEXT,
  max_attributes_per_set INTEGER
);

CREATE TABLE IF NOT EXISTS custom_security_attribute_definitions (
  id              TEXT PRIMARY KEY,                -- "{attributeSet}_{name}"
  attribute_set   TEXT NOT NULL REFERENCES attribute_sets(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  type            TEXT NOT NULL,                   -- String | Integer | Boolean
  status          TEXT NOT NULL DEFAULT 'Available',
  is_collection   INTEGER NOT NULL DEFAULT 0,
  is_searchable   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_custom_security_attributes (
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  definition_id TEXT NOT NULL,
  value        TEXT NOT NULL,                      -- JSON-encoded, typed by the definition
  PRIMARY KEY (user_id, definition_id)
);

CREATE TABLE IF NOT EXISTS session_apps (
  session_id TEXT NOT NULL,
  app_id     TEXT NOT NULL,
  PRIMARY KEY (session_id, app_id)
);

CREATE TABLE IF NOT EXISTS administrative_units (
  id           TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  description  TEXT,
  visibility   TEXT NOT NULL DEFAULT 'Public',   -- Public | HiddenMembership
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS administrative_unit_members (
  au_id       TEXT NOT NULL REFERENCES administrative_units(id) ON DELETE CASCADE,
  member_id   TEXT NOT NULL,
  member_type TEXT NOT NULL,                     -- user | group
  PRIMARY KEY (au_id, member_id)
);

CREATE TABLE IF NOT EXISTS custom_role_definitions (
  id               TEXT PRIMARY KEY,
  display_name     TEXT NOT NULL,
  description      TEXT,
  is_enabled       INTEGER NOT NULL DEFAULT 1,
  role_permissions TEXT NOT NULL DEFAULT '[]',   -- JSON array of allowedResourceActions
  created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_federated_credentials (
  id           TEXT PRIMARY KEY,
  app_id       TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  issuer       TEXT NOT NULL,             -- external OIDC issuer (iss)
  subject      TEXT NOT NULL,             -- external workload identity (sub)
  audiences    TEXT NOT NULL,             -- comma-separated accepted aud values
  description  TEXT,
  created_at   INTEGER NOT NULL,
  UNIQUE (app_id, name)
);

CREATE TABLE IF NOT EXISTS app_key_credentials (
  id           TEXT PRIMARY KEY,
  app_id       TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  public_key   TEXT NOT NULL,             -- PEM (PKIX public key or certificate)
  display_name TEXT,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_app_key_creds_app ON app_key_credentials(app_id);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id          TEXT PRIMARY KEY,          -- credential id (base64url)
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key  BLOB NOT NULL,             -- COSE public key
  sign_count  INTEGER NOT NULL DEFAULT 0,
  aaguid      BLOB,
  transports  TEXT,                       -- CSV
  name        TEXT,                       -- friendly label
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE TABLE IF NOT EXISTS workspace_identities (
  id             TEXT PRIMARY KEY,          -- the identity's (service principal) object id
  tenant_id      TEXT NOT NULL REFERENCES tenants(id),
  app_id         TEXT NOT NULL REFERENCES app_registrations(app_id) ON DELETE CASCADE,
  workspace_id   TEXT NOT NULL,             -- linked Fabric workspace GUID
  workspace_name TEXT NOT NULL,             -- name follows the workspace
  state          TEXT NOT NULL DEFAULT 'Active', -- Fabric provisioning state
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workspace_identities_app ON workspace_identities(app_id);
CREATE TABLE IF NOT EXISTS deleted_items (
  id           TEXT PRIMARY KEY,          -- object id, preserved across soft-delete
  object_type  TEXT NOT NULL,             -- user | group | application
  tenant_id    TEXT NOT NULL,
  display_name TEXT,                       -- denormalized for listing
  payload      TEXT NOT NULL,             -- JSON snapshot (object + relationships) for restore
  deleted_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deleted_items_type ON deleted_items(object_type);
CREATE TABLE IF NOT EXISTS oauth2_permission_grants (
  id           TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL,             -- client service principal (app) id
  consent_type TEXT NOT NULL,             -- AllPrincipals | Principal
  resource_id  TEXT NOT NULL,             -- resource/API service principal (app) id
  principal_id TEXT,                       -- user id; NULL for AllPrincipals
  scope        TEXT NOT NULL,             -- space-separated delegated scope values
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_o2pg_client ON oauth2_permission_grants(client_id);
CREATE INDEX IF NOT EXISTS idx_o2pg_resource ON oauth2_permission_grants(resource_id);
CREATE TABLE IF NOT EXISTS app_role_assignments (
  id             TEXT PRIMARY KEY,
  principal_id   TEXT NOT NULL,           -- grantee: client app (SP) or user
  principal_type TEXT NOT NULL DEFAULT 'ServicePrincipal', -- ServicePrincipal | User
  resource_id    TEXT NOT NULL,           -- resource service principal (app) id
  app_role_id    TEXT NOT NULL,           -- app role GUID, or all-zero GUID for the default assignment
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ara_resource ON app_role_assignments(resource_id);
CREATE INDEX IF NOT EXISTS idx_ara_principal ON app_role_assignments(principal_id);
CREATE TABLE IF NOT EXISTS directory_role_assignments (
  id                 TEXT PRIMARY KEY,
  role_definition_id TEXT NOT NULL,       -- built-in role template GUID
  principal_id       TEXT NOT NULL,       -- user id
  directory_scope_id TEXT NOT NULL DEFAULT '/', -- "/" = tenant-wide (drives wids)
  created_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dra_principal ON directory_role_assignments(principal_id);
-- SCIM externalId lives beside the directory rather than on users/groups: it is
-- the provisioning client's own identifier for the resource, not a directory
-- attribute, and real Entra does not surface it on the Graph object.
CREATE TABLE IF NOT EXISTS scim_external_ids (
  resource_type TEXT NOT NULL,            -- User | Group
  resource_id   TEXT NOT NULL,
  external_id   TEXT NOT NULL,
  PRIMARY KEY (resource_type, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_scim_ext ON scim_external_ids(resource_type, external_id);
`

// Open opens (creating if needed) the SQLite store and applies migrations.
func Open(path string) (*Store, error) {
	// ":memory:" is a DSN, not a path — MkdirAll on it would create a
	// directory of that name beside the binary.
	if dir := filepath.Dir(path); path != ":memory:" && dir != "." {
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
	// Best-effort additive column migrations for DBs created before these
	// columns existed. SQLite errors "duplicate column name" when already
	// present — ignored so re-runs are idempotent.
	for _, alter := range []string{
		`ALTER TABLE authorization_codes ADD COLUMN amr TEXT`,
		`ALTER TABLE sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'pwd'`,
		`ALTER TABLE tenants ADD COLUMN initial_domain TEXT`,
		`ALTER TABLE users ADD COLUMN updated_at INTEGER`,
		`ALTER TABLE users ADD COLUMN user_type TEXT NOT NULL DEFAULT 'Member'`,
		`ALTER TABLE users ADD COLUMN external_user_state TEXT`,
		`ALTER TABLE app_registrations ADD COLUMN frontchannel_logout_uri TEXT`,
		`ALTER TABLE users ADD COLUMN invite_redirect_url TEXT`,
	} {
		if _, err := s.db.Exec(alter); err != nil &&
			!strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("store: migrate alter: %w", err)
		}
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
