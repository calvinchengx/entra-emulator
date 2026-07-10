package store

import "database/sql"

// Fixed seed identifiers — deterministic GUIDs so CI fixtures and
// documentation stay stable (docs/03-data-model-and-seed.md).
const (
	SeedUserAliceID  = "aaaaaaaa-0000-0000-0000-000000000001"
	SeedUserBobID    = "aaaaaaaa-0000-0000-0000-000000000002"
	SeedGroupEngID   = "bbbbbbbb-0000-0000-0000-000000000001"
	SeedAppSPAID     = "cccccccc-0000-0000-0000-000000000001"
	SeedAppDaemonID  = "cccccccc-0000-0000-0000-000000000002"
	SeedPassword     = "Password1!"        // intentionally public dev value
	SeedDaemonSecret = "daemon-app-secret" // intentionally public dev value
)

// IsSeeded reports whether the directory has a tenant row.
func (s *Store) IsSeeded() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Seed applies the deterministic directory. Idempotent (INSERT OR IGNORE):
// safe to force-run over an existing directory; never deletes anything.
// Returns true when the tenant row was absent beforehand.
func (s *Store) Seed(tenantID, issuer string) (bool, error) {
	seeded, err := s.IsSeeded()
	if err != nil {
		return false, err
	}
	alicePwd, err := HashSecret(SeedPassword)
	if err != nil {
		return false, err
	}
	bobPwd, err := HashSecret(SeedPassword)
	if err != nil {
		return false, err
	}
	daemonHash, err := HashSecret(SeedDaemonSecret)
	if err != nil {
		return false, err
	}
	now := s.Now()

	err = s.tx(func(tx *sql.Tx) error {
		exec := func(q string, args ...any) error { _, err := tx.Exec(q, args...); return err }

		if err := exec(`INSERT OR IGNORE INTO tenants (id, display_name, issuer, created_at) VALUES (?,?,?,?)`,
			tenantID, "Entra Emulator", issuer, now); err != nil {
			return err
		}
		if err := exec(`INSERT OR IGNORE INTO users
			(id, tenant_id, user_principal_name, display_name, given_name, surname, mail, password_hash, account_enabled, created_at)
			VALUES (?,?,?,?,?,?,?,?,1,?)`,
			SeedUserAliceID, tenantID, "alice@entraemulator.dev", "Alice Example", "Alice", "Example",
			"alice@entraemulator.dev", alicePwd, now); err != nil {
			return err
		}
		if err := exec(`INSERT OR IGNORE INTO users
			(id, tenant_id, user_principal_name, display_name, given_name, surname, mail, password_hash, account_enabled, created_at)
			VALUES (?,?,?,?,?,?,?,?,1,?)`,
			SeedUserBobID, tenantID, "bob@entraemulator.dev", "Bob Example", "Bob", "Example",
			"bob@entraemulator.dev", bobPwd, now); err != nil {
			return err
		}
		if err := exec(`INSERT OR IGNORE INTO groups (id, tenant_id, display_name, description, created_at)
			VALUES (?,?,?,?,?)`,
			SeedGroupEngID, tenantID, "Engineering", "Seeded engineering group", now); err != nil {
			return err
		}
		for _, uid := range []string{SeedUserAliceID, SeedUserBobID} {
			if err := exec(`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)`,
				SeedGroupEngID, uid); err != nil {
				return err
			}
		}

		// Public SPA app.
		if err := exec(`INSERT OR IGNORE INTO app_registrations
			(app_id, tenant_id, display_name, is_confidential, app_id_uri, group_membership_claims, created_at)
			VALUES (?,?,?,0,?,'None',?)`,
			SeedAppSPAID, tenantID, "Sample SPA", "api://"+SeedAppSPAID, now); err != nil {
			return err
		}
		if err := exec(`INSERT OR IGNORE INTO app_redirect_uris (app_id, uri, type) VALUES (?,?,'spa')`,
			SeedAppSPAID, "https://localhost:3000"); err != nil {
			return err
		}
		if err := exec(`INSERT OR IGNORE INTO app_scopes (id, app_id, value, admin_consent_display_name, is_enabled)
			VALUES (?,?,?,?,1)`,
			"dddddddd-0000-0000-0000-000000000001", SeedAppSPAID, "access_as_user",
			"Access Sample SPA as the signed-in user"); err != nil {
			return err
		}

		// Confidential daemon app.
		if err := exec(`INSERT OR IGNORE INTO app_registrations
			(app_id, tenant_id, display_name, is_confidential, app_id_uri, group_membership_claims, created_at)
			VALUES (?,?,?,1,?,'None',?)`,
			SeedAppDaemonID, tenantID, "Sample Daemon", "api://"+SeedAppDaemonID, now); err != nil {
			return err
		}
		if err := exec(`INSERT OR IGNORE INTO app_secrets (id, app_id, display_name, secret_hash, hint, created_at)
			VALUES (?,?,?,?,?,?)`,
			"eeeeeeee-0000-0000-0000-000000000001", SeedAppDaemonID, "Seeded dev secret",
			daemonHash, secretHint(SeedDaemonSecret), now); err != nil {
			return err
		}
		return exec(`INSERT OR IGNORE INTO app_roles (id, app_id, value, display_name, allowed_member_types, is_enabled)
			VALUES (?,?,?,?,'Application',1)`,
			"ffffffff-0000-0000-0000-000000000001", SeedAppDaemonID, "Tasks.Read.All", "Read all tasks")
	})
	if err != nil {
		return false, err
	}
	return !seeded, nil
}

// Reset empties all data tables inside one transaction, preserving the
// tenants row and (unless resetKeys) the signing keys, then optionally
// reseeds. Returns whether a reseed ran.
func (s *Store) Reset(tenantID, issuer string, reseed, resetKeys bool) (bool, error) {
	err := s.tx(func(tx *sql.Tx) error {
		tables := []string{
			"authorization_codes", "refresh_tokens", "sessions", "device_codes",
			"group_members", "app_redirect_uris", "app_secrets", "app_scopes", "app_roles",
			"app_registrations", "groups", "users",
		}
		if resetKeys {
			tables = append(tables, "signing_keys")
		}
		for _, t := range tables {
			if _, err := tx.Exec(`DELETE FROM ` + t); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if reseed {
		if _, err := s.Seed(tenantID, issuer); err != nil {
			return false, err
		}
	}
	return reseed, nil
}

// secretHint renders the portal-facing hint: first 3 + last 2 characters.
func secretHint(plaintext string) string {
	if len(plaintext) <= 5 {
		return plaintext[:1] + "…"
	}
	return plaintext[:3] + "…" + plaintext[len(plaintext)-2:]
}
