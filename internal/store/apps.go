package store

import (
	"database/sql"
	"errors"
)

const appCols = `app_id, tenant_id, display_name, is_confidential, COALESCE(app_id_uri,''),
	COALESCE(optional_claims,''), group_membership_claims, COALESCE(group_overage_limit,0), created_at`

func scanApp(row interface{ Scan(...any) error }) (*App, error) {
	a := &App{}
	err := row.Scan(&a.ID, &a.TenantID, &a.DisplayName, &a.IsConfidential, &a.AppIDURI,
		&a.OptionalClaims, &a.GroupMembershipClaims, &a.GroupOverageLimit, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) GetApp(appID string) (*App, error) {
	return scanApp(s.db.QueryRow(`SELECT `+appCols+` FROM app_registrations WHERE app_id=?`, appID))
}

func (s *Store) GetAppByIDURI(uri string) (*App, error) {
	return scanApp(s.db.QueryRow(`SELECT `+appCols+` FROM app_registrations WHERE app_id_uri=?`, uri))
}

func (s *Store) ListApps(top, skip int, search string) ([]*App, int, error) {
	where, args := "", []any{}
	if search != "" {
		where = ` WHERE display_name LIKE ? COLLATE NOCASE`
		args = append(args, "%"+search+"%")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM app_registrations`+where, args...).Scan(&count); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT `+appCols+` FROM app_registrations`+where+` ORDER BY app_id LIMIT ? OFFSET ?`,
		append(args, top, skip)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, count, rows.Err()
}

// appIDURITaken reports whether another app already claims the URI
// (uniqueness required for unambiguous `.default` resolution).
func (s *Store) appIDURITaken(uri, exceptAppID string) (bool, error) {
	if uri == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM app_registrations WHERE app_id_uri=? AND app_id<>?`,
		uri, exceptAppID).Scan(&n)
	return n > 0, err
}

func (s *Store) CreateApp(a *App) error {
	if taken, err := s.appIDURITaken(a.AppIDURI, a.ID); err != nil {
		return err
	} else if taken {
		return ErrConflict
	}
	_, err := s.db.Exec(`INSERT INTO app_registrations
		(app_id, tenant_id, display_name, is_confidential, app_id_uri, optional_claims, group_membership_claims, group_overage_limit, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		a.ID, a.TenantID, a.DisplayName, a.IsConfidential, nullable(a.AppIDURI),
		nullable(a.OptionalClaims), coalesceStr(a.GroupMembershipClaims, "None"),
		nullableInt(a.GroupOverageLimit), a.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) UpdateApp(a *App) error {
	if taken, err := s.appIDURITaken(a.AppIDURI, a.ID); err != nil {
		return err
	} else if taken {
		return ErrConflict
	}
	res, err := s.db.Exec(`UPDATE app_registrations SET display_name=?, is_confidential=?,
		app_id_uri=?, optional_claims=?, group_membership_claims=?, group_overage_limit=? WHERE app_id=?`,
		a.DisplayName, a.IsConfidential, nullable(a.AppIDURI), nullable(a.OptionalClaims),
		coalesceStr(a.GroupMembershipClaims, "None"), nullableInt(a.GroupOverageLimit), a.ID)
	if err != nil {
		return mapConstraint(err)
	}
	return requireRow(res)
}

func (s *Store) DeleteApp(appID string) error {
	return s.tx(func(tx *sql.Tx) error {
		// Grants reference apps without CASCADE; clear them explicitly.
		for _, q := range []string{
			`DELETE FROM authorization_codes WHERE app_id=?`,
			`DELETE FROM refresh_tokens WHERE app_id=?`,
			`DELETE FROM device_codes WHERE app_id=?`,
		} {
			if _, err := tx.Exec(q, appID); err != nil {
				return err
			}
		}
		res, err := tx.Exec(`DELETE FROM app_registrations WHERE app_id=?`, appID)
		if err != nil {
			return err
		}
		return requireRow(res)
	})
}

// ---- Redirect URIs ----

func (s *Store) ListRedirectURIs(appID string) ([]*RedirectURI, error) {
	rows, err := s.db.Query(`SELECT id, app_id, uri, type FROM app_redirect_uris WHERE app_id=? ORDER BY id`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RedirectURI
	for rows.Next() {
		r := &RedirectURI{}
		if err := rows.Scan(&r.ID, &r.AppID, &r.URI, &r.Type); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddRedirectURI(appID, uri, typ string) (*RedirectURI, error) {
	res, err := s.db.Exec(`INSERT INTO app_redirect_uris (app_id, uri, type) VALUES (?,?,?)`,
		appID, uri, coalesceStr(typ, "web"))
	if err != nil {
		return nil, mapConstraint(err)
	}
	id, _ := res.LastInsertId()
	return &RedirectURI{ID: id, AppID: appID, URI: uri, Type: coalesceStr(typ, "web")}, nil
}

func (s *Store) DeleteRedirectURI(appID string, id int64) error {
	res, err := s.db.Exec(`DELETE FROM app_redirect_uris WHERE app_id=? AND id=?`, appID, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// HasRedirectURI reports whether uri exactly matches a registered URI.
func (s *Store) HasRedirectURI(appID, uri string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM app_redirect_uris WHERE app_id=? AND uri=?`, appID, uri).Scan(&n)
	return n > 0, err
}

// ---- Secrets ----

func (s *Store) ListSecrets(appID string) ([]*AppSecret, error) {
	rows, err := s.db.Query(`SELECT id, app_id, COALESCE(display_name,''), secret_hash,
		COALESCE(hint,''), COALESCE(expires_at,0), created_at FROM app_secrets WHERE app_id=? ORDER BY created_at`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppSecret
	for rows.Next() {
		sec := &AppSecret{}
		if err := rows.Scan(&sec.ID, &sec.AppID, &sec.DisplayName, &sec.SecretHash,
			&sec.Hint, &sec.ExpiresAt, &sec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

func (s *Store) AddSecret(sec *AppSecret) error {
	_, err := s.db.Exec(`INSERT INTO app_secrets (id, app_id, display_name, secret_hash, hint, expires_at, created_at)
		VALUES (?,?,?,?,?,?,?)`,
		sec.ID, sec.AppID, nullable(sec.DisplayName), sec.SecretHash, nullable(sec.Hint),
		nullableInt64(sec.ExpiresAt), sec.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) DeleteSecret(appID, secretID string) error {
	res, err := s.db.Exec(`DELETE FROM app_secrets WHERE app_id=? AND id=?`, appID, secretID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// VerifyAppSecret checks the plaintext against every unexpired secret of the app.
func (s *Store) VerifyAppSecret(appID, plaintext string) (bool, error) {
	secrets, err := s.ListSecrets(appID)
	if err != nil {
		return false, err
	}
	now := s.Now()
	for _, sec := range secrets {
		if sec.ExpiresAt != 0 && sec.ExpiresAt <= now {
			continue
		}
		if VerifySecret(plaintext, sec.SecretHash) {
			return true, nil
		}
	}
	return false, nil
}

// ---- Scopes ----

func (s *Store) ListScopes(appID string) ([]*AppScope, error) {
	rows, err := s.db.Query(`SELECT id, app_id, value, COALESCE(admin_consent_display_name,''), is_enabled
		FROM app_scopes WHERE app_id=? ORDER BY value`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppScope
	for rows.Next() {
		sc := &AppScope{}
		if err := rows.Scan(&sc.ID, &sc.AppID, &sc.Value, &sc.AdminConsentDisplayName, &sc.IsEnabled); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Store) AddScope(sc *AppScope) error {
	_, err := s.db.Exec(`INSERT INTO app_scopes (id, app_id, value, admin_consent_display_name, is_enabled)
		VALUES (?,?,?,?,?)`,
		sc.ID, sc.AppID, sc.Value, nullable(sc.AdminConsentDisplayName), sc.IsEnabled)
	return mapConstraint(err)
}

func (s *Store) UpdateScope(sc *AppScope) error {
	res, err := s.db.Exec(`UPDATE app_scopes SET admin_consent_display_name=?, is_enabled=? WHERE app_id=? AND id=?`,
		nullable(sc.AdminConsentDisplayName), sc.IsEnabled, sc.AppID, sc.ID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) DeleteScope(appID, scopeID string) error {
	res, err := s.db.Exec(`DELETE FROM app_scopes WHERE app_id=? AND id=?`, appID, scopeID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// ---- App roles ----

func (s *Store) ListRoles(appID string) ([]*AppRole, error) {
	rows, err := s.db.Query(`SELECT id, app_id, value, COALESCE(display_name,''), allowed_member_types, is_enabled
		FROM app_roles WHERE app_id=? ORDER BY value`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppRole
	for rows.Next() {
		r := &AppRole{}
		if err := rows.Scan(&r.ID, &r.AppID, &r.Value, &r.DisplayName, &r.AllowedMemberTypes, &r.IsEnabled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddRole(r *AppRole) error {
	_, err := s.db.Exec(`INSERT INTO app_roles (id, app_id, value, display_name, allowed_member_types, is_enabled)
		VALUES (?,?,?,?,?,?)`,
		r.ID, r.AppID, r.Value, nullable(r.DisplayName),
		coalesceStr(r.AllowedMemberTypes, "Application"), r.IsEnabled)
	return mapConstraint(err)
}

func (s *Store) UpdateRole(r *AppRole) error {
	res, err := s.db.Exec(`UPDATE app_roles SET display_name=?, allowed_member_types=?, is_enabled=? WHERE app_id=? AND id=?`,
		nullable(r.DisplayName), coalesceStr(r.AllowedMemberTypes, "Application"), r.IsEnabled, r.AppID, r.ID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) DeleteRole(appID, roleID string) error {
	res, err := s.db.Exec(`DELETE FROM app_roles WHERE app_id=? AND id=?`, appID, roleID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func coalesceStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
