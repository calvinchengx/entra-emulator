package store

import "database/sql"

// DirectorySnapshot is a portable dump of the directory (roadmap #7):
// users, groups + memberships, and app registrations with their sub-resources.
// It deliberately excludes signing keys (tenant crypto, kept stable) and live
// grants (auth codes, refresh tokens, sessions, device codes — transient).
// Password and secret hashes ARE included so a round-trip preserves auth.
type DirectorySnapshot struct {
	Version      int               `json:"version"`
	Users        []*User           `json:"users"`
	Groups       []*Group          `json:"groups"`
	GroupMembers []GroupMembership `json:"groupMembers"`
	Apps         []AppExport       `json:"apps"`
}

// GroupMembership is a (group, user) edge.
type GroupMembership struct {
	GroupID string `json:"groupId"`
	UserID  string `json:"userId"`
}

// AppExport bundles an app registration with its sub-resources.
type AppExport struct {
	App          *App           `json:"app"`
	RedirectURIs []*RedirectURI `json:"redirectUris"`
	Secrets      []*AppSecret   `json:"secrets"` // hash + hint (never plaintext)
	Scopes       []*AppScope    `json:"scopes"`
	Roles        []*AppRole     `json:"roles"`
}

// ExportDirectory reads the full directory into a snapshot.
func (s *Store) ExportDirectory() (*DirectorySnapshot, error) {
	snap := &DirectorySnapshot{Version: 1}

	users, _, err := s.ListUsers(1_000_000, 0, "")
	if err != nil {
		return nil, err
	}
	snap.Users = users

	groups, _, err := s.ListGroups(1_000_000, 0, "")
	if err != nil {
		return nil, err
	}
	snap.Groups = groups
	for _, g := range groups {
		members, err := s.ListGroupMembers(g.ID)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			snap.GroupMembers = append(snap.GroupMembers, GroupMembership{GroupID: g.ID, UserID: m.ID})
		}
	}

	apps, _, err := s.ListApps(1_000_000, 0, "")
	if err != nil {
		return nil, err
	}
	for _, a := range apps {
		ae := AppExport{App: a}
		if ae.RedirectURIs, err = s.ListRedirectURIs(a.ID); err != nil {
			return nil, err
		}
		if ae.Secrets, err = s.ListSecrets(a.ID); err != nil {
			return nil, err
		}
		if ae.Scopes, err = s.ListScopes(a.ID); err != nil {
			return nil, err
		}
		if ae.Roles, err = s.ListRoles(a.ID); err != nil {
			return nil, err
		}
		snap.Apps = append(snap.Apps, ae)
	}
	return snap, nil
}

// ImportDirectory replaces the directory with the snapshot in one
// transaction, preserving the tenant row and signing keys. Live grants are
// cleared (they reference users/apps that are about to change).
func (s *Store) ImportDirectory(snap *DirectorySnapshot, tenantID string) error {
	now := s.Now()
	return s.tx(func(tx *sql.Tx) error {
		// Clear directory + grants (keep tenants, signing_keys).
		for _, t := range []string{
			"authorization_codes", "refresh_tokens", "sessions", "device_codes",
			"group_members", "app_redirect_uris", "app_secrets", "app_scopes", "app_roles",
			"app_registrations", "groups", "users",
		} {
			if _, err := tx.Exec(`DELETE FROM ` + t); err != nil {
				return err
			}
		}

		exec := func(q string, args ...any) error { _, err := tx.Exec(q, args...); return err }

		for _, u := range snap.Users {
			tid := u.TenantID
			if tid == "" {
				tid = tenantID
			}
			created := u.CreatedAt
			if created == 0 {
				created = now
			}
			if err := exec(`INSERT INTO users
				(id, tenant_id, user_principal_name, display_name, given_name, surname, mail, password_hash, account_enabled, created_at)
				VALUES (?,?,?,?,?,?,?,?,?,?)`,
				u.ID, tid, u.UserPrincipalName, u.DisplayName,
				nullable(u.GivenName), nullable(u.Surname), nullable(u.Mail), nullable(u.PasswordHash),
				u.AccountEnabled, created); err != nil {
				return err
			}
		}
		for _, g := range snap.Groups {
			tid := g.TenantID
			if tid == "" {
				tid = tenantID
			}
			created := g.CreatedAt
			if created == 0 {
				created = now
			}
			if err := exec(`INSERT INTO groups (id, tenant_id, display_name, description, created_at)
				VALUES (?,?,?,?,?)`, g.ID, tid, g.DisplayName, nullable(g.Description), created); err != nil {
				return err
			}
		}
		for _, m := range snap.GroupMembers {
			if err := exec(`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)`,
				m.GroupID, m.UserID); err != nil {
				return err
			}
		}
		for _, ae := range snap.Apps {
			a := ae.App
			tid := a.TenantID
			if tid == "" {
				tid = tenantID
			}
			created := a.CreatedAt
			if created == 0 {
				created = now
			}
			if err := exec(`INSERT INTO app_registrations
				(app_id, tenant_id, display_name, is_confidential, app_id_uri, optional_claims, group_membership_claims, group_overage_limit, created_at)
				VALUES (?,?,?,?,?,?,?,?,?)`,
				a.ID, tid, a.DisplayName, a.IsConfidential, nullable(a.AppIDURI),
				nullable(a.OptionalClaims), coalesceStr(a.GroupMembershipClaims, "None"),
				nullableInt(a.GroupOverageLimit), created); err != nil {
				return err
			}
			for _, ru := range ae.RedirectURIs {
				if err := exec(`INSERT INTO app_redirect_uris (app_id, uri, type) VALUES (?,?,?)`,
					a.ID, ru.URI, coalesceStr(ru.Type, "web")); err != nil {
					return err
				}
			}
			for _, sec := range ae.Secrets {
				if err := exec(`INSERT INTO app_secrets (id, app_id, display_name, secret_hash, hint, expires_at, created_at)
					VALUES (?,?,?,?,?,?,?)`,
					sec.ID, a.ID, nullable(sec.DisplayName), sec.SecretHash, nullable(sec.Hint),
					nullableInt64(sec.ExpiresAt), orNow(sec.CreatedAt, now)); err != nil {
					return err
				}
			}
			for _, sc := range ae.Scopes {
				if err := exec(`INSERT INTO app_scopes (id, app_id, value, admin_consent_display_name, is_enabled)
					VALUES (?,?,?,?,?)`,
					sc.ID, a.ID, sc.Value, nullable(sc.AdminConsentDisplayName), sc.IsEnabled); err != nil {
					return err
				}
			}
			for _, role := range ae.Roles {
				if err := exec(`INSERT INTO app_roles (id, app_id, value, display_name, allowed_member_types, is_enabled)
					VALUES (?,?,?,?,?,?)`,
					role.ID, a.ID, role.Value, nullable(role.DisplayName),
					coalesceStr(role.AllowedMemberTypes, "Application"), role.IsEnabled); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func orNow(v, now int64) int64 {
	if v == 0 {
		return now
	}
	return v
}
