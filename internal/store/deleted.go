package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Soft-delete / recycle bin (docs/20-stateful-directory.md). Deleting a user,
// group, or application moves it to the deleted_items graveyard with a JSON
// snapshot of the object plus the relationships needed to restore it. The live
// tables lose the row entirely, so no read path (sign-in, token issuance, Graph
// reads) needs to filter soft-deleted objects. Restore re-materializes the
// object; a purge (permanent delete or 30-day expiry) drops the snapshot.

const (
	DeletedTypeUser  = "user"
	DeletedTypeGroup = "group"
	DeletedTypeApp   = "application"

	// DeletedItemRetentionSeconds is Entra's 30-day recycle-bin window. Measured
	// against the controllable clock, so retention is deterministically testable.
	DeletedItemRetentionSeconds = 30 * 24 * 60 * 60
)

// DeletedItem is a soft-deleted directory object awaiting restore or purge.
type DeletedItem struct {
	ID          string
	ObjectType  string // DeletedType{User,Group,App}
	TenantID    string
	DisplayName string
	Payload     string // JSON snapshot (object + relationships)
	DeletedAt   int64
}

type deletedUserPayload struct {
	User     *User    `json:"user"`
	GroupIDs []string `json:"groupIds"`
}

type deletedGroupPayload struct {
	Group     *Group   `json:"group"`
	MemberIDs []string `json:"memberIds"`
}

// SoftDeleteUser snapshots a user (with its group memberships) and moves it to
// the recycle bin, clearing live grants exactly like a hard DeleteUser would.
func (s *Store) SoftDeleteUser(id string) error {
	u, err := s.GetUser(id)
	if err != nil {
		return err
	}
	groups, err := s.ListGroupsForUser(id)
	if err != nil {
		return err
	}
	gids := make([]string, 0, len(groups))
	for _, g := range groups {
		gids = append(gids, g.ID)
	}
	payload, err := json.Marshal(deletedUserPayload{User: u, GroupIDs: gids})
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM authorization_codes WHERE user_id=?`,
			`DELETE FROM refresh_tokens WHERE user_id=?`,
			`UPDATE device_codes SET user_id=NULL WHERE user_id=?`,
		} {
			if _, err := tx.Exec(q, id); err != nil {
				return err
			}
		}
		res, err := tx.Exec(`DELETE FROM users WHERE id=?`, id)
		if err != nil {
			return err
		}
		if err := requireRow(res); err != nil {
			return err
		}
		return insertDeletedTx(tx, DeletedItem{ID: u.ID, ObjectType: DeletedTypeUser,
			TenantID: u.TenantID, DisplayName: u.DisplayName, Payload: string(payload), DeletedAt: s.Now()})
	})
}

// SoftDeleteGroup snapshots a group (with its members) and recycles it.
func (s *Store) SoftDeleteGroup(id string) error {
	g, err := s.GetGroup(id)
	if err != nil {
		return err
	}
	members, err := s.ListGroupMembers(id)
	if err != nil {
		return err
	}
	mids := make([]string, 0, len(members))
	for _, m := range members {
		mids = append(mids, m.ID)
	}
	payload, err := json.Marshal(deletedGroupPayload{Group: g, MemberIDs: mids})
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM groups WHERE id=?`, id) // cascades group_members
		if err != nil {
			return err
		}
		if err := requireRow(res); err != nil {
			return err
		}
		return insertDeletedTx(tx, DeletedItem{ID: g.ID, ObjectType: DeletedTypeGroup,
			TenantID: g.TenantID, DisplayName: g.DisplayName, Payload: string(payload), DeletedAt: s.Now()})
	})
}

// SoftDeleteApp snapshots an app registration with all its sub-resources and
// recycles it, clearing live grants like a hard DeleteApp would.
func (s *Store) SoftDeleteApp(appID string) error {
	a, err := s.GetApp(appID)
	if err != nil {
		return err
	}
	ae := AppExport{App: a}
	if ae.RedirectURIs, err = s.ListRedirectURIs(appID); err != nil {
		return err
	}
	if ae.Secrets, err = s.ListSecrets(appID); err != nil {
		return err
	}
	if ae.Scopes, err = s.ListScopes(appID); err != nil {
		return err
	}
	if ae.Roles, err = s.ListRoles(appID); err != nil {
		return err
	}
	payload, err := json.Marshal(ae)
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM authorization_codes WHERE app_id=?`,
			`DELETE FROM refresh_tokens WHERE app_id=?`,
			`DELETE FROM device_codes WHERE app_id=?`,
		} {
			if _, err := tx.Exec(q, appID); err != nil {
				return err
			}
		}
		res, err := tx.Exec(`DELETE FROM app_registrations WHERE app_id=?`, appID) // cascades children
		if err != nil {
			return err
		}
		if err := requireRow(res); err != nil {
			return err
		}
		return insertDeletedTx(tx, DeletedItem{ID: a.ID, ObjectType: DeletedTypeApp,
			TenantID: a.TenantID, DisplayName: a.DisplayName, Payload: string(payload), DeletedAt: s.Now()})
	})
}

func insertDeletedTx(tx *sql.Tx, d DeletedItem) error {
	_, err := tx.Exec(
		`INSERT INTO deleted_items (id, object_type, tenant_id, display_name, payload, deleted_at)
		 VALUES (?,?,?,?,?,?)`,
		d.ID, d.ObjectType, d.TenantID, nullable(d.DisplayName), d.Payload, d.DeletedAt)
	return err
}

const deletedCols = `id, object_type, tenant_id, COALESCE(display_name,''), payload, deleted_at`

func scanDeleted(row interface{ Scan(...any) error }) (*DeletedItem, error) {
	d := &DeletedItem{}
	err := row.Scan(&d.ID, &d.ObjectType, &d.TenantID, &d.DisplayName, &d.Payload, &d.DeletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// purgeExpired hard-deletes recycle-bin items past the 30-day window. Called
// lazily before any recycle-bin read so retention needs no background sweep.
func (s *Store) purgeExpired() error {
	_, err := s.db.Exec(`DELETE FROM deleted_items WHERE deleted_at <= ?`,
		s.Now()-DeletedItemRetentionSeconds)
	return err
}

// ListDeletedItems returns recycle-bin items, optionally filtered by object
// type ("" = all), newest first. Expired items are purged first.
func (s *Store) ListDeletedItems(objectType string) ([]*DeletedItem, error) {
	if err := s.purgeExpired(); err != nil {
		return nil, err
	}
	q := `SELECT ` + deletedCols + ` FROM deleted_items`
	args := []any{}
	if objectType != "" {
		q += ` WHERE object_type = ?`
		args = append(args, objectType)
	}
	q += ` ORDER BY deleted_at DESC, id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DeletedItem
	for rows.Next() {
		d, err := scanDeleted(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDeletedItem returns one recycle-bin item (any type), or ErrNotFound if it
// was never deleted or has been purged.
func (s *Store) GetDeletedItem(id string) (*DeletedItem, error) {
	if err := s.purgeExpired(); err != nil {
		return nil, err
	}
	return scanDeleted(s.db.QueryRow(`SELECT `+deletedCols+` FROM deleted_items WHERE id=?`, id))
}

// PurgeDeletedItem permanently removes a recycle-bin item.
func (s *Store) PurgeDeletedItem(id string) error {
	if err := s.purgeExpired(); err != nil {
		return err
	}
	res, err := s.db.Exec(`DELETE FROM deleted_items WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// RestoreDeletedItem re-materializes a soft-deleted object (with the
// relationships captured at delete time) and removes it from the recycle bin.
// Returns ErrNotFound if it is not restorable, ErrConflict if a live object now
// occupies its unique key (e.g. the UPN was reused).
func (s *Store) RestoreDeletedItem(id string) (*DeletedItem, error) {
	d, err := s.GetDeletedItem(id)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	err = s.tx(func(tx *sql.Tx) error {
		switch d.ObjectType {
		case DeletedTypeUser:
			var p deletedUserPayload
			if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
				return err
			}
			if err := restoreUserTx(tx, p, now); err != nil {
				return err
			}
		case DeletedTypeGroup:
			var p deletedGroupPayload
			if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
				return err
			}
			if err := restoreGroupTx(tx, p, now); err != nil {
				return err
			}
		case DeletedTypeApp:
			var ae AppExport
			if err := json.Unmarshal([]byte(d.Payload), &ae); err != nil {
				return err
			}
			if err := insertAppExportTx(tx, ae, now); err != nil {
				return err
			}
		default:
			return fmt.Errorf("store: unknown deleted object type %q", d.ObjectType)
		}
		res, err := tx.Exec(`DELETE FROM deleted_items WHERE id=?`, id)
		if err != nil {
			return err
		}
		return requireRow(res)
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func restoreUserTx(tx *sql.Tx, p deletedUserPayload, now int64) error {
	u := p.User
	created := u.CreatedAt
	if created == 0 {
		created = now
	}
	updated := u.UpdatedAt
	if updated == 0 {
		updated = created
	}
	if _, err := tx.Exec(`INSERT INTO users
		(id, tenant_id, user_principal_name, display_name, given_name, surname, mail, password_hash, account_enabled, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.TenantID, u.UserPrincipalName, u.DisplayName,
		nullable(u.GivenName), nullable(u.Surname), nullable(u.Mail), nullable(u.PasswordHash),
		u.AccountEnabled, created, updated); err != nil {
		return mapConstraint(err)
	}
	return reattachMembersTx(tx, p.GroupIDs, `SELECT 1 FROM groups WHERE id=?`,
		func(gid string) (string, string) { return gid, u.ID })
}

func restoreGroupTx(tx *sql.Tx, p deletedGroupPayload, now int64) error {
	g := p.Group
	created := g.CreatedAt
	if created == 0 {
		created = now
	}
	if _, err := tx.Exec(`INSERT INTO groups (id, tenant_id, display_name, description, created_at)
		VALUES (?,?,?,?,?)`, g.ID, g.TenantID, g.DisplayName, nullable(g.Description), created); err != nil {
		return mapConstraint(err)
	}
	return reattachMembersTx(tx, p.MemberIDs, `SELECT 1 FROM users WHERE id=?`,
		func(uid string) (string, string) { return g.ID, uid })
}

// reattachMembersTx re-adds group_members edges for each id whose counterpart
// still exists (existsQ probes the counterpart; edge maps id -> (groupID, userID)).
func reattachMembersTx(tx *sql.Tx, ids []string, existsQ string, edge func(string) (groupID, userID string)) error {
	for _, id := range ids {
		var one int
		switch err := tx.QueryRow(existsQ, id).Scan(&one); {
		case errors.Is(err, sql.ErrNoRows):
			continue // counterpart gone; skip, matching Entra's best-effort restore
		case err != nil:
			return err
		}
		gid, uid := edge(id)
		if _, err := tx.Exec(`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)`, gid, uid); err != nil {
			return err
		}
	}
	return nil
}

// insertAppExportTx re-inserts an app registration and all its sub-resources,
// mirroring the app-insert path in ImportDirectory.
func insertAppExportTx(tx *sql.Tx, ae AppExport, now int64) error {
	a := ae.App
	created := a.CreatedAt
	if created == 0 {
		created = now
	}
	exec := func(q string, args ...any) error { _, err := tx.Exec(q, args...); return err }
	if _, err := tx.Exec(`INSERT INTO app_registrations
		(app_id, tenant_id, display_name, is_confidential, app_id_uri, optional_claims, group_membership_claims, group_overage_limit, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		a.ID, a.TenantID, a.DisplayName, a.IsConfidential, nullable(a.AppIDURI),
		nullable(a.OptionalClaims), coalesceStr(a.GroupMembershipClaims, "None"),
		nullableInt(a.GroupOverageLimit), created); err != nil {
		return mapConstraint(err)
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
	return nil
}
