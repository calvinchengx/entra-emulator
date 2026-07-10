package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned on unique-constraint violations.
var ErrConflict = errors.New("store: conflict")

func mapConstraint(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrConflict
	}
	return err
}

// ---- Tenants ----

func (s *Store) GetTenant() (*Tenant, error) {
	row := s.db.QueryRow(`SELECT id, display_name, issuer, created_at FROM tenants LIMIT 1`)
	t := &Tenant{}
	if err := row.Scan(&t.ID, &t.DisplayName, &t.Issuer, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

// ---- Users ----

const userCols = `id, tenant_id, user_principal_name, display_name,
	COALESCE(given_name,''), COALESCE(surname,''), COALESCE(mail,''),
	COALESCE(password_hash,''), account_enabled, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.TenantID, &u.UserPrincipalName, &u.DisplayName,
		&u.GivenName, &u.Surname, &u.Mail, &u.PasswordHash, &u.AccountEnabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) GetUser(id string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) GetUserByUPN(upn string) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT `+userCols+` FROM users WHERE user_principal_name = ? COLLATE NOCASE`, upn))
}

// ListUsers returns a page ordered by id plus the total matching count.
func (s *Store) ListUsers(top, skip int, search string) ([]*User, int, error) {
	where, args := "", []any{}
	if search != "" {
		where = ` WHERE (user_principal_name LIKE ? COLLATE NOCASE OR display_name LIKE ? COLLATE NOCASE)`
		pat := "%" + search + "%"
		args = append(args, pat, pat)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`+where, args...).Scan(&count); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT `+userCols+` FROM users`+where+` ORDER BY id LIMIT ? OFFSET ?`,
		append(args, top, skip)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, count, rows.Err()
}

func (s *Store) CreateUser(u *User) error {
	_, err := s.db.Exec(`INSERT INTO users
		(id, tenant_id, user_principal_name, display_name, given_name, surname, mail, password_hash, account_enabled, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.TenantID, u.UserPrincipalName, u.DisplayName,
		nullable(u.GivenName), nullable(u.Surname), nullable(u.Mail), nullable(u.PasswordHash),
		u.AccountEnabled, u.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) UpdateUser(u *User) error {
	res, err := s.db.Exec(`UPDATE users SET user_principal_name=?, display_name=?, given_name=?,
		surname=?, mail=?, password_hash=?, account_enabled=? WHERE id=?`,
		u.UserPrincipalName, u.DisplayName, nullable(u.GivenName), nullable(u.Surname),
		nullable(u.Mail), nullable(u.PasswordHash), u.AccountEnabled, u.ID)
	if err != nil {
		return mapConstraint(err)
	}
	return requireRow(res)
}

func (s *Store) DeleteUser(id string) error {
	return s.tx(func(tx *sql.Tx) error {
		// Grants reference users without CASCADE; clear them explicitly.
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
		return requireRow(res)
	})
}

// VerifyPassword returns the user when the UPN + password pair is valid and
// the account is enabled.
func (s *Store) VerifyPassword(upn, password string) (*User, error) {
	u, err := s.GetUserByUPN(upn)
	if err != nil {
		return nil, err
	}
	if !u.AccountEnabled || u.PasswordHash == "" || !VerifySecret(password, u.PasswordHash) {
		return nil, ErrNotFound
	}
	return u, nil
}

// ---- Groups ----

const groupCols = `id, tenant_id, display_name, COALESCE(description,''), created_at`

func scanGroup(row interface{ Scan(...any) error }) (*Group, error) {
	g := &Group{}
	err := row.Scan(&g.ID, &g.TenantID, &g.DisplayName, &g.Description, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

func (s *Store) GetGroup(id string) (*Group, error) {
	return scanGroup(s.db.QueryRow(`SELECT `+groupCols+` FROM groups WHERE id=?`, id))
}

func (s *Store) ListGroups(top, skip int, search string) ([]*Group, int, error) {
	where, args := "", []any{}
	if search != "" {
		where = ` WHERE display_name LIKE ? COLLATE NOCASE`
		args = append(args, "%"+search+"%")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM groups`+where, args...).Scan(&count); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT `+groupCols+` FROM groups`+where+` ORDER BY id LIMIT ? OFFSET ?`,
		append(args, top, skip)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, count, rows.Err()
}

func (s *Store) CreateGroup(g *Group) error {
	_, err := s.db.Exec(`INSERT INTO groups (id, tenant_id, display_name, description, created_at)
		VALUES (?,?,?,?,?)`, g.ID, g.TenantID, g.DisplayName, nullable(g.Description), g.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) UpdateGroup(g *Group) error {
	res, err := s.db.Exec(`UPDATE groups SET display_name=?, description=? WHERE id=?`,
		g.DisplayName, nullable(g.Description), g.ID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) DeleteGroup(id string) error {
	res, err := s.db.Exec(`DELETE FROM groups WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// AddGroupMember is idempotent; ErrNotFound for a missing group or user.
func (s *Store) AddGroupMember(groupID, userID string) error {
	if _, err := s.GetGroup(groupID); err != nil {
		return err
	}
	if _, err := s.GetUser(userID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)`,
		groupID, userID)
	return err
}

func (s *Store) RemoveGroupMember(groupID, userID string) error {
	_, err := s.db.Exec(`DELETE FROM group_members WHERE group_id=? AND user_id=?`, groupID, userID)
	return err
}

func (s *Store) ListGroupMembers(groupID string) ([]*User, error) {
	rows, err := s.db.Query(`SELECT `+userCols+` FROM users
		JOIN group_members gm ON gm.user_id = users.id WHERE gm.group_id=? ORDER BY users.id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListGroupsForUser(userID string) ([]*Group, error) {
	rows, err := s.db.Query(`SELECT `+groupCols+` FROM groups
		JOIN group_members gm ON gm.group_id = groups.id WHERE gm.user_id=? ORDER BY groups.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) CountGroupMembers(groupID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, groupID).Scan(&n)
	return n, err
}

// ---- helpers ----

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func requireRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if n > 1 {
		return fmt.Errorf("store: expected 1 row affected, got %d", n)
	}
	return nil
}
