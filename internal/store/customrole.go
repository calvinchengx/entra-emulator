package store

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// CustomRoleDefinition is a tenant-authored directory role. Built-in roles are
// a fixed list in the Graph layer; these are created at runtime and live here.
//
// They are deliberately excluded from the `wids` claim: real Entra emits
// built-in role TEMPLATE GUIDs there and never custom definitions, so
// TenantWideRoleTemplateIDs filters this table out.
type CustomRoleDefinition struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	Description     string   `json:"description,omitempty"`
	IsEnabled       bool     `json:"isEnabled"`
	RolePermissions []string `json:"rolePermissions"` // allowedResourceActions
	CreatedAt       int64    `json:"createdAt"`
}

const customRoleCols = `id, display_name, COALESCE(description,''), is_enabled, role_permissions, created_at`

func scanCustomRole(row interface{ Scan(...any) error }) (*CustomRoleDefinition, error) {
	d := &CustomRoleDefinition{}
	var perms string
	if err := row.Scan(&d.ID, &d.DisplayName, &d.Description, &d.IsEnabled, &perms, &d.CreatedAt); err != nil {
		return nil, err
	}
	d.RolePermissions = []string{}
	_ = json.Unmarshal([]byte(perms), &d.RolePermissions)
	return d, nil
}

// CreateCustomRoleDefinition stores a tenant-authored role.
func (s *Store) CreateCustomRoleDefinition(d *CustomRoleDefinition) error {
	perms, err := json.Marshal(d.RolePermissions)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO custom_role_definitions (id, display_name, description, is_enabled, role_permissions, created_at)
		 VALUES (?,?,?,?,?,?)`,
		d.ID, d.DisplayName, d.Description, d.IsEnabled, string(perms), d.CreatedAt)
	return err
}

// ListCustomRoleDefinitions returns every tenant-authored role.
func (s *Store) ListCustomRoleDefinitions() ([]*CustomRoleDefinition, error) {
	rows, err := s.db.Query(`SELECT ` + customRoleCols + ` FROM custom_role_definitions ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CustomRoleDefinition{}
	for rows.Next() {
		d, err := scanCustomRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetCustomRoleDefinition returns one tenant-authored role.
func (s *Store) GetCustomRoleDefinition(id string) (*CustomRoleDefinition, error) {
	row := s.db.QueryRow(`SELECT `+customRoleCols+` FROM custom_role_definitions WHERE id=?`, id)
	d, err := scanCustomRole(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// UpdateCustomRoleDefinition patches display name, description, enabled state
// and permissions.
func (s *Store) UpdateCustomRoleDefinition(d *CustomRoleDefinition) error {
	perms, err := json.Marshal(d.RolePermissions)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE custom_role_definitions SET display_name=?, description=?, is_enabled=?, role_permissions=? WHERE id=?`,
		d.DisplayName, d.Description, d.IsEnabled, string(perms), d.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCustomRoleDefinition removes a role and any assignments referencing it,
// so a deleted role cannot keep granting access.
func (s *Store) DeleteCustomRoleDefinition(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`DELETE FROM custom_role_definitions WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM directory_role_assignments WHERE role_definition_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
