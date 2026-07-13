package store

import (
	"database/sql"
	"errors"
)

// Directory-role assignments (docs/20-stateful-directory.md): the unified-RBAC
// roleManagement/directory/roleAssignments state. A tenant-wide assignment
// (directory_scope_id = "/") puts the role's template GUID into the user's wids
// claim. Built-in role definitions are static reference data (roles.go in the
// graph package); only assignments are persisted here.

type DirectoryRoleAssignment struct {
	ID               string
	RoleDefinitionID string
	PrincipalID      string
	DirectoryScopeID string
	CreatedAt        int64
}

const draCols = `id, role_definition_id, principal_id, directory_scope_id, created_at`

func scanDRA(row interface{ Scan(...any) error }) (*DirectoryRoleAssignment, error) {
	a := &DirectoryRoleAssignment{}
	err := row.Scan(&a.ID, &a.RoleDefinitionID, &a.PrincipalID, &a.DirectoryScopeID, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) CreateDirectoryRoleAssignment(a *DirectoryRoleAssignment) error {
	if a.DirectoryScopeID == "" {
		a.DirectoryScopeID = "/"
	}
	_, err := s.db.Exec(`INSERT INTO directory_role_assignments
		(id, role_definition_id, principal_id, directory_scope_id, created_at)
		VALUES (?,?,?,?,?)`,
		a.ID, a.RoleDefinitionID, a.PrincipalID, a.DirectoryScopeID, a.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) GetDirectoryRoleAssignment(id string) (*DirectoryRoleAssignment, error) {
	return scanDRA(s.db.QueryRow(`SELECT `+draCols+` FROM directory_role_assignments WHERE id=?`, id))
}

// ListDirectoryRoleAssignments returns all assignments (handler applies $filter).
func (s *Store) ListDirectoryRoleAssignments() ([]*DirectoryRoleAssignment, error) {
	rows, err := s.db.Query(`SELECT ` + draCols + ` FROM directory_role_assignments ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DirectoryRoleAssignment
	for rows.Next() {
		a, err := scanDRA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DeleteDirectoryRoleAssignment(id string) error {
	res, err := s.db.Exec(`DELETE FROM directory_role_assignments WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// TenantWideRoleTemplateIDs returns the distinct role template GUIDs assigned
// tenant-wide (directory_scope_id = "/") to a principal — the values of its
// wids claim.
func (s *Store) TenantWideRoleTemplateIDs(principalID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT role_definition_id FROM directory_role_assignments
		 WHERE principal_id=? AND directory_scope_id='/' ORDER BY role_definition_id`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
