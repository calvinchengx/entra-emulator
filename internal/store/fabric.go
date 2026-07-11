package store

import (
	"database/sql"
	"errors"
)

// Fabric workspace identities (roadmap #16). A workspace identity owns an app
// registration (its service principal); deleting the identity deletes that app
// (which cascades this row), and renaming the workspace renames the SP.

const workspaceIdentityCols = `id, tenant_id, app_id, workspace_id, workspace_name, state, created_at`

// workspaceIdentityStates is the Fabric workspace-identity lifecycle enum.
var workspaceIdentityStates = map[string]bool{
	"Active": true, "Provisioning": true, "Failed": true, "Deprovisioning": true,
}

// ValidWorkspaceIdentityState reports whether s is a recognized state.
func ValidWorkspaceIdentityState(s string) bool { return workspaceIdentityStates[s] }

func scanWorkspaceIdentity(row interface{ Scan(...any) error }) (*WorkspaceIdentity, error) {
	wi := &WorkspaceIdentity{}
	err := row.Scan(&wi.ID, &wi.TenantID, &wi.AppID, &wi.WorkspaceID,
		&wi.WorkspaceName, &wi.State, &wi.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return wi, err
}

// CreateWorkspaceIdentity provisions the SP app and the identity row in one
// transaction. The app is the confidential service principal whose display
// name follows the workspace.
func (s *Store) CreateWorkspaceIdentity(wi *WorkspaceIdentity, app *App) error {
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO app_registrations
			(app_id, tenant_id, display_name, is_confidential, group_membership_claims, created_at)
			VALUES (?,?,?,1,'None',?)`,
			app.ID, app.TenantID, app.DisplayName, app.CreatedAt); err != nil {
			return mapConstraint(err)
		}
		_, err := tx.Exec(`INSERT INTO workspace_identities
			(`+workspaceIdentityCols+`) VALUES (?,?,?,?,?,?,?)`,
			wi.ID, wi.TenantID, wi.AppID, wi.WorkspaceID, wi.WorkspaceName, wi.State, wi.CreatedAt)
		return mapConstraint(err)
	})
}

func (s *Store) GetWorkspaceIdentity(id string) (*WorkspaceIdentity, error) {
	return scanWorkspaceIdentity(s.db.QueryRow(
		`SELECT `+workspaceIdentityCols+` FROM workspace_identities WHERE id=?`, id))
}

func (s *Store) ListWorkspaceIdentities() ([]*WorkspaceIdentity, error) {
	rows, err := s.db.Query(`SELECT ` + workspaceIdentityCols + ` FROM workspace_identities ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WorkspaceIdentity
	for rows.Next() {
		wi, err := scanWorkspaceIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, wi)
	}
	return out, rows.Err()
}

// UpdateWorkspaceIdentity persists workspace_name and state changes. When the
// workspace is renamed the SP app's display name follows it.
func (s *Store) UpdateWorkspaceIdentity(wi *WorkspaceIdentity) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE workspace_identities SET workspace_name=?, state=? WHERE id=?`,
			wi.WorkspaceName, wi.State, wi.ID)
		if err != nil {
			return err
		}
		if err := requireRow(res); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE app_registrations SET display_name=? WHERE app_id=?`,
			wi.WorkspaceName, wi.AppID)
		return err
	})
}

// DeleteWorkspaceIdentity removes the identity by deleting its SP app; the
// ON DELETE CASCADE on workspace_identities.app_id clears this row, and the
// app's own grant cleanup runs via DeleteApp.
func (s *Store) DeleteWorkspaceIdentity(id string) error {
	wi, err := s.GetWorkspaceIdentity(id)
	if err != nil {
		return err
	}
	return s.DeleteApp(wi.AppID)
}
