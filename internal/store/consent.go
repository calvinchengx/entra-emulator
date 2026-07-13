package store

import (
	"database/sql"
	"errors"
	"strings"
)

// Consent grants (docs/20-stateful-directory.md): the stored state a user/admin
// consent produces on a resource service principal. Delegated consent lives in
// oauth2_permission_grants (→ the scp claim in user tokens); application
// permissions live in app_role_assignments (→ the roles claim in app tokens).
// Because an app registration is its own service principal here, client_id /
// resource_id / principal_id (for SP grantees) are app ids.

// ZeroGUID is Entra's "default assignment, no specific role" app-role id.
const ZeroGUID = "00000000-0000-0000-0000-000000000000"

type OAuth2PermissionGrant struct {
	ID          string
	ClientID    string
	ConsentType string // AllPrincipals | Principal
	ResourceID  string
	PrincipalID string // empty for AllPrincipals
	Scope       string // space-separated
	CreatedAt   int64
}

type AppRoleAssignment struct {
	ID            string
	PrincipalID   string
	PrincipalType string // ServicePrincipal | User
	ResourceID    string
	AppRoleID     string
	CreatedAt     int64
}

// ---- oauth2PermissionGrants ----

const o2pgCols = `id, client_id, consent_type, resource_id, COALESCE(principal_id,''), scope, created_at`

func scanO2PG(row interface{ Scan(...any) error }) (*OAuth2PermissionGrant, error) {
	g := &OAuth2PermissionGrant{}
	err := row.Scan(&g.ID, &g.ClientID, &g.ConsentType, &g.ResourceID, &g.PrincipalID, &g.Scope, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

func (s *Store) CreateOAuth2Grant(g *OAuth2PermissionGrant) error {
	_, err := s.db.Exec(`INSERT INTO oauth2_permission_grants
		(id, client_id, consent_type, resource_id, principal_id, scope, created_at)
		VALUES (?,?,?,?,?,?,?)`,
		g.ID, g.ClientID, g.ConsentType, g.ResourceID, nullable(g.PrincipalID), g.Scope, g.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) GetOAuth2Grant(id string) (*OAuth2PermissionGrant, error) {
	return scanO2PG(s.db.QueryRow(`SELECT `+o2pgCols+` FROM oauth2_permission_grants WHERE id=?`, id))
}

// ListOAuth2Grants returns all grants (handler applies any $filter).
func (s *Store) ListOAuth2Grants() ([]*OAuth2PermissionGrant, error) {
	rows, err := s.db.Query(`SELECT ` + o2pgCols + ` FROM oauth2_permission_grants ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OAuth2PermissionGrant
	for rows.Next() {
		g, err := scanO2PG(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) DeleteOAuth2Grant(id string) error {
	res, err := s.db.Exec(`DELETE FROM oauth2_permission_grants WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// ConsentedScopes returns the set of delegated scope names consented for
// (client, resource) that apply to userID — tenant-wide (AllPrincipals) grants
// plus a Principal grant matching the user — and whether any grant exists for
// (client, resource) at all. Callers intersect requested scopes with the set
// only when hasGrant is true (otherwise the emulator auto-consents).
func (s *Store) ConsentedScopes(clientID, resourceID, userID string) (scopes map[string]bool, hasGrant bool, err error) {
	rows, err := s.db.Query(
		`SELECT consent_type, COALESCE(principal_id,''), scope FROM oauth2_permission_grants
		 WHERE client_id=? AND resource_id=?`, clientID, resourceID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	scopes = map[string]bool{}
	for rows.Next() {
		var consentType, principalID, scope string
		if err := rows.Scan(&consentType, &principalID, &scope); err != nil {
			return nil, false, err
		}
		hasGrant = true
		if consentType == "AllPrincipals" || (consentType == "Principal" && principalID == userID) {
			for _, sc := range strings.Fields(scope) {
				scopes[sc] = true
			}
		}
	}
	return scopes, hasGrant, rows.Err()
}

// ---- appRoleAssignments ----

const araCols = `id, principal_id, principal_type, resource_id, app_role_id, created_at`

func scanARA(row interface{ Scan(...any) error }) (*AppRoleAssignment, error) {
	a := &AppRoleAssignment{}
	err := row.Scan(&a.ID, &a.PrincipalID, &a.PrincipalType, &a.ResourceID, &a.AppRoleID, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) CreateAppRoleAssignment(a *AppRoleAssignment) error {
	if a.PrincipalType == "" {
		a.PrincipalType = "ServicePrincipal"
	}
	_, err := s.db.Exec(`INSERT INTO app_role_assignments
		(id, principal_id, principal_type, resource_id, app_role_id, created_at)
		VALUES (?,?,?,?,?,?)`,
		a.ID, a.PrincipalID, a.PrincipalType, a.ResourceID, a.AppRoleID, a.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) GetAppRoleAssignment(id string) (*AppRoleAssignment, error) {
	return scanARA(s.db.QueryRow(`SELECT `+araCols+` FROM app_role_assignments WHERE id=?`, id))
}

func (s *Store) listARA(where string, arg string) ([]*AppRoleAssignment, error) {
	rows, err := s.db.Query(`SELECT `+araCols+` FROM app_role_assignments WHERE `+where+` ORDER BY created_at, id`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppRoleAssignment
	for rows.Next() {
		a, err := scanARA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAppRoleAssignmentsToResource returns assignments granted ON a resource SP
// (Graph: servicePrincipals/{id}/appRoleAssignedTo).
func (s *Store) ListAppRoleAssignmentsToResource(resourceID string) ([]*AppRoleAssignment, error) {
	return s.listARA("resource_id=?", resourceID)
}

// ListAppRoleAssignmentsForPrincipal returns assignments a principal HOLDS
// (Graph: servicePrincipals/{id}/appRoleAssignments).
func (s *Store) ListAppRoleAssignmentsForPrincipal(principalID string) ([]*AppRoleAssignment, error) {
	return s.listARA("principal_id=?", principalID)
}

func (s *Store) DeleteAppRoleAssignment(id string) error {
	res, err := s.db.Exec(`DELETE FROM app_role_assignments WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// AssignedAppRoleValues returns the app-role values assigned to principal on
// resource (resolving app_role_id → role value, skipping the zero-GUID default)
// and whether any assignment exists for the pair. When an assignment exists the
// caller treats the returned values as authoritative for the roles claim.
func (s *Store) AssignedAppRoleValues(principalID, resourceID string) (values []string, hasAssignment bool, err error) {
	rows, err := s.db.Query(
		`SELECT ara.app_role_id, COALESCE(r.value,'')
		   FROM app_role_assignments ara
		   LEFT JOIN app_roles r ON r.id = ara.app_role_id
		  WHERE ara.principal_id=? AND ara.resource_id=?`, principalID, resourceID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var appRoleID, value string
		if err := rows.Scan(&appRoleID, &value); err != nil {
			return nil, false, err
		}
		hasAssignment = true
		if appRoleID != ZeroGUID && value != "" {
			values = append(values, value)
		}
	}
	return values, hasAssignment, rows.Err()
}
