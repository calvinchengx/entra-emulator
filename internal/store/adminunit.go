package store

import (
	"database/sql"
	"errors"
)

// AdministrativeUnit is a directory container that scopes administration to a
// subset of users and groups. Membership here is what a scoped role assignment
// (directoryScopeId = /administrativeUnits/{id}) refers to.
type AdministrativeUnit struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Visibility  string `json:"visibility"` // Public | HiddenMembership
	CreatedAt   int64  `json:"createdAt"`
}

// AdminUnitMember is one membership row: the object and what kind it is, so the
// Graph layer can stamp the right @odata.type without a second lookup.
type AdminUnitMember struct {
	ID   string
	Type string // user | group
}

const auCols = `id, display_name, COALESCE(description,''), visibility, created_at`

func scanAU(row interface{ Scan(...any) error }) (*AdministrativeUnit, error) {
	a := &AdministrativeUnit{}
	err := row.Scan(&a.ID, &a.DisplayName, &a.Description, &a.Visibility, &a.CreatedAt)
	return a, err
}

func (s *Store) CreateAdministrativeUnit(a *AdministrativeUnit) error {
	if a.Visibility == "" {
		a.Visibility = "Public"
	}
	_, err := s.db.Exec(
		`INSERT INTO administrative_units (id, display_name, description, visibility, created_at)
		 VALUES (?,?,?,?,?)`,
		a.ID, a.DisplayName, a.Description, a.Visibility, a.CreatedAt)
	return err
}

func (s *Store) ListAdministrativeUnits() ([]*AdministrativeUnit, error) {
	rows, err := s.db.Query(`SELECT ` + auCols + ` FROM administrative_units ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AdministrativeUnit{}
	for rows.Next() {
		a, err := scanAU(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAdministrativeUnit(id string) (*AdministrativeUnit, error) {
	a, err := scanAU(s.db.QueryRow(`SELECT `+auCols+` FROM administrative_units WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) UpdateAdministrativeUnit(a *AdministrativeUnit) error {
	res, err := s.db.Exec(
		`UPDATE administrative_units SET display_name=?, description=?, visibility=? WHERE id=?`,
		a.DisplayName, a.Description, a.Visibility, a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAdministrativeUnit(id string) error {
	res, err := s.db.Exec(`DELETE FROM administrative_units WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddAdminUnitMember puts an existing user or group into the unit. The object
// must exist: an AU that "contains" a dangling id would scope administration to
// nothing.
func (s *Store) AddAdminUnitMember(auID, memberID string) error {
	if _, err := s.GetAdministrativeUnit(auID); err != nil {
		return err
	}
	memberType := "user"
	if _, err := s.GetUser(memberID); err != nil {
		if _, gerr := s.GetGroup(memberID); gerr != nil {
			return ErrNotFound
		}
		memberType = "group"
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO administrative_unit_members (au_id, member_id, member_type) VALUES (?,?,?)`,
		auID, memberID, memberType)
	return err
}

func (s *Store) RemoveAdminUnitMember(auID, memberID string) error {
	res, err := s.db.Exec(`DELETE FROM administrative_unit_members WHERE au_id=? AND member_id=?`, auID, memberID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListAdminUnitMembers(auID string) ([]AdminUnitMember, error) {
	rows, err := s.db.Query(
		`SELECT member_id, member_type FROM administrative_unit_members WHERE au_id=? ORDER BY member_id`, auID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminUnitMember{}
	for rows.Next() {
		var m AdminUnitMember
		if err := rows.Scan(&m.ID, &m.Type); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
