package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Custom security attributes: tenant-defined, typed metadata on directory
// objects. An attribute set namespaces definitions, and a definition's id is
// always "{attributeSet}_{name}" — Entra's own composite key.

type AttributeSet struct {
	ID                  string `json:"id"`
	Description         string `json:"description,omitempty"`
	MaxAttributesPerSet *int   `json:"maxAttributesPerSet,omitempty"`
}

type CustomSecurityAttributeDefinition struct {
	ID           string `json:"id"`
	AttributeSet string `json:"attributeSet"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Type         string `json:"type"`   // String | Integer | Boolean
	Status       string `json:"status"` // Available | Deprecated
	IsCollection bool   `json:"isCollection"`
	IsSearchable bool   `json:"isSearchable"`
}

func (s *Store) CreateAttributeSet(a *AttributeSet) error {
	_, err := s.db.Exec(
		`INSERT INTO attribute_sets (id, description, max_attributes_per_set) VALUES (?,?,?)`,
		a.ID, nullable(a.Description), a.MaxAttributesPerSet)
	return mapConstraint(err)
}

func (s *Store) ListAttributeSets() ([]*AttributeSet, error) {
	rows, err := s.db.Query(`SELECT id, COALESCE(description,''), max_attributes_per_set FROM attribute_sets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AttributeSet{}
	for rows.Next() {
		a := &AttributeSet{}
		if err := rows.Scan(&a.ID, &a.Description, &a.MaxAttributesPerSet); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAttributeSet(id string) (*AttributeSet, error) {
	a := &AttributeSet{}
	err := s.db.QueryRow(`SELECT id, COALESCE(description,''), max_attributes_per_set FROM attribute_sets WHERE id=?`, id).
		Scan(&a.ID, &a.Description, &a.MaxAttributesPerSet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

const csaDefCols = `id, attribute_set, name, COALESCE(description,''), type, status, is_collection, is_searchable`

func scanCSADef(row interface{ Scan(...any) error }) (*CustomSecurityAttributeDefinition, error) {
	d := &CustomSecurityAttributeDefinition{}
	err := row.Scan(&d.ID, &d.AttributeSet, &d.Name, &d.Description, &d.Type, &d.Status,
		&d.IsCollection, &d.IsSearchable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// CreateCSADefinition requires its attribute set to exist — a definition in a
// set that was never created would be unaddressable.
func (s *Store) CreateCSADefinition(d *CustomSecurityAttributeDefinition) error {
	if _, err := s.GetAttributeSet(d.AttributeSet); err != nil {
		return err
	}
	d.ID = d.AttributeSet + "_" + d.Name
	_, err := s.db.Exec(`INSERT INTO custom_security_attribute_definitions
		(id, attribute_set, name, description, type, status, is_collection, is_searchable)
		VALUES (?,?,?,?,?,?,?,?)`,
		d.ID, d.AttributeSet, d.Name, nullable(d.Description), d.Type, d.Status,
		d.IsCollection, d.IsSearchable)
	return mapConstraint(err)
}

func (s *Store) ListCSADefinitions() ([]*CustomSecurityAttributeDefinition, error) {
	rows, err := s.db.Query(`SELECT ` + csaDefCols + ` FROM custom_security_attribute_definitions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CustomSecurityAttributeDefinition{}
	for rows.Next() {
		d, err := scanCSADef(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetCSADefinition(id string) (*CustomSecurityAttributeDefinition, error) {
	return scanCSADef(s.db.QueryRow(`SELECT `+csaDefCols+` FROM custom_security_attribute_definitions WHERE id=?`, id))
}

// SetUserCustomSecurityAttribute assigns a value, validating it against the
// definition's declared type — an Integer attribute must not silently accept a
// string, or the "typed" in "typed metadata" means nothing. A nil value clears.
func (s *Store) SetUserCustomSecurityAttribute(userID, setName, attrName string, value any) error {
	def, err := s.GetCSADefinition(setName + "_" + attrName)
	if err != nil {
		return err
	}
	if value == nil {
		_, err := s.db.Exec(`DELETE FROM user_custom_security_attributes WHERE user_id=? AND definition_id=?`,
			userID, def.ID)
		return err
	}
	if err := validateCSAValue(def, value); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO user_custom_security_attributes (user_id, definition_id, value) VALUES (?,?,?)
		 ON CONFLICT(user_id, definition_id) DO UPDATE SET value=excluded.value`,
		userID, def.ID, string(encoded))
	return err
}

// validateCSAValue enforces the definition's type and collection-ness.
func validateCSAValue(def *CustomSecurityAttributeDefinition, value any) error {
	check := func(v any) error {
		switch def.Type {
		case "String":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("attribute %q is String", def.ID)
			}
		case "Integer":
			f, ok := v.(float64) // JSON numbers
			if !ok || f != float64(int64(f)) {
				return fmt.Errorf("attribute %q is Integer", def.ID)
			}
		case "Boolean":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("attribute %q is Boolean", def.ID)
			}
		}
		return nil
	}
	if def.IsCollection {
		list, ok := value.([]any)
		if !ok {
			return fmt.Errorf("attribute %q is a collection", def.ID)
		}
		for _, v := range list {
			if err := check(v); err != nil {
				return err
			}
		}
		return nil
	}
	if _, isList := value.([]any); isList {
		return fmt.Errorf("attribute %q is not a collection", def.ID)
	}
	return check(value)
}

// UserCustomSecurityAttributes returns the assigned values grouped by
// attribute set, which is the shape Graph returns them in.
func (s *Store) UserCustomSecurityAttributes(userID string) (map[string]map[string]any, error) {
	rows, err := s.db.Query(
		`SELECT d.attribute_set, d.name, u.value
		   FROM user_custom_security_attributes u
		   JOIN custom_security_attribute_definitions d ON d.id = u.definition_id
		  WHERE u.user_id = ? ORDER BY d.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]any{}
	for rows.Next() {
		var set, name, raw string
		if err := rows.Scan(&set, &name, &raw); err != nil {
			return nil, err
		}
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			continue
		}
		if out[set] == nil {
			out[set] = map[string]any{}
		}
		out[set][name] = v
	}
	return out, rows.Err()
}
