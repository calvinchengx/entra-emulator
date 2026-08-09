package store

import "database/sql"

// SCIM externalId storage. Kept out of the User/Group types deliberately: it is
// the provisioning client's identifier for a resource, meaningful only on the
// SCIM wire, and putting it on the directory object would leak it into Graph
// responses and export/import where Entra has no such field.

// SetExternalID records (or clears, when id is empty) a resource's externalId.
func (s *Store) SetExternalID(resourceType, resourceID, externalID string) error {
	if externalID == "" {
		_, err := s.db.Exec(
			`DELETE FROM scim_external_ids WHERE resource_type = ? AND resource_id = ?`,
			resourceType, resourceID)
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO scim_external_ids (resource_type, resource_id, external_id)
		 VALUES (?, ?, ?)
		 ON CONFLICT(resource_type, resource_id) DO UPDATE SET external_id = excluded.external_id`,
		resourceType, resourceID, externalID)
	return err
}

// ExternalID returns the stored externalId, or "" when none is set.
func (s *Store) ExternalID(resourceType, resourceID string) string {
	var ext string
	err := s.db.QueryRow(
		`SELECT external_id FROM scim_external_ids WHERE resource_type = ? AND resource_id = ?`,
		resourceType, resourceID).Scan(&ext)
	if err != nil && err != sql.ErrNoRows {
		return ""
	}
	return ext
}

// ExternalIDs returns resourceID→externalId for a whole resource type, so list
// responses can be decorated without a query per row.
func (s *Store) ExternalIDs(resourceType string) map[string]string {
	out := map[string]string{}
	rows, err := s.db.Query(
		`SELECT resource_id, external_id FROM scim_external_ids WHERE resource_type = ?`,
		resourceType)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, ext string
		if rows.Scan(&id, &ext) == nil {
			out[id] = ext
		}
	}
	return out
}

// FindByExternalID returns the resource id carrying an externalId, if any.
func (s *Store) FindByExternalID(resourceType, externalID string) (string, bool) {
	var id string
	err := s.db.QueryRow(
		`SELECT resource_id FROM scim_external_ids WHERE resource_type = ? AND external_id = ?`,
		resourceType, externalID).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}

// DeleteExternalID drops any mapping for a resource, called when it is deleted.
func (s *Store) DeleteExternalID(resourceType, resourceID string) {
	_, _ = s.db.Exec(
		`DELETE FROM scim_external_ids WHERE resource_type = ? AND resource_id = ?`,
		resourceType, resourceID)
}
