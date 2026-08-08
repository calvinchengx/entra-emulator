package store

// Front-channel logout: an app registers a frontchannel_logout_uri, and the
// emulator records which apps a given SSO session actually signed into, so
// logout notifies exactly those relying parties — not every app in the
// directory, which would log a user out of things they never used.

// SetFrontchannelLogoutURI registers (or clears, with "") an app's logout URI.
func (s *Store) SetFrontchannelLogoutURI(appID, uri string) error {
	res, err := s.db.Exec(`UPDATE app_registrations SET frontchannel_logout_uri=? WHERE app_id=?`,
		nullable(uri), appID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// FrontchannelLogoutURI returns an app's registered logout URI, if any.
func (s *Store) FrontchannelLogoutURI(appID string) (string, error) {
	var uri *string
	err := s.db.QueryRow(`SELECT frontchannel_logout_uri FROM app_registrations WHERE app_id=?`, appID).Scan(&uri)
	if err != nil {
		return "", err
	}
	if uri == nil {
		return "", nil
	}
	return *uri, nil
}

// RecordSessionApp notes that this SSO session signed into this app.
func (s *Store) RecordSessionApp(sessionID, appID string) error {
	if sessionID == "" || appID == "" {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO session_apps (session_id, app_id) VALUES (?,?)`, sessionID, appID)
	return err
}

// SessionLogoutURIs returns the logout URIs of the apps this session signed
// into, so logout notifies precisely those relying parties.
func (s *Store) SessionLogoutURIs(sessionID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT a.frontchannel_logout_uri
		   FROM session_apps sa JOIN app_registrations a ON a.app_id = sa.app_id
		  WHERE sa.session_id = ? AND a.frontchannel_logout_uri IS NOT NULL
		    AND a.frontchannel_logout_uri <> ''
		  ORDER BY a.app_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		out = append(out, uri)
	}
	return out, rows.Err()
}

// ForgetSessionApps drops a session's RP list once it has been logged out.
func (s *Store) ForgetSessionApps(sessionID string) error {
	_, err := s.db.Exec(`DELETE FROM session_apps WHERE session_id=?`, sessionID)
	return err
}
