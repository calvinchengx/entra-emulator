package store

// Access token version: Entra's per-app accessTokenAcceptedVersion
// (api.requestedAccessTokenVersion in the Graph application resource).
//
// Entra pairs a v2.0 access token ("ver": "2.0") with "aud": "{client id}" and
// a v1.0 token with "aud": the App ID URI. The emulator always issues v2.0
// tokens, so an app set to 2 gets the client id as its audience, matching
// Entra; unset (or 1) keeps the App ID URI audience the emulator has always
// used, so existing behaviour is unchanged.

// SetAccessTokenAcceptedVersion records an app's accepted access token
// version: 1 or 2, or 0 to clear it.
func (s *Store) SetAccessTokenAcceptedVersion(appID string, version int) error {
	var value any
	if version != 0 {
		value = version
	}
	res, err := s.db.Exec(`UPDATE app_registrations SET access_token_accepted_version=? WHERE app_id=?`,
		value, appID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// AccessTokenAcceptedVersion returns an app's accepted access token version,
// or 0 when it is not set.
func (s *Store) AccessTokenAcceptedVersion(appID string) (int, error) {
	var version *int
	err := s.db.QueryRow(`SELECT access_token_accepted_version FROM app_registrations WHERE app_id=?`,
		appID).Scan(&version)
	if err != nil {
		return 0, err
	}
	if version == nil {
		return 0, nil
	}
	return *version, nil
}
