package store

// AppKeyCredential is a public key registered on an app for private_key_jwt /
// certificate client authentication (roadmap #13).
type AppKeyCredential struct {
	ID          string
	AppID       string
	PublicKey   string // PEM (PKIX public key or X.509 certificate)
	DisplayName string
	CreatedAt   int64
}

func (s *Store) AddAppKeyCredential(c *AppKeyCredential) error {
	_, err := s.db.Exec(`INSERT INTO app_key_credentials (id, app_id, public_key, display_name, created_at)
		VALUES (?,?,?,?,?)`, c.ID, c.AppID, c.PublicKey, nullable(c.DisplayName), c.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) ListAppKeyCredentials(appID string) ([]*AppKeyCredential, error) {
	rows, err := s.db.Query(`SELECT id, app_id, public_key, COALESCE(display_name,''), created_at
		FROM app_key_credentials WHERE app_id=? ORDER BY created_at`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppKeyCredential
	for rows.Next() {
		c := &AppKeyCredential{}
		if err := rows.Scan(&c.ID, &c.AppID, &c.PublicKey, &c.DisplayName, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAppKeyCredential(appID, id string) error {
	res, err := s.db.Exec(`DELETE FROM app_key_credentials WHERE app_id=? AND id=?`, appID, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}
