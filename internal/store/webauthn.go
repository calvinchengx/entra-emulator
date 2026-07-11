package store

import (
	"database/sql"
	"errors"
)

// WebAuthnCredential is a registered passkey (roadmap #11).
type WebAuthnCredential struct {
	ID         string // credential id, base64url
	UserID     string
	PublicKey  []byte // COSE public key
	SignCount  uint32
	AAGUID     []byte
	Transports string // CSV
	Name       string
	CreatedAt  int64
}

func (s *Store) AddWebAuthnCredential(c *WebAuthnCredential) error {
	_, err := s.db.Exec(`INSERT INTO webauthn_credentials
		(id, user_id, public_key, sign_count, aaguid, transports, name, created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		c.ID, c.UserID, c.PublicKey, c.SignCount, c.AAGUID, nullable(c.Transports),
		nullable(c.Name), c.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) ListWebAuthnCredentials(userID string) ([]*WebAuthnCredential, error) {
	rows, err := s.db.Query(`SELECT id, user_id, public_key, sign_count, COALESCE(aaguid, x''),
		COALESCE(transports,''), COALESCE(name,''), created_at
		FROM webauthn_credentials WHERE user_id=? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebAuthnCredential
	for rows.Next() {
		c := &WebAuthnCredential{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &c.AAGUID,
			&c.Transports, &c.Name, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetWebAuthnCredential(id string) (*WebAuthnCredential, error) {
	row := s.db.QueryRow(`SELECT id, user_id, public_key, sign_count, COALESCE(aaguid, x''),
		COALESCE(transports,''), COALESCE(name,''), created_at
		FROM webauthn_credentials WHERE id=?`, id)
	c := &WebAuthnCredential{}
	err := row.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &c.AAGUID,
		&c.Transports, &c.Name, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) UpdateWebAuthnSignCount(id string, count uint32) error {
	_, err := s.db.Exec(`UPDATE webauthn_credentials SET sign_count=? WHERE id=?`, count, id)
	return err
}

func (s *Store) DeleteWebAuthnCredential(userID, id string) error {
	res, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE user_id=? AND id=?`, userID, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// HasWebAuthnCredentials reports whether a user has any passkeys.
func (s *Store) HasWebAuthnCredentials(userID string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?`, userID).Scan(&n)
	return n > 0, err
}
