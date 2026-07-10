package store

import (
	"database/sql"
	"errors"
)

// ---- Signing keys ----

func (s *Store) GetActiveSigningKey(tenantID string) (*SigningKey, error) {
	return scanKey(s.db.QueryRow(`SELECT kid, tenant_id, alg, public_jwk, private_pkcs8, is_active,
		created_at, COALESCE(not_after,0) FROM signing_keys WHERE tenant_id=? AND is_active=1 LIMIT 1`, tenantID))
}

func (s *Store) GetSigningKey(kid string) (*SigningKey, error) {
	return scanKey(s.db.QueryRow(`SELECT kid, tenant_id, alg, public_jwk, private_pkcs8, is_active,
		created_at, COALESCE(not_after,0) FROM signing_keys WHERE kid=?`, kid))
}

// ListPublishableKeys returns active keys plus retired keys whose not_after
// is unset or in the future (rotation-ready JWKS union).
func (s *Store) ListPublishableKeys(tenantID string, now int64) ([]*SigningKey, error) {
	rows, err := s.db.Query(`SELECT kid, tenant_id, alg, public_jwk, private_pkcs8, is_active,
		created_at, COALESCE(not_after,0) FROM signing_keys
		WHERE tenant_id=? AND (is_active=1 OR not_after IS NULL OR not_after > ?) ORDER BY created_at`, tenantID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SigningKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) InsertSigningKey(k *SigningKey) error {
	_, err := s.db.Exec(`INSERT INTO signing_keys (kid, tenant_id, alg, public_jwk, private_pkcs8, is_active, created_at, not_after)
		VALUES (?,?,?,?,?,?,?,?)`,
		k.Kid, k.TenantID, coalesceStr(k.Alg, "RS256"), k.PublicJWK, k.PrivatePKCS8,
		k.IsActive, k.CreatedAt, nullableInt64(k.NotAfter))
	return mapConstraint(err)
}

func scanKey(row interface{ Scan(...any) error }) (*SigningKey, error) {
	k := &SigningKey{}
	err := row.Scan(&k.Kid, &k.TenantID, &k.Alg, &k.PublicJWK, &k.PrivatePKCS8,
		&k.IsActive, &k.CreatedAt, &k.NotAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

// ---- Authorization codes ----

func (s *Store) InsertAuthCode(c *AuthCode) error {
	_, err := s.db.Exec(`INSERT INTO authorization_codes
		(code, app_id, user_id, redirect_uri, scopes, resource, code_challenge, code_challenge_method, nonce, expires_at, consumed, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,0,?)`,
		c.Code, c.AppID, c.UserID, c.RedirectURI, c.Scopes, nullable(c.Resource),
		nullable(c.CodeChallenge), nullable(c.CodeChallengeMethod), nullable(c.Nonce),
		c.ExpiresAt, c.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) GetAuthCode(code string) (*AuthCode, error) {
	row := s.db.QueryRow(`SELECT code, app_id, user_id, redirect_uri, scopes, COALESCE(resource,''),
		COALESCE(code_challenge,''), COALESCE(code_challenge_method,''), COALESCE(nonce,''),
		expires_at, consumed, created_at FROM authorization_codes WHERE code=?`, code)
	c := &AuthCode{}
	err := row.Scan(&c.Code, &c.AppID, &c.UserID, &c.RedirectURI, &c.Scopes, &c.Resource,
		&c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &c.ExpiresAt, &c.Consumed, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ConsumeAuthCode atomically marks the code consumed; false means it was
// already consumed (replay) or unknown.
func (s *Store) ConsumeAuthCode(code string) (bool, error) {
	res, err := s.db.Exec(`UPDATE authorization_codes SET consumed=1 WHERE code=? AND consumed=0`, code)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ---- Refresh tokens ----

// GetRefreshTokenByHash intentionally returns revoked/expired rows too —
// reuse detection depends on observing revoked rows.
func (s *Store) GetRefreshTokenByHash(hash string) (*RefreshToken, error) {
	row := s.db.QueryRow(`SELECT token, app_id, user_id, scopes, COALESCE(resource,''),
		expires_at, COALESCE(rotated_from,''), revoked, created_at FROM refresh_tokens WHERE token=?`, hash)
	t := &RefreshToken{}
	err := row.Scan(&t.TokenHash, &t.AppID, &t.UserID, &t.Scopes, &t.Resource,
		&t.ExpiresAt, &t.RotatedFrom, &t.Revoked, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (s *Store) InsertRefreshToken(t *RefreshToken) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens
		(token, app_id, user_id, scopes, resource, expires_at, rotated_from, revoked, created_at)
		VALUES (?,?,?,?,?,?,?,0,?)`,
		t.TokenHash, t.AppID, t.UserID, t.Scopes, nullable(t.Resource), t.ExpiresAt,
		nullable(t.RotatedFrom), t.CreatedAt)
	return mapConstraint(err)
}

// RotateRefreshToken atomically revokes the presented token (CAS revoked=0)
// and inserts its successor. false = the presented token was already revoked
// (concurrent redemption lost the race → treat as reuse).
func (s *Store) RotateRefreshToken(oldHash string, successor *RefreshToken) (bool, error) {
	won := false
	err := s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE token=? AND revoked=0`, oldHash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return nil // lost the race; no successor
		}
		won = true
		_, err = tx.Exec(`INSERT INTO refresh_tokens
			(token, app_id, user_id, scopes, resource, expires_at, rotated_from, revoked, created_at)
			VALUES (?,?,?,?,?,?,?,0,?)`,
			successor.TokenHash, successor.AppID, successor.UserID, successor.Scopes,
			nullable(successor.Resource), successor.ExpiresAt, oldHash, successor.CreatedAt)
		return err
	})
	return won, err
}

// RevokeRefreshTokenFamily revokes the presented token's whole rotation
// chain — ancestors via rotated_from links and all descendants.
func (s *Store) RevokeRefreshTokenFamily(hash string) error {
	return s.tx(func(tx *sql.Tx) error {
		seen := map[string]bool{}
		frontier := []string{hash}
		for len(frontier) > 0 {
			h := frontier[len(frontier)-1]
			frontier = frontier[:len(frontier)-1]
			if seen[h] {
				continue
			}
			seen[h] = true
			var parent sql.NullString
			err := tx.QueryRow(`SELECT rotated_from FROM refresh_tokens WHERE token=?`, h).Scan(&parent)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if parent.Valid && parent.String != "" && !seen[parent.String] {
				frontier = append(frontier, parent.String)
			}
			rows, err := tx.Query(`SELECT token FROM refresh_tokens WHERE rotated_from=?`, h)
			if err != nil {
				return err
			}
			for rows.Next() {
				var child string
				if err := rows.Scan(&child); err != nil {
					rows.Close()
					return err
				}
				if !seen[child] {
					frontier = append(frontier, child)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		for h := range seen {
			if _, err := tx.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE token=?`, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- Sessions ----

func (s *Store) CreateSession(sess *Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?,?,?,?)`,
		sess.ID, sess.UserID, sess.CreatedAt, sess.ExpiresAt)
	return mapConstraint(err)
}

func (s *Store) GetSession(id string) (*Session, error) {
	row := s.db.QueryRow(`SELECT id, user_id, created_at, expires_at FROM sessions WHERE id=?`, id)
	sess := &Session{}
	err := row.Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sess, err
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

// ---- Device codes ----

func (s *Store) InsertDeviceCode(d *DeviceCode) error {
	_, err := s.db.Exec(`INSERT INTO device_codes
		(device_code, user_code, app_id, user_id, scopes, status, interval, expires_at, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		d.DeviceCodeHash, d.UserCode, d.AppID, nullable(d.UserID), d.Scopes,
		coalesceStr(d.Status, "pending"), d.Interval, d.ExpiresAt, d.CreatedAt)
	return mapConstraint(err)
}

const deviceCols = `device_code, user_code, app_id, COALESCE(user_id,''), scopes, status, interval, expires_at, created_at`

func scanDevice(row interface{ Scan(...any) error }) (*DeviceCode, error) {
	d := &DeviceCode{}
	err := row.Scan(&d.DeviceCodeHash, &d.UserCode, &d.AppID, &d.UserID, &d.Scopes,
		&d.Status, &d.Interval, &d.ExpiresAt, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

func (s *Store) GetDeviceCodeByHash(hash string) (*DeviceCode, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM device_codes WHERE device_code=?`, hash))
}

func (s *Store) GetDeviceCodeByUserCode(userCode string) (*DeviceCode, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM device_codes WHERE user_code=?`, userCode))
}

func (s *Store) SetDeviceCodeDecision(userCode, status, userID string) error {
	res, err := s.db.Exec(`UPDATE device_codes SET status=?, user_id=? WHERE user_code=? AND status='pending'`,
		status, nullable(userID), userCode)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// ConsumeApprovedDeviceCode is the atomic single-use redemption: it deletes
// and returns the row only while it is still approved, bound to the client,
// and unexpired. nil result = lost the race / already consumed / mismatch.
func (s *Store) ConsumeApprovedDeviceCode(hash, appID string, now int64) (*DeviceCode, error) {
	row := s.db.QueryRow(`DELETE FROM device_codes
		WHERE device_code=? AND app_id=? AND status='approved' AND expires_at>?
		RETURNING `+deviceCols, hash, appID, now)
	d, err := scanDevice(row)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return d, err
}

// DeleteDeviceCode removes a row (lazy expiry / denied cleanup).
func (s *Store) DeleteDeviceCode(hash string) error {
	_, err := s.db.Exec(`DELETE FROM device_codes WHERE device_code=?`, hash)
	return err
}

func (s *Store) UserCodeExists(userCode string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM device_codes WHERE user_code=?`, userCode).Scan(&n)
	return n > 0, err
}
