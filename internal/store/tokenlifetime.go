package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Token lifetime policies. Entra carries the actual settings inside a JSON
// STRING in `definition` — a nested encoding, not a nested object — so the
// emulator parses the same shape rather than inventing a friendlier one:
//
//	"definition": ["{\"TokenLifetimePolicy\":{\"Version\":1,\"AccessTokenLifetime\":\"08:00:00\"}}"]
type TokenLifetimePolicy struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName"`
	Definition            []string `json:"definition"`
	IsOrganizationDefault bool     `json:"isOrganizationDefault"`
	CreatedAt             int64    `json:"createdAt"`
}

// TokenLifetimes carries the durations a policy sets, in seconds. Zero means
// "unset — keep the configured default".
type PolicyLifetimes struct {
	AccessToken  int
	IDToken      int
	RefreshToken int
}

const tlpCols = `id, display_name, definition, is_organization_default, created_at`

func scanTLP(row interface{ Scan(...any) error }) (*TokenLifetimePolicy, error) {
	p := &TokenLifetimePolicy{}
	var def string
	if err := row.Scan(&p.ID, &p.DisplayName, &def, &p.IsOrganizationDefault, &p.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Definition = []string{}
	_ = json.Unmarshal([]byte(def), &p.Definition)
	return p, nil
}

func (s *Store) CreateTokenLifetimePolicy(p *TokenLifetimePolicy) error {
	def, err := json.Marshal(p.Definition)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO token_lifetime_policies (id, display_name, definition, is_organization_default, created_at)
		 VALUES (?,?,?,?,?)`,
		p.ID, p.DisplayName, string(def), p.IsOrganizationDefault, p.CreatedAt)
	return mapConstraint(err)
}

func (s *Store) ListTokenLifetimePolicies() ([]*TokenLifetimePolicy, error) {
	rows, err := s.db.Query(`SELECT ` + tlpCols + ` FROM token_lifetime_policies ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TokenLifetimePolicy{}
	for rows.Next() {
		p, err := scanTLP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetTokenLifetimePolicy(id string) (*TokenLifetimePolicy, error) {
	return scanTLP(s.db.QueryRow(`SELECT `+tlpCols+` FROM token_lifetime_policies WHERE id=?`, id))
}

func (s *Store) DeleteTokenLifetimePolicy(id string) error {
	res, err := s.db.Exec(`DELETE FROM token_lifetime_policies WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// AssignTokenLifetimePolicy links a policy to an application. Entra allows at
// most one per application, so an assignment replaces any previous one.
func (s *Store) AssignTokenLifetimePolicy(appID, policyID string) error {
	if _, err := s.GetTokenLifetimePolicy(policyID); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM app_token_lifetime_policies WHERE app_id=?`, appID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO app_token_lifetime_policies (app_id, policy_id) VALUES (?,?)`, appID, policyID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UnassignTokenLifetimePolicy(appID, policyID string) error {
	res, err := s.db.Exec(
		`DELETE FROM app_token_lifetime_policies WHERE app_id=? AND policy_id=?`, appID, policyID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// AppTokenLifetimePolicies returns the policies assigned to an application.
func (s *Store) AppTokenLifetimePolicies(appID string) ([]*TokenLifetimePolicy, error) {
	rows, err := s.db.Query(`SELECT p.id, p.display_name, p.definition, p.is_organization_default, p.created_at`+
		` FROM app_token_lifetime_policies a JOIN token_lifetime_policies p ON p.id = a.policy_id
		  WHERE a.app_id = ?`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TokenLifetimePolicy{}
	for rows.Next() {
		p, err := scanTLP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// EffectiveTokenLifetimes resolves the durations that apply to an app: its
// assigned policy if it has one, otherwise the organization default if one is
// set, otherwise nothing (the caller keeps its configured defaults).
func (s *Store) EffectiveTokenLifetimes(appID string) PolicyLifetimes {
	assigned, err := s.AppTokenLifetimePolicies(appID)
	if err == nil && len(assigned) > 0 {
		return parsePolicyLifetimes(assigned[0])
	}
	all, err := s.ListTokenLifetimePolicies()
	if err != nil {
		return PolicyLifetimes{}
	}
	for _, p := range all {
		if p.IsOrganizationDefault {
			return parsePolicyLifetimes(p)
		}
	}
	return PolicyLifetimes{}
}

// parsePolicyLifetimes reads Entra's nested JSON-in-a-string definition.
func parsePolicyLifetimes(p *TokenLifetimePolicy) PolicyLifetimes {
	var out PolicyLifetimes
	for _, raw := range p.Definition {
		var wrapper struct {
			TokenLifetimePolicy struct {
				Version              int    `json:"Version"`
				AccessTokenLifetime  string `json:"AccessTokenLifetime"`
				IDTokenLifetime      string `json:"IdTokenLifetime"`
				RefreshTokenLifetime string `json:"MaxInactiveTime"`
			} `json:"TokenLifetimePolicy"`
		}
		if json.Unmarshal([]byte(raw), &wrapper) != nil {
			continue
		}
		d := wrapper.TokenLifetimePolicy
		if v, ok := ParseTimeSpan(d.AccessTokenLifetime); ok {
			out.AccessToken = v
		}
		if v, ok := ParseTimeSpan(d.IDTokenLifetime); ok {
			out.IDToken = v
		}
		if v, ok := ParseTimeSpan(d.RefreshTokenLifetime); ok {
			out.RefreshToken = v
		}
	}
	return out
}

// ParseTimeSpan reads .NET's "[d.]hh:mm:ss" duration, which is what Entra's
// policy definitions carry — not an ISO-8601 duration and not seconds.
func ParseTimeSpan(v string) (int, bool) {
	if v == "" {
		return 0, false
	}
	days := 0
	rest := v
	if i := strings.IndexByte(rest, '.'); i >= 0 && strings.Count(rest, ":") == 2 && i < strings.IndexByte(rest, ':') {
		d, err := strconv.Atoi(rest[:i])
		if err != nil {
			return 0, false
		}
		days, rest = d, rest[i+1:]
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return 0, false
	}
	var hms [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return 0, false
		}
		hms[i] = n
	}
	total := days*86400 + hms[0]*3600 + hms[1]*60 + hms[2]
	if total <= 0 {
		return 0, false
	}
	return total, true
}

// EffectiveFromPolicy exposes the parsed durations so a caller can reject a
// definition that would be silently inert.
func EffectiveFromPolicy(p *TokenLifetimePolicy) PolicyLifetimes { return parsePolicyLifetimes(p) }
