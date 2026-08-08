package store

import (
	"database/sql"
	"errors"
	"strings"
)

// FederatedCredential is a workload-identity-federation trust: it lets an
// EXTERNAL OIDC issuer's token stand in for this app's client secret, so a
// workload (a CI job, a Kubernetes pod) authenticates with no stored secret.
// A presented assertion must match issuer + subject and carry one of audiences.
type FederatedCredential struct {
	ID          string   `json:"id"`
	AppID       string   `json:"appId"`
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Audiences   []string `json:"audiences"`
	Description string   `json:"description,omitempty"`
	CreatedAt   int64    `json:"createdAt"`
}

// DefaultFederatedAudience is the audience Entra expects a federated assertion
// to carry unless the credential says otherwise.
const DefaultFederatedAudience = "api://AzureADTokenExchange"

func scanFederatedCredential(sc interface{ Scan(...any) error }) (*FederatedCredential, error) {
	c := &FederatedCredential{}
	var auds string
	if err := sc.Scan(&c.ID, &c.AppID, &c.Name, &c.Issuer, &c.Subject, &auds, &c.Description, &c.CreatedAt); err != nil {
		return nil, err
	}
	for _, a := range strings.Split(auds, ",") {
		if a = strings.TrimSpace(a); a != "" {
			c.Audiences = append(c.Audiences, a)
		}
	}
	return c, nil
}

const federatedCredCols = `id, app_id, name, issuer, subject, audiences, COALESCE(description,''), created_at`

// CreateFederatedCredential registers a federation trust for an app.
func (s *Store) CreateFederatedCredential(c *FederatedCredential) error {
	if len(c.Audiences) == 0 {
		c.Audiences = []string{DefaultFederatedAudience}
	}
	_, err := s.db.Exec(
		`INSERT INTO app_federated_credentials (id, app_id, name, issuer, subject, audiences, description, created_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		c.ID, c.AppID, c.Name, c.Issuer, c.Subject, strings.Join(c.Audiences, ","), c.Description, c.CreatedAt)
	return err
}

// ListFederatedCredentials returns an app's federation trusts.
func (s *Store) ListFederatedCredentials(appID string) ([]*FederatedCredential, error) {
	rows, err := s.db.Query(`SELECT `+federatedCredCols+
		` FROM app_federated_credentials WHERE app_id=? ORDER BY created_at`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FederatedCredential{}
	for rows.Next() {
		c, err := scanFederatedCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteFederatedCredential removes one trust by id.
func (s *Store) DeleteFederatedCredential(appID, id string) error {
	res, err := s.db.Exec(`DELETE FROM app_federated_credentials WHERE app_id=? AND id=?`, appID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MatchFederatedCredential finds the trust that accepts this assertion's
// issuer/subject/audience triple — the check Entra makes before it will mint a
// token for an external workload. Returns ErrNotFound when nothing matches, so
// callers can answer with Entra's AADSTS700213-style rejection.
func (s *Store) MatchFederatedCredential(appID, issuer, subject, audience string) (*FederatedCredential, error) {
	row := s.db.QueryRow(`SELECT `+federatedCredCols+
		` FROM app_federated_credentials WHERE app_id=? AND issuer=? AND subject=?`,
		appID, issuer, subject)
	c, err := scanFederatedCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	for _, a := range c.Audiences {
		if a == audience {
			return c, nil
		}
	}
	return nil, ErrNotFound
}
