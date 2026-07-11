// Package customext emulates Microsoft Entra custom authentication
// extensions — specifically the onTokenIssuanceStart event (roadmap #10).
// During delegated-token minting the emulator calls a per-app webhook with
// the documented request shape and merges the claims it returns, with
// timeout-and-continue semantics so a slow or failing webhook never blocks
// token issuance.
//
// Ref: entra-docs/docs/identity-platform/custom-extension-tokenissuancestart-*.
package customext

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// DefaultTimeout mirrors Entra's ~2s cap on the extension callout.
const DefaultTimeout = 2 * time.Second

// Config is a per-app custom-extension registration.
type Config struct {
	// Endpoint is the webhook URL called on token issuance.
	Endpoint string `json:"endpoint"`
	// Claims optionally allowlists which returned claim names are merged.
	// Empty means merge every returned claim (still subject to the token
	// service's protocol-claim protection).
	Claims []string `json:"claims,omitempty"`
	// TimeoutMs overrides DefaultTimeout when > 0.
	TimeoutMs int `json:"timeoutMs,omitempty"`
}

// Store holds custom-extension configs keyed by app (client) id. In-memory,
// like the other admin-controlled testing knobs.
type Store struct {
	mu   sync.RWMutex
	cfgs map[string]Config
}

func NewStore() *Store { return &Store{cfgs: map[string]Config{}} }

func (s *Store) Get(appID string) (Config, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cfgs[appID]
	return c, ok
}

func (s *Store) Set(appID string, c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfgs[appID] = c
}

func (s *Store) Delete(appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cfgs, appID)
}

func (s *Store) All() map[string]Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Config, len(s.cfgs))
	for k, v := range s.cfgs {
		out[k] = v
	}
	return out
}

// ---- Webhook contract (Microsoft-documented shapes) ----

type calloutRequest struct {
	Type   string      `json:"type"`
	Source string      `json:"source"`
	Data   calloutData `json:"data"`
}

type calloutData struct {
	ODataType                       string      `json:"@odata.type"`
	TenantID                        string      `json:"tenantId"`
	AuthenticationEventListenerID   string      `json:"authenticationEventListenerId"`
	CustomAuthenticationExtensionID string      `json:"customAuthenticationExtensionId"`
	AuthenticationContext           authContext `json:"authenticationContext"`
}

type authContext struct {
	CorrelationID          string   `json:"correlationId"`
	Protocol               string   `json:"protocol"`
	ClientServicePrincipal spData   `json:"clientServicePrincipal"`
	User                   userData `json:"user"`
}

type spData struct {
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
}

type userData struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName,omitempty"`
	Surname           string `json:"surname,omitempty"`
	Mail              string `json:"mail,omitempty"`
	UserPrincipalName string `json:"userPrincipalName"`
	UserType          string `json:"userType"`
}

type calloutResponse struct {
	Data struct {
		ODataType string `json:"@odata.type"`
		Actions   []struct {
			ODataType string         `json:"@odata.type"`
			Claims    map[string]any `json:"claims"`
		} `json:"actions"`
	} `json:"data"`
}

// Invoker calls a webhook and returns the claims to merge. bearerMinter
// produces the system bearer token that authenticates the callout (like
// Entra authenticating to the customer's Function with its own token).
type Invoker struct {
	Client   *http.Client
	TenantID string
	// BearerMinter returns an app-only token to send as the callout's
	// Authorization header. May be nil (no auth header) for simple setups.
	BearerMinter func(audience string) string
}

// Invoke calls the webhook for (app, user) and returns the merged claim set,
// honoring the allowlist. Errors (including timeout) are returned so the
// caller can continue-without-enrichment.
func (iv *Invoker) Invoke(cfg Config, app *store.App, user *store.User) (map[string]any, error) {
	timeout := DefaultTimeout
	if cfg.TimeoutMs > 0 {
		timeout = time.Duration(cfg.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	reqBody := calloutRequest{
		Type:   "microsoft.graph.authenticationEvent.tokenIssuanceStart",
		Source: "/tenants/" + iv.TenantID + "/applications/" + app.ID,
		Data: calloutData{
			ODataType:                       "microsoft.graph.onTokenIssuanceStartCalloutData",
			TenantID:                        iv.TenantID,
			AuthenticationEventListenerID:   store.NewGUID(),
			CustomAuthenticationExtensionID: store.NewGUID(),
			AuthenticationContext: authContext{
				CorrelationID:          store.NewGUID(),
				Protocol:               "OAUTH2.0",
				ClientServicePrincipal: spData{AppID: app.ID, DisplayName: app.DisplayName},
				User: userData{
					ID: user.ID, DisplayName: user.DisplayName, GivenName: user.GivenName,
					Surname: user.Surname, Mail: user.Mail,
					UserPrincipalName: user.UserPrincipalName, UserType: "Member",
				},
			},
		},
	}
	raw, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if iv.BearerMinter != nil {
		req.Header.Set("Authorization", "Bearer "+iv.BearerMinter(cfg.Endpoint))
	}

	client := iv.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errStatus(resp.StatusCode)
	}

	var out calloutResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	merged := map[string]any{}
	allow := allowSet(cfg.Claims)
	for _, action := range out.Data.Actions {
		if action.ODataType != "" &&
			action.ODataType != "microsoft.graph.tokenIssuanceStart.provideClaimsForToken" {
			continue
		}
		for k, v := range action.Claims {
			if allow != nil && !allow[k] {
				continue
			}
			merged[k] = v
		}
	}
	return merged, nil
}

func allowSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

type statusError int

func (e statusError) Error() string { return "custom extension returned non-200" }
func errStatus(code int) error      { return statusError(code) }
