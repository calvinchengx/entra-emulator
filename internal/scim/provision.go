package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Provisioner is the SCIM provisioning *client* (phase 2 of
// docs/15-scim-provisioning.md): it pushes the emulator's directory OUT to a
// configured SCIM endpoint, replicating Entra's outbound provisioning cycle
// (existence probe → create / update / soft-deprovision). Admin-controlled,
// in-memory, like the fault/clock knobs.
type Provisioner struct {
	Store  *store.Store
	Now    func() int64
	client *http.Client

	mu     sync.Mutex
	target *Target
	log    []LogEntry
}

// Target is the downstream SCIM service the emulator provisions to.
type Target struct {
	Endpoint string `json:"endpoint"` // base SCIM URL, e.g. https://app.example/scim/v2
	Token    string `json:"token"`    // bearer secret the emulator presents
}

// LogEntry records one outbound SCIM request (the provisioning trail).
type LogEntry struct {
	Time     int64  `json:"time"`
	Resource string `json:"resource"` // User
	Subject  string `json:"subject"`  // userName
	Action   string `json:"action"`   // probe|create|update|deprovision
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// SyncResult tallies a provisioning cycle.
type SyncResult struct {
	Mode          string `json:"mode"`
	Created       int    `json:"created"`
	Updated       int    `json:"updated"`
	Deprovisioned int    `json:"deprovisioned"`
	Skipped       int    `json:"skipped"`
	Failed        int    `json:"failed"`
}

const provisionLogCap = 500

func NewProvisioner(st *store.Store) *Provisioner {
	return &Provisioner{Store: st, Now: st.Now, client: &http.Client{Timeout: 10 * time.Second}}
}

func (p *Provisioner) SetTarget(t Target) {
	p.mu.Lock()
	p.target = &t
	p.mu.Unlock()
}

func (p *Provisioner) Target() (Target, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.target == nil {
		return Target{}, false
	}
	return *p.target, true
}

func (p *Provisioner) ClearTarget() {
	p.mu.Lock()
	p.target = nil
	p.mu.Unlock()
}

func (p *Provisioner) Log() []LogEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]LogEntry, len(p.log))
	copy(out, p.log)
	return out
}

func (p *Provisioner) ClearLog() {
	p.mu.Lock()
	p.log = nil
	p.mu.Unlock()
}

func (p *Provisioner) appendLog(e LogEntry) {
	p.mu.Lock()
	p.log = append(p.log, e)
	if len(p.log) > provisionLogCap {
		p.log = p.log[len(p.log)-provisionLogCap:]
	}
	p.mu.Unlock()
}

// Sync reconciles every user to the target using Entra's request sequence:
// GET ?filter=userName eq (probe) → POST (new+active) / PATCH active:false
// (deprovision disabled) / PATCH attributes (update). mode is recorded but both
// "initial" and "incremental" currently do a full reconcile.
func (p *Provisioner) Sync(mode string) (*SyncResult, error) {
	p.mu.Lock()
	t := p.target
	p.mu.Unlock()
	if t == nil {
		return nil, errors.New("no provisioning target configured")
	}

	users, _, err := p.Store.ListUsers(1<<30, 0, "")
	if err != nil {
		return nil, err
	}
	res := &SyncResult{Mode: mode}
	for _, u := range users {
		existing := p.probeUser(*t, u.UserPrincipalName)
		switch {
		case existing == "" && u.AccountEnabled:
			p.tally(res, "create", p.send(*t, "POST", "/Users", outboundUser(u), u.UserPrincipalName, "create"))
		case existing != "" && !u.AccountEnabled:
			p.tally(res, "deprovision", p.send(*t, "PATCH", "/Users/"+existing, replaceActive(false), u.UserPrincipalName, "deprovision"))
		case existing != "":
			p.tally(res, "update", p.send(*t, "PATCH", "/Users/"+existing, updatePatch(u), u.UserPrincipalName, "update"))
		default: // absent and disabled — nothing to do
			res.Skipped++
		}
	}
	return res, nil
}

func (p *Provisioner) tally(res *SyncResult, action string, status int) {
	ok := status >= 200 && status < 300
	switch {
	case !ok:
		res.Failed++
	case action == "create":
		res.Created++
	case action == "update":
		res.Updated++
	case action == "deprovision":
		res.Deprovisioned++
	}
}

// probeUser returns the target's id for a userName, or "" if absent.
func (p *Provisioner) probeUser(t Target, upn string) string {
	q := url.Values{"filter": {`userName eq "` + upn + `"`}}
	status, body := p.request(t, "GET", "/Users?"+q.Encode(), nil, upn, "probe")
	if status != http.StatusOK {
		return ""
	}
	var list struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	_ = json.Unmarshal(body, &list)
	if len(list.Resources) > 0 {
		return list.Resources[0].ID
	}
	return ""
}

func (p *Provisioner) send(t Target, method, path string, body any, subject, action string) int {
	status, _ := p.request(t, method, path, body, subject, action)
	return status
}

func (p *Provisioner) request(t Target, method, path string, body any, subject, action string) (int, []byte) {
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, t.Endpoint+path, r)
	req.Header.Set("Authorization", "Bearer "+t.Token)
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	entry := LogEntry{Time: p.Now(), Resource: "User", Subject: subject, Action: action, Method: method, Path: path}
	resp, err := p.client.Do(req)
	var respBody []byte
	if err != nil {
		entry.Detail = err.Error()
	} else {
		entry.Status = resp.StatusCode
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	p.appendLog(entry)
	return entry.Status, respBody
}

// ---- outbound SCIM payloads ----

func outboundUser(u *store.User) map[string]any {
	res := map[string]any{
		"schemas":     []string{userSchema},
		"externalId":  u.ID, // Entra correlates by its own object id
		"userName":    u.UserPrincipalName,
		"displayName": u.DisplayName,
		"active":      u.AccountEnabled,
		"name":        map[string]any{"givenName": u.GivenName, "familyName": u.Surname},
	}
	if u.Mail != "" {
		res["emails"] = []map[string]any{{"value": u.Mail, "type": "work", "primary": true}}
	}
	return res
}

func replaceActive(active bool) map[string]any {
	return map[string]any{
		"schemas":    []string{patchSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": active}},
	}
}

func updatePatch(u *store.User) map[string]any {
	return map[string]any{
		"schemas": []string{patchSchema},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": u.AccountEnabled},
			{"op": "replace", "path": "displayName", "value": u.DisplayName},
		},
	}
}
