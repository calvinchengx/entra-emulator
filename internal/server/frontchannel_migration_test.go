package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

func TestLegacyGrantsSurviveSessionIDMigration(t *testing.T) {
	old, cfg, st := newTestServer(t)
	old.Close()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Remove precisely the columns introduced by this change, then insert grants
	// using the old schema. Reopening must migrate, rather than reset, this DB.
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"ALTER TABLE authorization_codes DROP COLUMN session_id",
		"ALTER TABLE refresh_tokens DROP COLUMN session_id",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO authorization_codes
		(code,app_id,user_id,redirect_uri,scopes,expires_at,created_at)
		VALUES (?,?,?,?,?,?,?)`, "legacy-code", spaID, aliceID, redirect, "openid offline_access", now+300, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO refresh_tokens
		(token,app_id,user_id,scopes,expires_at,created_at) VALUES (?,?,?,?,?,?)`,
		store.HashToken("legacy-refresh"), spaID, aliceID, "openid offline_access", now+3600, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, st, &tokens.Service{Store: st, Signer: signer, Cfg: cfg}, nil, "test")
	hts := httptest.NewServer(srv.Handler)
	t.Cleanup(hts.Close)
	endpoint := hts.URL + "/" + tenant + "/oauth2/v2.0/token"
	for _, grant := range []url.Values{
		{"grant_type": {"authorization_code"}, "code": {"legacy-code"}, "client_id": {spaID}, "redirect_uri": {redirect}},
		{"grant_type": {"refresh_token"}, "refresh_token": {"legacy-refresh"}, "client_id": {spaID}},
	} {
		for range 3 {
			resp, body := postForm(t, http.DefaultClient, endpoint, grant)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("legacy grant failed after migration: %v", body)
			}
			if _, ok := decodeJWTPayload(t, body["id_token"].(string))["sid"]; ok {
				t.Fatal("legacy grants must not invent a browser session")
			}
			grant = url.Values{"grant_type": {"refresh_token"}, "client_id": {spaID}, "refresh_token": {body["refresh_token"].(string)}}
		}
	}
}
