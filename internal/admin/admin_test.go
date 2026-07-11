package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/scim"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// newTestAdmin builds an *Admin directly against a fresh on-disk store, wiring
// only the collaborators the package-internal handler tests need. Passing nil
// for the optional deps exercises New's nil-defaulting branches.
func newTestAdmin(t *testing.T) *Admin {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"ORIGIN_MODE": "compat",
			"TLS_ENABLED": "false",
		}[k]
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.EnsureTenant(cfg.TenantID, cfg.Issuer); err != nil {
		t.Fatalf("EnsureTenant: %v", err)
	}
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}
	ts := &tokens.Service{Store: st, Signer: signer, Cfg: cfg}
	// nil optional deps make New default them (faults, audit, customext, provisioner).
	return New(cfg, st, ts, nil, nil, nil, nil, nil, "test")
}

// TestCertificateMetaPresent covers certificateMeta's cert-present branch,
// which the server integration harness cannot reach (it runs without a cert).
func TestCertificateMetaPresent(t *testing.T) {
	a := newTestAdmin(t)
	mat, err := tlscert.LoadOrCreate(t.TempDir(), "entra.localhost", nil)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	a.Cert = mat

	rec := httptest.NewRecorder()
	a.certificateMeta(rec, httptest.NewRequest(http.MethodGet, "/admin/api/certificate", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	fp, _ := body["fingerprintSHA256"].(string)
	if strings.Count(fp, ":") != 31 || strings.ToUpper(fp) != fp {
		t.Fatalf("fingerprintSHA256 = %q, want colon-separated uppercase hex", fp)
	}
	if got, _ := body["certPath"].(string); got != mat.CertPath {
		t.Fatalf("certPath = %q, want %q", got, mat.CertPath)
	}
	if _, ok := body["baseDomain"]; !ok {
		t.Fatalf("missing baseDomain in %v", body)
	}
}

// TestCertificateMetaAbsent covers the TLS-disabled (nil cert) branch.
func TestCertificateMetaAbsent(t *testing.T) {
	a := newTestAdmin(t)
	a.Cert = nil
	rec := httptest.NewRecorder()
	a.certificateMeta(rec, httptest.NewRequest(http.MethodGet, "/admin/api/certificate", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestCertificatePEMPresent covers certificatePEM's cert-present branch.
func TestCertificatePEMPresent(t *testing.T) {
	a := newTestAdmin(t)
	mat, err := tlscert.LoadOrCreate(t.TempDir(), "entra.localhost", nil)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	a.Cert = mat

	rec := httptest.NewRecorder()
	a.certificatePEM(rec, httptest.NewRequest(http.MethodGet, "/admin/api/certificate/pem", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Fatalf("Content-Type = %q, want application/x-pem-file", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "entra-emulator-cert.pem") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if !strings.HasPrefix(rec.Body.String(), "-----BEGIN CERTIFICATE") {
		t.Fatalf("body does not start with PEM certificate header: %.40q", rec.Body.String())
	}
}

// TestCertificatePEMAbsent covers the TLS-disabled (nil cert) branch.
func TestCertificatePEMAbsent(t *testing.T) {
	a := newTestAdmin(t)
	a.Cert = nil
	rec := httptest.NewRecorder()
	a.certificatePEM(rec, httptest.NewRequest(http.MethodGet, "/admin/api/certificate/pem", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestCertificateMetaFingerprintError covers the branch where Fingerprint
// fails (invalid certificate PEM), which writeStoreErr maps to a 500.
func TestCertificateMetaFingerprintError(t *testing.T) {
	a := newTestAdmin(t)
	a.Cert = &tlscert.Material{CertPEM: []byte("not a pem")}
	rec := httptest.NewRecorder()
	a.certificateMeta(rec, httptest.NewRequest(http.MethodGet, "/admin/api/certificate", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for invalid cert PEM; body=%s", rec.Code, rec.Body.String())
	}
}

// TestScimTargetLifecycle covers getScimTarget/setScimTarget/clearScimTarget,
// including the missing-endpoint validation branch.
func TestScimTargetLifecycle(t *testing.T) {
	a := newTestAdmin(t)

	// Initially unconfigured.
	rec := httptest.NewRecorder()
	a.getScimTarget(rec, httptest.NewRequest(http.MethodGet, "/admin/api/scim/target", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if configured, _ := got["configured"].(bool); configured {
		t.Fatalf("expected unconfigured target initially: %v", got)
	}

	// Missing endpoint -> 400.
	rec = httptest.NewRecorder()
	a.setScimTarget(rec, httptest.NewRequest(http.MethodPost, "/admin/api/scim/target", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("set (empty endpoint) status = %d, want 400", rec.Code)
	}

	// Valid endpoint -> 200 and now configured.
	rec = httptest.NewRecorder()
	a.setScimTarget(rec, httptest.NewRequest(http.MethodPost, "/admin/api/scim/target",
		strings.NewReader(`{"endpoint":"https://scim.example/v2","token":"secret"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("set status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := a.Provisioner.Target(); !ok {
		t.Fatalf("target not set on provisioner")
	}

	// Clear -> 204.
	rec = httptest.NewRecorder()
	a.clearScimTarget(rec, httptest.NewRequest(http.MethodDelete, "/admin/api/scim/target", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clear status = %d, want 204", rec.Code)
	}
}

// TestScimLogClear covers clearScimLog.
func TestScimLogClear(t *testing.T) {
	a := newTestAdmin(t)
	rec := httptest.NewRecorder()
	a.clearScimLog(rec, httptest.NewRequest(http.MethodDelete, "/admin/api/scim/log", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clearScimLog status = %d, want 204", rec.Code)
	}
}

// TestDecodeBodyRejectsUnknownFields covers decodeBody's error branch via a
// handler that runs it (setScimTarget) with a body containing an unknown field.
func TestDecodeBodyRejectsUnknownFields(t *testing.T) {
	a := newTestAdmin(t)
	rec := httptest.NewRecorder()
	a.setScimTarget(rec, httptest.NewRequest(http.MethodPost, "/admin/api/scim/target",
		strings.NewReader(`{"endpoint":"https://x","bogus":true}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown field", rec.Code)
	}
}

// TestProvisionerDefaulted confirms New defaulted the nil provisioner so the
// handlers above operate against a real *scim.Provisioner.
func TestProvisionerDefaulted(t *testing.T) {
	a := newTestAdmin(t)
	if a.Provisioner == nil {
		t.Fatal("Provisioner should have been defaulted by New")
	}
	var _ *scim.Provisioner = a.Provisioner
}
