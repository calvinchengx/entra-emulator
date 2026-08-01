package tlscert

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// Reloader serves a TLS certificate that can be swapped at runtime without
// dropping the listener — wire GetCertificate into tls.Config, then call Reload
// (or let the server poll) after the on-disk pair changes, e.g. `step ca renew`
// or a re-issued mkcert/step leaf. The previous certificate keeps serving if a
// reload fails, so a bad rotation never takes the listener down.
type Reloader struct {
	certPath, keyPath string
	cur               atomic.Pointer[tls.Certificate]
	mu                sync.Mutex // serializes Reload
	sum               [32]byte   // sha256 of the last-loaded cert PEM (skip no-op reloads)
}

// NewReloader loads the initial pair from the Material and returns a Reloader.
// If the Material carries on-disk paths (LoadOrCreate / LoadCustom) the pair can
// be reloaded; an in-memory-only Material yields a static, non-reloadable holder.
func NewReloader(m *Material) (*Reloader, error) {
	pair, err := tls.X509KeyPair(m.CertPEM, m.KeyPEM)
	if err != nil {
		return nil, err
	}
	r := &Reloader{certPath: m.CertPath, keyPath: m.KeyPath}
	r.cur.Store(&pair)
	r.sum = sha256.Sum256(m.CertPEM)
	return r, nil
}

// CanReload reports whether on-disk paths are available to reload from.
func (r *Reloader) CanReload() bool { return r.certPath != "" && r.keyPath != "" }

// GetCertificate returns the current certificate; plug it into
// tls.Config.GetCertificate so every handshake picks up the latest pair.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cur.Load(), nil
}

// Reload re-reads the pair from disk and atomically swaps it in. It reports
// whether the certificate actually changed and, on error (missing or invalid
// files), leaves the current certificate in place.
func (r *Reloader) Reload() (changed bool, err error) {
	if !r.CanReload() {
		return false, fmt.Errorf("tlscert: no on-disk paths to reload from")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	certPEM, err := os.ReadFile(r.certPath)
	if err != nil {
		return false, fmt.Errorf("tlscert: reload read cert: %w", err)
	}
	sum := sha256.Sum256(certPEM)
	if sum == r.sum {
		return false, nil // identical bytes → nothing to do
	}
	keyPEM, err := os.ReadFile(r.keyPath)
	if err != nil {
		return false, fmt.Errorf("tlscert: reload read key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("tlscert: reload invalid pair (keeping current): %w", err)
	}
	r.cur.Store(&pair)
	r.sum = sum
	return true, nil
}
