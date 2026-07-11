package tokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

func bigOne() *big.Int          { return big.NewInt(1) }
func nameCN(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

const testTenant = "11111111-1111-1111-1111-111111111111"

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.EnsureTenant(testTenant, "https://issuer/"+testTenant+"/v2.0"); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestEnsureActiveKeyGeneratesAndReuses(t *testing.T) {
	st := newStore(t)

	s1, err := EnsureActiveKey(st, testTenant)
	if err != nil {
		t.Fatalf("first EnsureActiveKey: %v", err)
	}
	if s1.Kid == "" || s1.PrivateKey == nil {
		t.Fatalf("empty signer: %+v", s1)
	}
	// Second call loads the persisted key (same kid) — exercises parsePrivatePEM.
	s2, err := EnsureActiveKey(st, testTenant)
	if err != nil {
		t.Fatalf("second EnsureActiveKey: %v", err)
	}
	if s2.Kid != s1.Kid {
		t.Fatalf("kid changed across loads: %s vs %s", s1.Kid, s2.Kid)
	}

	// ActiveKid reflects the signer.
	svc := &Service{Store: st, Signer: s1}
	if svc.ActiveKid() != s1.Kid {
		t.Fatalf("ActiveKid = %s, want %s", svc.ActiveKid(), s1.Kid)
	}
}

func TestJWKSAndVerificationKeyRoundTrip(t *testing.T) {
	st := newStore(t)
	signer, _ := EnsureActiveKey(st, testTenant)

	raw, err := JWKS(st, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.Unmarshal(raw, &set)
	if len(set.Keys) != 1 || set.Keys[0]["kid"] != signer.Kid {
		t.Fatalf("JWKS missing active key: %s", raw)
	}

	// A token signed with the signer verifies against the published key.
	pub, err := VerificationKey(st, signer.Kid)
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	jwt, err := SignRS256(signer.PrivateKey, signer.Kid, map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("token did not verify against published JWK: %v", err)
	}

	// Unknown kid → error.
	if _, err := VerificationKey(st, "no-such-kid"); err == nil {
		t.Fatal("VerificationKey should fail for unknown kid")
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// PKIX public key PEM.
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pkix := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if pub, err := parsePublicKeyPEM(pkix); err != nil || pub.N.Cmp(key.PublicKey.N) != 0 {
		t.Fatalf("PKIX parse: %v", err)
	}

	// Self-signed certificate PEM.
	tmpl := &x509.Certificate{SerialNumber: bigOne(), Subject: nameCN("t")}
	cder, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder}))
	if _, err := parsePublicKeyPEM(certPEM); err != nil {
		t.Fatalf("certificate parse: %v", err)
	}

	// Garbage → error.
	if _, err := parsePublicKeyPEM("not pem"); err == nil {
		t.Fatal("garbage PEM should error")
	}
}

func TestParsePrivatePEMErrors(t *testing.T) {
	if _, err := parsePrivatePEM("not pem"); err == nil {
		t.Fatal("garbage private PEM should error")
	}
}
