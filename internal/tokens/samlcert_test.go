package tokens

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Kid: "kid-under-test", PrivateKey: key}
}

// The whole no-migration design rests on this: derive twice, get the same
// bytes. If it ever stops holding, metadata and assertions can disagree about
// which certificate signed what, and the fix is to persist the certificate
// rather than to paper over the difference.
func TestSAMLCertificateIsDeterministic(t *testing.T) {
	s := testSigner(t)
	const created = 1723200000

	first, err := s.SAMLCertificate("tenant-a", created)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.SAMLCertificate("tenant-a", created)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("re-deriving the certificate produced different DER")
	}
}

func TestSAMLCertificateWrapsTheSigningKey(t *testing.T) {
	s := testSigner(t)
	der, err := s.SAMLCertificate("tenant-a", 1723200000)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("certificate carries %T, want *rsa.PublicKey", cert.PublicKey)
	}
	// The point of the certificate is that a service provider verifying an
	// assertion with it is verifying against the same key that signs the
	// tenant's JWTs. A certificate over some other key would validate happily
	// and prove nothing.
	if pub.N.Cmp(s.PrivateKey.N) != 0 || pub.E != s.PrivateKey.E {
		t.Fatal("certificate public key is not the signing key")
	}
	// Verified as a signature, NOT with CheckSignatureFrom, which additionally
	// demands the issuer be a CA. A SAML signing certificate deliberately is
	// not one: Entra's own is a self-signed leaf, and service providers match
	// it against metadata rather than building a chain. Setting IsCA to please
	// the stricter helper would misrepresent the certificate to every SP that
	// reads it.
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("certificate signature does not verify under its own key: %v", err)
	}
	if cert.IsCA {
		t.Fatal("signing certificate must not claim to be a CA")
	}
}

// 397 days, for the reason recorded in samlcert.go: a decade-long local
// certificate is the shape that cost arm-emulator its .NET-on-macOS witness.
func TestSAMLCertificateLifetimeStaysUnderThePlatformCeiling(t *testing.T) {
	s := testSigner(t)
	const created = 1723200000
	der, err := s.SAMLCertificate("tenant-a", created)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	life := cert.NotAfter.Sub(cert.NotBefore)
	if life > 825*24*time.Hour {
		t.Fatalf("certificate valid for %v, over the 825-day ceiling Apple enforces", life)
	}
	if life != samlCertValidity {
		t.Fatalf("certificate valid for %v, want %v", life, samlCertValidity)
	}
}

func TestSAMLCertificatePEMParses(t *testing.T) {
	s := testSigner(t)
	got, err := s.SAMLCertificatePEM("tenant-a", 1723200000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatalf("not PEM armoured: %q", got[:40])
	}
}

func TestSAMLCertificateRefusesAnEmptySigner(t *testing.T) {
	var s *Signer
	if _, err := s.SAMLCertificate("tenant-a", 0); err == nil {
		t.Fatal("want an error for a nil signer, got none")
	}
	if _, err := (&Signer{Kid: "k"}).SAMLCertificate("tenant-a", 0); err == nil {
		t.Fatal("want an error for a signer with no key, got none")
	}
}

// The all-zero serial cannot arise from SHA-256 in practice, which is exactly
// why the branch needs a test: an unexecuted guard is an assumption, not a
// safety net. x509 rejects a non-positive serial outright.
func TestSerialFromDigestNeverReturnsZero(t *testing.T) {
	if got := serialFromDigest(make([]byte, 16)); got.Sign() <= 0 {
		t.Fatalf("all-zero digest produced serial %v, want a positive number", got)
	}
	if got := serialFromDigest(nil); got.Sign() <= 0 {
		t.Fatalf("empty digest produced serial %v, want a positive number", got)
	}
	// A normal digest must pass through unchanged rather than be replaced.
	b := []byte{0x00, 0x01, 0x02, 0x03}
	if got := serialFromDigest(b); got.Int64() != 0x00010203 {
		t.Fatalf("serial %v, want the digest value", got)
	}
}

func TestSAMLCertificatePEMPropagatesTheError(t *testing.T) {
	if _, err := (&Signer{Kid: "k"}).SAMLCertificatePEM("tenant-a", 0); err == nil {
		t.Fatal("want the underlying certificate error, got none")
	}
}
