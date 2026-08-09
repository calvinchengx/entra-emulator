package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// SAML publishes a CERTIFICATE where OIDC publishes a JWK.
//
// Both describe the same tenant signing key. A relying party on the OIDC side
// fetches /jwks and gets a bare public key; a SAML service provider reads the
// IdP metadata and expects <X509Certificate>, because XML-DSIG's KeyInfo is
// specified in terms of certificates. So the same RSA key has to appear in two
// envelopes, and a token this emulator signs and an assertion it signs are
// backed by the same private key.
//
// DERIVED, NOT STORED. Every field is a function of its arguments, and PKCS#1
// v1.5 with SHA-256 is a deterministic signature, so the same inputs produce
// byte-identical DER. No schema migration, no second source of truth, and no
// chance of metadata advertising one certificate while assertions are signed
// under another.
//
// THE WINDOW IS THE CALLER'S, AND THAT IS THE POINT. This first derived it
// from the key's creation time, which was reproducible and wrong: a key older
// than the validity period yields an EXPIRED certificate, and a service
// provider that checks validity then rejects every assertion the emulator
// ever signs. A test dated 2024 running in 2026 found it. Callers pass a
// window covering now; determinism survives because the parameter is explicit
// rather than because the value never moves.

// samlCertValidity is 397 days, not the ten years a local dev certificate
// invites. Apple refuses to trust any TLS server certificate longer than 825
// days, and arm-emulator lost a whole .NET-on-macOS witness to exactly that
// before anyone noticed. The rule is about server certificates rather than
// signing certificates, so this is caution rather than compliance, but a
// number no platform argues with costs nothing.
const samlCertValidity = 397 * 24 * time.Hour

// SAMLCertificate returns the tenant's SAML signing certificate, DER encoded,
// wrapping the same RSA key that signs its JWTs.
func (s *Signer) SAMLCertificate(tenantID string, notBefore time.Time) ([]byte, error) {
	if s == nil || s.PrivateKey == nil {
		return nil, fmt.Errorf("tokens: no signing key for tenant %s", tenantID)
	}
	sum := sha256.Sum256([]byte(s.Kid))
	serial := serialFromDigest(sum[:16])

	notBefore = notBefore.UTC().Truncate(time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: samlCertCN(tenantID)},
		Issuer:                pkix.Name{CommonName: samlCertCN(tenantID)},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(samlCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// SHA256WithRSA is PKCS#1 v1.5, which is deterministic. Naming it
		// explicitly is what makes the whole certificate reproducible; leaving
		// it to the default would still pick this today, but silently.
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	// Self-signed: the template is both subject and issuer, and the key signs
	// for itself. rand is required by the signature but unused by PKCS#1 v1.5.
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &s.PrivateKey.PublicKey, s.PrivateKey)
}

// SAMLCertificatePEM is SAMLCertificate in the PEM form humans and openssl
// expect. Metadata carries the base64 DER without the armour, so callers that
// build XML want SAMLCertificate directly.
func (s *Signer) SAMLCertificatePEM(tenantID string, notBefore time.Time) ([]byte, error) {
	der, err := s.SAMLCertificate(tenantID, notBefore)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// serialFromDigest turns a hash prefix into a certificate serial.
//
// Split out from the caller so the all-zero case is reachable from a test. It
// cannot occur in practice, since it would need SHA-256 to produce sixteen
// leading zero bytes, but x509 rejects a non-positive serial and a branch that
// has never once been executed is not a safety net, it is an assumption.
func serialFromDigest(b []byte) *big.Int {
	serial := new(big.Int).SetBytes(b)
	if serial.Sign() == 0 {
		return big.NewInt(1)
	}
	return serial
}

func samlCertCN(tenantID string) string {
	return "entra-emulator SAML signing " + tenantID
}
