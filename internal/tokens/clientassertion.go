package tokens

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// VerifyClientAssertion validates a private_key_jwt client assertion
// (roadmap #13) against an app's registered public keys. It checks the
// signature (RS256) and the registered-client-authentication claims per
// entra-docs certificate-credentials: iss == sub == clientID, aud ∈
// acceptedAudiences, and not expired. Returns nil on success.
func VerifyClientAssertion(assertion, clientID string, publicKeysPEM []string,
	acceptedAudiences []string, now int64) error {
	if len(publicKeysPEM) == 0 {
		return fmt.Errorf("no registered key credentials for the client")
	}

	// Signature: accept if any registered key verifies it.
	var verified bool
	for _, pemStr := range publicKeysPEM {
		pub, err := parsePublicKeyPEM(pemStr)
		if err != nil {
			continue
		}
		if _, err := VerifyRS256(pub, assertion); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return fmt.Errorf("assertion signature does not match any registered key")
	}

	claims, err := DecodeUnverified(assertion)
	if err != nil {
		return err
	}
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss != clientID || sub != clientID {
		return fmt.Errorf("assertion iss/sub must equal the client_id")
	}
	if exp, ok := numClaimF(claims, "exp"); !ok || now > exp+clockSkewSeconds {
		return fmt.Errorf("assertion expired")
	}
	if nbf, ok := numClaimF(claims, "nbf"); ok && now < nbf-clockSkewSeconds {
		return fmt.Errorf("assertion not yet valid")
	}
	aud, _ := claims["aud"].(string)
	for _, a := range acceptedAudiences {
		if aud == a {
			return nil
		}
	}
	return fmt.Errorf("assertion aud %q is not an accepted token-endpoint audience", aud)
}

// parsePublicKeyPEM accepts either a PKIX public key or an X.509 certificate
// PEM and returns the RSA public key.
func parsePublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("certificate is not RSA")
	default: // PUBLIC KEY (PKIX)
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("public key is not RSA")
	}
}

func numClaimF(claims map[string]any, key string) (int64, bool) {
	f, ok := claims[key].(float64)
	return int64(f), ok
}
