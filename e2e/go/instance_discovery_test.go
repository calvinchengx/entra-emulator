package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// TestMSALGoInstanceDiscovery witnesses /common/discovery/instance with a real
// MSAL client performing its real instance-discovery call.
//
// Two facts shape this test, both established by measurement rather than
// assumption:
//
//  1. Every other suite passes WithInstanceDiscovery(false), so MSAL treats the
//     emulator as a plain authority and never performs discovery at all. The
//     endpoint is implemented and graded, and no client had ever exercised it.
//  2. MSAL Go does NOT call the authority's own host for instance discovery. It
//     hardcodes login.microsoftonline.com and asks *that* about the authority.
//     Enabling discovery against a localhost authority therefore reaches for the
//     real service and fails offline. (The handler's comment saying "MSAL calls
//     this before every token request" is true only once the name resolves to
//     the emulator.)
//
// So the endpoint is reachable exactly the way it is reachable in practice: when
// login.microsoftonline.com resolves to the emulator, which is what several
// composes in this family already do. The dialer below is that aliasing, and
// nothing more — the request MSAL builds, the URL it chooses and the reply it
// must parse are all untouched. TLS verification is kept on, against the
// emulator's real cert, by verifying the name the cert actually carries; only
// the DNS answer is supplied by the test.
func TestMSALGoInstanceDiscovery(t *testing.T) {
	origin, tenant := env(t, "EMU_ORIGIN"), env(t, "EMU_TENANT")

	emuURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	emuAddr := emuURL.Host // host:port the emulator actually listens on

	pem, err := os.ReadFile(env(t, "EMU_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("emulator cert did not parse")
	}

	var instanceHits, tokenHits int64
	var mu sync.Mutex
	var fetched []string

	transport := &http.Transport{
		// The aliasing: login.microsoftonline.com resolves to the emulator.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "login.microsoftonline.com:") {
				addr = emuAddr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		// Verification stays ON against the emulator's own certificate; the
		// cert carries "localhost", not the aliased name, so that is the name
		// checked. Skipping verification here would make the test pass against
		// anything answering the socket.
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: emuURL.Hostname()},
	}

	hc := &http.Client{Transport: &countingRT{inner: transport, seen: func(u string) {
		mu.Lock()
		fetched = append(fetched, u)
		mu.Unlock()
		switch {
		case strings.Contains(u, "/common/discovery/instance"):
			atomic.AddInt64(&instanceHits, 1)
		case strings.HasSuffix(u, "/oauth2/v2.0/token"):
			atomic.AddInt64(&tokenHits, 1)
		}
	}}}

	cred, err := confidential.NewCredFromSecret(daemonSecret)
	if err != nil {
		t.Fatal(err)
	}
	// No WithInstanceDiscovery(false): the default path a real client takes.
	client, err := confidential.New(origin+"/"+tenant, daemonID, cred,
		confidential.WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.AcquireTokenByCredential(context.Background(),
		[]string{"api://" + daemonID + "/.default"})
	if err != nil {
		mu.Lock()
		for _, u := range fetched {
			t.Logf("  MSAL fetched: %s", u)
		}
		mu.Unlock()
		t.Fatalf("client credentials with instance discovery enabled: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("no access token")
	}
	// Order matters: without a token request the counts prove nothing, so check
	// the transport was live before believing what it did or did not observe.
	if n := atomic.LoadInt64(&tokenHits); n == 0 {
		t.Fatal("no token request observed — the transport is not wired in")
	}
	if n := atomic.LoadInt64(&instanceHits); n == 0 {
		t.Fatal("MSAL never called /common/discovery/instance: the endpoint is not on the path a real client takes")
	}
	t.Logf("instance discovery hits=%d token hits=%d", instanceHits, tokenHits)
}

// countingRT observes what MSAL actually fetches. The token alone cannot tell
// us which path produced it, so the transport is the witness.
type countingRT struct {
	inner http.RoundTripper
	seen  func(string)
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.seen(r.URL.String())
	return c.inner.RoundTrip(r)
}
