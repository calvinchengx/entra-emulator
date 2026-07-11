// Command externalized-authz is a teaching sample: a Go resource API that
// authenticates callers with Entra-emulator JWTs (validated via JWKS) and then
// delegates fine-grained authorization to an external Policy Decision Point
// (PDP) — the "Entra authenticates, a separate service authorizes" pattern.
// See README.md. It needs no emulator features; it consumes the emulator only
// as a standards-compliant token issuer.
//
// The reusable pieces (token validator, PDP port, resource server, in-memory
// PDP) live in the authz package so they can be imported — notably by the
// compat/ module, which proves the PDP port works against real engines
// (OpenFGA, Casbin, …). This file is only the standalone runner.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

func main() {
	jwksURL := env("EMULATOR_JWKS_URL", "http://localhost:8080/"+env("TENANT_ID", "11111111-1111-1111-1111-111111111111")+"/discovery/v2.0/keys")
	issuer := env("EMULATOR_ISSUER", "http://localhost:8080/"+env("TENANT_ID", "11111111-1111-1111-1111-111111111111")+"/v2.0")
	audience := env("RESOURCE_AUDIENCE", "api://docs-api")
	addr := env("LISTEN_ADDR", ":9090")

	// Seed the PDP with a couple of relationship tuples. In production these
	// live in the real PDP (OpenFGA, …) and are managed independently.
	pdp := authz.NewInMemoryPDP()
	if reader := os.Getenv("SEED_READER_OID"); reader != "" {
		pdp.Write("user:"+reader, "reader", "doc:readme")
	}

	srv := &authz.ResourceServer{
		Validator: &authz.TokenValidator{JWKSURL: jwksURL, Issuer: issuer, Audience: audience},
		PDP:       pdp,
	}
	log.Printf("externalized-authz resource API listening on %s (aud=%s)", addr, audience)
	log.Fatal(listenAndServe(context.Background(), addr, srv.Handler()))
}

func listenAndServe(_ context.Context, addr string, h http.Handler) error {
	return (&http.Server{Addr: addr, Handler: h}).ListenAndServe()
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
