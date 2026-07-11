// Package compat proves the externalized-authz sample's PDP port behaves
// identically against real authorization engines (OpenFGA, Casbin, …).
//
// The actual suite lives in _test.go files guarded by the `pdp_integration`
// build tag, so the default build stays dependency-free. Run it with:
//
//	go test -tags=pdp_integration ./...
//
// See README.md for the design (canonical decision matrix + per-engine
// harness) and the honest caveat about ReBAC-vs-RBAC model translation.
package compat
