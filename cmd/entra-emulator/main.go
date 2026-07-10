// Command entra-emulator boots the local Entra ID emulator: one HTTPS
// listener serving the STS, minimal Graph, and admin surfaces.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/server"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

var version = "dev" // stamped via -ldflags at release time

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "entra-emulator:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	if len(os.Args) > 1 {
		return runSubcommand(cfg, os.Args[1:])
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// The tenant is infrastructure (the signing key FK-references it); ensure
	// it independently of SEED_ON_START so an unseeded boot still works.
	if err := st.EnsureTenant(cfg.TenantID, cfg.Issuer); err != nil {
		return fmt.Errorf("ensure tenant: %w", err)
	}
	if cfg.SeedOnStart {
		if seeded, err := st.Seed(cfg.TenantID, cfg.Issuer); err != nil {
			return fmt.Errorf("seed: %w", err)
		} else if seeded {
			log.Printf("seeded deterministic directory (tenant %s)", cfg.TenantID)
		}
	}

	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	ts := &tokens.Service{Store: st, Signer: signer, Cfg: cfg}

	var cert *tlscert.Material
	if cfg.TLSEnabled {
		if cfg.TLSCertPath != "" {
			cert, err = tlscert.LoadCustom(cfg.TLSCertPath, cfg.TLSKeyPath)
		} else {
			cert, err = tlscert.LoadOrCreate(cfg.TLSCertDir, cfg.BaseDomain, cfg.LocalDomains)
		}
		if err != nil {
			return err
		}
	}

	srv := server.New(cfg, st, ts, cert, version)
	log.Printf("entra-emulator %s", version)
	log.Printf("  login:  %s", cfg.Origins.Login)
	log.Printf("  portal: %s", cfg.Origins.Portal)
	log.Printf("  graph:  %s", cfg.Origins.Graph)
	log.Printf("  issuer: %s", cfg.Issuer)
	if cfg.OriginMode == "subdomains" {
		log.Printf("  hint: if *.%s does not resolve, run `entra-emulator hosts --apply`", cfg.BaseDomain)
	}
	log.Printf("listening on %s:%d (tls=%v)", cfg.Host, cfg.Port, cfg.TLSEnabled)
	return srv.Listen()
}
