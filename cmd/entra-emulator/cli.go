package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
)

// runSubcommand handles the print-by-default CLI verbs (hosts, cert-path,
// show-cert). Trust-store mutation is intentionally left to the printed
// platform commands.
func runSubcommand(cfg *config.Config, args []string) error {
	switch args[0] {
	case "hosts":
		return runHosts(cfg, args[1:])
	case "cert-path", "show-cert":
		cert, err := tlscert.LoadOrCreate(cfg.TLSCertDir, cfg.BaseDomain, cfg.LocalDomains)
		if err != nil {
			return err
		}
		fmt.Println(cert.CertPath)
		if args[0] == "show-cert" {
			fp, err := cert.Fingerprint()
			if err != nil {
				return err
			}
			fmt.Println("SHA-256:", fp)
		}
		return nil
	case "trust":
		cert, err := tlscert.LoadOrCreate(cfg.TLSCertDir, cfg.BaseDomain, cfg.LocalDomains)
		if err != nil {
			return err
		}
		printTrustCommand(cert.CertPath)
		return nil
	case "healthcheck":
		return runHealthcheck(cfg)
	case "help", "--help", "-h":
		printHelp()
		return nil
	default:
		printHelp()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// runHealthcheck probes the running instance's /health for container
// HEALTHCHECK (distroless has no shell/curl). Non-zero exit = unhealthy.
func runHealthcheck(cfg *config.Config) error {
	scheme := "http"
	if cfg.TLSEnabled {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Self-probe over the emulator's own self-signed cert.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(fmt.Sprintf("%s://localhost:%d/health", scheme, cfg.Port))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned %d", resp.StatusCode)
	}
	return nil
}

func printHelp() {
	fmt.Println(`entra-emulator — a local, MSAL-compatible Entra ID emulator

Usage:
  entra-emulator            start the emulator
  entra-emulator hosts      print the hosts-file block (--apply to write it)
  entra-emulator trust      print the platform command to trust the TLS cert
  entra-emulator cert-path  print the path to cert.pem
  entra-emulator show-cert  print the cert path + SHA-256 fingerprint
  entra-emulator healthcheck  probe /health (exit 0 healthy) — for containers`)
}

const hostsMarkerBegin = "# entra-emulator BEGIN"
const hostsMarkerEnd = "# entra-emulator END"

func hostsEntries(cfg *config.Config) []string {
	domains := append([]string{cfg.BaseDomain}, cfg.LocalDomains...)
	var lines []string
	for _, d := range domains {
		for _, sub := range []string{"login", "portal", "graph"} {
			lines = append(lines, "127.0.0.1  "+sub+"."+d)
		}
	}
	return lines
}

// hostsFilePathFn resolves the hosts file to edit; a var so tests can point it
// at a scratch file instead of the real system hosts file.
var hostsFilePathFn = hostsFilePath

func hostsFilePath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// mergeHostsBlock returns content with the managed block removed (idempotent)
// and, unless remove is set, re-appended. Pure so the add/remove/idempotency
// logic is unit-testable without filesystem access.
func mergeHostsBlock(content, block string, remove bool) string {
	if start := strings.Index(content, hostsMarkerBegin); start >= 0 {
		if end := strings.Index(content, hostsMarkerEnd); end >= 0 {
			content = content[:start] + content[end+len(hostsMarkerEnd):]
			content = strings.TrimRight(content, "\n") + "\n"
		}
	}
	if !remove {
		content = strings.TrimRight(content, "\n") + "\n\n" + block + "\n"
	}
	return content
}

func runHosts(cfg *config.Config, args []string) error {
	apply, remove := false, false
	for _, a := range args {
		switch a {
		case "--apply":
			apply = true
		case "--remove":
			remove = true
		}
	}
	block := hostsMarkerBegin + "\n" + strings.Join(hostsEntries(cfg), "\n") + "\n" + hostsMarkerEnd

	if !apply {
		fmt.Printf("Map the emulator local domains to 127.0.0.1\n  hosts file: %s (needs elevation)\n\n", hostsFilePath())
		if remove {
			fmt.Println("Re-run with --apply to remove the block below:")
		} else {
			fmt.Println("Add the following block (or re-run with --apply to write it):")
		}
		fmt.Println("\n" + block)
		return nil
	}

	path := hostsFilePathFn()
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s (elevation required?): %w", path, err)
	}
	content := mergeHostsBlock(string(raw), block, remove)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s (elevation required?): %w", path, err)
	}
	if remove {
		fmt.Println("Removed the entra-emulator hosts block.")
	} else {
		fmt.Println("Wrote the entra-emulator hosts block.")
	}
	return nil
}

func printTrustCommand(certPath string) {
	fmt.Println("Trust the emulator certificate (dev only):")
	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "windows":
		fmt.Printf("  certutil -addstore -f ROOT %s\n", certPath)
	default:
		fmt.Printf("  sudo cp %s /usr/local/share/ca-certificates/entra-emulator.crt && sudo update-ca-certificates\n", certPath)
	}
	fmt.Println("For Node clients: NODE_EXTRA_CA_CERTS=" + certPath)
}
