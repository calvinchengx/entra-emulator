package config

import (
	"os"
	"path/filepath"
	"testing"
)

// ENTRA_DATA_DIR names the state directory, matching <PREFIX>_DATA_DIR across
// the family. DB_PATH predates it and still wins, so existing deployments are
// unaffected — that back-compatibility is the point of the change, and this
// test is what keeps it true.
func TestDataDirDefaulting(t *testing.T) {
	clear := func(t *testing.T) {
		t.Helper()
		for _, k := range []string{"ENTRA_DATA_DIR", "DB_PATH", "TLS_CERT_DIR"} {
			t.Setenv(k, "")
			if err := os.Unsetenv(k); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("unset keeps the historic layout", func(t *testing.T) {
		clear(t)
		c, err := Load(os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(DefaultDataDir, "entra-emulator.db"); c.DBPath != want {
			t.Fatalf("DBPath = %q, want %q", c.DBPath, want)
		}
		if want := filepath.Join(DefaultDataDir, "tls"); c.TLSCertDir != want {
			t.Fatalf("TLSCertDir = %q, want %q", c.TLSCertDir, want)
		}
	})

	t.Run("a path moves both the DB and the TLS material", func(t *testing.T) {
		clear(t)
		// The expectations are joined the same way the config joins them.
		// Hard-coding "/tmp/entra-state/..." asserted the POSIX separator, so
		// this failed on Windows where filepath.Join yields backslashes — the
		// separator was never what the test set out to prove.
		dir := t.TempDir()
		t.Setenv("ENTRA_DATA_DIR", dir)
		c, err := Load(os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(dir, "entra-emulator.db"); c.DBPath != want {
			t.Fatalf("DBPath = %q, want %q", c.DBPath, want)
		}
		if want := filepath.Join(dir, "tls"); c.TLSCertDir != want {
			t.Fatalf("TLSCertDir = %q, want %q", c.TLSCertDir, want)
		}
	})

	t.Run("explicitly empty keeps nothing", func(t *testing.T) {
		clear(t)
		t.Setenv("ENTRA_DATA_DIR", "")
		c, err := Load(os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		// Not "entra-emulator.db" in the working directory, which is what a
		// bare filepath.Join would have produced.
		if c.DBPath != InMemoryDB {
			t.Fatalf("DBPath = %q, want %q", c.DBPath, InMemoryDB)
		}
		if c.TLSCertDir != "" {
			t.Fatalf("TLSCertDir = %q, want \"\" (ephemeral)", c.TLSCertDir)
		}
	})

	t.Run("DB_PATH still wins, so existing setups are unaffected", func(t *testing.T) {
		clear(t)
		t.Setenv("ENTRA_DATA_DIR", "/tmp/entra-state")
		t.Setenv("DB_PATH", "/var/lib/legacy.db")
		c, err := Load(os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		if c.DBPath != "/var/lib/legacy.db" {
			t.Fatalf("DBPath = %q, want the explicit DB_PATH", c.DBPath)
		}
	})
}
