package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/portal"
)

// portalFS holds the embedded Svelte portal; nil falls back to a plain
// placeholder (defensive — the dist is committed, so it should never be nil).
var portalFS fs.FS

func init() {
	if sub, err := portal.Dist(); err == nil {
		if _, err := fs.Stat(sub, "index.html"); err == nil {
			portalFS = sub
		}
	}
}

// servePortal serves an asset path from the embedded portal, or index.html
// for SPA routes.
func servePortal(w http.ResponseWriter, r *http.Request) {
	if portalFS == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Entra Emulator</title><h1>Entra Emulator</h1><p>Portal assets missing from this build; the admin REST API is available under /admin/api.</p>"))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if _, err := fs.Stat(portalFS, path); err != nil {
		path = "index.html" // SPA fallback
	}
	http.ServeFileFS(w, r, portalFS, path)
}
