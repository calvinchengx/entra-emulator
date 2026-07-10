// Package portal embeds the built Svelte admin portal (dist/) into the
// emulator binary. Run `npm run build` here after changing the UI; the Go
// toolchain needs only the committed dist output.
package portal

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built portal assets rooted at the dist directory.
func Dist() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
