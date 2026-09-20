// Command graphroutes prints every Microsoft Graph route the emulator
// registers, one "METHOD /path" per line, unprefixed.
//
// It is an input to scripts/check_graph_ledger.py and is not part of the
// released binary (GoReleaser builds cmd/entra-emulator only). It exists because
// http.ServeMux cannot list its own patterns; see graph.Router.
package main

import (
	"fmt"

	"github.com/calvinchengx/entra-emulator/internal/graph"
)

func main() {
	for _, p := range graph.RegisteredPatterns("") {
		fmt.Println(p)
	}
}
