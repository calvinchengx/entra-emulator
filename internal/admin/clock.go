package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// getClock returns the current controllable-clock state.
func (a *Admin) getClock(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, a.Store.Clock.State())
}

// clockRequest controls the emulator clock (roadmap #6). Fields are applied
// in order: offset (absolute) → advance (delta) → freeze/unfreeze.
type clockRequest struct {
	OffsetSeconds  *int64 `json:"offsetSeconds"`  // set absolute offset from real time
	AdvanceSeconds *int64 `json:"advanceSeconds"` // move time forward (or back)
	Frozen         *bool  `json:"frozen"`         // pin/resume time
}

func (a *Admin) setClock(w http.ResponseWriter, r *http.Request) {
	var req clockRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.OffsetSeconds != nil {
		a.Store.Clock.SetOffset(*req.OffsetSeconds)
	}
	if req.AdvanceSeconds != nil {
		a.Store.Clock.Advance(*req.AdvanceSeconds)
	}
	if req.Frozen != nil {
		if *req.Frozen {
			a.Store.Clock.Freeze()
		} else {
			a.Store.Clock.Unfreeze()
		}
	}
	httpx.WriteJSON(w, http.StatusOK, a.Store.Clock.State())
}

// resetClock returns the emulator to real time.
func (a *Admin) resetClock(w http.ResponseWriter, _ *http.Request) {
	a.Store.Clock.Reset()
	w.WriteHeader(http.StatusNoContent)
}
