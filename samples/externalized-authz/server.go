package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ResourceServer is a protected API. Every request is (1) authenticated by
// validating the emulator JWT, then (2) authorized by asking the PDP. The two
// steps use different components on purpose — Entra says who you are, the PDP
// says what you may do.
type ResourceServer struct {
	Validator *TokenValidator
	PDP       PDP
}

// Handler wires the routes. GET /documents/{id} needs `reader`; POST needs
// `writer`.
func (s *ResourceServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /documents/{id}", s.authorize("reader", s.readDocument))
	mux.HandleFunc("POST /documents/{id}", s.authorize("writer", s.writeDocument))
	return mux
}

type authedHandler func(w http.ResponseWriter, r *http.Request, c *Claims)

// authorize is the middleware: authenticate, then PDP-check the relation for
// the addressed object before the handler runs.
func (s *ResourceServer) authorize(relation string, next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" || bearer == r.Header.Get("Authorization") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := s.Validator.Validate(bearer)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token: "+err.Error())
			return
		}
		if claims.OID == "" {
			writeErr(w, http.StatusForbidden, "token has no user subject (oid)")
			return
		}

		object := "doc:" + r.PathValue("id")
		groups := make([]string, len(claims.Groups))
		for i, g := range claims.Groups {
			groups[i] = "group:" + g
		}
		allowed, err := s.PDP.Check(r.Context(), CheckRequest{
			Subject:  "user:" + claims.OID,
			Relation: relation,
			Object:   object,
			Groups:   groups,
		})
		if err != nil {
			writeErr(w, http.StatusBadGateway, "authorization service error: "+err.Error())
			return
		}
		if !allowed {
			writeErr(w, http.StatusForbidden, "not permitted to "+relation+" "+object)
			return
		}
		next(w, r, claims)
	}
}

func (s *ResourceServer) readDocument(w http.ResponseWriter, r *http.Request, c *Claims) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id": r.PathValue("id"), "action": "read", "subject": c.OID,
	})
}

func (s *ResourceServer) writeDocument(w http.ResponseWriter, r *http.Request, c *Claims) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id": r.PathValue("id"), "action": "write", "subject": c.OID,
	})
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
