package scim

import (
	"net/http"
	"strconv"
	"strings"
)

// RFC 7644 §3.9 attribute projection.
//
// A client asks for a subset with ?attributes=, or for everything-but with
// ?excludedAttributes=. They are mutually exclusive. Serving the full resource
// regardless is silently wrong: the client believes it asked for less, and a
// caller that sends excludedAttributes=password-ish fields has no way to tell
// it was ignored.

// alwaysReturned are the attributes RFC 7643 §7 marks returned="always"; they
// survive both projections. id identifies the resource, schemas types it, and
// meta carries the location a client follows next.
var alwaysReturned = map[string]bool{"id": true, "schemas": true, "meta": true}

// projectionFrom reads the two query parameters, returning nil,nil when the
// client asked for no projection.
func projectionFrom(r *http.Request) (include, exclude []string) {
	q := r.URL.Query()
	return splitAttrs(q.Get("attributes")), splitAttrs(q.Get("excludedAttributes"))
}

func splitAttrs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// project returns res filtered by include / exclude. Paths may name a
// sub-attribute ("name.givenName"), in which case only that leaf is affected.
func project(res map[string]any, include, exclude []string) map[string]any {
	switch {
	case len(include) > 0:
		out := map[string]any{}
		for k, v := range res {
			if alwaysReturned[strings.ToLower(k)] {
				out[k] = v
			}
		}
		for _, path := range include {
			top, sub, nested := strings.Cut(path, ".")
			key, val, ok := lookup(res, top)
			if !ok {
				continue
			}
			if !nested {
				out[key] = val
				continue
			}
			if child, ok := val.(map[string]any); ok {
				k2, v2, ok2 := lookup(child, sub)
				if !ok2 {
					continue
				}
				existing, _ := out[key].(map[string]any)
				if existing == nil {
					existing = map[string]any{}
				}
				existing[k2] = v2
				out[key] = existing
			}
		}
		return out

	case len(exclude) > 0:
		out := map[string]any{}
		for k, v := range res {
			out[k] = v
		}
		for _, path := range exclude {
			top, sub, nested := strings.Cut(path, ".")
			key, val, ok := lookup(out, top)
			if !ok || alwaysReturned[strings.ToLower(key)] {
				continue
			}
			if !nested {
				delete(out, key)
				continue
			}
			if child, ok := val.(map[string]any); ok {
				if k2, _, ok2 := lookup(child, sub); ok2 {
					clone := map[string]any{}
					for k3, v3 := range child {
						if k3 != k2 {
							clone[k3] = v3
						}
					}
					out[key] = clone
				}
			}
		}
		return out
	}
	return res
}

// lookup finds a key case-insensitively, as SCIM attribute names are not
// case-sensitive on the wire.
func lookup(m map[string]any, name string) (string, any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return k, v, true
		}
	}
	return "", nil, false
}

// writeResource writes a single resource with the request's projection applied.
func writeResource(w http.ResponseWriter, r *http.Request, status int, res map[string]any) {
	inc, exc := projectionFrom(r)
	writeSCIM(w, status, project(res, inc, exc))
}

// projectAll applies a projection across a slice of resources.
func projectAll(resources []any, include, exclude []string) []any {
	if len(include) == 0 && len(exclude) == 0 {
		return resources
	}
	out := make([]any, 0, len(resources))
	for _, r := range resources {
		if m, ok := r.(map[string]any); ok {
			out = append(out, project(m, include, exclude))
			continue
		}
		out = append(out, r)
	}
	return out
}

// searchRequest is the POST /.search body of RFC 7644 §3.4.3. It carries the
// same knobs as the GET query string, for clients whose filters are too long
// or too sensitive to put in a URL.
type searchRequest struct {
	Schemas            []string `json:"schemas"`
	Filter             string   `json:"filter"`
	StartIndex         *int     `json:"startIndex"`
	Count              *int     `json:"count"`
	Attributes         []string `json:"attributes"`
	ExcludedAttributes []string `json:"excludedAttributes"`
}

// toQuery rewrites a search body onto the request's query string, so the search
// handlers can reuse the list handlers unchanged rather than growing a second,
// subtly different implementation of filtering and paging.
func (sr *searchRequest) toQuery(r *http.Request) {
	q := r.URL.Query()
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("filter", sr.Filter)
	set("attributes", strings.Join(sr.Attributes, ","))
	set("excludedAttributes", strings.Join(sr.ExcludedAttributes, ","))
	if sr.StartIndex != nil {
		set("startIndex", strconv.Itoa(*sr.StartIndex))
	}
	if sr.Count != nil {
		set("count", strconv.Itoa(*sr.Count))
	}
	r.URL.RawQuery = q.Encode()
}

// ---- query by POST (RFC 7644 §3.4.3) ----

// readSearch decodes a SearchRequest and rewrites it onto the request's query
// string, so the GET list handlers can serve it unchanged.
func (s *Service) readSearch(w http.ResponseWriter, r *http.Request) bool {
	var sr searchRequest
	if r.ContentLength != 0 {
		if !decode(w, r, &sr) {
			return false
		}
	}
	sr.toQuery(r)
	return true
}

func (s *Service) searchUsers(w http.ResponseWriter, r *http.Request) {
	if s.readSearch(w, r) {
		s.listUsers(w, r)
	}
}

func (s *Service) searchGroups(w http.ResponseWriter, r *http.Request) {
	if s.readSearch(w, r) {
		s.listGroups(w, r)
	}
}

// searchAll serves the root /.search, which spans every resource type.
func (s *Service) searchAll(w http.ResponseWriter, r *http.Request) {
	if !s.readSearch(w, r) {
		return
	}
	inc, exc := projectionFrom(r)
	b := base(r)

	resources := make([]any, 0)
	if users, _, err := s.Store.ListUsers(allRows, 0, ""); err == nil {
		ext := s.Store.ExternalIDs("User")
		for _, u := range users {
			resources = append(resources, userResource(u, b, ext[u.ID]))
		}
	}
	if groups, _, err := s.Store.ListGroups(allRows, 0, ""); err == nil {
		ext := s.Store.ExternalIDs("Group")
		for _, g := range groups {
			members, _ := s.Store.ListGroupMembers(g.ID)
			resources = append(resources, groupResource(g, members, b, ext[g.ID]))
		}
	}
	total := len(resources)
	start, end := paginate(r.URL.Query(), total)
	writeSCIM(w, http.StatusOK,
		withTotal(listResponse(projectAll(resources[start:end], inc, exc), start+1), total))
}
