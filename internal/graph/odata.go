package graph

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// Minimal OData system-query support for the Graph read surface (roadmap #17):
// $select, $filter, $top, $count. $top/$skiptoken paging is preserved from the
// original handlers; filtering and projection run in-memory over the shaped
// entities, which is fine at emulator data sizes.

type odataQuery struct {
	Select []string                    // projected fields; empty = all
	Filter func(map[string]any) bool   // nil = no filter
	Top    int
	Skip   int
	Count  bool
}

func parseOData(r *http.Request) (odataQuery, error) {
	q := odataQuery{}
	q.Top, q.Skip = paging(r)
	if sel := r.URL.Query().Get("$select"); sel != "" {
		for _, f := range strings.Split(sel, ",") {
			if f = strings.TrimSpace(f); f != "" {
				q.Select = append(q.Select, f)
			}
		}
	}
	if strings.EqualFold(r.URL.Query().Get("$count"), "true") {
		q.Count = true
	}
	if f := strings.TrimSpace(r.URL.Query().Get("$filter")); f != "" {
		pred, err := parseFilter(f)
		if err != nil {
			return q, err
		}
		q.Filter = pred
	}
	return q, nil
}

var (
	reFuncFilter = regexp.MustCompile(`^(startswith|endswith)\(\s*([A-Za-z0-9_]+)\s*,\s*'([^']*)'\s*\)$`)
	reCmpFilter  = regexp.MustCompile(`^([A-Za-z0-9_]+)\s+(eq|ne)\s+(.+)$`)
)

// parseFilter supports a single clause: `field eq|ne 'value'`, `field eq|ne
// true|false`, and `startswith|endswith(field,'value')`. Logical and/or is out
// of scope for "basic" OData.
func parseFilter(expr string) (func(map[string]any) bool, error) {
	if m := reFuncFilter.FindStringSubmatch(expr); m != nil {
		fn, field, want := m[1], m[2], m[3]
		return func(shape map[string]any) bool {
			got := fieldString(shape, field)
			if fn == "startswith" {
				return strings.HasPrefix(got, want)
			}
			return strings.HasSuffix(got, want)
		}, nil
	}
	if m := reCmpFilter.FindStringSubmatch(expr); m != nil {
		field, op, rawVal := m[1], m[2], strings.TrimSpace(m[3])
		want, isStr := literalValue(rawVal)
		if want == nil && !isStr {
			return nil, fmt.Errorf("unparseable filter value %q", rawVal)
		}
		return func(shape map[string]any) bool {
			eq := valueEquals(shape[field], want, isStr)
			if op == "ne" {
				return !eq
			}
			return eq
		}, nil
	}
	return nil, fmt.Errorf("unsupported $filter: %q", expr)
}

// literalValue parses an OData literal: 'quoted string', true/false, or null.
// isStr distinguishes a (possibly empty) string literal from a bare token.
func literalValue(raw string) (val any, isStr bool) {
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], true
	}
	switch strings.ToLower(raw) {
	case "true":
		return true, false
	case "false":
		return false, false
	case "null":
		return nil, false
	}
	return nil, false
}

func valueEquals(got, want any, wantIsStr bool) bool {
	if wantIsStr {
		if got == nil {
			return want == ""
		}
		return fmt.Sprint(got) == want.(string)
	}
	// bool / null comparison
	return got == want
}

func fieldString(shape map[string]any, field string) string {
	v, ok := shape[field]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// applySelect projects a shape to the selected fields. Graph always returns
// id, so it is retained even when not explicitly selected.
func applySelect(shape map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return shape
	}
	out := make(map[string]any, len(fields)+1)
	if id, ok := shape["id"]; ok {
		out["id"] = id
	}
	for _, f := range fields {
		if v, ok := shape[f]; ok {
			out[f] = v
		}
	}
	return out
}

// writeCollection applies $filter, $count, $top/$skiptoken paging, and $select
// to a fully-materialized slice of shaped entities, then writes the OData
// collection envelope.
func (g *Graph) writeCollection(w http.ResponseWriter, r *http.Request, contextSuffix string, shapes []map[string]any, q odataQuery) {
	if q.Filter != nil {
		kept := make([]map[string]any, 0, len(shapes))
		for _, s := range shapes {
			if q.Filter(s) {
				kept = append(kept, s)
			}
		}
		shapes = kept
	}
	count := len(shapes)

	start := q.Skip
	if start > count {
		start = count
	}
	end := start + q.Top
	if end > count {
		end = count
	}
	page := shapes[start:end]

	value := make([]map[string]any, 0, len(page))
	for _, s := range page {
		value = append(value, applySelect(s, q.Select))
	}
	resp := map[string]any{"@odata.context": g.contextURL(contextSuffix), "value": value}
	if q.Count {
		resp["@odata.count"] = count
	}
	if end < count {
		resp["@odata.nextLink"] = g.nextLink(r, end)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
