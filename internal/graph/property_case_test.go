package graph

import (
	"reflect"
	"testing"
)

// Microsoft documents API property names as case-insensitive
// (learn.microsoft.com/graph/traverse-the-graph). $select and $filter name
// properties, so both have to resolve them that way.

func TestApplySelectResolvesPropertyNamesIgnoringCaseAndKeepsTheirOwnSpelling(t *testing.T) {
	shape := map[string]any{"id": "1", "displayName": "Alice", "userPrincipalName": "a@x"}
	for _, tc := range []struct {
		name string
		sel  []string
		want map[string]any
	}{
		{"exact", []string{"displayName"}, map[string]any{"displayName": "Alice"}},
		{"upper", []string{"DISPLAYNAME"}, map[string]any{"displayName": "Alice"}},
		{"several, mixed", []string{"Id", "userprincipalname"}, map[string]any{"id": "1", "userPrincipalName": "a@x"}},
		{"the same property twice is one key", []string{"displayName", "DISPLAYNAME"}, map[string]any{"displayName": "Alice"}},
		{"an unknown property is still ignored", []string{"NoSuchThing", "displayname"}, map[string]any{"displayName": "Alice"}},
		{"no select keeps everything", nil, shape},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := applySelect(shape, tc.sel); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("applySelect(%v) = %v, want %v", tc.sel, got, tc.want)
			}
		})
	}
}

func TestParseFilterResolvesPropertyNamesButComparesLiteralsExactly(t *testing.T) {
	shape := map[string]any{"displayName": "Alice", "accountEnabled": true, "mail": nil}
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{"displayName eq 'Alice'", true},
		{"DISPLAYNAME eq 'Alice'", true},
		{"displayname ne 'Alice'", false},
		{"DisplayName eq 'ALICE'", false}, // the literal is a value: case-sensitive
		{"ACCOUNTENABLED eq true", true},
		{"MAIL eq null", true},
		{"STARTSWITH(displayName,'Al')", false}, // function names are not folded here
		{"startswith(DISPLAYNAME,'Al')", true},
		{"endswith(DisplayName,'ce')", true},
	} {
		pred, err := parseFilter(tc.expr)
		if err != nil {
			if tc.want {
				t.Errorf("%s: %v", tc.expr, err)
			}
			continue
		}
		if got := pred(shape); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestGrantFilterFieldNameIsCaseInsensitiveAndItsLiteralIsNot(t *testing.T) {
	if v, ok := grantFilterField("CLIENTID eq 'AbC'", "clientId"); !ok || v != "AbC" {
		t.Errorf("got %q %v, want the literal exactly as written", v, ok)
	}
	if _, ok := grantFilterField("consentType eq 'x'", "clientId"); ok {
		t.Error("a different property must not match")
	}
}
