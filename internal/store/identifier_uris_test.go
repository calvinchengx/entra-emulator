package store

import (
	"errors"
	"slices"
	"testing"
)

func TestSetIdentifierURIs(t *testing.T) {
	a := &App{}
	a.SetIdentifierURIs([]string{"", "api://one", "https://two", "api://one"})
	if a.AppIDURI != "api://one" || !slices.Equal(a.AdditionalIdentifierURIs, []string{"https://two"}) {
		t.Fatalf("split: primary %q additional %v", a.AppIDURI, a.AdditionalIdentifierURIs)
	}
	if got := a.IdentifierURIs(); !slices.Equal(got, []string{"api://one", "https://two"}) {
		t.Fatalf("IdentifierURIs: %v", got)
	}
	a.SetIdentifierURIs(nil)
	if a.AppIDURI != "" || a.AdditionalIdentifierURIs != nil || len(a.IdentifierURIs()) != 0 {
		t.Fatalf("clear: %+v", a)
	}
}

// TestMultipleIdentifierURIs proves every identifier URI resolves the app,
// stays unique across apps, and survives the recycle bin and export/import.
func TestMultipleIdentifierURIs(t *testing.T) {
	st := newTestStore(t)
	app := &App{ID: NewGUID(), TenantID: testTenantID, DisplayName: "Multi", CreatedAt: 1}
	app.SetIdentifierURIs([]string{"api://multi", "https://multi.example.com", "https://alt.example.com"})
	if err := st.CreateApp(app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	lookup := func(label string) {
		t.Helper()
		for _, uri := range app.IdentifierURIs() {
			got, err := st.GetAppByIDURI(uri)
			if err != nil || got.ID != app.ID {
				t.Fatalf("%s: GetAppByIDURI(%q): %v %+v", label, uri, err, got)
			}
			if !slices.Equal(got.IdentifierURIs(), app.IdentifierURIs()) {
				t.Fatalf("%s: round trip: %v", label, got.IdentifierURIs())
			}
		}
	}
	lookup("created")

	// Any URI already held by another app conflicts, primary or additional.
	for _, uri := range []string{"api://multi", "https://alt.example.com"} {
		other := &App{ID: NewGUID(), TenantID: testTenantID, DisplayName: "Other", CreatedAt: 1}
		other.SetIdentifierURIs([]string{"api://other", uri})
		if err := st.CreateApp(other); !errors.Is(err, ErrConflict) {
			t.Fatalf("CreateApp claiming %q: want ErrConflict, got %v", uri, err)
		}
	}

	// Recycle bin round trip.
	if err := st.SoftDeleteApp(app.ID); err != nil {
		t.Fatalf("SoftDeleteApp: %v", err)
	}
	if _, err := st.GetAppByIDURI("https://alt.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted app still resolves: %v", err)
	}
	if _, err := st.RestoreDeletedItem(app.ID); err != nil {
		t.Fatalf("RestoreDeletedItem: %v", err)
	}
	lookup("restored")

	// Export/import round trip.
	snap, err := st.ExportDirectory()
	if err != nil {
		t.Fatalf("ExportDirectory: %v", err)
	}
	if err := st.ImportDirectory(snap, testTenantID); err != nil {
		t.Fatalf("ImportDirectory: %v", err)
	}
	lookup("imported")

	// Updating to fewer URIs releases the dropped ones.
	app.SetIdentifierURIs([]string{"https://multi.example.com"})
	if err := st.UpdateApp(app); err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	if _, err := st.GetAppByIDURI("https://alt.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dropped URI still resolves: %v", err)
	}
	lookup("updated")
}
