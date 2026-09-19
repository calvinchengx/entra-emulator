package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingFront puts the recorder in front of the real handler stack, which is
// where Listen puts it: outermost, seeing the request as the client sent it.
// Returns the front's URL and the path the recording is written to.
func recordingFront(t *testing.T, upstream string) (front string, file string) {
	t.Helper()
	file = filepath.Join(t.TempDir(), "responses.jsonl")
	rec := newRecorder(file)
	if rec == nil {
		t.Fatal("recorder was not created")
	}
	t.Cleanup(func() { _ = rec.Close() }) // Windows cannot delete an open file
	target, _ := url.Parse(upstream)
	hts := httptest.NewServer(record(rec, httputil.NewSingleHostReverseProxy(target)))
	t.Cleanup(hts.Close)
	return hts.URL, file
}

func readRecording(t *testing.T, file string) []recorded {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []recorded
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
	for sc.Scan() {
		var r recorded
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("a recording line is not JSON: %v: %s", err, sc.Text())
		}
		out = append(out, r)
	}
	return out
}

func TestRecorderCapturesGraphResponsesFromTheRealStack(t *testing.T) {
	hts, _, _ := newTestServer(t)
	access := driveAuthCode(t, hts, "verifier-for-the-recorder-0123456789abcdef")["access_token"].(string)
	front, file := recordingFront(t, hts.URL)

	get := func(path, bearer string) int {
		req, _ := http.NewRequest("GET", front+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("/graph/v1.0/me", access); got != 200 {
		t.Fatalf("/me = %d", got)
	}
	get("/graph/v1.0/users?$top=1&$select=id", access)
	if got := get("/graph/v1.0/me", ""); got != 401 {
		t.Fatalf("unauthenticated /me = %d", got)
	}
	// Neither of these is Graph: the admin API is the emulator's own, and
	// userinfo is OIDC. Recording them would bury the routes the spec covers.
	get("/graph/oidc/userinfo", access)
	get("/admin/api/apps", "")

	got := readRecording(t, file)
	if len(got) != 3 {
		t.Fatalf("want exactly the three Graph responses, got %d: %+v", len(got), got)
	}

	me := got[0]
	if me.Method != "GET" || me.Status != 200 {
		t.Errorf("first entry = %+v", me)
	}
	// The compat-mode prefix must be gone, or every recorded path reads to the
	// checker as a route the spec does not document.
	if me.Path != "/v1.0/me" {
		t.Errorf("path = %q, want it normalised to the spec's spelling /v1.0/me", me.Path)
	}
	var body map[string]any
	if err := json.Unmarshal(me.Body, &body); err != nil || body["userPrincipalName"] != "alice@entraemulator.dev" {
		t.Errorf("the body was not captured intact: %s (%v)", me.Body, err)
	}

	if got[1].Query != "$top=1&$select=id" {
		t.Errorf("query = %q, want it kept: $select changes which properties are present", got[1].Query)
	}

	if got[2].Status != 401 || !strings.Contains(string(got[2].Body), "InvalidAuthenticationToken") {
		t.Errorf("an error response must be recorded with its envelope: %+v", got[2])
	}
}

// The recording is written to a file CI may upload as an artifact, so a bearer
// token in it would be published. This reads the whole file as text rather than
// checking fields, because the failure that matters is a token turning up
// anywhere.
func TestRecordingNeverContainsACredential(t *testing.T) {
	hts, _, _ := newTestServer(t)
	access := driveAuthCode(t, hts, "verifier-for-credential-leak-0123456789ab")["access_token"].(string)
	front, file := recordingFront(t, hts.URL)

	req, _ := http.NewRequest("GET", front+"/graph/v1.0/me", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	raw, err := os.ReadFile(file)
	if err != nil || len(raw) == 0 {
		t.Fatalf("nothing was recorded, so this proves nothing: %v", err)
	}
	for _, needle := range []string{access, "Bearer", "Authorization", "authorization"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("the recording contains %q", needle)
		}
	}
}

func TestGraphPathNormalisesBothSpellings(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"/v1.0/users", "/v1.0/users", true},       // Graph on its own origin
		{"/graph/v1.0/users", "/v1.0/users", true}, // compat mode
		{"/graph/v1.0/users/abc/memberOf", "/v1.0/users/abc/memberOf", true},
		{"/graph/oidc/userinfo", "", false}, // OIDC, not in the spec
		{"/oidc/userinfo", "", false},
		{"/admin/api/apps", "", false},
		{"/beta/users", "", false}, // not served, not vendored
		{"/graph/beta/users", "", false},
		{"/v1.0", "", false}, // the bare prefix is not a route
	} {
		got, ok := graphPath(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("graphPath(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRecorderFailsOpenAndLoud(t *testing.T) {
	// An unwritable path must not stop the emulator, or a typo in a CI variable
	// becomes a broken stack. It returns nil, and the handler chain is untouched.
	if rec := newRecorder(filepath.Join(t.TempDir(), "no-such-dir", "r.jsonl")); rec != nil {
		t.Fatal("an unopenable path must yield no recorder")
	}
	if rec := newRecorder(""); rec != nil {
		t.Fatal("no path must yield no recorder")
	}
	h := http.NotFoundHandler()
	if got := record(nil, h); got == nil {
		t.Fatal("record(nil, h) must return a usable handler")
	}
}
