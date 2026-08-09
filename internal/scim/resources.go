package scim

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// ---- Users ----

func (s *Service) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var users []*store.User
	if attr, value, ok := filterEq(q.Get("filter")); ok {
		switch attr {
		case "username":
			if u, err := s.Store.GetUserByUPN(value); err == nil {
				users = []*store.User{u}
			}
		case "externalid":
			// Entra correlates by externalId on re-sync, so a provisioning
			// client that lost its local mapping must be able to look one up.
			if id, ok := s.Store.FindByExternalID("User", value); ok {
				if u, err := s.Store.GetUser(id); err == nil {
					users = []*store.User{u}
				}
			}
		default:
			scimErr(w, http.StatusBadRequest, "Only 'userName eq' and 'externalId eq' filters are supported.")
			return
		}
	} else {
		all, _, err := s.Store.ListUsers(allRows, 0, "")
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		users = all
	}
	start, page := paginate(q, len(users))
	b := base(r)
	ext := s.Store.ExternalIDs("User")
	resources := make([]any, 0)
	for _, u := range users[start:page] {
		resources = append(resources, userResource(u, b, ext[u.ID]))
	}
	inc, exc := projectionFrom(r)
	writeSCIM(w, http.StatusOK,
		withTotal(listResponse(projectAll(resources, inc, exc), start+1), len(users)))
}

func (s *Service) createUser(w http.ResponseWriter, r *http.Request) {
	var body userBody
	if !decode(w, r, &body) {
		return
	}
	if body.UserName == "" {
		scimErr(w, http.StatusBadRequest, "userName is required.")
		return
	}
	u := &store.User{ID: store.NewGUID(), TenantID: s.TenantID, AccountEnabled: true, CreatedAt: s.Store.Now()}
	body.applyTo(u)
	if body.Password != "" {
		hash, err := store.HashSecret(body.Password)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		u.PasswordHash = hash
	}
	if err := s.Store.CreateUser(u); err != nil {
		writeStoreErr(w, err)
		return
	}
	if body.ExternalID != "" {
		_ = s.Store.SetExternalID("User", u.ID, body.ExternalID)
	}
	writeResource(w, r, http.StatusCreated, userResource(u, base(r), body.ExternalID))
}

func (s *Service) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeResource(w, r, http.StatusOK,
		userResource(u, base(r), s.Store.ExternalID("User", u.ID)))
}

func (s *Service) replaceUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var body userBody
	if !decode(w, r, &body) {
		return
	}
	body.applyTo(u)
	if err := s.Store.UpdateUser(u); err != nil {
		writeStoreErr(w, err)
		return
	}
	// PUT replaces the resource wholesale, so an absent externalId clears it.
	_ = s.Store.SetExternalID("User", u.ID, body.ExternalID)
	writeResource(w, r, http.StatusOK, userResource(u, base(r), body.ExternalID))
}

func (s *Service) patchUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	ops, ok := decodePatch(w, r)
	if !ok {
		return
	}
	ext := s.Store.ExternalID("User", u.ID)
	for _, op := range ops {
		applyUserOp(u, op, &ext)
	}
	if err := s.Store.UpdateUser(u); err != nil {
		writeStoreErr(w, err)
		return
	}
	_ = s.Store.SetExternalID("User", u.ID, ext)
	writeResource(w, r, http.StatusOK, userResource(u, base(r), ext))
}

func (s *Service) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteUser(id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.Store.DeleteExternalID("User", id)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Groups ----

type groupBody struct {
	DisplayName string `json:"displayName"`
	ExternalID  string `json:"externalId"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (s *Service) listGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	all, _, err := s.Store.ListGroups(allRows, 0, "")
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if attr, value, ok := filterEq(q.Get("filter")); ok {
		filtered := all[:0]
		for _, g := range all {
			switch attr {
			case "displayname":
				if g.DisplayName == value {
					filtered = append(filtered, g)
				}
			case "externalid":
				if s.Store.ExternalID("Group", g.ID) == value {
					filtered = append(filtered, g)
				}
			}
		}
		all = filtered
	}
	start, page := paginate(q, len(all))
	b := base(r)
	ext := s.Store.ExternalIDs("Group")
	resources := make([]any, 0)
	for _, g := range all[start:page] {
		members, _ := s.Store.ListGroupMembers(g.ID)
		resources = append(resources, groupResource(g, members, b, ext[g.ID]))
	}
	inc, exc := projectionFrom(r)
	writeSCIM(w, http.StatusOK,
		withTotal(listResponse(projectAll(resources, inc, exc), start+1), len(all)))
}

func (s *Service) createGroup(w http.ResponseWriter, r *http.Request) {
	var body groupBody
	if !decode(w, r, &body) {
		return
	}
	if body.DisplayName == "" {
		scimErr(w, http.StatusBadRequest, "displayName is required.")
		return
	}
	g := &store.Group{ID: store.NewGUID(), TenantID: s.TenantID, DisplayName: body.DisplayName, CreatedAt: s.Store.Now()}
	if err := s.Store.CreateGroup(g); err != nil {
		writeStoreErr(w, err)
		return
	}
	for _, m := range body.Members {
		_ = s.Store.AddGroupMember(g.ID, m.Value)
	}
	if body.ExternalID != "" {
		_ = s.Store.SetExternalID("Group", g.ID, body.ExternalID)
	}
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeResource(w, r, http.StatusCreated, groupResource(g, members, base(r), body.ExternalID))
}

func (s *Service) getGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeResource(w, r, http.StatusOK,
		groupResource(g, members, base(r), s.Store.ExternalID("Group", g.ID)))
}

// replaceGroup implements PUT /Groups/{id} (RFC 7644 §3.5.1): the resource is
// replaced wholesale — displayName is overwritten and membership becomes exactly
// the submitted set, so members absent from the body are removed.
func (s *Service) replaceGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var body groupBody
	if !decode(w, r, &body) {
		return
	}
	if body.DisplayName == "" {
		scimErr(w, http.StatusBadRequest, "displayName is required.")
		return
	}
	g.DisplayName = body.DisplayName
	if err := s.Store.UpdateGroup(g); err != nil {
		writeStoreErr(w, err)
		return
	}

	// Reconcile membership to exactly what the body carries.
	want := make(map[string]bool, len(body.Members))
	for _, m := range body.Members {
		if m.Value != "" {
			want[m.Value] = true
		}
	}
	current, _ := s.Store.ListGroupMembers(g.ID)
	have := make(map[string]bool, len(current))
	for _, u := range current {
		have[u.ID] = true
		if !want[u.ID] {
			_ = s.Store.RemoveGroupMember(g.ID, u.ID)
		}
	}
	for _, m := range body.Members {
		if m.Value != "" && !have[m.Value] {
			_ = s.Store.AddGroupMember(g.ID, m.Value)
		}
	}

	_ = s.Store.SetExternalID("Group", g.ID, body.ExternalID)
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeResource(w, r, http.StatusOK, groupResource(g, members, base(r), body.ExternalID))
}

func (s *Service) patchGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	ops, ok := decodePatch(w, r)
	if !ok {
		return
	}
	ext := s.Store.ExternalID("Group", g.ID)
	for _, op := range ops {
		s.applyGroupOp(g, op, &ext)
	}
	if err := s.Store.UpdateGroup(g); err != nil {
		writeStoreErr(w, err)
		return
	}
	_ = s.Store.SetExternalID("Group", g.ID, ext)
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeResource(w, r, http.StatusOK, groupResource(g, members, base(r), ext))
}

func (s *Service) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteGroup(id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.Store.DeleteExternalID("Group", id)
	w.WriteHeader(http.StatusNoContent)
}

// ---- PatchOp ----

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func decodePatch(w http.ResponseWriter, r *http.Request) ([]patchOp, bool) {
	var body struct {
		Operations []patchOp `json:"Operations"`
	}
	if !decode(w, r, &body) {
		return nil, false
	}
	return body.Operations, true
}

// applyUserOp applies one PatchOp (RFC 7644 §3.5.2) to a user. add and replace
// both write the value; remove clears the attribute named by the path.
//
// Previously remove was a no-op and only five paths were writable, so a client
// that patched name, emails or externalId got 200 OK and no change — the worst
// kind of failure, because it looks like success.
func applyUserOp(u *store.User, op patchOp, ext *string) {
	remove := strings.EqualFold(op.Op, "remove")
	if op.Path == "" {
		// RFC 7644 §3.5.2.2: remove requires a path. A no-path value is an
		// object of attributes to write.
		if remove {
			return
		}
		var attrs map[string]json.RawMessage
		if json.Unmarshal(op.Value, &attrs) == nil {
			for k, v := range attrs {
				setUserAttr(u, k, v, ext, false)
			}
		}
		return
	}
	setUserAttr(u, op.Path, op.Value, ext, remove)
}

// nameBody is the complex "name" attribute as a whole-object patch target.
type nameBody struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

// emailBody mirrors the multi-valued "emails" attribute.
type emailBody struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

func setUserAttr(u *store.User, path string, raw json.RawMessage, ext *string, remove bool) {
	// Multi-valued paths arrive as emails[type eq "work"].value; the emulator
	// keeps a single mail, so the sub-path collapses onto it.
	lower := strings.ToLower(path)
	if i := strings.Index(lower, "["); i >= 0 {
		lower = lower[:i]
	}
	switch lower {
	case "active":
		// accountEnabled is non-nullable in the directory, exactly as it is in
		// Entra, so remove resets it to the default rather than unsetting it.
		if remove {
			u.AccountEnabled = true
			return
		}
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			u.AccountEnabled = b
		}
	case "displayname":
		u.DisplayName = valueOrEmpty(raw, remove)
	case "username":
		if !remove { // userName is required; removing it would orphan the user
			u.UserPrincipalName = asString(raw)
		}
	case "externalid":
		*ext = valueOrEmpty(raw, remove)
	case "name":
		if remove {
			u.GivenName, u.Surname = "", ""
			return
		}
		var n nameBody
		if json.Unmarshal(raw, &n) == nil {
			u.GivenName, u.Surname = n.GivenName, n.FamilyName
		}
	case "name.givenname":
		u.GivenName = valueOrEmpty(raw, remove)
	case "name.familyname":
		u.Surname = valueOrEmpty(raw, remove)
	case "emails":
		if remove {
			u.Mail = ""
			return
		}
		u.Mail = firstEmail(raw)
	}
}

// valueOrEmpty returns "" for a remove, else the decoded string.
func valueOrEmpty(raw json.RawMessage, remove bool) string {
	if remove {
		return ""
	}
	return asString(raw)
}

// firstEmail accepts either the array form or a bare string (the sub-path
// emails[...].value case), preferring the primary entry.
func firstEmail(raw json.RawMessage) string {
	var list []emailBody
	if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
		for _, e := range list {
			if e.Primary && e.Value != "" {
				return e.Value
			}
		}
		return list[0].Value
	}
	return asString(raw)
}

var memberPathRe = regexp.MustCompile(`members\[value eq "([^"]+)"\]`)

// applyGroupOp handles displayName / externalId replace and members add/remove.
func (s *Service) applyGroupOp(g *store.Group, op patchOp, ext *string) {
	remove := strings.EqualFold(op.Op, "remove")
	// Rename.
	if strings.EqualFold(op.Path, "displayName") {
		if !remove { // displayName is required on a Group
			g.DisplayName = asString(op.Value)
		}
		return
	}
	if strings.EqualFold(op.Path, "externalId") {
		*ext = valueOrEmpty(op.Value, remove)
		return
	}
	// Remove by path filter: members[value eq "id"].
	if m := memberPathRe.FindStringSubmatch(op.Path); m != nil {
		_ = s.Store.RemoveGroupMember(g.ID, m[1])
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.SplitN(op.Path, "[", 2)[0]), "members") && op.Path != "" {
		return
	}
	// members value is an array of {value:id}.
	var members []struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(op.Value, &members) != nil {
		// `remove` on the whole members attribute carries no value and clears
		// the membership; without this the op silently did nothing.
		if remove {
			if current, err := s.Store.ListGroupMembers(g.ID); err == nil {
				for _, u := range current {
					_ = s.Store.RemoveGroupMember(g.ID, u.ID)
				}
			}
		}
		return
	}
	if remove && len(members) == 0 {
		if current, err := s.Store.ListGroupMembers(g.ID); err == nil {
			for _, u := range current {
				_ = s.Store.RemoveGroupMember(g.ID, u.ID)
			}
		}
		return
	}
	for _, m := range members {
		if strings.EqualFold(op.Op, "remove") {
			_ = s.Store.RemoveGroupMember(g.ID, m.Value)
		} else {
			_ = s.Store.AddGroupMember(g.ID, m.Value)
		}
	}
}

func asString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// ---- shared ----

// paginate returns the [start, end) slice bounds from SCIM startIndex/count.
func paginate(q map[string][]string, total int) (start, end int) {
	startIndex := 1
	if v := first(q, "startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			startIndex = n
		}
	}
	count := 100
	if v := first(q, "count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			count = n
		}
	}
	start = startIndex - 1
	if start > total {
		start = total
	}
	end = start + count
	if end > total {
		end = total
	}
	return start, end
}

func first(q map[string][]string, key string) string {
	if v := q[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// withTotal overrides totalResults with the full (pre-pagination) count.
func withTotal(list map[string]any, total int) map[string]any {
	list["totalResults"] = total
	return list
}
