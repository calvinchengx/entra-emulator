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
		if attr != "username" {
			scimErr(w, http.StatusBadRequest, "Only 'userName eq' filters are supported.")
			return
		}
		if u, err := s.Store.GetUserByUPN(value); err == nil {
			users = []*store.User{u}
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
	resources := make([]any, 0)
	for _, u := range users[start:page] {
		resources = append(resources, userResource(u, b))
	}
	writeSCIM(w, http.StatusOK, withTotal(listResponse(resources, start+1), len(users)))
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
	writeSCIM(w, http.StatusCreated, userResource(u, base(r)))
}

func (s *Service) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, userResource(u, base(r)))
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
	writeSCIM(w, http.StatusOK, userResource(u, base(r)))
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
	for _, op := range ops {
		applyUserOp(u, op)
	}
	if err := s.Store.UpdateUser(u); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, userResource(u, base(r)))
}

func (s *Service) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteUser(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Groups ----

type groupBody struct {
	DisplayName string `json:"displayName"`
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
	if attr, value, ok := filterEq(q.Get("filter")); ok && attr == "displayname" {
		filtered := all[:0]
		for _, g := range all {
			if g.DisplayName == value {
				filtered = append(filtered, g)
			}
		}
		all = filtered
	}
	start, page := paginate(q, len(all))
	b := base(r)
	resources := make([]any, 0)
	for _, g := range all[start:page] {
		members, _ := s.Store.ListGroupMembers(g.ID)
		resources = append(resources, groupResource(g, members, b))
	}
	writeSCIM(w, http.StatusOK, withTotal(listResponse(resources, start+1), len(all)))
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
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeSCIM(w, http.StatusCreated, groupResource(g, members, base(r)))
}

func (s *Service) getGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeSCIM(w, http.StatusOK, groupResource(g, members, base(r)))
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
	for _, op := range ops {
		s.applyGroupOp(g, op)
	}
	if err := s.Store.UpdateGroup(g); err != nil {
		writeStoreErr(w, err)
		return
	}
	members, _ := s.Store.ListGroupMembers(g.ID)
	writeSCIM(w, http.StatusOK, groupResource(g, members, base(r)))
}

func (s *Service) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteGroup(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
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

// applyUserOp handles the common Entra user patches: replace active / displayName
// / name.* / userName, either pathed or as a no-path object of attributes.
func applyUserOp(u *store.User, op patchOp) {
	if strings.EqualFold(op.Op, "remove") {
		return
	}
	if op.Path == "" {
		// No-path replace: value is an object of attributes.
		var attrs map[string]json.RawMessage
		if json.Unmarshal(op.Value, &attrs) == nil {
			for k, v := range attrs {
				setUserAttr(u, k, v)
			}
		}
		return
	}
	setUserAttr(u, op.Path, op.Value)
}

func setUserAttr(u *store.User, path string, raw json.RawMessage) {
	switch strings.ToLower(path) {
	case "active":
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			u.AccountEnabled = b
		}
	case "displayname":
		u.DisplayName = asString(raw)
	case "username":
		u.UserPrincipalName = asString(raw)
	case "name.givenname":
		u.GivenName = asString(raw)
	case "name.familyname":
		u.Surname = asString(raw)
	}
}

var memberPathRe = regexp.MustCompile(`members\[value eq "([^"]+)"\]`)

// applyGroupOp handles displayName replace and members add/remove.
func (s *Service) applyGroupOp(g *store.Group, op patchOp) {
	// Rename.
	if strings.EqualFold(op.Path, "displayName") {
		g.DisplayName = asString(op.Value)
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
