package api

import (
	"context"
	"encoding/json"
	"github.com/wyw14/solo-039/internal/service"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func routedServer(t *testing.T) (*Server, string) {
	t.Helper()
	plant := service.NewPlant(t.TempDir())
	if _, err := plant.Start(context.Background(), "polymer-a", "primary"); err != nil {
		t.Fatalf("start: %v", err)
	}
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if _, err := plant.AddSample(0.50, now+int64(i)); err != nil {
			t.Fatalf("sample: %v", err)
		}
	}
	if err := plant.RouteProduct("tank-7"); err != nil {
		t.Fatalf("route: %v", err)
	}
	return NewServerWith(plant), plant.Campaign.Snapshot().Revision.String()
}

func doJSON(t *testing.T, h http.Handler, method, target, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v: %s", target, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestReleaseLifecycleEndpoints(t *testing.T) {
	server, revision := routedServer(t)
	handler := server.Handler()

	code, issue := doJSON(t, handler, http.MethodPost, "/api/releases/issue", `{"revision":"`+revision+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("issue status %d: %v", code, issue)
	}
	if issue["verifies"] != true {
		t.Fatalf("issued package does not verify: %v", issue)
	}
	packageMap := issue["package"].(map[string]any)
	if packageMap["digest"] == "" {
		t.Fatal("package was not sealed")
	}

	code, list := doJSON(t, handler, http.MethodGet, "/api/releases?revision="+revision, "")
	if code != http.StatusOK {
		t.Fatalf("list status %d", code)
	}
	versions := list["versions"].([]any)
	if len(versions) != 1 {
		t.Fatalf("expected one version, got %d", len(versions))
	}

	// A duplicate issue is rejected; supplement/revoke create new versions.
	if code, duplicate := doJSON(t, handler, http.MethodPost, "/api/releases/issue", `{}`); code != http.StatusConflict {
		t.Fatalf("duplicate issue should conflict, got %d %v", code, duplicate)
	}
	code, revoke := doJSON(t, handler, http.MethodPost, "/api/releases/revoke", `{"reason":"customer objection"}`)
	if code != http.StatusCreated || revoke == nil {
		t.Fatalf("revoke status %d: %v", code, revoke)
	}

	code, history := doJSON(t, handler, http.MethodGet, "/api/releases?revision="+revision, "")
	if code != http.StatusOK {
		t.Fatalf("history status %d", code)
	}
	if len(history["versions"].([]any)) != 2 {
		t.Fatal("revocation must append, not overwrite, a version")
	}
}

func TestSparseIssueFlagsMissingSections(t *testing.T) {
	plant := service.NewPlant(t.TempDir())
	if _, err := plant.Start(context.Background(), "polymer-a", "primary"); err != nil {
		t.Fatalf("start: %v", err)
	}
	server := NewServerWith(plant)
	code, body := doJSON(t, server.Handler(), http.MethodPost, "/api/releases/issue", `{}`)
	if code != http.StatusCreated {
		t.Fatalf("status %d: %v", code, body)
	}
	missing := body["missing"].([]any)
	if len(missing) == 0 {
		t.Fatal("package before routing must list missing sections")
	}
	if body["verifies"] != true {
		t.Fatal("an honestly-incomplete package should still verify its gaps")
	}
}

func TestRevokeRequiresReason(t *testing.T) {
	server, revision := routedServer(t)
	if code, _ := doJSON(t, server.Handler(), http.MethodPost, "/api/releases/issue", `{}`); code != http.StatusCreated {
		t.Fatalf("issue: %d", code)
	}
	if code, body := doJSON(t, server.Handler(), http.MethodPost, "/api/releases/revoke", `{"revision":"`+revision+`"}`); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reasonless revoke, got %d: %v", code, body)
	}
}
