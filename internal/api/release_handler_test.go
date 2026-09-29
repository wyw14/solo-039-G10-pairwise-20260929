package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func doJSON(t *testing.T, handler http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s %s: %v body=%s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func routedServer(t *testing.T) http.Handler {
	t.Helper()
	server := NewServerWithData(t.TempDir())
	plant := server.plant
	if _, err := plant.Start(context.Background(), "polymer-grade", "tank-A"); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Unix()
	for i, value := range []float64{0.95, 0.96, 0.97} {
		if _, err := plant.AddSample(value, base+int64(i)*10); err != nil {
			t.Fatal(err)
		}
	}
	if err := plant.RouteProduct("can-line-3"); err != nil {
		t.Fatal(err)
	}
	return server.Handler()
}

func TestReleaseEndpointsAssembleFetchVerifyHistory(t *testing.T) {
	handler := routedServer(t)

	status, out := doJSON(t, handler, http.MethodPost, "/api/release/packages", `{"can_id":"CAN-2026-0007","note":"customer review"}`)
	if status != http.StatusCreated {
		t.Fatalf("assemble status = %d body = %v", status, out)
	}
	pkg := out["package"].(map[string]any)
	if pkg["decision"] != "released" {
		t.Fatalf("decision = %v", pkg["decision"])
	}
	verification := out["verification"].(map[string]any)
	if verification["valid"] != true {
		t.Fatalf("verification = %v", verification)
	}
	id := pkg["id"].(string)

	// Fetch by version, by id, and as latest: all must verify.
	for _, path := range []string{"/api/release/packages/versions/1", "/api/release/packages/latest", "/api/release/packages/" + id} {
		status, fetched := doJSON(t, handler, http.MethodGet, path, "")
		if status != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, status)
		}
		if fetched["verification"].(map[string]any)["valid"] != true {
			t.Fatalf("GET %s failed verification", path)
		}
	}

	// Resupplement issues v2; history shows both versions.
	status, out = doJSON(t, handler, http.MethodPost, "/api/release/resupplement", `{"note":"documents attached"}`)
	if status != http.StatusCreated {
		t.Fatalf("resupplement status = %d body = %v", status, out)
	}
	if out["package"].(map[string]any)["version"].(float64) != 2 {
		t.Fatal("resupplement did not issue version 2")
	}
	status, out = doJSON(t, handler, http.MethodGet, "/api/release/packages", "")
	if status != http.StatusOK || out["count"].(float64) != 2 {
		t.Fatalf("history = %v", out)
	}

	// Revoke issues v3; the delivered v1 still verifies.
	status, out = doJSON(t, handler, http.MethodPost, "/api/release/revoke", `{"reason":"certificate withdrawn"}`)
	if status != http.StatusCreated {
		t.Fatalf("revoke status = %d body = %v", status, out)
	}
	if out["package"].(map[string]any)["decision"] != "revoked" {
		t.Fatal("revoke did not issue a revoked package")
	}
	status, out = doJSON(t, handler, http.MethodGet, "/api/release/packages/versions/1", "")
	if status != http.StatusOK || out["verification"].(map[string]any)["valid"] != true {
		t.Fatalf("old delivery no longer verifies after revoke: %v", out)
	}
	pkgV1 := out["package"].(map[string]any)
	if pkgV1["decision"] != "released" || pkgV1["revoked"] != true {
		t.Fatalf("v1 should stay released but flagged revoked, got decision %v revoked %v", pkgV1["decision"], pkgV1["revoked"])
	}
}

func TestReleaseAssembleRejectsBlankCan(t *testing.T) {
	handler := routedServer(t)
	status, out := doJSON(t, handler, http.MethodPost, "/api/release/packages", `{"can_id":"  "}`)
	if status != http.StatusConflict {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(out["error"].(string), "can id") {
		t.Fatalf("error = %v", out["error"])
	}
}

func TestReleaseLatestNotFound(t *testing.T) {
	server := NewServerWithData(t.TempDir())
	status, _ := doJSON(t, server.Handler(), http.MethodGet, "/api/release/packages/latest", "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}
