package service

import (
	"context"
	"testing"
	"time"

	"github.com/wyw14/solo-039/internal/release"
)

func newTestPlant(t *testing.T) *Plant {
	t.Helper()
	return NewPlant(t.TempDir())
}

func routeProductForTest(t *testing.T, plant *Plant, target string) {
	t.Helper()
	base := time.Now().Unix()
	for i, value := range []float64{0.95, 0.96, 0.97} {
		if _, err := plant.AddSample(value, base+int64(i)*10); err != nil {
			t.Fatalf("sample %d rejected: %v", i, err)
		}
	}
	if err := plant.RouteProduct(target); err != nil {
		t.Fatalf("route product: %v", err)
	}
}

// Before routing, a reviewer assembling the package must see the missing feed
// context is bound but analyzer, interlock, product and durable sections are
// flagged — the package still seals and verifies as held.
func TestReleasePackageBeforeRoutingIsHeldWithMissingSections(t *testing.T) {
	plant := newTestPlant(t)
	if _, err := plant.Start(context.Background(), "polymer-grade", "tank-A"); err != nil {
		t.Fatal(err)
	}

	pkg, err := plant.AssembleReleasePackage("CAN-2026-0001", "customer review")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Decision != release.Held {
		t.Fatalf("decision = %q, want held", pkg.Decision)
	}
	for _, name := range []string{release.SectionAnalyzer, release.SectionInterlock, release.SectionProduct, release.SectionDurable} {
		if pkg.Sections[name].Status != release.StatusMissing {
			t.Fatalf("section %s = %s, want missing", name, pkg.Sections[name].Status)
		}
	}
	if pkg.Sections[release.SectionFeed].Status != release.StatusPresent {
		t.Fatal("feed section should be present after start")
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("held package failed verification: %v", err)
	}
}

// After routing, the package binds all five categories and releases; all
// subsequent versions verify and the original delivery is preserved.
func TestReleasePackageLifecycleAfterRouting(t *testing.T) {
	plant := newTestPlant(t)
	ctx := context.Background()
	if _, err := plant.Start(ctx, "polymer-grade", "tank-A"); err != nil {
		t.Fatal(err)
	}
	routeProductForTest(t, plant, "can-line-3")

	v1, err := plant.AssembleReleasePackage("CAN-2026-0007", "")
	if err != nil {
		t.Fatal(err)
	}
	if v1.Decision != release.Released || !v1.Complete() {
		t.Fatalf("v1 decision = %q missing = %v", v1.Decision, v1.MissingItems())
	}
	for _, name := range release.Sections() {
		if v1.Sections[name].Status != release.StatusPresent {
			t.Fatalf("section %s is not present: %s", name, v1.Sections[name].Reason)
		}
	}
	if err := v1.Verify(); err != nil {
		t.Fatalf("v1 failed verification: %v", err)
	}
	if target := v1.Sections[release.SectionProduct].Detail["target"]; target != "can-line-3" {
		t.Fatalf("product target = %v", target)
	}
	if allowed := v1.Sections[release.SectionInterlock].Detail["allowed"]; allowed != true {
		t.Fatalf("interlock allowed = %v", allowed)
	}

	// Resupplementation issues v2 and leaves v1 intact.
	v2, err := plant.ResupplementRelease("supporting documents reattached")
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 || v2.Supersedes != v1.ID {
		t.Fatalf("v2 = version %d supersedes %s", v2.Version, v2.Supersedes)
	}
	if err := v2.Verify(); err != nil {
		t.Fatalf("v2 failed verification: %v", err)
	}

	// Revocation issues v3; the old delivery keeps its seal and conclusion.
	v3, err := plant.RevokeRelease("calibration certificate withdrawn")
	if err != nil {
		t.Fatal(err)
	}
	if v3.Decision != release.Revoked {
		t.Fatalf("v3 decision = %q", v3.Decision)
	}
	old, err := plant.ReleasePackage(1)
	if err != nil {
		t.Fatal(err)
	}
	if old.Decision != release.Released || !old.Revoked {
		t.Fatalf("old delivery mutated: decision %q revoked %t", old.Decision, old.Revoked)
	}
	if err := old.Verify(); err != nil {
		t.Fatalf("revoked delivery must still verify its original conclusion: %v", err)
	}
	if history := plant.ReleasePackages(); len(history) != 3 {
		t.Fatalf("history length = %d, want 3", len(history))
	}
}

func TestAssembleRequiresCanID(t *testing.T) {
	plant := newTestPlant(t)
	if _, err := plant.Start(context.Background(), "polymer-grade", "tank-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := plant.AssembleReleasePackage("  ", ""); err == nil {
		t.Fatal("expected error when can id is blank")
	}
}

func TestResupplementWithoutPackageFails(t *testing.T) {
	plant := newTestPlant(t)
	if _, err := plant.ResupplementRelease("late proof"); err == nil {
		t.Fatal("resupplementation requires an existing package")
	}
}

func TestRevokeWithoutPackageFails(t *testing.T) {
	plant := newTestPlant(t)
	if _, err := plant.RevokeRelease("reason"); err == nil {
		t.Fatal("revocation requires an existing package")
	}
}
