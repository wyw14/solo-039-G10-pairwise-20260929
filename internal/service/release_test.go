package service

import (
	"context"
	"github.com/wyw14/solo-039/internal/model"
	"github.com/wyw14/solo-039/internal/release"
	"testing"
	"time"
)

func routedPlant(t *testing.T) *Plant {
	t.Helper()
	plant := NewPlant(t.TempDir())
	ctx := context.Background()
	if _, err := plant.Start(ctx, "polymer-a", "primary"); err != nil {
		t.Fatalf("start: %v", err)
	}
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if _, err := plant.AddSample(0.50, now+int64(i)); err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
	}
	if err := plant.RouteProduct("tank-7"); err != nil {
		t.Fatalf("route: %v", err)
	}
	return plant
}

func TestIssueReleaseAfterRoutingGathersEverySection(t *testing.T) {
	plant := routedPlant(t)
	revision := plant.Campaign.Snapshot().Revision.String()

	pkg, err := plant.IssueRelease(revision)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pkg.Conclusion.Release != release.ReleaseReleased {
		t.Fatalf("expected released, got %s: %s", pkg.Conclusion.Release, pkg.Conclusion.Reason)
	}
	for _, section := range release.Order {
		bundle := pkg.Sections[section]
		if !bundle.Present {
			t.Fatalf("section %s missing: %s", section, bundle.Reason)
		}
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The package must carry analyzer + pressure proofs and the durable event.
	if len(pkg.Proofs) < 2 {
		t.Fatalf("expected embedded independent proofs, got %d", len(pkg.Proofs))
	}
	if len(pkg.Events) == 0 {
		t.Fatal("durable journal events were not embedded")
	}
	if pkg.Conclusion.Decision.Target != "tank-7" || !pkg.Conclusion.Decision.Opened {
		t.Fatalf("wrong release decision: %+v", pkg.Conclusion.Decision)
	}
}

func TestSupplementFillsGapsAndOldVersionStaysVerifiable(t *testing.T) {
	plant := NewPlant(t.TempDir())
	if _, err := plant.Start(context.Background(), "polymer-a", "primary"); err != nil {
		t.Fatalf("start: %v", err)
	}
	revision := plant.Campaign.Snapshot().Revision.String()

	first, err := plant.IssueRelease(revision)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if first.Conclusion.Release != release.ReleaseIncomplete {
		t.Fatalf("expected gaps flagged before routing, got %s", first.Conclusion.Release)
	}
	if missing := first.MissingSections(); len(missing) == 0 {
		t.Fatal("gaps were not marked on the first version")
	}

	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if _, err := plant.AddSample(0.50, now+int64(i)); err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
	}
	if err := plant.RouteProduct("tank-7"); err != nil {
		t.Fatalf("route: %v", err)
	}

	second, err := plant.SupplementRelease(revision)
	if err != nil {
		t.Fatalf("supplement: %v", err)
	}
	if second.Version != 2 || second.Supersedes != first.ID {
		t.Fatal("supplement must chain to the original version")
	}
	if second.Conclusion.Release != release.ReleaseSupplemented {
		t.Fatalf("expected supplemented, got %s", second.Conclusion.Release)
	}
	if err := second.Verify(); err != nil {
		t.Fatalf("verify supplement: %v", err)
	}
	original, err := plant.ReleasePackageVersion(first.ID)
	if err != nil {
		t.Fatalf("fetch original: %v", err)
	}
	if err := original.Verify(); err != nil {
		t.Fatalf("old delivered package must still verify its original conclusion: %v", err)
	}
	if original.Conclusion.Release != release.ReleaseIncomplete {
		t.Fatal("original conclusion was mutated")
	}
}

func TestRevokePreservesOriginalRelease(t *testing.T) {
	plant := routedPlant(t)
	revision := plant.Campaign.Snapshot().Revision.String()
	released, err := plant.IssueRelease(revision)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := plant.RevokeRelease(revision, ""); err == nil {
		t.Fatal("revocation without a reason must fail")
	}
	revoked, err := plant.RevokeRelease(revision, "feed label mismatch found by customer")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Conclusion.Release != release.ReleaseRevoked {
		t.Fatalf("expected revoked, got %s", revoked.Conclusion.Release)
	}
	history, err := plant.ReleaseHistory(revision)
	if err != nil || len(history) != 2 {
		t.Fatalf("expected two retained versions, got %d (%v)", len(history), err)
	}
	original, _ := plant.ReleasePackageVersion(released.ID)
	if original.Conclusion.Release != release.ReleaseReleased || original.Verify() != nil {
		t.Fatal("the original delivered release must remain intact and verifiable after revocation")
	}
}

func TestReleasePackageTracksCampaignRevision(t *testing.T) {
	plant := routedPlant(t)
	firstRevision := plant.Campaign.Snapshot().Revision.String()
	if _, err := plant.Transition(context.Background(), "polymer-b", "secondary"); err != nil {
		t.Fatalf("transition: %v", err)
	}
	secondRevision := plant.Campaign.Snapshot().Revision.String()
	if firstRevision == secondRevision {
		t.Fatal("grade transition must advance the revision")
	}

	// The old batch's evidence is still assembled from retained records even
	// though the live plant has moved on.
	in, err := plant.ReleaseInputsFor(firstRevision)
	if err != nil {
		t.Fatalf("inputs for retired revision: %v", err)
	}
	if in.Campaign.Revision.String() != firstRevision {
		t.Fatal("did not reconstruct the retired campaign revision")
	}
	if len(in.Feed) == 0 {
		t.Fatal("feed switch for the retired revision was lost")
	}
	if plant.Campaign.Snapshot().Phase != model.Transitioning {
		t.Fatalf("unexpected live phase %s", plant.Campaign.Snapshot().Phase)
	}
}
