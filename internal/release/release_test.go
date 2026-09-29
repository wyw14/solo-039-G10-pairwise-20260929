package release

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/model"
)

func analyzerProof(revision uuid.UUID) model.Proof {
	proof := model.Proof{ID: uuid.New(), Revision: revision, Source: "analyzer:calibration-1", Durable: true, Independent: true, At: 100}
	proof.Digest = model.ProofDigest(proof)
	return proof
}

func completeSources(campaign model.Campaign) Sources {
	proof := analyzerProof(campaign.Revision)
	event := model.NewEvent("proof.durable", campaign, proof.Digest)
	return Sources{
		FeedRevision: campaign.Revision,
		FeedSource:   "tank-A",
		FeedSwitch: &FeedSwitch{
			OldRevision: uuid.New(), OldSource: "tank-B", OldClosed: true,
			NewRevision: campaign.Revision, NewSource: "tank-A", NewOpened: true,
		},
		AnalyzerProofs: []model.Proof{proof},
		Permit:         &PermitConclusion{Allowed: true, Proofs: []model.Proof{proof}},
		Destination:    &Destination{Target: "can-line-3", Opened: true, Reason: "durable proof accepted"},
		DurableEvents:  []model.Event{event},
	}
}

func TestAssembleFlagsMissingSections(t *testing.T) {
	assembler := NewAssembler()
	book := NewBook()
	campaign := model.NewCampaign("polymer-grade")

	// Only the feed revision is known: the reviewer must see exactly which
	// other evidence categories are missing.
	pkg, err := book.Issue(assembler, campaign, Sources{FeedRevision: campaign.Revision, FeedSource: "tank-A"}, Options{CanID: "CAN-2026-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Version != 1 {
		t.Fatalf("expected version 1, got %d", pkg.Version)
	}
	if pkg.Decision != Held {
		t.Fatalf("expected held decision, got %q", pkg.Decision)
	}
	if pkg.Complete() {
		t.Fatal("incomplete package reported complete")
	}
	wantMissing := map[string]bool{SectionAnalyzer: true, SectionInterlock: true, SectionProduct: true, SectionDurable: true}
	if len(pkg.MissingItems()) != len(wantMissing) {
		t.Fatalf("missing = %v", pkg.MissingItems())
	}
	for _, name := range pkg.MissingItems() {
		if !wantMissing[name] {
			t.Fatalf("unexpected missing section %q", name)
		}
		if pkg.Sections[name].Reason == "" {
			t.Fatalf("missing section %q carries no reason", name)
		}
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("held package must still seal and verify: %v", err)
	}
}

func TestCompletePackageReleasedAndVerifies(t *testing.T) {
	assembler := NewAssembler()
	book := NewBook()
	campaign := model.NewCampaign("polymer-grade")

	sources := completeSources(campaign)
	pkg, err := book.Issue(assembler, campaign, sources, Options{CanID: "CAN-2026-0007"})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Decision != Released {
		t.Fatalf("expected released, got %q", pkg.Decision)
	}
	if !pkg.Complete() {
		t.Fatalf("package is missing sections: %v", pkg.MissingItems())
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("released package failed verification: %v", err)
	}
	durable := pkg.Sections[SectionDurable]
	if len(durable.References) != 1 || durable.References[0].Kind != "proof.durable" {
		t.Fatalf("durable references = %v", durable.References)
	}
}

func TestResupplementIssuesNewVersionAndOldPackageStillVerifies(t *testing.T) {
	assembler := NewAssembler()
	book := NewBook()
	campaign := model.NewCampaign("polymer-grade")
	sealedAt := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

	// v1: routed, but the analyzer proof and durable event never made it into
	// the package.
	v1, err := book.Issue(assembler, campaign, Sources{
		FeedRevision: campaign.Revision,
		FeedSource:   "tank-A",
		Permit:       &PermitConclusion{Allowed: true},
		Destination:  &Destination{Target: "can-line-3", Opened: true},
	}, Options{CanID: "CAN-2026-0007", At: sealedAt})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Decision != Held {
		t.Fatalf("expected held v1, got %q", v1.Decision)
	}

	// Supplementary evidence arrives later: a new version closes the gaps.
	supplementary := completeSources(campaign)
	v2, err := book.Resupplement(assembler, Sources{
		AnalyzerProofs: supplementary.AnalyzerProofs,
		DurableEvents:  supplementary.DurableEvents,
	}, Options{Note: "analyzer certificate and durable event supplied after customer review", At: sealedAt.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 || v2.Decision != Released {
		t.Fatalf("expected released v2, got version %d decision %q", v2.Version, v2.Decision)
	}
	if !v2.Complete() {
		t.Fatalf("v2 still missing: %v", v2.MissingItems())
	}
	if v2.Supersedes != v1.ID {
		t.Fatal("v2 does not chain back to v1")
	}
	if v2.CanID != v1.CanID {
		t.Fatal("resupplementation lost the can identity")
	}
	if err := v2.Verify(); err != nil {
		t.Fatalf("v2 failed verification: %v", err)
	}

	// The originally delivered package remains available and still proves its
	// original conclusion (held, with the original gaps listed).
	delivered, err := book.Version(1)
	if err != nil {
		t.Fatal(err)
	}
	if delivered.ID != v1.ID || delivered.Decision != Held {
		t.Fatal("v1 was mutated by resupplementation")
	}
	if err := delivered.Verify(); err != nil {
		t.Fatalf("old delivery no longer verifies: %v", err)
	}
	if len(book.History()) != 2 {
		t.Fatal("history must retain every version")
	}
}

func TestRevokeIssuesRevocationVersionWithoutBreakingOldSeals(t *testing.T) {
	assembler := NewAssembler()
	book := NewBook()
	campaign := model.NewCampaign("polymer-grade")

	v1, err := book.Issue(assembler, campaign, completeSources(campaign), Options{CanID: "CAN-2026-0007"})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := book.Revoke(assembler, "analyzer calibration found defective", time.Time{}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 || v2.Decision != Revoked {
		t.Fatalf("expected revoked v2, got version %d decision %q", v2.Version, v2.Decision)
	}
	if !v2.Revoked || v2.Revocation == "" {
		t.Fatal("revocation version is not marked revoked")
	}
	if err := v2.Verify(); err != nil {
		t.Fatalf("revocation version failed verification: %v", err)
	}

	// v1 carries the revocation marker for reviewers, but its seal and its
	// original released conclusion are intact.
	old, err := book.Version(1)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Revoked || old.ID != v1.ID {
		t.Fatal("revocation marker was not attached to the old delivery")
	}
	if old.Decision != Released {
		t.Fatal("revocation rewrote the original conclusion")
	}
	if err := old.Verify(); err != nil {
		t.Fatalf("revoked delivery must still verify its original conclusion: %v", err)
	}

	if _, err := book.Revoke(assembler, "again", time.Time{}, uuid.New()); err == nil {
		t.Fatal("revoking an already revoked latest version should fail")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	assembler := NewAssembler()
	book := NewBook()
	campaign := model.NewCampaign("polymer-grade")
	pkg, err := book.Issue(assembler, campaign, completeSources(campaign), Options{})
	if err != nil {
		t.Fatal(err)
	}

	forged := pkg
	forged.Seal = "deadbeef"
	if err := forged.Verify(); err == nil {
		t.Fatal("forged seal accepted")
	}

	altered := pkg
	analyzer := altered.Sections[SectionAnalyzer]
	proofs := append([]model.Proof(nil), analyzer.Evidence...)
	proofs[0].Source = "analyzer:swapped-calibration"
	analyzer.Evidence = proofs
	altered.Sections[SectionAnalyzer] = analyzer
	if err := altered.Verify(); err == nil {
		t.Fatal("swapped proof accepted without resealing")
	}
}

func TestDeniedInterlockHoldsRelease(t *testing.T) {
	assembler := NewAssembler()
	book := NewBook()
	campaign := model.NewCampaign("polymer-grade")
	sources := completeSources(campaign)
	sources.Permit.Allowed = false
	sources.Permit.Reasons = []string{"campaign is not on-spec"}

	pkg, err := book.Issue(assembler, campaign, sources, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Decision != Held {
		t.Fatalf("denied interlock must hold release, got %q", pkg.Decision)
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("held package failed verification: %v", err)
	}
	if pkg.Sections[SectionInterlock].Detail["allowed"] != false {
		t.Fatal("interlock section lost its denied verdict")
	}
}

func TestBookVersionLookupErrors(t *testing.T) {
	book := NewBook()
	if _, err := book.Latest(); err == nil {
		t.Fatal("expected error on empty book")
	}
	if _, err := book.Version(1); err == nil {
		t.Fatal("expected error for missing version")
	}
	if _, err := book.Get(uuid.New()); err == nil {
		t.Fatal("expected error for unknown package id")
	}
	if _, err := book.Revoke(NewAssembler(), "reason", time.Time{}, uuid.New()); err == nil {
		t.Fatal("revoking an empty book should fail")
	}
}
