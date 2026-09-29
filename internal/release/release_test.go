package release

import (
	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/model"
	"testing"
)

func completeInputs() Inputs {
	campaign := model.NewCampaign("polymer-a")
	proof := model.Proof{ID: uuid.New(), Revision: campaign.Revision, Source: "analyzer", Independent: true, Durable: true, At: 100}
	proof.Digest = model.ProofDigest(proof)
	pressure := model.Proof{ID: uuid.New(), Revision: campaign.Revision, Source: "column-pressure", Independent: true, Durable: true, At: 101}
	pressure.Digest = model.ProofDigest(pressure)
	event := model.NewEvent("proof.durable", campaign, proof.Digest)
	event.At = 102
	return Inputs{
		Campaign: campaign,
		Target:   "tank-7",
		Feed: []FeedChange{{
			Stage: "new-active", OldSource: "", NewSource: "primary",
			OldRevision: uuid.Nil, NewRevision: uuid.New(), At: 10,
		}},
		Proofs: []model.Proof{proof, pressure},
		Interlock: &InterlockConclusion{
			Allowed: true, Sources: []string{"analyzer", "column-pressure"}, At: 103,
		},
		Dispositions: []Disposition{{Target: "tank-7", Opened: true, Reason: "durable proof accepted", At: 104}},
		Events:       []model.Event{event},
		Durability:   nil, // a healthy batch has none; absence must not count as missing
	}
}

func TestIssueCompletePackageIsReleasedAndVerifies(t *testing.T) {
	registry := NewRegistry()
	pkg, err := registry.Issue(completeInputs(), 1000)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pkg.Version != 1 || pkg.Action != ActionIssue {
		t.Fatalf("unexpected identity: version=%d action=%s", pkg.Version, pkg.Action)
	}
	if pkg.Conclusion.Release != ReleaseReleased {
		t.Fatalf("expected released, got %s (%s)", pkg.Conclusion.Release, pkg.Conclusion.Reason)
	}
	if missing := pkg.MissingSections(); len(missing) != 0 {
		t.Fatalf("complete package has missing sections: %v", missing)
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if pkg.ID != pkg.Lineage {
		t.Fatal("first version should anchor the lineage")
	}
}

func TestSparsePackageIsMarkedIncomplete(t *testing.T) {
	campaign := model.NewCampaign("polymer-a")
	registry := NewRegistry()
	pkg, err := registry.Issue(Inputs{Campaign: campaign, Target: "tank-7"}, 1000)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pkg.Conclusion.Release != ReleaseIncomplete {
		t.Fatalf("expected incomplete, got %s", pkg.Conclusion.Release)
	}
	missing := pkg.MissingSections()
	if len(missing) != 5 {
		t.Fatalf("expected 5 missing sections (durability absence is fine), got %v", missing)
	}
	for _, section := range []Section{SectionFeed, SectionAnalysis, SectionInterlock, SectionDisposition, SectionDurable} {
		bundle := pkg.Sections[section]
		if bundle.Present || bundle.Reason == "" {
			t.Fatalf("section %s should be missing with a reason", section)
		}
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("incomplete package should verify its own gaps: %v", err)
	}
}

func TestSupplementIssuesNewVersionAndKeepsOldVerifiable(t *testing.T) {
	registry := NewRegistry()
	in := completeInputs()

	sparse := Inputs{Campaign: in.Campaign, Target: in.Target}
	first, err := registry.Issue(sparse, 1000)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if first.Conclusion.Release != ReleaseIncomplete {
		t.Fatalf("expected incomplete first version, got %s", first.Conclusion.Release)
	}

	second, err := registry.Supplement(in, 2000)
	if err != nil {
		t.Fatalf("supplement: %v", err)
	}
	if second.Version != 2 || second.Action != ActionSupplement {
		t.Fatalf("unexpected supplement identity: %d %s", second.Version, second.Action)
	}
	if second.Supersedes != first.ID || second.Lineage != first.Lineage || second.ID == first.ID {
		t.Fatal("supplement must be a new version chained to the old one")
	}
	if second.Conclusion.Release != ReleaseSupplemented {
		t.Fatalf("expected supplemented conclusion, got %s", second.Conclusion.Release)
	}
	if err := second.Verify(); err != nil {
		t.Fatalf("verify supplement: %v", err)
	}

	// Old delivered package is retained and still verifies its original conclusion.
	stored, err := registry.Get(first.ID)
	if err != nil {
		t.Fatalf("get original: %v", err)
	}
	if err := stored.Verify(); err != nil {
		t.Fatalf("original package no longer verifies: %v", err)
	}
	if stored.Conclusion.Release != ReleaseIncomplete {
		t.Fatal("original conclusion was rewritten")
	}

	history, err := registry.History(in.Campaign.Revision.String())
	if err != nil || len(history) != 2 {
		t.Fatalf("history should retain both versions, got %d (%v)", len(history), err)
	}
	if latest, _ := registry.Latest(in.Campaign.Revision.String()); latest.ID != second.ID {
		t.Fatal("latest does not point at the supplement")
	}
}

func TestRevokeWithdrawsButPreservesHistory(t *testing.T) {
	registry := NewRegistry()
	in := completeInputs()
	released, err := registry.Issue(in, 1000)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	revoked, err := registry.Revoke(in.Campaign.Revision.String(), "customer found a feed labeling error", 3000)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Version != 2 || revoked.Conclusion.Release != ReleaseRevoked {
		t.Fatalf("unexpected revocation: %d %s", revoked.Version, revoked.Conclusion.Release)
	}
	if err := revoked.Verify(); err != nil {
		t.Fatalf("revocation verify: %v", err)
	}
	if _, err := registry.Revoke(in.Campaign.Revision.String(), "again", 3001); err == nil {
		t.Fatal("revoking an already revoked revision must fail")
	}
	if _, err := registry.Supplement(in, 3002); err == nil {
		t.Fatal("supplementing a revoked revision must fail")
	}

	original, err := registry.Get(released.ID)
	if err != nil {
		t.Fatalf("get released: %v", err)
	}
	if err := original.Verify(); err != nil {
		t.Fatalf("original release must still verify after revocation: %v", err)
	}
	if original.Conclusion.Release != ReleaseReleased {
		t.Fatal("original release conclusion was changed by revocation")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	registry := NewRegistry()
	pkg, err := registry.Issue(completeInputs(), 1000)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	altered := pkg
	altered.Target = "tank-99"
	if err := altered.Verify(); err == nil {
		t.Fatal("package content change after sealing was not detected")
	}

	proofTampered := pkg
	proofTampered.Proofs[0].Digest = "forged"
	if err := proofTampered.Verify(); err == nil {
		t.Fatal("forged embedded proof was not detected")
	}

	foreign := pkg
	foreign.Proofs[0].Revision = uuid.New()
	foreign.Proofs[0].Digest = model.ProofDigest(foreign.Proofs[0])
	if err := foreign.Verify(); err == nil {
		t.Fatal("proof from another revision was not detected")
	}
}

func TestRegistryGuards(t *testing.T) {
	registry := NewRegistry()
	in := completeInputs()
	if _, err := registry.Issue(in, 1); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := registry.Issue(in, 2); err == nil {
		t.Fatal("duplicate issue for the same revision must fail")
	}
	other := Inputs{Campaign: model.NewCampaign("polymer-b")}
	if _, err := registry.Supplement(other, 2); err == nil {
		t.Fatal("supplement without an issue must fail")
	}
	if _, err := registry.Revoke(other.Campaign.Revision.String(), "none", 2); err == nil {
		t.Fatal("revoke without an issue must fail")
	}
	if _, err := registry.Get(uuid.New()); err == nil {
		t.Fatal("get of unknown package must fail")
	}
}

func TestDurabilityIncidentsAreRecorded(t *testing.T) {
	in := completeInputs()
	in.Durability = []DurabilityEvent{{Kind: "relief-timeout", Detail: "flare valve exceeded timeout", At: 90, Resolved: false}}
	registry := NewRegistry()
	pkg, err := registry.Issue(in, 1000)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	bundle := pkg.Sections[SectionDurability]
	if !bundle.Present || len(bundle.Items) != 1 {
		t.Fatalf("durability incident not gathered: %+v", bundle)
	}
	if err := pkg.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
