package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/model"
	"sort"
	"strings"
)

// shortDigest binds a derived section item to the underlying record content.
func shortDigest(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// FeedChange is one observed feed-source switch relevant to the batch.
type FeedChange struct {
	Stage            string
	CampaignRevision uuid.UUID
	OldSource        string
	NewSource        string
	OldRevision      uuid.UUID
	NewRevision      uuid.UUID
	At               int64
}

// InterlockConclusion is the permit decision taken over the batch evidence.
type InterlockConclusion struct {
	Allowed bool
	Reasons []string
	Sources []string
	At      int64
}

// Disposition is one product release decision recorded for the revision.
type Disposition struct {
	Target string
	Opened bool
	Reason string
	At     int64
}

// DurabilityEvent is a relief/incident event bearing on batch durability.
type DurabilityEvent struct {
	Kind     string
	Detail   string
	At       int64
	Resolved bool
}

// Inputs gathers everything the assembler can find for one revision. The
// caller (plant wiring) adapts live components into these neutral records, so
// the package logic stays independent of service state.
type Inputs struct {
	Campaign     model.Campaign
	Target       string
	Feed         []FeedChange
	Proofs       []model.Proof
	Interlock    *InterlockConclusion
	Dispositions []Disposition
	Events       []model.Event
	Durability   []DurabilityEvent
}

// Build assembles a package (identity fields left to the registry) and seals
// nothing yet: the registry assigns id/lineage/version, then seals. Missing
// sections are marked in place and listed in the conclusion.
func Build(in Inputs, now int64) Package {
	revision := in.Campaign.Revision.String()
	sections := make(map[Section]SectionBundle)

	sections[SectionFeed] = buildFeed(in.Feed)
	sections[SectionAnalysis] = buildAnalysis(in.Proofs)
	sections[SectionInterlock] = buildInterlock(in.Interlock, in.Proofs)
	sections[SectionDisposition] = buildDisposition(in.Dispositions)
	sections[SectionDurable] = buildDurable(in.Events, revision)
	sections[SectionDurability] = buildDurability(in.Durability)

	missing := make([]Section, 0)
	for _, section := range Order {
		if !sections[section].Present {
			missing = append(missing, section)
		}
	}

	proofs := append([]model.Proof(nil), in.Proofs...)
	sort.SliceStable(proofs, func(i, j int) bool {
		if proofs[i].At != proofs[j].At {
			return proofs[i].At < proofs[j].At
		}
		return proofs[i].ID.String() < proofs[j].ID.String()
	})
	events := filterRevision(in.Events, revision)

	decision := latestDisposition(in.Dispositions, in.Target)
	proofIDs := make([]string, 0, len(proofs))
	for _, proof := range proofs {
		proofIDs = append(proofIDs, proof.ID.String())
	}

	durablePresent := sections[SectionDurable].Present
	permitAllowed := in.Interlock != nil && in.Interlock.Allowed
	released := len(missing) == 0 && permitAllowed && decision.Opened && durablePresent

	conclusion := Conclusion{Decision: decision, ProofIDs: proofIDs}
	if released {
		conclusion.Release = ReleaseReleased
		conclusion.Reason = "all sections present; interlock allowed; durable proof on file"
	} else {
		conclusion.Release = ReleaseIncomplete
		conclusion.Missing = missing
		reasons := make([]string, 0)
		if !permitAllowed {
			if in.Interlock == nil {
				reasons = append(reasons, "interlock never evaluated")
			} else {
				reasons = append(reasons, "interlock denied: "+strings.Join(in.Interlock.Reasons, "; "))
			}
		}
		if !durablePresent {
			reasons = append(reasons, "no durable proof event")
		}
		if !decision.Opened {
			reasons = append(reasons, "no opened product route")
		}
		if len(missing) > 0 {
			reasons = append(reasons, "missing sections: "+joinSections(missing))
		}
		conclusion.Reason = strings.Join(reasons, "; ")
	}

	return Package{
		Campaign:   in.Campaign.ID.String(),
		Revision:   revision,
		Grade:      in.Campaign.Grade,
		Target:     in.Target,
		IssuedAt:   now,
		Action:     ActionIssue,
		Sections:   sections,
		Conclusion: conclusion,
		Proofs:     proofs,
		Events:     events,
	}
}

func buildFeed(changes []FeedChange) SectionBundle {
	if len(changes) == 0 {
		return SectionBundle{Present: false, Reason: "no feed switch recorded for batch"}
	}
	items := make([]Item, 0, len(changes))
	refs := make([]string, 0)
	for i, change := range changes {
		key := fmt.Sprintf("feed-%d", i+1)
		digest := fmt.Sprintf("%s|%s|%s|%s|%s|%s", change.CampaignRevision, change.Stage, change.OldSource, change.NewSource, change.OldRevision, change.NewRevision)
		items = append(items, Item{Key: key, Source: nonEmpty(change.NewSource, change.OldSource), Digest: shortDigest(digest), At: change.At})
		if change.NewRevision != uuid.Nil {
			refs = append(refs, change.NewRevision.String())
		}
	}
	return SectionBundle{Present: true, Items: items, Refs: refs}
}

func buildAnalysis(proofs []model.Proof) SectionBundle {
	if len(proofs) == 0 {
		return SectionBundle{Present: false, Reason: "no independent analyzer proof on file"}
	}
	items := make([]Item, 0, len(proofs))
	refs := make([]string, 0, len(proofs))
	for _, proof := range proofs {
		items = append(items, Item{Key: "proof-" + proof.ID.String(), Source: proof.Source, Digest: proof.Digest, At: proof.At})
		refs = append(refs, proof.ID.String())
	}
	return SectionBundle{Present: true, Items: items, Refs: refs}
}

func buildInterlock(conclusion *InterlockConclusion, proofs []model.Proof) SectionBundle {
	if conclusion == nil {
		return SectionBundle{Present: false, Reason: "interlock never evaluated for revision"}
	}
	refs := append([]string(nil), conclusion.Sources...)
	sort.Strings(refs)
	reason := ""
	if !conclusion.Allowed {
		reason = "denied: " + strings.Join(conclusion.Reasons, "; ")
	}
	return SectionBundle{Present: true, Reason: reason, Refs: refs}
}

func buildDisposition(decisions []Disposition) SectionBundle {
	if len(decisions) == 0 {
		return SectionBundle{Present: false, Reason: "no product release decision recorded"}
	}
	items := make([]Item, 0, len(decisions))
	for i, decision := range decisions {
		digest := fmt.Sprintf("%s|%t|%s|%d", decision.Target, decision.Opened, decision.Reason, decision.At)
		items = append(items, Item{Key: fmt.Sprintf("decision-%d", i+1), Source: "product-audit", Digest: shortDigest(digest), At: decision.At})
	}
	return SectionBundle{Present: true, Items: items}
}

func buildDurable(events []model.Event, revision string) SectionBundle {
	items := make([]Item, 0)
	for _, event := range events {
		if event.Kind != "proof.durable" || event.Revision.String() != revision {
			continue
		}
		items = append(items, Item{Key: "durable-" + event.ID.String(), Source: "journal", Digest: shortDigest(event.Payload), At: event.At})
	}
	if len(items) == 0 {
		return SectionBundle{Present: false, Reason: "no durable proof event for revision"}
	}
	return SectionBundle{Present: true, Items: items}
}

func buildDurability(events []DurabilityEvent) SectionBundle {
	if len(events) == 0 {
		// Checked and none found: a healthy batch carries no incidents, which is
		// evidence itself, not a gap.
		return SectionBundle{Present: true, Reason: "no relief or durability incidents during the batch"}
	}
	items := make([]Item, 0, len(events))
	for i, event := range events {
		state := "open"
		if event.Resolved {
			state = "resolved"
		}
		digest := fmt.Sprintf("%s|%s|%s|%d", event.Kind, state, event.Detail, event.At)
		items = append(items, Item{Key: fmt.Sprintf("durability-%d", i+1), Source: event.Kind, Digest: shortDigest(digest), At: event.At})
	}
	return SectionBundle{Present: true, Items: items}
}

func latestDisposition(decisions []Disposition, fallback string) Decision {
	if len(decisions) == 0 {
		return Decision{Target: fallback}
	}
	latest := decisions[0]
	for _, decision := range decisions[1:] {
		if decision.At >= latest.At {
			latest = decision
		}
	}
	return Decision{Target: nonEmpty(latest.Target, fallback), Opened: latest.Opened, Reason: latest.Reason, At: latest.At}
}

func filterRevision(events []model.Event, revision string) []model.Event {
	out := make([]model.Event, 0)
	for _, event := range events {
		if event.Revision.String() == revision {
			out = append(out, event)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

func nonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
