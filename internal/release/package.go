// Package release assembles batch release evidence packages: feed
// revisions, analyzer proofs, interlock conclusions, product dispositions and
// durable/durability events for one campaign revision, flags anything missing,
// and keeps every issued version frozen and independently verifiable.
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/model"
	"sort"
	"strings"
)

// Section identifies one required family of release evidence.
type Section string

const (
	SectionFeed        Section = "feed-revisions"
	SectionAnalysis    Section = "analyzer-proofs"
	SectionInterlock   Section = "interlock-conclusions"
	SectionDisposition Section = "product-disposition"
	SectionDurable     Section = "durable-events"
	SectionDurability  Section = "durability-events"
)

// Order is the fixed assembly order used for canonical summaries.
var Order = []Section{
	SectionFeed,
	SectionAnalysis,
	SectionInterlock,
	SectionDisposition,
	SectionDurable,
	SectionDurability,
}

// Item is one gathered piece of evidence.
type Item struct {
	Key    string `json:"key"`
	Source string `json:"source"`
	Digest string `json:"content_digest"`
	At     int64  `json:"at"`
}

// SectionBundle is one section of the package, present-or-missing.
type SectionBundle struct {
	Present bool     `json:"present"`
	Reason  string   `json:"reason,omitempty"`
	Items   []Item   `json:"items,omitempty"`
	Refs    []string `json:"refs,omitempty"`
}

// Decision records the release disposition taken for the batch.
type Decision struct {
	Target string `json:"target"`
	Opened bool   `json:"opened"`
	Reason string `json:"reason"`
	At     int64  `json:"at"`
}

// Conclusion is the release decision carried by a package version.
type Conclusion struct {
	Release  string    `json:"release"`
	Reason   string    `json:"reason"`
	Missing  []Section `json:"missing,omitempty"`
	Decision Decision  `json:"decision"`
	ProofIDs []string  `json:"proof_ids,omitempty"`
}

// Action values describe why a version exists.
const (
	ActionIssue      = "issue"
	ActionSupplement = "supplement"
	ActionRevoke     = "revoke"
)

// Release decisions.
const (
	ReleaseReleased     = "released"            // evidence complete, original release stands
	ReleaseIncomplete   = "incomplete-evidence" // issued with gaps, no release claim
	ReleaseSupplemented = "supplemented"        // missing evidence supplied in a new version
	ReleaseRevoked      = "revoked"             // release withdrawn, original kept for audit
)

// Package is one frozen version of a batch release evidence package.
type Package struct {
	ID         uuid.UUID                 `json:"id"`
	Lineage    uuid.UUID                 `json:"lineage_id"`
	Version    int                       `json:"version"`
	Supersedes uuid.UUID                 `json:"supersedes,omitempty"`
	Campaign   string                    `json:"campaign"`
	Revision   string                    `json:"revision"`
	Grade      string                    `json:"grade"`
	Target     string                    `json:"target"`
	IssuedAt   int64                     `json:"issued_at"`
	Action     string                    `json:"action"`
	Sections   map[Section]SectionBundle `json:"sections"`
	Conclusion Conclusion                `json:"conclusion"`
	Proofs     []model.Proof             `json:"proofs,omitempty"`
	Events     []model.Event             `json:"events,omitempty"`
	Digest     string                    `json:"digest"`
}

// MissingSections returns the sections that could not be assembled.
func (p *Package) MissingSections() []Section {
	missing := make([]Section, 0)
	for _, section := range Order {
		bundle, ok := p.Sections[section]
		if !ok || !bundle.Present {
			missing = append(missing, section)
		}
	}
	return missing
}

// Verifiable reports whether the original release conclusion can be checked
// against the embedded evidence: a released batch must have every section and
// a decision that actually opened a product route.
func (p *Package) Verifiable() error {
	switch p.Conclusion.Release {
	case ReleaseReleased, ReleaseSupplemented:
		if len(p.MissingSections()) > 0 {
			return fmt.Errorf("release conclusion has missing sections: %s", joinSections(p.MissingSections()))
		}
		if !p.Conclusion.Decision.Opened {
			return errors.New("release conclusion has no opened product route")
		}
		if len(p.Conclusion.ProofIDs) == 0 {
			return errors.New("release conclusion names no evidence")
		}
	case ReleaseIncomplete:
		// An explicitly incomplete package is honest about its gaps; the gaps
		// themselves are what a reviewer verifies.
		if len(p.Conclusion.Missing) == 0 {
			return errors.New("incomplete package names no missing sections")
		}
	case ReleaseRevoked:
		// A revocation withdraws the decision; the old version still carries the
		// original conclusion and remains verifiable on its own.
		return nil
	default:
		return fmt.Errorf("unknown release conclusion %q", p.Conclusion.Release)
	}
	return nil
}

// CanonicalDigest hashes everything a reviewer must rely on, in a fixed order.
func CanonicalDigest(p Package) string {
	var b strings.Builder
	fmt.Fprintf(&b, "campaign=%s|revision=%s|grade=%s|target=%s|version=%d|action=%s",
		p.Campaign, p.Revision, p.Grade, p.Target, p.Version, p.Action)
	if p.Supersedes != uuid.Nil {
		fmt.Fprintf(&b, "|supersedes=%s", p.Supersedes)
	}
	for _, section := range Order {
		bundle := p.Sections[section]
		fmt.Fprintf(&b, "|%s:present=%t", section, bundle.Present)
		if bundle.Reason != "" {
			fmt.Fprintf(&b, ":reason=%s", bundle.Reason)
		}
		for _, ref := range bundle.Refs {
			fmt.Fprintf(&b, ":ref=%s", ref)
		}
		for _, item := range bundle.Items {
			fmt.Fprintf(&b, ":item=%s,%s,%s,%d", item.Key, item.Source, item.Digest, item.At)
		}
	}
	c := p.Conclusion
	fmt.Fprintf(&b, "|conclusion=%s:%s:target=%s:opened=%t:at=%d",
		c.Release, c.Reason, c.Decision.Target, c.Decision.Opened, c.Decision.At)
	writeSortedStrings(&b, "proof", c.ProofIDs)
	for _, proof := range p.Proofs {
		fmt.Fprintf(&b, "|proof=%s,%s,%s,%s,%t,%t,%d",
			proof.ID, proof.Revision, proof.Source, proof.Digest, proof.Durable, proof.Independent, proof.At)
	}
	for _, event := range p.Events {
		fmt.Fprintf(&b, "|event=%s,%s,%s,%d,%s,%d",
			event.ID, event.Kind, event.Revision, event.Epoch, event.Payload, event.At)
	}
	hash := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(hash[:])
}

// Seal fills the digest on a freshly assembled package.
func (p *Package) Seal() { p.Digest = CanonicalDigest(*p) }

// Verify checks the package digest and, for release-bearing versions, the
// integrity of every embedded proof against its own canonical digest.
func (p *Package) Verify() error {
	if p.ID == uuid.Nil || p.Revision == "" {
		return errors.New("package identity is incomplete")
	}
	if CanonicalDigest(*p) != p.Digest {
		return errors.New("package digest mismatch: content was altered after sealing")
	}
	named := make(map[string]struct{}, len(p.Conclusion.ProofIDs))
	for _, id := range p.Conclusion.ProofIDs {
		named[id] = struct{}{}
	}
	for _, proof := range p.Proofs {
		if proof.Digest == "" {
			return fmt.Errorf("embedded proof %s has no digest", proof.ID)
		}
		if model.ProofDigest(proof) != proof.Digest {
			return fmt.Errorf("embedded proof %s digest mismatch", proof.ID)
		}
		if proof.Revision.String() != p.Revision {
			return fmt.Errorf("embedded proof %s belongs to another revision", proof.ID)
		}
		delete(named, proof.ID.String())
	}
	if p.Conclusion.Release == ReleaseReleased || p.Conclusion.Release == ReleaseSupplemented {
		if len(named) > 0 {
			return errors.New("conclusion names proofs that are not embedded")
		}
	}
	return p.Verifiable()
}

func joinSections(sections []Section) string {
	values := make([]string, 0, len(sections))
	for _, section := range sections {
		values = append(values, string(section))
	}
	return strings.Join(values, ",")
}

func writeSortedStrings(b *strings.Builder, label string, values []string) {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	for _, value := range sorted {
		fmt.Fprintf(b, "|%s_id=%s", label, value)
	}
}
