package service

import (
	"errors"
	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/interlock"
	"github.com/wyw14/solo-039/internal/journal"
	"github.com/wyw14/solo-039/internal/model"
	"github.com/wyw14/solo-039/internal/release"
	"strings"
	"time"
)

// ReleasePackages returns every issued release evidence package version.
func (p *Plant) ReleasePackages() []release.Package { return p.ReleaseBook.History() }

// ReleasePackage returns one issued package by version number.
func (p *Plant) ReleasePackage(version int) (release.Package, error) {
	return p.ReleaseBook.Version(version)
}

// ReleasePackageByID returns one issued package by its seal ID.
func (p *Plant) ReleasePackageByID(id uuid.UUID) (release.Package, error) {
	return p.ReleaseBook.Get(id)
}

// LatestReleasePackage returns the current release evidence package.
func (p *Plant) LatestReleasePackage() (release.Package, error) {
	return p.ReleaseBook.Latest()
}

// releaseSources gathers the five evidence categories for the current campaign
// revision out of the live subsystems. Sections without backing data come back
// empty and are flagged missing during assembly.
func (p *Plant) releaseSources() release.Sources {
	current := p.Campaign.Snapshot()
	revision := current.Revision.String()

	sources := release.Sources{
		FeedRevision:   p.Feed.Current.Revision,
		FeedSource:     p.Feed.Current.Source,
		AnalyzerProofs: p.Evidence.Independent(revision),
	}
	if p.Feed.Current != nil && p.Feed.Previous != nil && p.Feed.Previous.Source != "" {
		sources.FeedSwitch = &release.FeedSwitch{
			OldRevision: p.Feed.Previous.Revision,
			OldSource:   p.Feed.Previous.Source,
			OldClosed:   !p.Feed.Previous.Open,
			NewRevision: p.Feed.Current.Revision,
			NewSource:   p.Feed.Current.Source,
			NewOpened:   p.Feed.Current.Open,
		}
	}

	permit := p.releasePermit(current)
	sources.Permit = permit
	sources.Destination = p.releaseDestination(current.Revision)
	sources.DurableEvents = p.durableEvents(current)
	return sources
}

// releasePermit returns the interlock verdict actually taken for the revision.
// It never re-evaluates evidence on the fly: before routing no conclusion was
// ever made, so the section is reported missing rather than fabricated. A
// denied routing still captures a verdict, which binds as a present-but-denied
// section.
func (p *Plant) releasePermit(current model.Campaign) *release.PermitConclusion {
	p.mu.RLock()
	captured := p.routePermit
	p.mu.RUnlock()
	if captured == nil || captured.Revision != current.Revision.String() {
		return nil
	}
	return &release.PermitConclusion{Allowed: captured.Allowed, Reasons: captured.Reasons, Proofs: captured.Proofs}
}

func (p *Plant) releaseDestination(revision uuid.UUID) *release.Destination {
	decisions := p.ProductAudit.ForRevision(revision.String())
	// Prefer the decision that actually opened the route (the release
	// decision); a failed attempt may be recorded earlier in the audit.
	for i := len(decisions) - 1; i >= 0; i-- {
		decision := decisions[i]
		if decision.Opened {
			return &release.Destination{Target: decision.Plan.Target, Opened: true, Reason: decision.Reason}
		}
	}
	if len(decisions) > 0 {
		decision := decisions[len(decisions)-1]
		return &release.Destination{Target: decision.Plan.Target, Opened: false, Reason: decision.Reason}
	}
	if p.Product.Route.Opened() {
		return &release.Destination{Target: p.Product.Route.Target(), Opened: true, Reason: "route open"}
	}
	return nil
}

// durableEvents returns journaled durable proof events for the campaign
// revision. The journal is the durability authority (journal.RequireProof reads
// the same events); events additionally flushed to the on-disk file log are
// annotated in the package detail.
func (p *Plant) durableEvents(current model.Campaign) []model.Event {
	out := make([]model.Event, 0)
	for _, event := range p.Journal.Events() {
		if event.Campaign != current.ID || event.Revision != current.Revision {
			continue
		}
		if event.Kind != "proof.durable" {
			continue
		}
		out = append(out, event)
	}
	return out
}

// AssembleReleasePackage seals a new release evidence package for the current
// campaign revision and can, marking every missing section. Issuing again after
// a new version exists chains the new version to the previous one.
func (p *Plant) AssembleReleasePackage(canID, note string) (release.Package, error) {
	canID = strings.TrimSpace(canID)
	if canID == "" {
		return release.Package{}, errors.New("can id is required to bind the evidence package")
	}
	current := p.Campaign.Snapshot()
	opts := release.Options{CanID: canID, Note: note, At: time.Now()}
	if latest, err := p.ReleaseBook.Latest(); err == nil && latest.Campaign == current.ID && latest.Revision == current.Revision {
		opts.Supersedes = latest.ID
	}
	pkg, err := p.ReleaseBook.Issue(release.NewAssembler(), current, p.releaseSources(), opts)
	if err != nil {
		return release.Package{}, err
	}
	return pkg, nil
}

// ResupplementRelease fills previously missing sections with whatever evidence
// is now available (for example a late analyzer certificate), backfills the
// durable journal entry, and issues a new package version. The delivered
// package is untouched and still verifies its original conclusion.
func (p *Plant) ResupplementRelease(note string) (release.Package, error) {
	if _, err := p.ReleaseBook.Latest(); err != nil {
		return release.Package{}, err
	}
	current := p.Campaign.Snapshot()

	// Backfill the durable analyzer proof when routing never persisted one for
	// the revision: write it to both the journal and the file log so the new
	// package references a genuinely durable event.
	if proof, ok := p.Analyzer.Proof(current.Revision); ok && !p.durableProofPresent(proof.Digest) {
		if err := journal.PersistProof(p.Journal, proof, current); err != nil {
			return release.Package{}, err
		}
		if event, ok := p.Journal.Last("proof.durable"); ok {
			if err := p.FileLog.Append(event); err != nil {
				return release.Package{}, err
			}
		}
	}

	pkg, err := p.ReleaseBook.Resupplement(release.NewAssembler(), p.releaseSources(), release.Options{
		Note: strings.TrimSpace(note),
		At:   time.Now(),
	})
	if err != nil {
		return release.Package{}, err
	}
	return pkg, nil
}

func (p *Plant) durableProofPresent(digest string) bool {
	for _, event := range p.Journal.Events() {
		if event.Kind == "proof.durable" && event.Payload == digest {
			return true
		}
	}
	return false
}

// RevokeRelease withdraws the current release decision and issues a revocation
// version. The revoked delivery keeps its seal and original conclusion.
func (p *Plant) RevokeRelease(reason string) (release.Package, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return release.Package{}, errors.New("revocation reason is required")
	}
	return p.ReleaseBook.Revoke(release.NewAssembler(), reason, time.Now(), p.actorID())
}

// actorID identifies the operator/system performing a revocation. When no
// request identity is plumbed through, a stable per-plant UUID is used.
func (p *Plant) actorID() uuid.UUID {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.actor == uuid.Nil {
		p.actor = uuid.New()
	}
	return p.actor
}

// capturedPermit is a release-shaped snapshot of the interlock verdict taken
// at routing time.
type capturedPermit struct {
	Allowed  bool
	Reasons  []string
	Proofs   []model.Proof
	Revision string
}

func (p *Plant) captureRoutePermit(permit interlock.Permit, revision uuid.UUID) {
	p.mu.Lock()
	p.routePermit = &capturedPermit{
		Allowed:  permit.Allowed,
		Reasons:  append([]string(nil), permit.Reasons...),
		Proofs:   append([]model.Proof(nil), permit.Evidence...),
		Revision: revision.String(),
	}
	p.mu.Unlock()
}
