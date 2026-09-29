package service

import (
	"errors"
	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/model"
	"github.com/wyw14/solo-039/internal/release"
	"time"
)

// ReleasePackage is a re-export so the API layer can refer to service types.
type ReleasePackage = release.Package

// ReleaseInputsFor gathers the evidence the release assembler needs for one
// campaign revision, adapting the live plant components.
func (p *Plant) ReleaseInputsFor(revision string) (release.Inputs, error) {
	campaignState, err := p.campaignForRevision(revision)
	if err != nil {
		return release.Inputs{}, err
	}

	decisions := p.ProductAudit.ForRevision(revision)
	target := ""
	dispositions := make([]release.Disposition, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Plan.Target != "" {
			target = decision.Plan.Target
		}
		dispositions = append(dispositions, release.Disposition{
			Target: decision.Plan.Target,
			Opened: decision.Opened,
			Reason: decision.Reason,
			At:     decision.At.Unix(),
		})
	}
	if target == "" {
		if targets := p.ProductTargets(); len(targets) > 0 {
			target = targets[0]
		}
	}

	proofs := p.Evidence.Independent(revision)
	normalized := make([]model.Proof, 0, len(proofs))
	for _, proof := range proofs {
		// The catalog keeps proofs as gathered (some carry a value digest from
		// the field); the package must embed canonical, self-verifying proofs.
		if model.ProofDigest(proof) != proof.Digest {
			proof.Digest = model.ProofDigest(proof)
		}
		normalized = append(normalized, proof)
	}

	var interlockConclusion *release.InterlockConclusion
	if decision, ok := p.InterlockLog.Latest(revision); ok {
		interlockConclusion = &release.InterlockConclusion{
			Allowed: decision.Allowed,
			Reasons: decision.Reasons,
			Sources: decision.Sources,
			At:      decision.At,
		}
	}

	durability := p.durabilityForRevision(revision)

	return release.Inputs{
		Campaign:     campaignState,
		Target:       target,
		Feed:         p.feedForRevision(revision),
		Proofs:       normalized,
		Interlock:    interlockConclusion,
		Dispositions: dispositions,
		Events:       p.Journal.Events(),
		Durability:   durability,
	}, nil
}

// IssueRelease assembles and issues the first release package version.
func (p *Plant) IssueRelease(revision string) (release.Package, error) {
	in, err := p.ReleaseInputsFor(revision)
	if err != nil {
		return release.Package{}, err
	}
	return p.Releases.Issue(in, time.Now().Unix())
}

// SupplementRelease re-gathers evidence (after补证) and issues a new version.
func (p *Plant) SupplementRelease(revision string) (release.Package, error) {
	in, err := p.ReleaseInputsFor(revision)
	if err != nil {
		return release.Package{}, err
	}
	return p.Releases.Supplement(in, time.Now().Unix())
}

// RevokeRelease withdraws a release, preserving the old delivered versions.
func (p *Plant) RevokeRelease(revision, reason string) (release.Package, error) {
	if reason == "" {
		return release.Package{}, errors.New("revocation reason is required")
	}
	return p.Releases.Revoke(revision, reason, time.Now().Unix())
}

// ReleaseHistory returns every version issued for a revision.
func (p *Plant) ReleaseHistory(revision string) ([]release.Package, error) {
	return p.Releases.History(revision)
}

// ReleasePackageVersion fetches one frozen package version by id.
func (p *Plant) ReleasePackageVersion(id uuid.UUID) (release.Package, error) {
	return p.Releases.Get(id)
}

// campaignForRevision reconstructs the campaign state associated with a
// revision; after a grade transition the live state has moved on, so the
// campaign history is the source of truth.
func (p *Plant) campaignForRevision(revision string) (model.Campaign, error) {
	current := p.Campaign.Snapshot()
	if current.Revision.String() == revision {
		return current, nil
	}
	changes := p.CampaignHistory.ForRevision(revision)
	for i := len(changes) - 1; i >= 0; i-- {
		if changes[i].After.Revision.String() == revision {
			return changes[i].After, nil
		}
	}
	return model.Campaign{}, errors.New("no campaign found for revision " + revision)
}

// feedForRevision returns the feed switches observed while the given campaign
// revision was active (isolation of the previous source plus activation of the
// new one).
func (p *Plant) feedForRevision(revision string) []release.FeedChange {
	changes := p.FeedEvidence.List()
	out := make([]release.FeedChange, 0, 2)
	for _, change := range changes {
		if change.CampaignRevision.String() == revision {
			out = append(out, change)
		}
	}
	return out
}

// durabilityForRevision collects open incidents for the revision and every
// relief failure still relevant to batch durability.
func (p *Plant) durabilityForRevision(revision string) []release.DurabilityEvent {
	out := make([]release.DurabilityEvent, 0)
	for _, incident := range p.Incidents.List(false) {
		if incident.Revision != revision {
			continue
		}
		out = append(out, release.DurabilityEvent{
			Kind:     incident.Kind,
			Detail:   incident.Message,
			At:       incident.At.Unix(),
			Resolved: !incident.Open,
		})
	}
	for _, attempt := range p.ReliefHistory.Failures() {
		out = append(out, release.DurabilityEvent{
			Kind:     "relief-failure",
			Detail:   attempt.Error,
			At:       attempt.At.Unix(),
			Resolved: !attempt.State.TimedOut,
		})
	}
	return out
}
