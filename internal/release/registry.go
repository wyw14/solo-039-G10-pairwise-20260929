package release

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"sort"
	"sync"
)

// Registry keeps every issued package version. Versions are immutable:
// supplements and revocations always add a new version in the same lineage and
// never rewrite an older one, so a delivered package always verifies against
// the conclusion it originally carried.
type Registry struct {
	mu       sync.Mutex
	lineages map[string][]Package // keyed by campaign revision
}

func NewRegistry() *Registry {
	return &Registry{lineages: make(map[string][]Package)}
}

// Issue assembles and seals the first version for a revision.
func (r *Registry) Issue(in Inputs, now int64) (Package, error) {
	pkg := Build(in, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.lineages[pkg.Revision]; exists {
		return Package{}, fmt.Errorf("release package for revision %s already issued; supplement or revoke instead", pkg.Revision)
	}
	pkg.ID = uuid.New()
	pkg.Lineage = pkg.ID
	pkg.Version = 1
	pkg.Seal()
	if err := pkg.Verify(); err != nil {
		return Package{}, fmt.Errorf("refusing to issue unverifiable package: %w", err)
	}
	r.lineages[pkg.Revision] = []Package{pkg}
	return pkg, nil
}

// Supplement rebuilds a package from completed inputs and issues it as a new
// version, chaining to the previous one. The previous version is retained.
func (r *Registry) Supplement(in Inputs, now int64) (Package, error) {
	revision := in.Campaign.Revision.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	versions, ok := r.lineages[revision]
	if !ok {
		return Package{}, errors.New("no released package to supplement; issue one first")
	}
	previous := versions[len(versions)-1]
	if previous.Conclusion.Release == ReleaseRevoked {
		return Package{}, errors.New("cannot supplement a revoked package")
	}

	pkg := Build(in, now)
	if pkg.Conclusion.Release == ReleaseReleased {
		pkg.Conclusion.Release = ReleaseSupplemented
		pkg.Conclusion.Reason = "supplemented: " + pkg.Conclusion.Reason
	}
	pkg.ID = uuid.New()
	pkg.Lineage = previous.Lineage
	pkg.Version = len(versions) + 1
	pkg.Supersedes = previous.ID
	pkg.Action = ActionSupplement
	pkg.Seal()
	if err := pkg.Verify(); err != nil {
		return Package{}, fmt.Errorf("refusing to issue unverifiable supplement: %w", err)
	}
	r.lineages[revision] = append(versions, pkg)
	return pkg, nil
}

// Revoke withdraws the current conclusion for a revision. The revocation is
// itself a new sealed version carrying a copy of the withdrawn evidence; every
// older version stays in the lineage and verifies as it did when delivered.
func (r *Registry) Revoke(revision, reason string, now int64) (Package, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	versions, ok := r.lineages[revision]
	if !ok {
		return Package{}, errors.New("no released package to revoke")
	}
	previous := versions[len(versions)-1]
	if previous.Conclusion.Release == ReleaseRevoked {
		return Package{}, errors.New("release package is already revoked")
	}

	pkg := Package{
		ID:         uuid.New(),
		Lineage:    previous.Lineage,
		Version:    len(versions) + 1,
		Supersedes: previous.ID,
		Campaign:   previous.Campaign,
		Revision:   previous.Revision,
		Grade:      previous.Grade,
		Target:     previous.Target,
		IssuedAt:   now,
		Action:     ActionRevoke,
		Sections:   previous.Sections,
		Proofs:     previous.Proofs,
		Events:     previous.Events,
		Conclusion: Conclusion{
			Release:  ReleaseRevoked,
			Reason:   reason,
			Decision: previous.Conclusion.Decision,
		},
	}
	pkg.Seal()
	if err := pkg.Verify(); err != nil {
		return Package{}, fmt.Errorf("refusing to issue unverifiable revocation: %w", err)
	}
	r.lineages[revision] = append(versions, pkg)
	return pkg, nil
}

// Get returns any issued version by its package id.
func (r *Registry) Get(id uuid.UUID) (Package, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, versions := range r.lineages {
		for _, pkg := range versions {
			if pkg.ID == id {
				return pkg, nil
			}
		}
	}
	return Package{}, fmt.Errorf("release package %s not found", id)
}

// History returns all versions for a revision, oldest first.
func (r *Registry) History(revision string) ([]Package, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	versions, ok := r.lineages[revision]
	if !ok {
		return nil, fmt.Errorf("no release package for revision %s", revision)
	}
	return append([]Package(nil), versions...), nil
}

// Latest returns the current version for a revision.
func (r *Registry) Latest(revision string) (Package, error) {
	versions, err := r.History(revision)
	if err != nil {
		return Package{}, err
	}
	return versions[len(versions)-1], nil
}

// Revisions lists revisions that have packages, sorted.
func (r *Registry) Revisions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.lineages))
	for revision := range r.lineages {
		out = append(out, revision)
	}
	sort.Strings(out)
	return out
}
