package interlock

import (
	"github.com/wyw14/solo-039/internal/model"
	"sort"
	"sync"
)

// Decision is a persisted record of one interlock evaluation over a feed
// revision, so a release package can show why routing was permitted or denied.
type Decision struct {
	Revision string
	Allowed  bool
	Reasons  []string
	Sources  []string
	At       int64
}

// DecisionLog keeps interlock conclusions per revision.
type DecisionLog struct {
	mu        sync.Mutex
	decisions []Decision
}

func NewDecisionLog() *DecisionLog { return &DecisionLog{decisions: make([]Decision, 0, 16)} }

func (l *DecisionLog) Record(permit Permit, revision string, at int64) {
	sources := make([]string, 0, len(permit.Evidence))
	for _, proof := range permit.Evidence {
		sources = append(sources, proof.Source)
	}
	sort.Strings(sources)
	l.mu.Lock()
	l.decisions = append(l.decisions, Decision{
		Revision: revision,
		Allowed:  permit.Allowed,
		Reasons:  append([]string(nil), permit.Reasons...),
		Sources:  sources,
		At:       at,
	})
	l.mu.Unlock()
}

func (l *DecisionLog) ForRevision(revision string) []Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Decision, 0)
	for _, decision := range l.decisions {
		if decision.Revision == revision {
			out = append(out, decision)
		}
	}
	return out
}

// Latest returns the most recent evaluation for a revision.
func (l *DecisionLog) Latest(revision string) (Decision, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.decisions) - 1; i >= 0; i-- {
		if l.decisions[i].Revision == revision {
			return l.decisions[i], true
		}
	}
	return Decision{}, false
}

func (l *DecisionLog) Count() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.decisions) }

// SourcesOf is a convenience for the evidence names backing a proof list.
func SourcesOf(proofs []model.Proof) []string { return EvidenceSources(proofs) }
