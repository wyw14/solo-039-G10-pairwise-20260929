package service

import (
	"github.com/wyw14/solo-039/internal/feed"
	"github.com/wyw14/solo-039/internal/release"
	"sync"
	"time"
)

// FeedEvidence records observed feed switches with their revisions, so a
// release package can reconstruct which feed was live during the batch.
type FeedEvidence struct {
	mu      sync.Mutex
	changes []release.FeedChange
}

func NewFeedEvidence() *FeedEvidence {
	return &FeedEvidence{changes: make([]release.FeedChange, 0, 16)}
}

func (f *FeedEvidence) Record(value feed.Transition) {
	f.mu.Lock()
	f.changes = append(f.changes, release.FeedChange{
		Stage:            value.Stage,
		CampaignRevision: value.CampaignRevision,
		OldSource:        value.OldSource,
		NewSource:        value.NewSource,
		OldRevision:      value.OldRevision,
		NewRevision:      value.NewRevision,
		At:               time.Now().Unix(),
	})
	f.mu.Unlock()
}

func (f *FeedEvidence) List() []release.FeedChange {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]release.FeedChange(nil), f.changes...)
}

func (f *FeedEvidence) Count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.changes) }
