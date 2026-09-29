// Package release assembles batch release evidence packages: feed revisions,
// analyzer proofs, interlock conclusions, product destinations and durable
// events are bound into one sealed package. Missing sections are flagged
// instead of failing assembly, and supplementary or revocation actions issue a
// new version while every previously delivered package stays independently
// verifiable.
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/model"
)

// Section names used both as map keys and in MissingItems. They are exported so
// callers (service, tests) can refer to a section without hard-coding strings.
const (
	SectionFeed      = "feed"
	SectionAnalyzer  = "analyzer"
	SectionInterlock = "interlock"
	SectionProduct   = "product"
	SectionDurable   = "durable"
)

// Sections lists the evidence sections every release package must cover.
func Sections() []string {
	return []string{SectionFeed, SectionAnalyzer, SectionInterlock, SectionProduct, SectionDurable}
}

// Status values for a section.
const (
	StatusPresent = "present"
	StatusMissing = "missing"
)

// Reference points at evidence kept outside the package (a journal event, a
// calibration record). It is part of the seal so a review can follow the link
// and confirm the referenced record.
type Reference struct {
	EventID  string `json:"event_id"`
	Kind     string `json:"kind"`
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
	At       int64  `json:"at"`
}

// Section is one evidence category. A section is either backed by Evidence or
// marked missing with a human-readable reason.
type Section struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason,omitempty"`
	Evidence   []model.Proof  `json:"evidence,omitempty"`
	References []Reference    `json:"references,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// Present reports whether the section carries evidence.
func (s Section) Present() bool { return s.Status == StatusPresent }

// Decision is the release conclusion a package was sealed under.
type Decision string

const (
	// Released means the batch was routed to product.
	Released Decision = "released"
	// Held means release was blocked by missing evidence or a denied interlock.
	Held Decision = "held"
	// Revoked means the release was withdrawn after delivery. The package that
	// carried the original release stays sealed and verifiable.
	Revoked Decision = "revoked"
)

// Package is an immutable, sealed version of a batch release evidence package.
type Package struct {
	ID         uuid.UUID          `json:"id"`
	Campaign   uuid.UUID          `json:"campaign"`
	Revision   uuid.UUID          `json:"revision"`
	CanID      string             `json:"can_id"`
	Version    int                `json:"version"`
	Decision   Decision           `json:"decision"`
	Sections   map[string]Section `json:"sections"`
	Missing    []string           `json:"missing"`
	Note       string             `json:"note,omitempty"`
	SealedAt   time.Time          `json:"sealed_at"`
	Supersedes uuid.UUID          `json:"supersedes,omitempty"`
	Seal       string             `json:"seal"`

	// Revoked is mutable state attached after delivery. It deliberately takes
	// no part in Seal so a revoked delivery still verifies its original
	// conclusion; Revocation carries the why.
	Revoked    bool       `json:"revoked"`
	Revocation string     `json:"revocation,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  uuid.UUID  `json:"revoked_by,omitempty"`
}

// Complete reports whether every required section is present.
func (p Package) Complete() bool { return len(p.Missing) == 0 }

// MissingItems enumerates sections that were not backed by evidence.
func (p Package) MissingItems() []string {
	out := make([]string, 0, len(p.Missing))
	return append(out, p.Missing...)
}

// Digest renders the content covered by the seal. It must not depend on map
// iteration order or on the mutable revocation fields.
func (p Package) Digest() string {
	var b strings.Builder
	b.WriteString("v1|")
	b.WriteString(p.ID.String())
	b.WriteString("|")
	b.WriteString(p.Campaign.String())
	b.WriteString("|")
	b.WriteString(p.Revision.String())
	b.WriteString("|")
	b.WriteString(p.CanID)
	b.WriteString("|")
	b.WriteString(strconv.Itoa(p.Version))
	b.WriteString("|")
	b.WriteString(string(p.Decision))
	b.WriteString("|")
	b.WriteString(p.Supersedes.String())
	b.WriteString("|")
	b.WriteString(p.Note)
	b.WriteString("|")
	b.WriteString(p.SealedAt.UTC().Format(time.RFC3339Nano))
	for _, name := range Sections() {
		section := p.Sections[name]
		b.WriteString("|#")
		b.WriteString(name)
		b.WriteString(":")
		b.WriteString(section.Status)
		b.WriteString(":")
		b.WriteString(section.Reason)
		if encoded, err := json.Marshal(canonicalDetail(section.Detail)); err == nil {
			b.WriteString(":")
			b.Write(encoded)
		}
		proofs := append([]model.Proof(nil), section.Evidence...)
		sort.SliceStable(proofs, func(i, j int) bool {
			if proofs[i].Source != proofs[j].Source {
				return proofs[i].Source < proofs[j].Source
			}
			return proofs[i].ID.String() < proofs[j].ID.String()
		})
		for _, proof := range proofs {
			b.WriteString("|")
			b.WriteString(proof.ID.String())
			b.WriteString("^")
			b.WriteString(proof.Revision.String())
			b.WriteString("^")
			b.WriteString(proof.Source)
			b.WriteString("^")
			b.WriteString(proof.Digest)
			b.WriteString("^")
			b.WriteString(strconv.FormatInt(proof.At, 10))
			if proof.Durable {
				b.WriteString("^D")
			}
			if proof.Independent {
				b.WriteString("^I")
			}
		}
		references := append([]Reference(nil), section.References...)
		sort.SliceStable(references, func(i, j int) bool {
			if references[i].Kind != references[j].Kind {
				return references[i].Kind < references[j].Kind
			}
			return references[i].EventID < references[j].EventID
		})
		for _, ref := range references {
			b.WriteString("|@")
			b.WriteString(ref.EventID)
			b.WriteString("^")
			b.WriteString(ref.Kind)
			b.WriteString("^")
			b.WriteString(ref.Revision)
			b.WriteString("^")
			b.WriteString(ref.Digest)
			b.WriteString("^")
			b.WriteString(strconv.FormatInt(ref.At, 10))
		}
	}
	for _, name := range p.Missing {
		b.WriteString("|~")
		b.WriteString(name)
	}
	hash := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(hash[:])
}

// Verify recomputes the seal and checks every embedded proof digest. A revoked
// or superseded package still verifies: verification answers "does this
// delivery still prove what it claimed when sealed", not "is it current".
func (p Package) Verify() error {
	if p.ID == uuid.Nil {
		return errors.New("package identity is missing")
	}
	if p.Seal == "" {
		return errors.New("package is not sealed")
	}
	if p.Digest() != p.Seal {
		return errors.New("package seal does not match its content")
	}
	for _, name := range Sections() {
		section := p.Sections[name]
		for _, proof := range section.Evidence {
			if proof.Digest == "" {
				return errors.New(name + " section carries a proof without digest")
			}
			if model.ProofDigest(proof) != proof.Digest {
				return errors.New(name + " section proof digest is invalid")
			}
		}
		for _, ref := range section.References {
			if ref.EventID == "" || ref.Kind == "" || ref.Digest == "" {
				return errors.New(name + " section carries an incomplete durable reference")
			}
		}
	}
	return nil
}

// Options controls one assembly action. The zero value assembles version 1 for
// the campaign revision from whatever sources provide.
type Options struct {
	// CanID ties a physical can to the package.
	CanID string
	// Decision forces the release conclusion. When empty it is derived:
	// released only when the package is complete and the interlock allowed.
	Decision Decision
	// Note documents why a version is issued.
	Note string
	// At is the seal time. Zero means time.Now.
	At time.Time
	// Supersedes chains a new version to the package it replaces.
	Supersedes uuid.UUID
	// Override replaces individual sections, keyed by Section* constants. It is
	// how resupplementation fills a previously missing section or replaces a
	// defective proof, and how revocation swaps the durable section.
	Override map[string]Section
}

// Sources supplies evidence for assembly. Every accessor is allowed to return
// empty values; the corresponding section is then marked missing.
type Sources struct {
	FeedRevision   uuid.UUID
	FeedSource     string
	FeedSwitch     *FeedSwitch
	AnalyzerProofs []model.Proof
	Permit         *PermitConclusion
	Destination    *Destination
	DurableEvents  []model.Event
}

// FeedSwitch captures the feed revision lineage (which route was isolated and
// which became active).
type FeedSwitch struct {
	OldRevision uuid.UUID
	OldSource   string
	OldClosed   bool
	NewRevision uuid.UUID
	NewSource   string
	NewOpened   bool
}

// PermitConclusion is the interlock decision bound at release time.
type PermitConclusion struct {
	Allowed bool
	Reasons []string
	Proofs  []model.Proof
}

// Destination records where released product went.
type Destination struct {
	Target string
	Opened bool
	Reason string
}

// Assembler seals packages from sources and keeps section construction in one
// place so service code cannot forget a category.
type Assembler struct {
	now func() time.Time
}

// NewAssembler builds an assembler using the wall clock.
func NewAssembler() *Assembler { return &Assembler{now: time.Now} }

func (a *Assembler) timestamp(at time.Time) time.Time {
	if !at.IsZero() {
		return at.UTC()
	}
	return a.now().UTC()
}

// Assemble seals a new package version for the campaign revision. Missing
// sections never abort assembly; they are listed on the package.
func (a *Assembler) Assemble(campaign model.Campaign, version int, sources Sources, opts Options) Package {
	sections := map[string]Section{
		SectionFeed:      a.feedSection(sources),
		SectionAnalyzer:  a.analyzerSection(sources),
		SectionInterlock: a.interlockSection(sources),
		SectionProduct:   a.productSection(sources),
		SectionDurable:   a.durableSection(sources),
	}
	for name, replacement := range opts.Override {
		if _, known := sections[name]; !known {
			continue
		}
		if replacement.Name == "" {
			replacement.Name = name
		}
		if replacement.Status == "" {
			replacement.Status = StatusPresent
		}
		sections[name] = replacement
	}

	missing := make([]string, 0)
	for _, name := range Sections() {
		if sections[name].Status != StatusPresent {
			missing = append(missing, name)
		}
	}

	decision := opts.Decision
	if decision == "" {
		decision = Released
		if len(missing) > 0 {
			decision = Held
		} else if sources.Permit != nil && !sources.Permit.Allowed {
			decision = Held
		} else if sources.Permit == nil {
			decision = Held
		} else if sources.Destination != nil && !sources.Destination.Opened {
			decision = Held
		}
	}

	pkg := Package{
		ID:         uuid.New(),
		Campaign:   campaign.ID,
		Revision:   campaign.Revision,
		CanID:      opts.CanID,
		Version:    version,
		Decision:   decision,
		Sections:   sections,
		Missing:    missing,
		Note:       opts.Note,
		SealedAt:   a.timestamp(opts.At),
		Supersedes: opts.Supersedes,
	}
	pkg.Seal = pkg.Digest()
	return pkg
}

func (a *Assembler) feedSection(s Sources) Section {
	section := Section{Name: SectionFeed}
	if s.FeedRevision == uuid.Nil {
		section.Status = StatusMissing
		section.Reason = "feed revision is not bound to the campaign"
		return section
	}
	proof := model.Proof{
		ID:       uuid.New(),
		Revision: s.FeedRevision,
		Source:   "feed-revision:" + s.FeedSource,
		At:       a.now().Unix(),
		Durable:  true,
	}
	proof.Digest = model.ProofDigest(proof)
	section.Status = StatusPresent
	section.Evidence = []model.Proof{proof}
	detail := map[string]any{"revision": s.FeedRevision.String(), "source": s.FeedSource}
	if s.FeedSwitch != nil {
		detail["old_revision"] = s.FeedSwitch.OldRevision.String()
		detail["old_source"] = s.FeedSwitch.OldSource
		detail["old_closed"] = s.FeedSwitch.OldClosed
		detail["new_revision"] = s.FeedSwitch.NewRevision.String()
		detail["new_source"] = s.FeedSwitch.NewSource
		detail["new_opened"] = s.FeedSwitch.NewOpened
	}
	section.Detail = detail
	return section
}

func (a *Assembler) analyzerSection(s Sources) Section {
	section := Section{Name: SectionAnalyzer}
	if len(s.AnalyzerProofs) == 0 {
		section.Status = StatusMissing
		section.Reason = "no independent analyzer proof on record for the feed revision"
		return section
	}
	section.Status = StatusPresent
	section.Evidence = append([]model.Proof(nil), s.AnalyzerProofs...)
	return section
}

func (a *Assembler) interlockSection(s Sources) Section {
	section := Section{Name: SectionInterlock}
	if s.Permit == nil {
		section.Status = StatusMissing
		section.Reason = "interlock was never evaluated for this release"
		return section
	}
	proof := model.Proof{
		ID:       uuid.New(),
		Revision: sectionRevision(s.Permit.Proofs),
		Source:   "interlock-permit",
		At:       a.now().Unix(),
	}
	allowed := "denied"
	if s.Permit.Allowed {
		allowed = "allowed"
		proof.Independent = true
	}
	proof.Digest = model.ProofDigest(proof)
	section.Status = StatusPresent
	// Only proofs whose digest recomputes via model.ProofDigest are embedded;
	// externally shaped proofs (for example a pressure reading with its own
	// digest scheme) are cited by source in the detail, never embedded where
	// Verify could reject them.
	cited := make([]string, 0, len(s.Permit.Proofs))
	for _, candidate := range s.Permit.Proofs {
		if candidate.Digest != "" && model.ProofDigest(candidate) == candidate.Digest {
			section.Evidence = append(section.Evidence, candidate)
		} else if candidate.Source != "" {
			cited = append(cited, candidate.Source)
		}
	}
	section.Evidence = append(section.Evidence, proof)
	section.Detail = map[string]any{"allowed": s.Permit.Allowed, "verdict": allowed, "reasons": append([]string(nil), s.Permit.Reasons...), "cited_sources": cited}
	return section
}

func (a *Assembler) productSection(s Sources) Section {
	section := Section{Name: SectionProduct}
	if s.Destination == nil || s.Destination.Target == "" {
		section.Status = StatusMissing
		section.Reason = "no product routing decision on record"
		return section
	}
	section.Status = StatusPresent
	section.Detail = map[string]any{
		"target": s.Destination.Target,
		"opened": s.Destination.Opened,
		"reason": s.Destination.Reason,
	}
	return section
}

func (a *Assembler) durableSection(s Sources) Section {
	section := Section{Name: SectionDurable}
	if len(s.DurableEvents) == 0 {
		section.Status = StatusMissing
		section.Reason = "no durable proof event written to the journal"
		return section
	}
	references := make([]Reference, 0, len(s.DurableEvents))
	kinds := make([]string, 0, len(s.DurableEvents))
	for _, event := range s.DurableEvents {
		references = append(references, Reference{
			EventID:  event.ID.String(),
			Kind:     event.Kind,
			Revision: event.Revision.String(),
			Digest:   event.Payload,
			At:       event.At,
		})
		kinds = append(kinds, event.Kind)
	}
	section.Status = StatusPresent
	section.References = references
	section.Detail = map[string]any{"events": kinds, "count": len(references)}
	return section
}

func sectionRevision(proofs []model.Proof) uuid.UUID {
	for _, proof := range proofs {
		if proof.Revision != uuid.Nil {
			return proof.Revision
		}
	}
	return uuid.Nil
}

// canonicalDetail renders section detail deterministically. encoding/json
// already sorts map keys; this additionally round-trips the value so only JSON
// types reach the seal and nil slices normalize consistently.
func canonicalDetail(detail map[string]any) map[string]any {
	if detail == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	if out == nil {
		return map[string]any{}
	}
	return out
}

// Book is the version register for one batch (can). Every issued version is
// retained forever; resupplementation and revocation append rather than mutate,
// so old deliveries keep verifying.
type Book struct {
	mu       sync.Mutex
	byID     map[uuid.UUID]Package
	versions []Package
}

// NewBook creates an empty register.
func NewBook() *Book {
	return &Book{byID: make(map[uuid.UUID]Package)}
}

// Issue seals and registers a new version. Version numbers are assigned by the
// book, starting at 1.
func (b *Book) Issue(assembler *Assembler, campaign model.Campaign, sources Sources, opts Options) (Package, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	next := len(b.versions) + 1
	pkg := assembler.Assemble(campaign, next, sources, opts)
	if err := pkg.Verify(); err != nil {
		return Package{}, err
	}
	b.byID[pkg.ID] = pkg
	b.versions = append(b.versions, pkg)
	return pkg, nil
}

// Latest returns the most recently issued version.
func (b *Book) Latest() (Package, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.versions) == 0 {
		return Package{}, errors.New("no release package issued")
	}
	return b.versions[len(b.versions)-1], nil
}

// Version returns a specific version number.
func (b *Book) Version(n int) (Package, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 1 || n > len(b.versions) {
		return Package{}, errors.New("release package version not found")
	}
	return b.versions[n-1], nil
}

// Get returns a package by its seal ID.
func (b *Book) Get(id uuid.UUID) (Package, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	pkg, ok := b.byID[id]
	if !ok {
		return Package{}, errors.New("release package not found")
	}
	return pkg, nil
}

// History returns every issued version, oldest first.
func (b *Book) History() []Package {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Package(nil), b.versions...)
}

// Resupplement issues a new version that carries the previous package forward
// and overrides sections with newly supplied evidence. The old package is not
// touched and still verifies.
func (b *Book) Resupplement(assembler *Assembler, sources Sources, opts Options) (Package, error) {
	b.mu.Lock()
	current, err := b.latestLocked()
	b.mu.Unlock()
	if err != nil {
		return Package{}, err
	}
	if opts.Decision == "" {
		opts.Decision = Released
	}
	if opts.Supersedes == uuid.Nil {
		opts.Supersedes = current.ID
	}
	if opts.CanID == "" {
		opts.CanID = current.CanID
	}
	campaign := model.Campaign{ID: current.Campaign, Revision: current.Revision}

	// Start from the sections the old package captured so resupplementation can
	// fill gaps even when the live sources no longer hold them, then apply the
	// fresh sources and the explicit overrides.
	merged := Options{
		CanID:      opts.CanID,
		Decision:   opts.Decision,
		Note:       opts.Note,
		At:         opts.At,
		Supersedes: opts.Supersedes,
		Override:   mergeSections(current.Sections, assembler, sources, opts.Override),
	}
	return b.Issue(assembler, campaign, Sources{
		FeedRevision: current.Revision,
		Permit:       permitFromSection(current.Sections[SectionInterlock]),
		Destination:  destinationFromSection(current.Sections[SectionProduct]),
	}, merged)
}

// Revoke marks every delivered version of the can (any package a customer might
// hold for this CanID) as revoked and issues a replacement version recording the
// withdrawal. The revoked deliveries stay sealed: Verify on them keeps
// succeeding and each decision remains what it was when delivered.
func (b *Book) Revoke(assembler *Assembler, reason string, at time.Time, by uuid.UUID) (Package, error) {
	if strings.TrimSpace(reason) == "" {
		return Package{}, errors.New("revocation reason is required")
	}
	b.mu.Lock()
	current, err := b.latestLocked()
	if err != nil {
		b.mu.Unlock()
		return Package{}, err
	}
	if current.Decision == Revoked {
		b.mu.Unlock()
		return Package{}, errors.New("latest release package is already revoked")
	}
	revokedAt := assembler.timestamp(at)
	for i, pkg := range b.versions {
		if pkg.CanID != current.CanID {
			continue
		}
		pkg.Revoked = true
		pkg.Revocation = reason
		pkg.RevokedAt = &revokedAt
		pkg.RevokedBy = by
		b.versions[i] = pkg
		b.byID[pkg.ID] = pkg
	}
	b.mu.Unlock()

	pkg, err := b.Issue(assembler, model.Campaign{ID: current.Campaign, Revision: current.Revision}, Sources{}, Options{
		CanID:      current.CanID,
		Decision:   Revoked,
		Note:       reason,
		At:         at,
		Supersedes: current.ID,
		Override:   copySections(current.Sections),
	})
	if err != nil {
		return Package{}, err
	}
	pkg.Revoked = true
	pkg.Revocation = reason
	pkg.RevokedAt = &revokedAt
	pkg.RevokedBy = by
	// Re-seal is not needed: revocation fields are outside the seal. Persist the
	// attached state in the register.
	b.mu.Lock()
	b.byID[pkg.ID] = pkg
	for i := range b.versions {
		if b.versions[i].ID == pkg.ID {
			b.versions[i] = pkg
		}
	}
	b.mu.Unlock()
	return pkg, nil
}

func (b *Book) latestLocked() (Package, error) {
	if len(b.versions) == 0 {
		return Package{}, errors.New("no release package issued")
	}
	return b.versions[len(b.versions)-1], nil
}

func copySections(in map[string]Section) map[string]Section {
	out := make(map[string]Section, len(in))
	for name, section := range in {
		section.Evidence = append([]model.Proof(nil), section.Evidence...)
		out[name] = section
	}
	return out
}

// mergeSections lets freshly assembled evidence replace the carried-forward
// section whenever it is present (the new version binds the subsystem's
// current evidence for the revision), keeps the old section when the live
// source has nothing newer, then applies explicit overrides last.
func mergeSections(previous map[string]Section, assembler *Assembler, sources Sources, override map[string]Section) map[string]Section {
	merged := copySections(previous)
	fresh := map[string]Section{
		SectionFeed:      assembler.feedSection(sources),
		SectionAnalyzer:  assembler.analyzerSection(sources),
		SectionInterlock: assembler.interlockSection(sources),
		SectionProduct:   assembler.productSection(sources),
		SectionDurable:   assembler.durableSection(sources),
	}
	for _, name := range Sections() {
		if fresh[name].Status == StatusPresent {
			merged[name] = fresh[name]
		}
	}
	for name, replacement := range override {
		if _, known := merged[name]; !known {
			continue
		}
		if replacement.Name == "" {
			replacement.Name = name
		}
		if replacement.Status == "" {
			replacement.Status = StatusPresent
		}
		merged[name] = replacement
	}
	return merged
}

func permitFromSection(section Section) *PermitConclusion {
	if section.Status != StatusPresent {
		return nil
	}
	permit := &PermitConclusion{}
	if allowed, ok := section.Detail["allowed"].(bool); ok {
		permit.Allowed = allowed
	}
	if reasons, ok := section.Detail["reasons"].([]string); ok {
		permit.Reasons = reasons
	}
	for _, proof := range section.Evidence {
		if proof.Source != "interlock-permit" {
			permit.Proofs = append(permit.Proofs, proof)
		}
	}
	return permit
}

func destinationFromSection(section Section) *Destination {
	if section.Status != StatusPresent {
		return nil
	}
	destination := &Destination{}
	if target, ok := section.Detail["target"].(string); ok {
		destination.Target = target
	}
	if opened, ok := section.Detail["opened"].(bool); ok {
		destination.Opened = opened
	}
	if reason, ok := section.Detail["reason"].(string); ok {
		destination.Reason = reason
	}
	return destination
}
