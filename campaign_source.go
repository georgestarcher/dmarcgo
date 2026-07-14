package dmarcgo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// CampaignConfigurationSnapshotVersion identifies the deterministic source
// resolution and merge contract.
const CampaignConfigurationSnapshotVersion = "1"

const (
	defaultCampaignMaximumSources     = 64
	defaultCampaignMaximumImportDepth = 8
	defaultCampaignDirectoryFiles     = 64
)

var (
	// ErrInvalidCampaignSourceOptions identifies empty source sets or invalid
	// source IDs, limits, roots, priorities, or adapters.
	ErrInvalidCampaignSourceOptions = errors.New("invalid campaign source options")
	// ErrCampaignSourceFailed identifies a required source, import, integrity,
	// or conflict failure. Error text never includes source-controlled values.
	ErrCampaignSourceFailed = errors.New("campaign configuration source failed")
	// ErrCampaignImportCycle identifies an import cycle among explicitly
	// supplied sources.
	ErrCampaignImportCycle = errors.New("campaign configuration import cycle")
	// ErrCampaignImportDepth identifies an import graph beyond the caller's
	// bounded depth.
	ErrCampaignImportDepth = errors.New("campaign configuration import depth exceeded")
)

// CampaignSourceFailurePolicy controls whether required-source failure returns
// a partial snapshot alone or a partial snapshot plus an error. Neither policy
// authorizes traffic from missing, invalid, or stale data.
type CampaignSourceFailurePolicy string

const (
	// CampaignSourceFailOpen continues ordinary analysis with authorization
	// disabled for an incomplete required inventory.
	CampaignSourceFailOpen CampaignSourceFailurePolicy = "fail_open"
	// CampaignSourceFailClosed returns ErrCampaignSourceFailed with the same
	// immutable partial snapshot.
	CampaignSourceFailClosed CampaignSourceFailurePolicy = "fail_closed"
)

// CampaignSourceState is the terminal state of one explicitly supplied source.
type CampaignSourceState string

const (
	CampaignSourceLoaded        CampaignSourceState = "loaded"
	CampaignSourceFailed        CampaignSourceState = "failed"
	CampaignSourceFuture        CampaignSourceState = "future"
	CampaignSourceExpired       CampaignSourceState = "expired"
	CampaignSourceStale         CampaignSourceState = "stale"
	CampaignSourceNotSelected   CampaignSourceState = "not_selected"
	CampaignSourceLastKnownGood CampaignSourceState = "last_known_good"
)

// CampaignConfigurationMetadata is adapter-supplied retrieval metadata. It is
// untrusted structured provenance. Signature bytes are passed only to an
// explicit verifier and are not retained in snapshots or routine output.
type CampaignConfigurationMetadata struct {
	RetrievedAt       time.Time
	ETag              string
	LastModified      time.Time
	ContentType       string
	DetachedSignature []byte
}

// CampaignConfigurationSource is an explicit caller-selected byte source.
// Implementations must honor context cancellation and must not hide refreshes,
// retries, caches, credentials, or last-known-good behavior.
type CampaignConfigurationSource interface {
	Load(context.Context) ([]byte, CampaignConfigurationMetadata, error)
}

// CampaignIntegrityVerifier verifies caller-selected detached integrity data.
// It receives defensive byte and metadata copies; mutations are discarded.
// Its errors are converted to value-safe diagnostics without copying text.
type CampaignIntegrityVerifier interface {
	Verify(context.Context, []byte, CampaignConfigurationMetadata) error
}

// CampaignConfigurationSourceSpec supplies caller-owned trust and override
// policy. Higher Priority wins only when its exact campaign ID is explicitly
// listed in ReplaceCampaignIDs; equal or implicit conflicts fail safely.
type CampaignConfigurationSourceSpec struct {
	ID                 string
	Source             CampaignConfigurationSource
	Required           bool
	Priority           int
	ReplaceCampaignIDs []string
	Verifier           CampaignIntegrityVerifier
}

// CampaignConfigurationResolveOptions bounds explicit loading and merging.
// Clock defaults to time.Now because this is an explicit I/O stage. A pure
// classifier never consults a clock.
type CampaignConfigurationResolveOptions struct {
	Clock              Clock
	RootSourceIDs      []string
	FailurePolicy      CampaignSourceFailurePolicy
	MaximumAge         time.Duration
	MaximumSources     int
	MaximumImportDepth int
	UseLastKnownGood   bool
	LastKnownGood      *CampaignConfigurationSnapshot
	// ProviderCatalog is optional context for detecting catalog drift. A
	// missing catalog entry never grants or removes campaign authorization.
	ProviderCatalog *ProviderCatalog
}

// CampaignSourceProvenance is immutable source and freshness evidence.
type CampaignSourceProvenance struct {
	SourceID           string              `json:"source_id"`
	Required           bool                `json:"required"`
	Priority           int                 `json:"priority"`
	ReplaceCampaignIDs []string            `json:"replace_campaign_ids"`
	State              CampaignSourceState `json:"state"`
	ContentDigest      AnalysisID          `json:"content_digest,omitempty"`
	DocumentDigest     AnalysisID          `json:"document_digest,omitempty"`
	GeneratedAt        time.Time           `json:"generated_at,omitempty"`
	EffectiveAt        time.Time           `json:"effective_at,omitempty"`
	ExpiresAt          time.Time           `json:"expires_at,omitempty"`
	RetrievedAt        time.Time           `json:"retrieved_at,omitempty"`
	LastModified       time.Time           `json:"last_modified,omitempty"`
	ETag               string              `json:"etag,omitempty"`
	ContentType        string              `json:"content_type,omitempty"`
	IntegrityVerified  bool                `json:"integrity_verified"`
	Sensitivity        Sensitivity         `json:"sensitivity"`
}

// CampaignSourceDiagnostic is library-generated and never interpolates source
// IDs, paths, URLs, HTTP text, parser values, or verifier errors.
type CampaignSourceDiagnostic struct {
	ID          AnalysisID      `json:"id"`
	Code        DiagnosticCode  `json:"code"`
	Severity    FindingSeverity `json:"severity"`
	SourceID    string          `json:"source_id,omitempty"`
	Message     string          `json:"message"`
	Sensitivity Sensitivity     `json:"sensitivity"`
}

// CampaignConfigurationSnapshot is an immutable resolved inventory. It owns
// complete source provenance and normalized campaigns and can be reused
// concurrently by pure classifiers.
type CampaignConfigurationSnapshot struct {
	metadata               ResultMetadata
	version                string
	digest                 AnalysisID
	previousDigest         AnalysisID
	complete               bool
	authorizationAvailable bool
	effectiveAt            time.Time
	expiresAt              time.Time
	campaigns              []SecuritySimulationCampaign
	sources                []CampaignSourceProvenance
	diagnostics            []CampaignSourceDiagnostic
}

func (snapshot CampaignConfigurationSnapshot) ResultMetadata() ResultMetadata {
	return snapshot.metadata
}
func (snapshot CampaignConfigurationSnapshot) Version() string    { return snapshot.version }
func (snapshot CampaignConfigurationSnapshot) Digest() AnalysisID { return snapshot.digest }
func (snapshot CampaignConfigurationSnapshot) PreviousDigest() AnalysisID {
	return snapshot.previousDigest
}
func (snapshot CampaignConfigurationSnapshot) Complete() bool { return snapshot.complete }
func (snapshot CampaignConfigurationSnapshot) AuthorizationAvailable() bool {
	return snapshot.authorizationAvailable
}
func (snapshot CampaignConfigurationSnapshot) EffectiveAt() time.Time { return snapshot.effectiveAt }
func (snapshot CampaignConfigurationSnapshot) ExpiresAt() time.Time   { return snapshot.expiresAt }
func (snapshot CampaignConfigurationSnapshot) Campaigns() []SecuritySimulationCampaign {
	return cloneSecuritySimulationCampaigns(snapshot.campaigns)
}
func (snapshot CampaignConfigurationSnapshot) Sources() []CampaignSourceProvenance {
	return cloneCampaignSourceProvenance(snapshot.sources)
}
func (snapshot CampaignConfigurationSnapshot) Diagnostics() []CampaignSourceDiagnostic {
	return append([]CampaignSourceDiagnostic(nil), snapshot.diagnostics...)
}

type campaignLoadedSource struct {
	spec       normalizedCampaignSourceSpec
	document   CampaignConfigurationDocument
	provenance CampaignSourceProvenance
	usable     bool
}

type normalizedCampaignSourceSpec struct {
	id           string
	source       CampaignConfigurationSource
	required     bool
	priority     int
	replacements map[string]struct{}
	verifier     CampaignIntegrityVerifier
}

type campaignSourceResolver struct {
	ctx             context.Context
	options         CampaignConfigurationResolveOptions
	now             time.Time
	specs           map[string]normalizedCampaignSourceSpec
	loaded          map[string]*campaignLoadedSource
	selected        map[string]bool
	runtimeRequired map[string]bool
	visiting        map[string]bool
	visited         map[string]bool
	diagnostics     []CampaignSourceDiagnostic
	requiredFailure bool
	graphFailure    bool
}

// ResolveCampaignConfiguration explicitly loads, verifies, parses, traverses,
// and merges only caller-supplied sources. At least one source is required. It
// performs no DNS, report parsing, mailbox access, credential discovery, or
// implicit network refresh.
func ResolveCampaignConfiguration(ctx context.Context, specs []CampaignConfigurationSourceSpec, options CampaignConfigurationResolveOptions) (CampaignConfigurationSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	options, normalized, err := normalizeCampaignSourceOptions(specs, options)
	if err != nil {
		return CampaignConfigurationSnapshot{}, err
	}
	now := options.Clock.Now().UTC()
	if !campaignTimeMarshalable(now) {
		return CampaignConfigurationSnapshot{}, ErrInvalidCampaignSourceOptions
	}
	resolver := campaignSourceResolver{
		ctx: ctx, options: options, now: now, specs: normalized,
		loaded: map[string]*campaignLoadedSource{}, selected: map[string]bool{}, runtimeRequired: map[string]bool{},
		visiting: map[string]bool{}, visited: map[string]bool{},
	}
	roots := options.RootSourceIDs
	if len(roots) == 0 {
		roots = make([]string, 0, len(normalized))
		for id := range normalized {
			roots = append(roots, id)
		}
		sort.Strings(roots)
	}
	for _, id := range roots {
		spec := normalized[id]
		resolver.runtimeRequired[id] = spec.required
		if visitErr := resolver.visit(id, 0); visitErr != nil {
			if errors.Is(visitErr, context.Canceled) || errors.Is(visitErr, context.DeadlineExceeded) {
				snapshot, snapshotErr := resolver.snapshot(nil, false, false)
				if snapshotErr != nil {
					return snapshot, errors.Join(visitErr, snapshotErr)
				}
				return snapshot, visitErr
			}
			resolver.graphFailure = true
		}
	}
	campaigns, mergeComplete := resolver.mergeCampaigns()
	resolver.validateProviderCatalog(campaigns)
	usableSelectedSource := resolver.hasUsableSelectedSource()
	complete := usableSelectedSource && !resolver.requiredFailure && !resolver.graphFailure && mergeComplete
	authorizationAvailable := usableSelectedSource && !resolver.requiredFailure && !resolver.graphFailure
	snapshot, err := resolver.snapshot(campaigns, complete, authorizationAvailable)
	if err != nil {
		return snapshot, err
	}
	if !authorizationAvailable && options.UseLastKnownGood && validCampaignLastKnownGood(options.LastKnownGood, resolver.now, options.MaximumAge) {
		snapshot, err = resolver.lastKnownGoodSnapshot(*options.LastKnownGood)
		if err != nil {
			return snapshot, err
		}
	}
	if options.FailurePolicy == CampaignSourceFailClosed && !snapshot.complete {
		return snapshot, ErrCampaignSourceFailed
	}
	return snapshot, nil
}

func (resolver *campaignSourceResolver) hasUsableSelectedSource() bool {
	for id := range resolver.selected {
		if loaded, ok := resolver.loaded[id]; ok && loaded.usable {
			return true
		}
	}
	return false
}

func normalizeCampaignSourceOptions(specs []CampaignConfigurationSourceSpec, options CampaignConfigurationResolveOptions) (CampaignConfigurationResolveOptions, map[string]normalizedCampaignSourceSpec, error) {
	if options.Clock == nil {
		options.Clock = ClockFunc(time.Now)
	}
	if options.FailurePolicy == "" {
		options.FailurePolicy = CampaignSourceFailOpen
	}
	if options.FailurePolicy != CampaignSourceFailOpen && options.FailurePolicy != CampaignSourceFailClosed || options.MaximumAge < 0 {
		return options, nil, ErrInvalidCampaignSourceOptions
	}
	if options.MaximumSources == 0 {
		options.MaximumSources = defaultCampaignMaximumSources
	}
	if options.MaximumImportDepth == 0 {
		options.MaximumImportDepth = defaultCampaignMaximumImportDepth
	}
	if options.MaximumSources < 1 || options.MaximumSources > maxCampaignDefinitions || options.MaximumImportDepth < 1 || options.MaximumImportDepth > 64 || len(specs) == 0 || len(specs) > options.MaximumSources {
		return options, nil, ErrInvalidCampaignSourceOptions
	}
	normalized := make(map[string]normalizedCampaignSourceSpec, len(specs))
	for _, value := range specs {
		id, ok := normalizeConfigID(value.ID)
		if !ok || nilCampaignConfigurationSource(value.Source) || value.Priority < 0 {
			return options, nil, ErrInvalidCampaignSourceOptions
		}
		if _, duplicate := normalized[id]; duplicate {
			return options, nil, ErrInvalidCampaignSourceOptions
		}
		replacements := map[string]struct{}{}
		for _, raw := range value.ReplaceCampaignIDs {
			campaignID, valid := normalizeConfigID(raw)
			if !valid {
				return options, nil, ErrInvalidCampaignSourceOptions
			}
			replacements[campaignID] = struct{}{}
		}
		normalized[id] = normalizedCampaignSourceSpec{id: id, source: value.Source, required: value.Required, priority: value.Priority, replacements: replacements, verifier: value.Verifier}
	}
	roots := make([]string, 0, len(options.RootSourceIDs))
	seenRoots := map[string]struct{}{}
	for _, raw := range options.RootSourceIDs {
		id, ok := normalizeConfigID(raw)
		if !ok {
			return options, nil, ErrInvalidCampaignSourceOptions
		}
		if _, exists := normalized[id]; !exists {
			return options, nil, ErrInvalidCampaignSourceOptions
		}
		if _, duplicate := seenRoots[id]; !duplicate {
			seenRoots[id] = struct{}{}
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	options.RootSourceIDs = roots
	if options.UseLastKnownGood && options.LastKnownGood == nil {
		return options, nil, ErrInvalidCampaignSourceOptions
	}
	if options.ProviderCatalog != nil && options.ProviderCatalog.digest == "" {
		return options, nil, ErrInvalidCampaignSourceOptions
	}
	return options, normalized, nil
}

func (resolver *campaignSourceResolver) visit(id string, depth int) error {
	if depth > resolver.options.MaximumImportDepth {
		resolver.requiredFailure = resolver.requiredFailure || resolver.runtimeRequired[id]
		resolver.addDiagnostic("campaign.source.import_depth", FindingSeverityHigh, id, "The campaign import graph exceeds the configured depth limit.")
		return ErrCampaignImportDepth
	}
	if resolver.visiting[id] {
		resolver.requiredFailure = resolver.requiredFailure || resolver.runtimeRequired[id]
		resolver.addDiagnostic("campaign.source.import_cycle", FindingSeverityHigh, id, "The campaign import graph contains a cycle.")
		return ErrCampaignImportCycle
	}
	if resolver.visited[id] {
		if resolver.runtimeRequired[id] {
			if loaded, ok := resolver.loaded[id]; ok && !loaded.usable {
				resolver.requiredFailure = true
			}
		}
		return nil
	}
	if len(resolver.selected) >= resolver.options.MaximumSources {
		resolver.requiredFailure = resolver.requiredFailure || resolver.runtimeRequired[id]
		resolver.addDiagnostic("campaign.source.limit", FindingSeverityHigh, id, "The campaign source count exceeds the configured limit.")
		return ErrCampaignSourceFailed
	}
	spec, exists := resolver.specs[id]
	if !exists {
		resolver.requiredFailure = resolver.requiredFailure || resolver.runtimeRequired[id]
		resolver.addDiagnostic("campaign.source.import_missing", FindingSeverityHigh, "", "A declared campaign import was not supplied by the caller.")
		return ErrCampaignSourceFailed
	}
	resolver.selected[id] = true
	resolver.visiting[id] = true
	defer delete(resolver.visiting, id)
	loaded, loadErr := resolver.load(spec)
	resolver.loaded[id] = loaded
	if loadErr != nil {
		return loadErr
	}
	if !loaded.usable {
		resolver.requiredFailure = resolver.requiredFailure || resolver.runtimeRequired[id] || spec.required
		resolver.visited[id] = true
		return nil
	}
	for _, imported := range loaded.document.Imports() {
		resolver.runtimeRequired[imported.SourceID] = resolver.runtimeRequired[imported.SourceID] || imported.Required
		if err := resolver.visit(imported.SourceID, depth+1); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if imported.Required {
				resolver.requiredFailure = true
			}
		}
	}
	resolver.visited[id] = true
	return nil
}

func (resolver *campaignSourceResolver) load(spec normalizedCampaignSourceSpec) (*campaignLoadedSource, error) {
	provenance := CampaignSourceProvenance{SourceID: spec.id, Required: spec.required || resolver.runtimeRequired[spec.id], Priority: spec.priority, ReplaceCampaignIDs: campaignReplacementIDs(spec.replacements), State: CampaignSourceFailed, Sensitivity: SensitivityRestricted}
	data, metadata, err := spec.source.Load(resolver.ctx)
	if err != nil {
		resolver.addDiagnostic("campaign.source.unavailable", FindingSeverityHigh, spec.id, "A campaign configuration source was unavailable.")
		loaded := &campaignLoadedSource{spec: spec, provenance: provenance}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return loaded, err
		}
		return loaded, nil
	}
	if len(data) > maxCampaignConfigurationBytes {
		resolver.addDiagnostic("campaign.source.too_large", FindingSeverityHigh, spec.id, "A campaign configuration source exceeded the size limit.")
		return &campaignLoadedSource{spec: spec, provenance: provenance}, nil
	}
	provenance.ContentDigest = StableAnalysisID("campaign_source_content", string(data))
	if metadata.RetrievedAt.IsZero() {
		metadata.RetrievedAt = resolver.now
	}
	metadata.RetrievedAt = metadata.RetrievedAt.UTC()
	metadata.LastModified = metadata.LastModified.UTC()
	if !campaignTimeMarshalable(metadata.RetrievedAt) || !campaignTimeMarshalable(metadata.LastModified) {
		resolver.addDiagnostic("campaign.source.invalid_metadata_time", FindingSeverityHigh, spec.id, "Campaign source retrieval metadata contained a timestamp outside the supported JSON range.")
		return &campaignLoadedSource{spec: spec, provenance: provenance}, nil
	}
	provenance.RetrievedAt = metadata.RetrievedAt
	provenance.LastModified = metadata.LastModified
	provenance.ETag = boundedCampaignMetadata(metadata.ETag)
	provenance.ContentType = boundedCampaignMetadata(metadata.ContentType)
	if spec.verifier != nil {
		verificationData := append([]byte(nil), data...)
		verificationMetadata := cloneCampaignConfigurationMetadata(metadata)
		if err := spec.verifier.Verify(resolver.ctx, verificationData, verificationMetadata); err != nil {
			resolver.addDiagnostic("campaign.source.integrity_failed", FindingSeverityHigh, spec.id, "Campaign configuration integrity verification failed.")
			loaded := &campaignLoadedSource{spec: spec, provenance: provenance}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return loaded, err
			}
			return loaded, nil
		}
		provenance.IntegrityVerified = true
	}
	document, err := LoadCampaignConfiguration(data)
	if err != nil {
		resolver.addDiagnostic("campaign.source.invalid", FindingSeverityHigh, spec.id, "A campaign configuration source could not be parsed and normalized.")
		return &campaignLoadedSource{spec: spec, provenance: provenance}, nil
	}
	provenance.DocumentDigest = document.Digest()
	provenance.GeneratedAt = document.GeneratedAt()
	provenance.EffectiveAt = document.EffectiveAt()
	provenance.ExpiresAt = document.ExpiresAt()
	switch {
	case document.GeneratedAt().After(resolver.now):
		provenance.State = CampaignSourceFuture
		resolver.addDiagnostic("campaign.source.future", FindingSeverityMedium, spec.id, "A campaign configuration source has a future generation time.")
		return &campaignLoadedSource{spec: spec, document: document, provenance: provenance}, nil
	case resolver.now.Before(document.EffectiveAt()):
		provenance.State = CampaignSourceFuture
		resolver.addDiagnostic("campaign.source.future", FindingSeverityMedium, spec.id, "A campaign configuration source is not effective yet.")
		return &campaignLoadedSource{spec: spec, document: document, provenance: provenance}, nil
	case !resolver.now.Before(document.ExpiresAt()):
		provenance.State = CampaignSourceExpired
		resolver.addDiagnostic("campaign.source.expired", FindingSeverityHigh, spec.id, "A campaign configuration source has expired.")
		return &campaignLoadedSource{spec: spec, document: document, provenance: provenance}, nil
	case resolver.options.MaximumAge > 0 && resolver.now.Sub(document.GeneratedAt()) > resolver.options.MaximumAge:
		provenance.State = CampaignSourceStale
		resolver.addDiagnostic("campaign.source.stale", FindingSeverityHigh, spec.id, "A campaign configuration source exceeds the configured maximum age.")
		return &campaignLoadedSource{spec: spec, document: document, provenance: provenance}, nil
	default:
		provenance.State = CampaignSourceLoaded
		return &campaignLoadedSource{spec: spec, document: document, provenance: provenance, usable: true}, nil
	}
}

func (resolver *campaignSourceResolver) mergeCampaigns() ([]SecuritySimulationCampaign, bool) {
	sources := make([]*campaignLoadedSource, 0, len(resolver.loaded))
	for id, value := range resolver.loaded {
		if resolver.selected[id] && value.usable {
			sources = append(sources, value)
		}
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].spec.priority != sources[j].spec.priority {
			return sources[i].spec.priority > sources[j].spec.priority
		}
		return sources[i].spec.id < sources[j].spec.id
	})
	byID := map[string]SecuritySimulationCampaign{}
	owners := map[string]*campaignLoadedSource{}
	conflicts := map[string]struct{}{}
	complete := true
	for _, source := range sources {
		for _, campaign := range source.document.Campaigns() {
			campaign.SourceID = source.spec.id
			campaign.SourcePriority = source.spec.priority
			current, exists := byID[campaign.ID]
			if !exists {
				byID[campaign.ID] = campaign
				owners[campaign.ID] = source
				continue
			}
			if current.Digest == campaign.Digest {
				continue
			}
			winner := owners[campaign.ID]
			_, explicitlyReplaced := winner.spec.replacements[campaign.ID]
			if winner.spec.priority > source.spec.priority && explicitlyReplaced {
				resolver.addDiagnostic("campaign.source.override_applied", FindingSeverityInfo, winner.spec.id, "A higher-priority source explicitly replaced a campaign definition.")
				continue
			}
			delete(byID, campaign.ID)
			delete(owners, campaign.ID)
			conflicts[campaign.ID] = struct{}{}
			complete = false
			resolver.addDiagnostic("campaign.source.definition_conflict", FindingSeverityHigh, "", "Conflicting campaign definitions were excluded from authorization.")
		}
	}
	result := make([]SecuritySimulationCampaign, 0, len(byID))
	for id, campaign := range byID {
		if _, conflicted := conflicts[id]; !conflicted {
			result = append(result, campaign)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, complete
}

func (resolver *campaignSourceResolver) validateProviderCatalog(campaigns []SecuritySimulationCampaign) {
	if resolver.options.ProviderCatalog == nil {
		return
	}
	for _, campaign := range campaigns {
		if campaign.Provider.Type != CampaignProviderCatalog {
			continue
		}
		if _, ok := resolver.options.ProviderCatalog.LookupProvider(campaign.Provider.ID); !ok {
			resolver.addDiagnostic("campaign.provider.catalog_drift", FindingSeverityMedium, campaign.SourceID, "A campaign references a provider absent from the supplied provider catalog.")
		}
	}
}

func (resolver *campaignSourceResolver) snapshot(campaigns []SecuritySimulationCampaign, complete, authorizationAvailable bool) (CampaignConfigurationSnapshot, error) {
	sources := make([]CampaignSourceProvenance, 0, len(resolver.specs))
	for id, spec := range resolver.specs {
		if loaded, ok := resolver.loaded[id]; ok {
			loaded.provenance.Required = loaded.provenance.Required || resolver.runtimeRequired[id]
			sources = append(sources, loaded.provenance)
		} else {
			sources = append(sources, CampaignSourceProvenance{SourceID: id, Required: spec.required, Priority: spec.priority, ReplaceCampaignIDs: campaignReplacementIDs(spec.replacements), State: CampaignSourceNotSelected, Sensitivity: SensitivityRestricted})
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourceID < sources[j].SourceID })
	sort.Slice(resolver.diagnostics, func(i, j int) bool { return resolver.diagnostics[i].ID < resolver.diagnostics[j].ID })
	effectiveAt, expiresAt := campaignSnapshotBounds(sources, resolver.options.MaximumAge)
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeCampaignValidation, GeneratedAt: resolver.now, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
	snapshot := CampaignConfigurationSnapshot{
		metadata: metadata, version: CampaignConfigurationSnapshotVersion, complete: complete, authorizationAvailable: authorizationAvailable,
		effectiveAt: effectiveAt, expiresAt: expiresAt, campaigns: cloneSecuritySimulationCampaigns(campaigns),
		sources: cloneCampaignSourceProvenance(sources), diagnostics: append([]CampaignSourceDiagnostic(nil), resolver.diagnostics...),
	}
	digest, err := campaignConfigurationSnapshotDigest(snapshot)
	if err != nil {
		return snapshot, ErrCampaignSourceFailed
	}
	snapshot.digest = digest
	return snapshot, nil
}

func (resolver *campaignSourceResolver) lastKnownGoodSnapshot(previous CampaignConfigurationSnapshot) (CampaignConfigurationSnapshot, error) {
	resolver.addDiagnostic("campaign.source.last_known_good", FindingSeverityMedium, "", "A caller-supplied last-known-good campaign snapshot was used.")
	snapshot, err := resolver.snapshot(previous.campaigns, false, true)
	if err != nil {
		return snapshot, err
	}
	snapshot.previousDigest = previous.digest
	snapshot.effectiveAt = previous.effectiveAt
	snapshot.expiresAt = campaignLastKnownGoodExpiresAt(&previous, resolver.options.MaximumAge)
	snapshot.sources = cloneCampaignSourceProvenance(previous.sources)
	for index := range snapshot.sources {
		if snapshot.sources[index].State == CampaignSourceLoaded || snapshot.sources[index].State == CampaignSourceLastKnownGood {
			snapshot.sources[index].State = CampaignSourceLastKnownGood
		}
	}
	digest, err := campaignConfigurationSnapshotDigest(snapshot)
	if err != nil {
		return snapshot, ErrCampaignSourceFailed
	}
	snapshot.digest = digest
	return snapshot, nil
}

func campaignConfigurationSnapshotDigest(snapshot CampaignConfigurationSnapshot) (AnalysisID, error) {
	canonical, err := json.Marshal(struct {
		Version                string                       `json:"version"`
		GeneratedAt            time.Time                    `json:"generated_at"`
		PreviousDigest         AnalysisID                   `json:"previous_digest,omitempty"`
		Complete               bool                         `json:"complete"`
		AuthorizationAvailable bool                         `json:"authorization_available"`
		EffectiveAt            time.Time                    `json:"effective_at"`
		ExpiresAt              time.Time                    `json:"expires_at"`
		Campaigns              []SecuritySimulationCampaign `json:"campaigns"`
		Sources                []CampaignSourceProvenance   `json:"sources"`
		Diagnostics            []CampaignSourceDiagnostic   `json:"diagnostics"`
	}{snapshot.version, snapshot.metadata.GeneratedAt, snapshot.previousDigest, snapshot.complete, snapshot.authorizationAvailable, snapshot.effectiveAt, snapshot.expiresAt, snapshot.campaigns, snapshot.sources, snapshot.diagnostics})
	if err != nil {
		return "", err
	}
	return StableAnalysisID("campaign_configuration_snapshot", string(canonical)), nil
}

func campaignSnapshotBounds(sources []CampaignSourceProvenance, maximumAge time.Duration) (time.Time, time.Time) {
	var effectiveAt, expiresAt time.Time
	for _, source := range sources {
		if source.State != CampaignSourceLoaded && source.State != CampaignSourceLastKnownGood {
			continue
		}
		if effectiveAt.IsZero() || source.EffectiveAt.After(effectiveAt) {
			effectiveAt = source.EffectiveAt
		}
		sourceExpiresAt := source.ExpiresAt
		if maximumAge > 0 {
			freshUntil := source.GeneratedAt.Add(maximumAge)
			if sourceExpiresAt.IsZero() || freshUntil.Before(sourceExpiresAt) {
				sourceExpiresAt = freshUntil
			}
		}
		if expiresAt.IsZero() || sourceExpiresAt.Before(expiresAt) {
			expiresAt = sourceExpiresAt
		}
	}
	return effectiveAt, expiresAt
}

func validCampaignLastKnownGood(snapshot *CampaignConfigurationSnapshot, now time.Time, maximumAge time.Duration) bool {
	if snapshot == nil || snapshot.digest == "" || !snapshot.complete || !snapshot.authorizationAvailable ||
		snapshot.metadata.GeneratedAt.IsZero() || now.Before(snapshot.metadata.GeneratedAt) ||
		snapshot.effectiveAt.IsZero() || now.Before(snapshot.effectiveAt) {
		return false
	}
	expiresAt := campaignLastKnownGoodExpiresAt(snapshot, maximumAge)
	return !expiresAt.IsZero() && now.Before(expiresAt)
}

func campaignLastKnownGoodExpiresAt(snapshot *CampaignConfigurationSnapshot, maximumAge time.Duration) time.Time {
	if snapshot == nil || snapshot.expiresAt.IsZero() {
		return time.Time{}
	}
	_, currentPolicyExpiry := campaignSnapshotBounds(snapshot.sources, maximumAge)
	if currentPolicyExpiry.IsZero() {
		return time.Time{}
	}
	if currentPolicyExpiry.Before(snapshot.expiresAt) {
		return currentPolicyExpiry
	}
	return snapshot.expiresAt
}

func (resolver *campaignSourceResolver) addDiagnostic(code DiagnosticCode, severity FindingSeverity, sourceID, message string) {
	id := StableAnalysisID("campaign_source_diagnostic", string(code), sourceID, message)
	resolver.diagnostics = append(resolver.diagnostics, CampaignSourceDiagnostic{
		ID: id, Code: code, Severity: severity, SourceID: sourceID, Message: message, Sensitivity: SensitivityRestricted,
	})
}

func boundedCampaignMetadata(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxCampaignStringBytes {
		return ""
	}
	return value
}

func campaignReplacementIDs(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloneCampaignSourceProvenance(values []CampaignSourceProvenance) []CampaignSourceProvenance {
	result := append([]CampaignSourceProvenance(nil), values...)
	for index := range result {
		result[index].ReplaceCampaignIDs = cloneStrings(result[index].ReplaceCampaignIDs)
	}
	return result
}

type campaignBytesSource struct {
	data     []byte
	metadata CampaignConfigurationMetadata
}

func (source campaignBytesSource) Load(ctx context.Context) ([]byte, CampaignConfigurationMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	return append([]byte(nil), source.data...), cloneCampaignConfigurationMetadata(source.metadata), nil
}

// NewCampaignBytesSource returns an inert defensive-copy source for inline or
// already-fetched bytes.
func NewCampaignBytesSource(data []byte, metadata CampaignConfigurationMetadata) CampaignConfigurationSource {
	return campaignBytesSource{data: append([]byte(nil), data...), metadata: cloneCampaignConfigurationMetadata(metadata)}
}

type campaignFileSource struct {
	path          string
	directoryPath string
	directoryInfo os.FileInfo
}

func (source campaignFileSource) Load(ctx context.Context) ([]byte, CampaignConfigurationMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	if err := source.validateDirectory(); err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	discovered, err := os.Lstat(source.path)
	if err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	if discovered.Mode()&os.ModeSymlink != 0 || !discovered.Mode().IsRegular() {
		return nil, CampaignConfigurationMetadata{}, ErrCampaignSourceFailed
	}
	file, err := os.Open(source.path)
	if err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	if directoryErr := source.validateDirectory(); directoryErr != nil {
		return nil, CampaignConfigurationMetadata{}, errors.Join(directoryErr, file.Close())
	}
	opened, statErr := file.Stat()
	if statErr != nil {
		return nil, CampaignConfigurationMetadata{}, errors.Join(statErr, file.Close())
	}
	if !opened.Mode().IsRegular() || !os.SameFile(discovered, opened) {
		closeErr := file.Close()
		return nil, CampaignConfigurationMetadata{}, errors.Join(ErrCampaignSourceFailed, closeErr)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCampaignConfigurationBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, CampaignConfigurationMetadata{}, errors.Join(readErr, closeErr)
	}
	if len(data) > maxCampaignConfigurationBytes {
		return nil, CampaignConfigurationMetadata{}, ErrCampaignConfigurationTooLarge
	}
	metadata := CampaignConfigurationMetadata{LastModified: opened.ModTime().UTC()}
	return data, metadata, nil
}

func (source campaignFileSource) validateDirectory() error {
	if source.directoryInfo == nil {
		return nil
	}
	current, err := os.Lstat(source.directoryPath)
	if err != nil {
		return errors.Join(ErrCampaignSourceFailed, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(source.directoryInfo, current) {
		return ErrCampaignSourceFailed
	}
	return nil
}

// NewCampaignFileSource creates an explicit bounded regular-file adapter. It
// rejects symlinks and a file replaced between discovery and opening.
func NewCampaignFileSource(path string) (CampaignConfigurationSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrInvalidCampaignSourceOptions
	}
	return campaignFileSource{path: filepath.Clean(path)}, nil
}

// CampaignDirectoryOptions bounds deterministic local fragment discovery.
// MaximumFiles limits both directory entries inspected and source specs
// returned, so unrelated files cannot make discovery unbounded.
type CampaignDirectoryOptions struct {
	SourceIDPrefix string
	Required       bool
	Priority       int
	MaximumFiles   int
}

// CampaignConfigurationSourcesFromDirectory returns stable file source specs
// for regular .yaml, .yml, and .json files. It rejects symlink roots and
// entries, generated source-ID collisions, and invalid combined source IDs;
// returned sources reject later root replacement.
func CampaignConfigurationSourcesFromDirectory(ctx context.Context, path string, options CampaignDirectoryOptions) ([]CampaignConfigurationSourceSpec, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix, ok := normalizeConfigID(options.SourceIDPrefix)
	if !ok || options.Priority < 0 {
		return nil, ErrInvalidCampaignSourceOptions
	}
	if options.MaximumFiles == 0 {
		options.MaximumFiles = defaultCampaignDirectoryFiles
	}
	if options.MaximumFiles < 1 || options.MaximumFiles > defaultCampaignMaximumSources {
		return nil, ErrInvalidCampaignSourceOptions
	}
	if strings.TrimSpace(path) == "" {
		return nil, ErrInvalidCampaignSourceOptions
	}
	directoryPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	discovered, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, err
	}
	if discovered.Mode()&os.ModeSymlink != 0 || !discovered.IsDir() {
		return nil, ErrCampaignSourceFailed
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return nil, err
	}
	opened, statErr := directory.Stat()
	if statErr != nil {
		return nil, errors.Join(statErr, directory.Close())
	}
	current, currentErr := os.Lstat(directoryPath)
	if currentErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(discovered, opened) || !os.SameFile(opened, current) {
		return nil, errors.Join(ErrCampaignSourceFailed, currentErr, directory.Close())
	}
	entries, readErr := directory.ReadDir(options.MaximumFiles + 1)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	current, currentErr = os.Lstat(directoryPath)
	if currentErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(opened, current) {
		return nil, errors.Join(ErrCampaignSourceFailed, readErr, currentErr, directory.Close())
	}
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(entries) > options.MaximumFiles {
		return nil, ErrInvalidCampaignSourceOptions
	}
	result := make([]CampaignConfigurationSourceSpec, 0)
	seenSourceIDs := make(map[string]struct{})
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrCampaignSourceFailed
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrCampaignSourceFailed
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if !info.Mode().IsRegular() || extension != ".yaml" && extension != ".yml" && extension != ".json" {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		fragment, valid := normalizeConfigID(base)
		if !valid {
			return nil, ErrInvalidCampaignSourceOptions
		}
		sourceID, valid := normalizeConfigID(prefix + "-" + fragment)
		if !valid {
			return nil, ErrInvalidCampaignSourceOptions
		}
		if _, duplicate := seenSourceIDs[sourceID]; duplicate {
			return nil, ErrInvalidCampaignSourceOptions
		}
		seenSourceIDs[sourceID] = struct{}{}
		source := campaignFileSource{path: filepath.Join(directoryPath, entry.Name()), directoryPath: directoryPath, directoryInfo: opened}
		result = append(result, CampaignConfigurationSourceSpec{ID: sourceID, Source: source, Required: options.Required, Priority: options.Priority})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

type campaignHTTPSSource struct {
	url    string
	client *http.Client
}

func (source campaignHTTPSSource) Load(ctx context.Context) ([]byte, CampaignConfigurationMetadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	request.Header.Set("Accept", "application/json, application/yaml, text/yaml")
	response, err := source.client.Do(request)
	if err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	if response == nil || response.Body == nil {
		return nil, CampaignConfigurationMetadata{}, ErrCampaignSourceFailed
	}
	if response.Request == nil || response.Request.URL == nil || !strings.EqualFold(response.Request.URL.Scheme, "https") || response.Request.URL.Host == "" || response.Request.URL.User != nil {
		_ = response.Body.Close() // Cleanup-only after rejecting the response.
		return nil, CampaignConfigurationMetadata{}, ErrCampaignSourceFailed
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close() // Cleanup-only; response content is not accepted.
		return nil, CampaignConfigurationMetadata{}, ErrCampaignSourceFailed
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxCampaignConfigurationBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, CampaignConfigurationMetadata{}, errors.Join(readErr, closeErr)
	}
	if len(data) > maxCampaignConfigurationBytes {
		return nil, CampaignConfigurationMetadata{}, ErrCampaignConfigurationTooLarge
	}
	metadata := CampaignConfigurationMetadata{ETag: response.Header.Get("ETag"), ContentType: response.Header.Get("Content-Type")}
	if lastModified := response.Header.Get("Last-Modified"); lastModified != "" {
		if parsed, parseErr := http.ParseTime(lastModified); parseErr == nil {
			metadata.LastModified = parsed.UTC()
		} else {
			_ = parseErr // Optional untrusted metadata does not affect the accepted response body.
		}
	}
	return data, metadata, nil
}

// NewCampaignHTTPSSource creates an explicit HTTPS-only adapter using a
// caller-controlled client. The adapter copies the client and blocks redirect
// targets that would leave HTTPS before any downgraded request is sent.
func NewCampaignHTTPSSource(rawURL string, client *http.Client) (CampaignConfigurationSource, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || client == nil || parsed.User != nil {
		return nil, ErrInvalidCampaignSourceOptions
	}
	clientCopy := *client
	callerCheckRedirect := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request == nil || request.URL == nil || !strings.EqualFold(request.URL.Scheme, "https") || request.URL.Host == "" || request.URL.User != nil {
			return ErrCampaignSourceFailed
		}
		if callerCheckRedirect != nil {
			return callerCheckRedirect(request, via)
		}
		if len(via) >= 10 {
			return ErrCampaignSourceFailed
		}
		return nil
	}
	return campaignHTTPSSource{url: parsed.String(), client: &clientCopy}, nil
}

// CampaignEnvironmentLookup resolves one explicitly requested value without
// allowing the library to read process environment variables itself.
type CampaignEnvironmentLookup func(string) (string, bool)

// CampaignEnvironmentValueKind makes path, HTTPS URL, and inline behavior
// explicit rather than guessing from untrusted content.
type CampaignEnvironmentValueKind string

const (
	CampaignEnvironmentInline CampaignEnvironmentValueKind = "inline"
	CampaignEnvironmentFile   CampaignEnvironmentValueKind = "file"
	CampaignEnvironmentHTTPS  CampaignEnvironmentValueKind = "https"
)

type campaignEnvironmentSource struct {
	name   string
	kind   CampaignEnvironmentValueKind
	lookup CampaignEnvironmentLookup
	client *http.Client
}

func (source campaignEnvironmentSource) Load(ctx context.Context) ([]byte, CampaignConfigurationMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, CampaignConfigurationMetadata{}, err
	}
	value, ok := source.lookup(source.name)
	if !ok || value == "" {
		return nil, CampaignConfigurationMetadata{}, ErrCampaignSourceFailed
	}
	switch source.kind {
	case CampaignEnvironmentInline:
		return []byte(value), CampaignConfigurationMetadata{}, nil
	case CampaignEnvironmentFile:
		fileSource, err := NewCampaignFileSource(value)
		if err != nil {
			return nil, CampaignConfigurationMetadata{}, err
		}
		return fileSource.Load(ctx)
	case CampaignEnvironmentHTTPS:
		httpsSource, err := NewCampaignHTTPSSource(value, source.client)
		if err != nil {
			return nil, CampaignConfigurationMetadata{}, err
		}
		return httpsSource.Load(ctx)
	default:
		return nil, CampaignConfigurationMetadata{}, ErrInvalidCampaignSourceOptions
	}
}

// NewCampaignEnvironmentSource creates an opt-in environment adapter. The
// caller supplies both lookup and interpretation; the library never calls
// os.Getenv and never auto-detects a path or URL.
func NewCampaignEnvironmentSource(name string, kind CampaignEnvironmentValueKind, lookup CampaignEnvironmentLookup, client *http.Client) (CampaignConfigurationSource, error) {
	if strings.TrimSpace(name) == "" || lookup == nil || kind != CampaignEnvironmentInline && kind != CampaignEnvironmentFile && kind != CampaignEnvironmentHTTPS || kind == CampaignEnvironmentHTTPS && client == nil {
		return nil, ErrInvalidCampaignSourceOptions
	}
	return campaignEnvironmentSource{name: name, kind: kind, lookup: lookup, client: client}, nil
}

func cloneCampaignConfigurationMetadata(value CampaignConfigurationMetadata) CampaignConfigurationMetadata {
	value.DetachedSignature = append([]byte(nil), value.DetachedSignature...)
	return value
}

func nilCampaignConfigurationSource(source CampaignConfigurationSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
