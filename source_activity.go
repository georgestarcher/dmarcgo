package dmarcgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// SourceActivityVersion identifies the normalized source-activity result
	// contract. It is independent of the Go module and output schemas.
	SourceActivityVersion = "1"

	defaultSourceActivityMaxQueries        = 16
	defaultSourceActivityMaxConcurrency    = 1
	defaultSourceActivityLookupTimeout     = 10 * time.Second
	defaultSourceActivityMaxMetrics        = 32
	defaultSourceActivityMaxThreatFeeds    = 64
	defaultSourceActivityMaxAssertions     = 16
	defaultSourceActivityMaxTextBytes      = 2048
	defaultSourceActivityMaxTotalTextBytes = 256 * 1024
	defaultSourceActivityMaxRetryAfter     = time.Hour
	maxSourceActivityQueries               = 64
	maxSourceActivityConcurrency           = 4
	maxSourceActivityLookupTimeout         = 5 * time.Minute
	maxSourceActivityItems                 = 256
	maxSourceActivityTextBytes             = 64 * 1024
	maxSourceActivityTotalTextBytes        = 4 * 1024 * 1024
	maxSourceActivityRetryAfter            = 7 * 24 * time.Hour
)

var (
	// ErrInvalidSourceActivityOptions identifies invalid selections, limits,
	// timestamps, or mismatched completed inputs.
	ErrInvalidSourceActivityOptions = errors.New("invalid source-activity options")
	// ErrInvalidSourceActivityResponse identifies structurally unsafe or
	// internally inconsistent caller-supplied provider evidence.
	ErrInvalidSourceActivityResponse = errors.New("invalid source-activity response")
	// ErrSourceActivityRateLimited is returned by an adapter when its provider
	// rate limits a lookup. Retry metadata belongs in SourceActivityResponse.
	ErrSourceActivityRateLimited = errors.New("source-activity provider rate limited")
	// ErrSourceActivityUnavailable identifies a supported lookup for which the
	// provider supplied no usable evidence.
	ErrSourceActivityUnavailable = errors.New("source activity unavailable")
	// ErrSourceActivityMalformed identifies a response that an adapter could
	// not safely normalize.
	ErrSourceActivityMalformed = errors.New("source-activity response malformed")
)

// SourceActivityStatus is the stable outcome for one selected source IP.
type SourceActivityStatus string

const (
	SourceActivityNotEvaluated SourceActivityStatus = "not_evaluated"
	SourceActivityNotEligible  SourceActivityStatus = "not_eligible"
	SourceActivitySuccess      SourceActivityStatus = "success"
	SourceActivityUnavailable  SourceActivityStatus = "unavailable"
	SourceActivityRateLimited  SourceActivityStatus = "rate_limited"
	SourceActivityMalformed    SourceActivityStatus = "malformed"
	SourceActivityFailed       SourceActivityStatus = "failed"
	SourceActivityCanceled     SourceActivityStatus = "canceled"
	SourceActivityTimeout      SourceActivityStatus = "timeout"
	SourceActivityStale        SourceActivityStatus = "stale"
	SourceActivityFuture       SourceActivityStatus = "future"
	SourceActivityConflicting  SourceActivityStatus = "conflicting"
)

// SourceActivityFreshness records whether provider evidence is current at the
// result timestamp. Unknown expiry never becomes an assertion of freshness.
type SourceActivityFreshness string

const (
	SourceActivityFreshnessUnknown SourceActivityFreshness = "unknown"
	SourceActivityFreshnessFresh   SourceActivityFreshness = "fresh"
	SourceActivityFreshnessStale   SourceActivityFreshness = "stale"
	SourceActivityFreshnessFuture  SourceActivityFreshness = "future"
)

// SourceActivityTimeRelationship compares report-period bounds with provider
// activity bounds. It is temporal context, not causal attribution.
type SourceActivityTimeRelationship string

const (
	SourceActivityTimeUnknown       SourceActivityTimeRelationship = "unknown"
	SourceActivityTimeOverlaps      SourceActivityTimeRelationship = "overlaps"
	SourceActivityTimeBeforeReports SourceActivityTimeRelationship = "before_reports"
	SourceActivityTimeAfterReports  SourceActivityTimeRelationship = "after_reports"
)

// SourceActivitySelection explicitly chooses candidates already present in a
// completed ThreatCandidateResult. CandidateIDs and SourceIPs are unioned.
type SourceActivitySelection struct {
	CandidateIDs []AnalysisID
	SourceIPs    []string
}

// SourceActivityOptions bounds explicitly selected lookups. Zero values use
// conservative defaults. Each deduplicated IP is supplied at most once and the
// stage never retries, sleeps, polls, or discovers additional addresses.
type SourceActivityOptions struct {
	Selection         SourceActivitySelection
	MaxQueries        int
	MaxConcurrency    int
	LookupTimeout     time.Duration
	MaxMetrics        int
	MaxThreatFeeds    int
	MaxAssertions     int
	MaxTextBytes      int
	MaxTotalTextBytes int
	MaxRetryAfter     time.Duration
	Clock             Clock
}

// SourceActivityMetric preserves a provider-described non-negative quantity.
// Name, Unit, and Semantics are untrusted structured data. The library does
// not infer a time window, population, sampling method, or malicious verdict.
type SourceActivityMetric struct {
	Name        string      `json:"name"`
	Value       uint64      `json:"value"`
	Unit        string      `json:"unit"`
	Semantics   string      `json:"semantics,omitempty"`
	Sensitivity Sensitivity `json:"sensitivity"`
}

// SourceActivityThreatFeed preserves provider-supplied feed membership and
// its optional time window. Name is untrusted data, not a classification.
type SourceActivityThreatFeed struct {
	Name        string      `json:"name"`
	FirstSeen   *time.Time  `json:"first_seen,omitempty"`
	LastSeen    *time.Time  `json:"last_seen,omitempty"`
	Sensitivity Sensitivity `json:"sensitivity"`
}

// SourceActivityNetworkAssertion is provider-supplied context associated with
// an activity response. Multiple contradictory assertions are all preserved.
type SourceActivityNetworkAssertion struct {
	ASN           uint32      `json:"asn,omitempty"`
	ASNName       string      `json:"asn_name,omitempty"`
	NetworkPrefix string      `json:"network_prefix,omitempty"`
	Organization  string      `json:"organization,omitempty"`
	CountryCode   string      `json:"country_code,omitempty"`
	Sensitivity   Sensitivity `json:"sensitivity"`
}

// SourceActivityResponse is returned by a caller-supplied provider. Every
// string is untrusted data. ActivityObserved distinguishes a provider match
// from a successful lookup with no described activity; neither state proves
// maliciousness or benignness.
type SourceActivityResponse struct {
	Provider         string                           `json:"provider"`
	Dataset          string                           `json:"dataset"`
	EndpointIdentity string                           `json:"endpoint_identity"`
	ReferenceID      string                           `json:"reference_id,omitempty"`
	ActivityObserved bool                             `json:"activity_observed"`
	FirstSeen        *time.Time                       `json:"first_seen,omitempty"`
	LastSeen         *time.Time                       `json:"last_seen,omitempty"`
	UpdatedAt        *time.Time                       `json:"updated_at,omitempty"`
	ExpiresAt        *time.Time                       `json:"expires_at,omitempty"`
	Metrics          []SourceActivityMetric           `json:"metrics"`
	ThreatFeeds      []SourceActivityThreatFeed       `json:"threat_feeds"`
	Assertions       []SourceActivityNetworkAssertion `json:"assertions"`
	RetryAfter       time.Duration                    `json:"-"`
	Truncated        bool                             `json:"truncated"`
}

// SourceActivityProvider is the only side-effect boundary for activity
// collection. Implementations must honor cancellation, bound raw responses,
// contact only an explicitly configured third-party service, and never contact
// the subject IP. Redirect, credentials, User-Agent, and destination policy are
// caller-owned. The library invokes this method at most once per selected IP.
type SourceActivityProvider interface {
	LookupSourceActivity(context.Context, netip.Addr) (SourceActivityResponse, error)
}

// SourceActivityRetryAfter is bounded scheduling metadata. The library never
// sleeps or retries automatically.
type SourceActivityRetryAfter struct {
	Available bool  `json:"available"`
	Seconds   int64 `json:"seconds,omitempty"`
	Capped    bool  `json:"capped"`
}

// SourceActivityProvenance identifies the selected provider and dataset. All
// strings are untrusted structured data.
type SourceActivityProvenance struct {
	Provider         string      `json:"provider"`
	Dataset          string      `json:"dataset"`
	EndpointIdentity string      `json:"endpoint_identity"`
	ReferenceID      string      `json:"reference_id,omitempty"`
	CollectedAt      time.Time   `json:"collected_at"`
	Sensitivity      Sensitivity `json:"sensitivity"`
}

// SourceActivityReportWindow retains the candidate report-evidence bounds.
type SourceActivityReportWindow struct {
	FirstSeen   ReportEvidenceTimestamp `json:"first_seen"`
	LastSeen    ReportEvidenceTimestamp `json:"last_seen"`
	Sensitivity Sensitivity             `json:"sensitivity"`
}

// SourceActivityEvidence is normalized provider activity for one IP.
type SourceActivityEvidence struct {
	ID               AnalysisID                       `json:"id"`
	ActivityObserved bool                             `json:"activity_observed"`
	FirstSeen        *time.Time                       `json:"first_seen,omitempty"`
	LastSeen         *time.Time                       `json:"last_seen,omitempty"`
	UpdatedAt        *time.Time                       `json:"updated_at,omitempty"`
	ExpiresAt        *time.Time                       `json:"expires_at,omitempty"`
	Metrics          []SourceActivityMetric           `json:"metrics"`
	ThreatFeeds      []SourceActivityThreatFeed       `json:"threat_feeds"`
	Assertions       []SourceActivityNetworkAssertion `json:"assertions"`
	ConflictFields   []string                         `json:"conflict_fields"`
	Freshness        SourceActivityFreshness          `json:"freshness"`
	TimeRelationship SourceActivityTimeRelationship   `json:"time_relationship"`
	Sensitivity      Sensitivity                      `json:"sensitivity"`
}

// SourceActivityRecord is one selected, canonical source IP and its matching
// immutable candidate and optional source-enrichment references.
type SourceActivityRecord struct {
	ID                       AnalysisID                 `json:"id"`
	SourceIP                 string                     `json:"source_ip"`
	CandidateIDs             []AnalysisID               `json:"candidate_ids"`
	EnrichmentAssertionIDs   []AnalysisID               `json:"enrichment_assertion_ids"`
	EnrichmentConflictFields []string                   `json:"enrichment_conflict_fields"`
	ReportWindow             SourceActivityReportWindow `json:"report_window"`
	Status                   SourceActivityStatus       `json:"status"`
	Provenance               SourceActivityProvenance   `json:"provenance"`
	Evidence                 SourceActivityEvidence     `json:"evidence"`
	RetryAfter               SourceActivityRetryAfter   `json:"retry_after"`
	Truncated                bool                       `json:"truncated"`
	FindingIDs               []FindingID                `json:"finding_ids"`
	Sensitivity              Sensitivity                `json:"sensitivity"`
}

// SourceActivityFinding uses only fixed library-controlled prose. Provider
// values remain in structured evidence and never enter generated guidance.
type SourceActivityFinding struct {
	ID             FindingID       `json:"id"`
	Code           FindingCode     `json:"code"`
	Severity       FindingSeverity `json:"severity"`
	RecordID       AnalysisID      `json:"record_id"`
	EvidenceIDs    []AnalysisID    `json:"evidence_ids"`
	Title          string          `json:"title"`
	Explanation    string          `json:"explanation"`
	Recommendation string          `json:"recommendation"`
	Sensitivity    Sensitivity     `json:"sensitivity"`
}

// SourceActivityDiagnostic is value-safe fixed prose. It never contains a
// provider error, response body, comment, feed name, or reference value.
type SourceActivityDiagnostic struct {
	Code     DiagnosticCode       `json:"code"`
	Severity FindingSeverity      `json:"severity"`
	RecordID AnalysisID           `json:"record_id"`
	Status   SourceActivityStatus `json:"status"`
	Message  string               `json:"message"`
}

// SourceActivityStatusCount is one deterministic status rollup.
type SourceActivityStatusCount struct {
	Status  SourceActivityStatus `json:"status"`
	Sources int                  `json:"sources"`
}

// SourceActivitySummary describes explicitly selected lookup coverage.
type SourceActivitySummary struct {
	Sources          int                         `json:"sources"`
	Eligible         int                         `json:"eligible"`
	ActivityObserved int                         `json:"activity_observed"`
	Truncated        int                         `json:"truncated"`
	Findings         int                         `json:"findings"`
	Statuses         []SourceActivityStatusCount `json:"statuses"`
}

// SourceActivityResult is an immutable result from the explicitly invoked
// source-activity stage.
type SourceActivityResult struct {
	metadata               ResultMetadata
	version                string
	organizationID         string
	threatCandidateDigest  AnalysisID
	sourceEnrichmentDigest AnalysisID
	digest                 AnalysisID
	complete               bool
	records                []SourceActivityRecord
	findings               []SourceActivityFinding
	diagnostics            []SourceActivityDiagnostic
	summary                SourceActivitySummary
}

func (result SourceActivityResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result SourceActivityResult) Version() string                { return result.version }
func (result SourceActivityResult) OrganizationID() string         { return result.organizationID }
func (result SourceActivityResult) ThreatCandidateDigest() AnalysisID {
	return result.threatCandidateDigest
}
func (result SourceActivityResult) SourceEnrichmentDigest() AnalysisID {
	return result.sourceEnrichmentDigest
}
func (result SourceActivityResult) Digest() AnalysisID { return result.digest }
func (result SourceActivityResult) Complete() bool     { return result.complete }
func (result SourceActivityResult) Records() []SourceActivityRecord {
	return cloneSourceActivityRecords(result.records)
}
func (result SourceActivityResult) Findings() []SourceActivityFinding {
	return cloneSourceActivityFindings(result.findings)
}
func (result SourceActivityResult) Diagnostics() []SourceActivityDiagnostic {
	return append([]SourceActivityDiagnostic(nil), result.diagnostics...)
}
func (result SourceActivityResult) Summary() SourceActivitySummary {
	return cloneSourceActivitySummary(result.summary)
}

// SourceActivityError retains cancellation while excluding provider text.
type SourceActivityError struct{ cause error }

func (err *SourceActivityError) Error() string {
	if errors.Is(err.cause, context.DeadlineExceeded) {
		return "source-activity collection deadline exceeded"
	}
	return "source-activity collection canceled"
}

func (err *SourceActivityError) Unwrap() error { return err.cause }

type sourceActivityPlanItem struct {
	ip                       netip.Addr
	candidateIDs             []AnalysisID
	reportWindow             SourceActivityReportWindow
	eligible                 bool
	enrichmentAssertionIDs   []AnalysisID
	enrichmentConflictFields []string
}

type sourceActivityLookupOutcome struct {
	index       int
	record      SourceActivityRecord
	findings    []SourceActivityFinding
	diagnostics []SourceActivityDiagnostic
	complete    bool
}

// CollectSourceActivity explicitly queries a caller-supplied third-party
// provider for selected review-eligible source IPs. A nil provider and an empty
// selection are no-clock, no-network results. Optional enrichment must match
// the supplied threat-candidate result. Activity evidence never mutates the
// candidate result or authorizes automatic action.
func CollectSourceActivity(ctx context.Context, candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, provider SourceActivityProvider, options SourceActivityOptions) (SourceActivityResult, error) {
	if err := validateSourceActivityInputs(candidates, enrichment); err != nil {
		return SourceActivityResult{}, err
	}
	providerAvailable := !nilSourceActivityProvider(provider)
	options, err := normalizeSourceActivityOptions(options, providerAvailable)
	if err != nil {
		return SourceActivityResult{}, err
	}
	plan, err := buildSourceActivityPlan(candidates, enrichment, options.Selection)
	if err != nil {
		return SourceActivityResult{}, err
	}
	if len(plan) > options.MaxQueries {
		return SourceActivityResult{}, fmt.Errorf("%w: selected source count exceeds the configured limit", ErrInvalidSourceActivityOptions)
	}
	baseTime := candidates.ResultMetadata().GeneratedAt
	if enrichment != nil && enrichment.ResultMetadata().GeneratedAt.After(baseTime) {
		baseTime = enrichment.ResultMetadata().GeneratedAt
	}
	if len(plan) == 0 {
		return newSourceActivityResult(candidates, enrichment, baseTime, Evaluation{State: EvaluationStateEvaluated}, true, nil, nil, nil)
	}
	if !providerAvailable {
		records := make([]SourceActivityRecord, len(plan))
		for index, item := range plan {
			status := SourceActivityNotEvaluated
			if !item.eligible {
				status = SourceActivityNotEligible
			}
			records[index] = emptySourceActivityRecord(item, status)
		}
		return newSourceActivityResult(candidates, enrichment, baseTime, Evaluation{State: EvaluationStateNotEvaluated, Reason: "No source-activity provider was supplied."}, false, records, nil, nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		records, diagnostics := canceledSourceActivityRecords(plan, err)
		result, resultErr := newSourceActivityResult(candidates, enrichment, baseTime, Evaluation{State: EvaluationStateEvaluated}, false, records, nil, diagnostics)
		if resultErr != nil {
			return SourceActivityResult{}, resultErr
		}
		return result, &SourceActivityError{cause: err}
	}
	generatedAt := options.Clock.Now().UTC()
	if generatedAt.IsZero() || !sourceEnrichmentTimeMarshalable(generatedAt) || generatedAt.Before(baseTime) {
		return SourceActivityResult{}, ErrInvalidSourceActivityOptions
	}
	outcomes := collectSourceActivityLookups(ctx, provider, plan, generatedAt, options)
	records := make([]SourceActivityRecord, len(plan))
	findings := make([]SourceActivityFinding, 0)
	diagnostics := make([]SourceActivityDiagnostic, 0)
	complete := true
	for index, item := range plan {
		if !item.eligible {
			records[index] = emptySourceActivityRecord(item, SourceActivityNotEligible)
			continue
		}
		outcome, ok := outcomes[index]
		if !ok {
			outcome = canceledSourceActivityLookupOutcome(index, item, ctx.Err())
		}
		records[index] = outcome.record
		findings = append(findings, outcome.findings...)
		diagnostics = append(diagnostics, outcome.diagnostics...)
		complete = complete && outcome.complete
	}
	sortSourceActivityFindings(findings)
	sortSourceActivityDiagnostics(diagnostics)
	result, err := newSourceActivityResult(candidates, enrichment, generatedAt, Evaluation{State: EvaluationStateEvaluated}, complete, records, findings, diagnostics)
	if err != nil {
		return SourceActivityResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return result, &SourceActivityError{cause: err}
	}
	return result, nil
}

func validateSourceActivityInputs(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult) error {
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return ErrInvalidAnalysisResult
	}
	if enrichment == nil {
		return nil
	}
	metadata := enrichment.ResultMetadata()
	if enrichment.Digest() == "" || enrichment.Version() != SourceEnrichmentVersion || enrichment.OrganizationID() != candidates.OrganizationID() ||
		enrichment.ThreatCandidateDigest() != candidates.Digest() || metadata.ContractVersion != AnalysisContractVersion ||
		metadata.Mode != AnalysisModeSourceEnrichment || (metadata.Evaluation.State != EvaluationStateEvaluated && metadata.Evaluation.State != EvaluationStateNotEvaluated) {
		return ErrInvalidAnalysisResult
	}
	return nil
}

func normalizeSourceActivityOptions(options SourceActivityOptions, requireClock bool) (SourceActivityOptions, error) {
	if options.MaxQueries == 0 {
		options.MaxQueries = defaultSourceActivityMaxQueries
	}
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = defaultSourceActivityMaxConcurrency
	}
	if options.LookupTimeout == 0 {
		options.LookupTimeout = defaultSourceActivityLookupTimeout
	}
	if options.MaxMetrics == 0 {
		options.MaxMetrics = defaultSourceActivityMaxMetrics
	}
	if options.MaxThreatFeeds == 0 {
		options.MaxThreatFeeds = defaultSourceActivityMaxThreatFeeds
	}
	if options.MaxAssertions == 0 {
		options.MaxAssertions = defaultSourceActivityMaxAssertions
	}
	if options.MaxTextBytes == 0 {
		options.MaxTextBytes = defaultSourceActivityMaxTextBytes
	}
	if options.MaxTotalTextBytes == 0 {
		options.MaxTotalTextBytes = defaultSourceActivityMaxTotalTextBytes
	}
	if options.MaxRetryAfter == 0 {
		options.MaxRetryAfter = defaultSourceActivityMaxRetryAfter
	}
	if options.MaxQueries < 1 || options.MaxQueries > maxSourceActivityQueries ||
		options.MaxConcurrency < 1 || options.MaxConcurrency > maxSourceActivityConcurrency ||
		options.LookupTimeout < time.Millisecond || options.LookupTimeout > maxSourceActivityLookupTimeout ||
		options.MaxMetrics < 1 || options.MaxMetrics > maxSourceActivityItems ||
		options.MaxThreatFeeds < 1 || options.MaxThreatFeeds > maxSourceActivityItems ||
		options.MaxAssertions < 1 || options.MaxAssertions > maxSourceActivityItems ||
		options.MaxTextBytes < 1 || options.MaxTextBytes > maxSourceActivityTextBytes ||
		options.MaxTotalTextBytes < 1 || options.MaxTotalTextBytes > maxSourceActivityTotalTextBytes ||
		options.MaxRetryAfter < 0 || options.MaxRetryAfter > maxSourceActivityRetryAfter {
		return SourceActivityOptions{}, ErrInvalidSourceActivityOptions
	}
	if requireClock && options.Clock == nil {
		options.Clock = ClockFunc(time.Now)
	}
	return options, nil
}

func buildSourceActivityPlan(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, selection SourceActivitySelection) ([]sourceActivityPlanItem, error) {
	if len(selection.CandidateIDs) == 0 && len(selection.SourceIPs) == 0 {
		return []sourceActivityPlanItem{}, nil
	}
	values := candidates.Candidates()
	byID := make(map[AnalysisID]ThreatCandidate, len(values))
	byIP := make(map[string][]ThreatCandidate, len(values))
	for _, candidate := range values {
		byID[candidate.ID] = candidate
		byIP[candidate.SourceIP] = append(byIP[candidate.SourceIP], candidate)
	}
	selectedIPs := map[string]struct{}{}
	selectedCandidateIDs := map[AnalysisID]struct{}{}
	explicitSourceIPs := map[string]struct{}{}
	for _, id := range selection.CandidateIDs {
		candidate, ok := byID[id]
		if !ok || id == "" {
			return nil, fmt.Errorf("%w: selected candidate ID is not present", ErrInvalidSourceActivityOptions)
		}
		selectedCandidateIDs[id] = struct{}{}
		selectedIPs[candidate.SourceIP] = struct{}{}
	}
	for _, value := range selection.SourceIPs {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || ip != ip.Unmap() || ip.String() != strings.TrimSpace(value) {
			return nil, fmt.Errorf("%w: selected source IP must be canonical", ErrInvalidSourceActivityOptions)
		}
		if _, ok := byIP[ip.String()]; !ok {
			return nil, fmt.Errorf("%w: selected source IP is not present", ErrInvalidSourceActivityOptions)
		}
		explicitSourceIPs[ip.String()] = struct{}{}
		selectedIPs[ip.String()] = struct{}{}
	}
	enrichmentByIP := sourceActivityEnrichmentByIP(enrichment)
	plan := make([]sourceActivityPlanItem, 0, len(selectedIPs))
	for sourceIP := range selectedIPs {
		ip := netip.MustParseAddr(sourceIP)
		matching := byIP[sourceIP]
		item := sourceActivityPlanItem{ip: ip}
		selectedCandidates := make([]ThreatCandidate, 0, len(matching))
		_, allCandidatesSelected := explicitSourceIPs[sourceIP]
		for _, candidate := range matching {
			_, candidateSelected := selectedCandidateIDs[candidate.ID]
			if !allCandidatesSelected && !candidateSelected {
				continue
			}
			selectedCandidates = append(selectedCandidates, candidate)
			item.candidateIDs = append(item.candidateIDs, candidate.ID)
			item.eligible = item.eligible || sourceActivityEligible(candidate)
		}
		item.reportWindow = sourceActivityReportWindow(selectedCandidates)
		sort.Slice(item.candidateIDs, func(i, j int) bool { return item.candidateIDs[i] < item.candidateIDs[j] })
		if value, ok := enrichmentByIP[sourceIP]; ok {
			item.enrichmentAssertionIDs = append([]AnalysisID(nil), value.assertionIDs...)
			item.enrichmentConflictFields = append([]string(nil), value.conflictFields...)
		}
		plan = append(plan, item)
	}
	sort.Slice(plan, func(i, j int) bool { return plan[i].ip.Compare(plan[j].ip) < 0 })
	return plan, nil
}

func sourceActivityEligible(candidate ThreatCandidate) bool {
	if !sourceEnrichmentEligible(candidate) {
		return false
	}
	return candidate.DualFailureMessages == 0 || candidate.ExpectedSenderFailureMessages < candidate.DualFailureMessages
}

type sourceActivityEnrichmentReference struct {
	assertionIDs   []AnalysisID
	conflictFields []string
}

func sourceActivityEnrichmentByIP(enrichment *SourceEnrichmentResult) map[string]sourceActivityEnrichmentReference {
	result := map[string]sourceActivityEnrichmentReference{}
	if enrichment == nil {
		return result
	}
	for _, value := range enrichment.Candidates() {
		entry := result[value.Candidate.SourceIP]
		for _, assertion := range value.Metadata.Assertions {
			entry.assertionIDs = append(entry.assertionIDs, assertion.ID)
		}
		entry.conflictFields = append(entry.conflictFields, value.Metadata.ConflictFields...)
		entry.assertionIDs = uniqueSortedAnalysisIDs(entry.assertionIDs)
		entry.conflictFields = uniqueSortedStrings(entry.conflictFields)
		result[value.Candidate.SourceIP] = entry
	}
	return result
}

func sourceActivityReportWindow(values []ThreatCandidate) SourceActivityReportWindow {
	result := SourceActivityReportWindow{Sensitivity: SensitivityRestricted}
	for _, candidate := range values {
		if candidate.FirstSeen.Available && (!result.FirstSeen.Available || candidate.FirstSeen.Value.Before(result.FirstSeen.Value)) {
			result.FirstSeen = candidate.FirstSeen
		}
		if candidate.LastSeen.Available && (!result.LastSeen.Available || candidate.LastSeen.Value.After(result.LastSeen.Value)) {
			result.LastSeen = candidate.LastSeen
		}
	}
	return result
}

func collectSourceActivityLookups(ctx context.Context, provider SourceActivityProvider, plan []sourceActivityPlanItem, generatedAt time.Time, options SourceActivityOptions) map[int]sourceActivityLookupOutcome {
	eligible := make([]int, 0, len(plan))
	for index := range plan {
		if plan[index].eligible {
			eligible = append(eligible, index)
		}
	}
	if len(eligible) == 0 || ctx.Err() != nil {
		return map[int]sourceActivityLookupOutcome{}
	}
	jobs := make(chan int)
	results := make(chan sourceActivityLookupOutcome, len(eligible))
	workerCount := min(options.MaxConcurrency, len(eligible))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() == nil {
					results <- lookupSourceActivity(ctx, provider, index, plan[index], generatedAt, options)
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, index := range eligible {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	outcomes := make(map[int]sourceActivityLookupOutcome, len(eligible))
	for outcome := range results {
		outcomes[outcome.index] = outcome
	}
	return outcomes
}

func lookupSourceActivity(ctx context.Context, provider SourceActivityProvider, index int, item sourceActivityPlanItem, generatedAt time.Time, options SourceActivityOptions) sourceActivityLookupOutcome {
	if err := ctx.Err(); err != nil {
		return canceledSourceActivityLookupOutcome(index, item, err)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, options.LookupTimeout)
	response, lookupErr := provider.LookupSourceActivity(lookupCtx, item.ip)
	contextErr := lookupCtx.Err()
	cancel()
	if contextErr != nil {
		lookupErr = contextErr
	}
	if lookupErr != nil {
		return failedSourceActivityLookupOutcome(index, item, response, lookupErr, ctx, options)
	}
	record, findings, diagnostics, err := normalizeSourceActivityResponse(item, response, generatedAt, options)
	if err != nil {
		return failedSourceActivityLookupOutcome(index, item, response, ErrSourceActivityMalformed, ctx, options)
	}
	return sourceActivityLookupOutcome{index: index, record: record, findings: findings, diagnostics: diagnostics, complete: true}
}

func normalizeSourceActivityResponse(item sourceActivityPlanItem, response SourceActivityResponse, generatedAt time.Time, options SourceActivityOptions) (SourceActivityRecord, []SourceActivityFinding, []SourceActivityDiagnostic, error) {
	response.Provider = strings.TrimSpace(response.Provider)
	response.Dataset = strings.TrimSpace(response.Dataset)
	response.EndpointIdentity = strings.TrimSpace(response.EndpointIdentity)
	response.ReferenceID = strings.TrimSpace(response.ReferenceID)
	if response.Provider == "" || response.Dataset == "" || response.EndpointIdentity == "" ||
		!validDNSPerspectiveText(response.Provider, options.MaxTextBytes) || !validDNSPerspectiveText(response.Dataset, options.MaxTextBytes) ||
		!validDNSPerspectiveText(response.EndpointIdentity, options.MaxTextBytes) || !validDNSPerspectiveText(response.ReferenceID, options.MaxTextBytes) ||
		len(response.Metrics) > options.MaxMetrics || len(response.ThreatFeeds) > options.MaxThreatFeeds || len(response.Assertions) > options.MaxAssertions {
		return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
	}
	textBytes := len(response.Provider) + len(response.Dataset) + len(response.EndpointIdentity) + len(response.ReferenceID)
	if textBytes > options.MaxTotalTextBytes {
		return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
	}
	times := []*time.Time{response.FirstSeen, response.LastSeen, response.UpdatedAt, response.ExpiresAt}
	for _, value := range times {
		if value != nil && (value.IsZero() || !sourceEnrichmentTimeMarshalable(value.UTC())) {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
	}
	if response.FirstSeen != nil && response.LastSeen != nil && response.LastSeen.Before(*response.FirstSeen) {
		return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
	}
	if !response.ActivityObserved && (response.FirstSeen != nil || response.LastSeen != nil || len(response.Metrics) != 0 || len(response.ThreatFeeds) != 0) {
		return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
	}
	metrics := make([]SourceActivityMetric, len(response.Metrics))
	seenMetrics := map[string]struct{}{}
	for index, value := range response.Metrics {
		value.Name, value.Unit, value.Semantics = strings.TrimSpace(value.Name), strings.TrimSpace(value.Unit), strings.TrimSpace(value.Semantics)
		if value.Name == "" || value.Unit == "" || !validDNSPerspectiveText(value.Name, options.MaxTextBytes) || !validDNSPerspectiveText(value.Unit, options.MaxTextBytes) || !validDNSPerspectiveText(value.Semantics, options.MaxTextBytes) {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		key := value.Name + "\x00" + value.Unit
		if _, ok := seenMetrics[key]; ok {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		seenMetrics[key] = struct{}{}
		textBytes += len(value.Name) + len(value.Unit) + len(value.Semantics)
		if textBytes > options.MaxTotalTextBytes {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		value.Sensitivity = SensitivityRestricted
		metrics[index] = value
	}
	sort.Slice(metrics, func(i, j int) bool {
		if metrics[i].Name != metrics[j].Name {
			return metrics[i].Name < metrics[j].Name
		}
		return metrics[i].Unit < metrics[j].Unit
	})
	feeds := make([]SourceActivityThreatFeed, len(response.ThreatFeeds))
	seenFeeds := map[string]struct{}{}
	for index, value := range response.ThreatFeeds {
		value.Name = strings.TrimSpace(value.Name)
		if value.Name == "" || !validDNSPerspectiveText(value.Name, options.MaxTextBytes) {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		if _, ok := seenFeeds[value.Name]; ok {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		seenFeeds[value.Name] = struct{}{}
		if err := validateSourceActivityWindow(value.FirstSeen, value.LastSeen); err != nil {
			return SourceActivityRecord{}, nil, nil, err
		}
		textBytes += len(value.Name)
		if textBytes > options.MaxTotalTextBytes {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		value.FirstSeen, value.LastSeen = cloneUTC(value.FirstSeen), cloneUTC(value.LastSeen)
		value.Sensitivity = SensitivityRestricted
		feeds[index] = value
	}
	sort.Slice(feeds, func(i, j int) bool { return feeds[i].Name < feeds[j].Name })
	assertions := make([]SourceActivityNetworkAssertion, len(response.Assertions))
	seenAssertions := map[string]struct{}{}
	for index, value := range response.Assertions {
		value.ASNName, value.NetworkPrefix, value.Organization, value.CountryCode = strings.TrimSpace(value.ASNName), strings.TrimSpace(value.NetworkPrefix), strings.TrimSpace(value.Organization), strings.ToUpper(strings.TrimSpace(value.CountryCode))
		if !validDNSPerspectiveText(value.ASNName, options.MaxTextBytes) || !validDNSPerspectiveText(value.NetworkPrefix, options.MaxTextBytes) || !validDNSPerspectiveText(value.Organization, options.MaxTextBytes) ||
			(value.CountryCode != "" && !validCountryCode(value.CountryCode)) {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		if value.NetworkPrefix != "" {
			prefix, err := netip.ParsePrefix(value.NetworkPrefix)
			if err != nil || !prefix.IsValid() {
				return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
			}
			value.NetworkPrefix = prefix.Masked().String()
		}
		key := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", value.ASN, value.ASNName, value.NetworkPrefix, value.Organization, value.CountryCode)
		if _, ok := seenAssertions[key]; ok {
			continue
		}
		seenAssertions[key] = struct{}{}
		textBytes += len(value.ASNName) + len(value.NetworkPrefix) + len(value.Organization) + len(value.CountryCode)
		if textBytes > options.MaxTotalTextBytes {
			return SourceActivityRecord{}, nil, nil, ErrInvalidSourceActivityResponse
		}
		value.Sensitivity = SensitivityRestricted
		assertions[index] = value
	}
	assertions = compactSourceActivityAssertions(assertions)
	retryAfter, err := normalizeSourceActivityRetryAfter(response.RetryAfter, options.MaxRetryAfter)
	if err != nil {
		return SourceActivityRecord{}, nil, nil, err
	}
	evidence := SourceActivityEvidence{
		ActivityObserved: response.ActivityObserved, FirstSeen: cloneUTC(response.FirstSeen), LastSeen: cloneUTC(response.LastSeen), UpdatedAt: cloneUTC(response.UpdatedAt), ExpiresAt: cloneUTC(response.ExpiresAt),
		Metrics: metrics, ThreatFeeds: feeds, Assertions: assertions, ConflictFields: sourceActivityConflictFields(assertions), Sensitivity: SensitivityRestricted,
	}
	evidence.Freshness = sourceActivityFreshness(evidence, generatedAt)
	evidence.TimeRelationship = sourceActivityTimeRelationship(item.reportWindow, evidence.FirstSeen, evidence.LastSeen)
	evidence.ID = sourceActivityEvidenceID(item.ip.String(), response, evidence)
	status := SourceActivitySuccess
	switch {
	case evidence.Freshness == SourceActivityFreshnessFuture:
		status = SourceActivityFuture
	case len(evidence.ConflictFields) > 0:
		status = SourceActivityConflicting
	case evidence.Freshness == SourceActivityFreshnessStale:
		status = SourceActivityStale
	}
	record := emptySourceActivityRecord(item, status)
	record.Provenance = SourceActivityProvenance{Provider: response.Provider, Dataset: response.Dataset, EndpointIdentity: response.EndpointIdentity, ReferenceID: response.ReferenceID, CollectedAt: generatedAt, Sensitivity: SensitivityRestricted}
	record.Evidence, record.RetryAfter, record.Truncated = evidence, retryAfter, response.Truncated
	findings := sourceActivityFindings(record)
	for _, finding := range findings {
		record.FindingIDs = append(record.FindingIDs, finding.ID)
	}
	diagnostics := sourceActivityResponseDiagnostics(record)
	return record, findings, diagnostics, nil
}

func validateSourceActivityWindow(first, last *time.Time) error {
	for _, value := range []*time.Time{first, last} {
		if value != nil && (value.IsZero() || !sourceEnrichmentTimeMarshalable(value.UTC())) {
			return ErrInvalidSourceActivityResponse
		}
	}
	if first != nil && last != nil && last.Before(*first) {
		return ErrInvalidSourceActivityResponse
	}
	return nil
}

func failedSourceActivityLookupOutcome(index int, item sourceActivityPlanItem, response SourceActivityResponse, lookupErr error, parent context.Context, options SourceActivityOptions) sourceActivityLookupOutcome {
	status, code, message, severity := SourceActivityFailed, DiagnosticCode("source_activity.failed"), "The caller-supplied source-activity provider failed.", FindingSeverityLow
	switch {
	case parent != nil && errors.Is(parent.Err(), context.Canceled), errors.Is(lookupErr, context.Canceled):
		status, code, message, severity = SourceActivityCanceled, "source_activity.canceled", "Source-activity collection was canceled before evidence was available.", FindingSeverityInfo
	case parent != nil && errors.Is(parent.Err(), context.DeadlineExceeded):
		status, code, message = SourceActivityCanceled, "source_activity.deadline_exceeded", "Source-activity collection exceeded its caller deadline."
	case errors.Is(lookupErr, context.DeadlineExceeded):
		status, code, message = SourceActivityTimeout, "source_activity.timeout", "The source-activity provider lookup exceeded its deadline."
	case errors.Is(lookupErr, ErrSourceActivityRateLimited):
		status, code, message = SourceActivityRateLimited, "source_activity.rate_limited", "The source-activity provider rate limited the lookup."
	case errors.Is(lookupErr, ErrSourceActivityUnavailable):
		status, code, message, severity = SourceActivityUnavailable, "source_activity.unavailable", "The source-activity provider returned no usable evidence.", FindingSeverityInfo
	case errors.Is(lookupErr, ErrSourceActivityMalformed), errors.Is(lookupErr, ErrInvalidSourceActivityResponse):
		status, code, message, severity = SourceActivityMalformed, "source_activity.malformed", "The source-activity provider returned malformed evidence.", FindingSeverityMedium
	}
	record := emptySourceActivityRecord(item, status)
	if retryAfter, err := normalizeSourceActivityRetryAfter(response.RetryAfter, options.MaxRetryAfter); err == nil {
		record.RetryAfter = retryAfter
	}
	diagnostic := SourceActivityDiagnostic{Code: code, Severity: severity, RecordID: record.ID, Status: status, Message: message}
	return sourceActivityLookupOutcome{index: index, record: record, diagnostics: []SourceActivityDiagnostic{diagnostic}, complete: status != SourceActivityCanceled}
}

func canceledSourceActivityLookupOutcome(index int, item sourceActivityPlanItem, err error) sourceActivityLookupOutcome {
	status, code, message := SourceActivityCanceled, DiagnosticCode("source_activity.canceled"), "Source-activity collection was canceled before evidence was available."
	if errors.Is(err, context.DeadlineExceeded) {
		code, message = "source_activity.deadline_exceeded", "Source-activity collection exceeded its caller deadline."
	}
	record := emptySourceActivityRecord(item, status)
	return sourceActivityLookupOutcome{index: index, record: record, diagnostics: []SourceActivityDiagnostic{{Code: code, Severity: FindingSeverityInfo, RecordID: record.ID, Status: status, Message: message}}, complete: false}
}

func canceledSourceActivityRecords(plan []sourceActivityPlanItem, err error) ([]SourceActivityRecord, []SourceActivityDiagnostic) {
	records := make([]SourceActivityRecord, len(plan))
	diagnostics := make([]SourceActivityDiagnostic, 0, len(plan))
	for index, item := range plan {
		if !item.eligible {
			records[index] = emptySourceActivityRecord(item, SourceActivityNotEligible)
			continue
		}
		outcome := canceledSourceActivityLookupOutcome(index, item, err)
		records[index] = outcome.record
		diagnostics = append(diagnostics, outcome.diagnostics...)
	}
	return records, diagnostics
}

func emptySourceActivityRecord(item sourceActivityPlanItem, status SourceActivityStatus) SourceActivityRecord {
	return SourceActivityRecord{
		ID: StableAnalysisID("source_activity_record", item.ip.String(), joinAnalysisIDs(item.candidateIDs)), SourceIP: item.ip.String(),
		CandidateIDs: append([]AnalysisID(nil), item.candidateIDs...), EnrichmentAssertionIDs: append([]AnalysisID(nil), item.enrichmentAssertionIDs...),
		EnrichmentConflictFields: append([]string(nil), item.enrichmentConflictFields...), ReportWindow: item.reportWindow, Status: status,
		Evidence:   SourceActivityEvidence{Metrics: []SourceActivityMetric{}, ThreatFeeds: []SourceActivityThreatFeed{}, Assertions: []SourceActivityNetworkAssertion{}, ConflictFields: []string{}, Freshness: SourceActivityFreshnessUnknown, TimeRelationship: SourceActivityTimeUnknown, Sensitivity: SensitivityRestricted},
		FindingIDs: []FindingID{}, Sensitivity: SensitivityRestricted,
	}
}

func sourceActivityFindings(record SourceActivityRecord) []SourceActivityFinding {
	findings := make([]SourceActivityFinding, 0, 3)
	if record.Evidence.ActivityObserved {
		findings = append(findings, newSourceActivityFinding(record, "source_activity.observed", FindingSeverityInfo,
			"A third-party source-activity provider returned activity context.",
			"The selected source address appeared in caller-selected third-party activity context. This does not prove malicious email behavior, compromise, ownership, or control.",
			"Review the DMARC evidence, time relationship, and shared-infrastructure limitations before retaining or escalating the candidate."))
	}
	if record.Evidence.TimeRelationship == SourceActivityTimeBeforeReports || record.Evidence.TimeRelationship == SourceActivityTimeAfterReports {
		findings = append(findings, newSourceActivityFinding(record, "source_activity.window_not_overlapping", FindingSeverityInfo,
			"Provider activity and report evidence do not overlap in time.",
			"The supplied provider activity window does not overlap the candidate report window, so temporal relevance is limited.",
			"Keep the evidence windows separate and do not infer that the provider activity explains the DMARC observations."))
	}
	if len(record.Evidence.ConflictFields) > 0 {
		findings = append(findings, newSourceActivityFinding(record, "source_activity.context_conflict", FindingSeverityInfo,
			"Provider network context contains conflicting assertions.",
			"The provider supplied contradictory network context. No preferred assertion was selected.",
			"Retain every assertion and resolve the conflict through an approved independent review workflow."))
	}
	return findings
}

func newSourceActivityFinding(record SourceActivityRecord, code FindingCode, severity FindingSeverity, title, explanation, recommendation string) SourceActivityFinding {
	evidenceIDs := []AnalysisID{}
	if record.Evidence.ID != "" {
		evidenceIDs = []AnalysisID{record.Evidence.ID}
	}
	return SourceActivityFinding{ID: FindingID(StableAnalysisID("source_activity_finding", string(code), string(record.ID))), Code: code, Severity: severity, RecordID: record.ID, EvidenceIDs: evidenceIDs, Title: title, Explanation: explanation, Recommendation: recommendation, Sensitivity: SensitivityRestricted}
}

func sourceActivityResponseDiagnostics(record SourceActivityRecord) []SourceActivityDiagnostic {
	result := make([]SourceActivityDiagnostic, 0, 3)
	if record.Truncated {
		result = append(result, SourceActivityDiagnostic{Code: "source_activity.provider_truncated", Severity: FindingSeverityLow, RecordID: record.ID, Status: record.Status, Message: "The provider reported that source-activity evidence was truncated."})
	}
	if record.Status == SourceActivityStale {
		result = append(result, SourceActivityDiagnostic{Code: "source_activity.stale", Severity: FindingSeverityInfo, RecordID: record.ID, Status: record.Status, Message: "The provider evidence was stale at the collection timestamp."})
	}
	if record.Status == SourceActivityFuture {
		result = append(result, SourceActivityDiagnostic{Code: "source_activity.future", Severity: FindingSeverityMedium, RecordID: record.ID, Status: record.Status, Message: "The provider evidence contains a timestamp after the collection timestamp."})
	}
	return result
}

func sourceActivityFreshness(evidence SourceActivityEvidence, generatedAt time.Time) SourceActivityFreshness {
	for _, value := range []*time.Time{evidence.FirstSeen, evidence.LastSeen, evidence.UpdatedAt} {
		if value != nil && value.After(generatedAt) {
			return SourceActivityFreshnessFuture
		}
	}
	if evidence.ExpiresAt == nil {
		return SourceActivityFreshnessUnknown
	}
	if !evidence.ExpiresAt.After(generatedAt) {
		return SourceActivityFreshnessStale
	}
	return SourceActivityFreshnessFresh
}

func sourceActivityTimeRelationship(report SourceActivityReportWindow, first, last *time.Time) SourceActivityTimeRelationship {
	if !report.FirstSeen.Available || !report.LastSeen.Available || first == nil || last == nil {
		return SourceActivityTimeUnknown
	}
	if last.Before(report.FirstSeen.Value) {
		return SourceActivityTimeBeforeReports
	}
	if first.After(report.LastSeen.Value) {
		return SourceActivityTimeAfterReports
	}
	return SourceActivityTimeOverlaps
}

func sourceActivityConflictFields(values []SourceActivityNetworkAssertion) []string {
	asns, names, prefixes, organizations, countries := map[uint32]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, value := range values {
		if value.ASN != 0 {
			asns[value.ASN] = struct{}{}
		}
		if value.ASNName != "" {
			names[value.ASNName] = struct{}{}
		}
		if value.NetworkPrefix != "" {
			prefixes[value.NetworkPrefix] = struct{}{}
		}
		if value.Organization != "" {
			organizations[value.Organization] = struct{}{}
		}
		if value.CountryCode != "" {
			countries[value.CountryCode] = struct{}{}
		}
	}
	result := []string{}
	if len(asns) > 1 {
		result = append(result, "asn")
	}
	if len(names) > 1 {
		result = append(result, "asn_name")
	}
	if len(prefixes) > 1 {
		result = append(result, "network_prefix")
	}
	if len(organizations) > 1 {
		result = append(result, "organization")
	}
	if len(countries) > 1 {
		result = append(result, "country_code")
	}
	sort.Strings(result)
	return result
}

func compactSourceActivityAssertions(values []SourceActivityNetworkAssertion) []SourceActivityNetworkAssertion {
	result := values[:0]
	for _, value := range values {
		if value.ASN != 0 || value.ASNName != "" || value.NetworkPrefix != "" || value.Organization != "" || value.CountryCode != "" {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return fmt.Sprintf("%010d\x00%s\x00%s\x00%s\x00%s", result[i].ASN, result[i].ASNName, result[i].NetworkPrefix, result[i].Organization, result[i].CountryCode) < fmt.Sprintf("%010d\x00%s\x00%s\x00%s\x00%s", result[j].ASN, result[j].ASNName, result[j].NetworkPrefix, result[j].Organization, result[j].CountryCode)
	})
	return result
}

func sourceActivityEvidenceID(sourceIP string, response SourceActivityResponse, evidence SourceActivityEvidence) AnalysisID {
	canonical, _ := json.Marshal(struct {
		SourceIP  string                 `json:"source_ip"`
		Provider  string                 `json:"provider"`
		Dataset   string                 `json:"dataset"`
		Endpoint  string                 `json:"endpoint"`
		Reference string                 `json:"reference"`
		Evidence  SourceActivityEvidence `json:"evidence"`
	}{sourceIP, response.Provider, response.Dataset, response.EndpointIdentity, response.ReferenceID, evidence})
	return StableAnalysisID("source_activity_evidence", string(canonical))
}

func normalizeSourceActivityRetryAfter(value, maximum time.Duration) (SourceActivityRetryAfter, error) {
	if value < 0 {
		return SourceActivityRetryAfter{}, ErrInvalidSourceActivityResponse
	}
	if value == 0 {
		return SourceActivityRetryAfter{}, nil
	}
	result := SourceActivityRetryAfter{Available: true}
	if maximum > 0 && value > maximum {
		value, result.Capped = maximum, true
	}
	result.Seconds = int64((value + time.Second - 1) / time.Second)
	return result, nil
}

func nilSourceActivityProvider(provider SourceActivityProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func newSourceActivityResult(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, generatedAt time.Time, evaluation Evaluation, complete bool, records []SourceActivityRecord, findings []SourceActivityFinding, diagnostics []SourceActivityDiagnostic) (SourceActivityResult, error) {
	if records == nil {
		records = []SourceActivityRecord{}
	}
	if findings == nil {
		findings = []SourceActivityFinding{}
	}
	if diagnostics == nil {
		diagnostics = []SourceActivityDiagnostic{}
	}
	enrichmentDigest := AnalysisID("")
	if enrichment != nil {
		enrichmentDigest = enrichment.Digest()
	}
	summary := summarizeSourceActivity(records, findings)
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeSourceActivity, GeneratedAt: generatedAt.UTC(), Evaluation: evaluation}
	canonical, err := json.Marshal(struct {
		Metadata               ResultMetadata             `json:"metadata"`
		Version                string                     `json:"version"`
		OrganizationID         string                     `json:"organization_id"`
		ThreatCandidateDigest  AnalysisID                 `json:"threat_candidate_digest"`
		SourceEnrichmentDigest AnalysisID                 `json:"source_enrichment_digest,omitempty"`
		Complete               bool                       `json:"complete"`
		Records                []SourceActivityRecord     `json:"records"`
		Findings               []SourceActivityFinding    `json:"findings"`
		Diagnostics            []SourceActivityDiagnostic `json:"diagnostics"`
		Summary                SourceActivitySummary      `json:"summary"`
	}{metadata, SourceActivityVersion, candidates.OrganizationID(), candidates.Digest(), enrichmentDigest, complete, records, findings, diagnostics, summary})
	if err != nil {
		return SourceActivityResult{}, errors.Join(ErrInvalidSourceActivityOptions, err)
	}
	return SourceActivityResult{metadata: metadata, version: SourceActivityVersion, organizationID: candidates.OrganizationID(), threatCandidateDigest: candidates.Digest(), sourceEnrichmentDigest: enrichmentDigest, digest: StableAnalysisID("source_activity", string(canonical)), complete: complete, records: cloneSourceActivityRecords(records), findings: cloneSourceActivityFindings(findings), diagnostics: append([]SourceActivityDiagnostic(nil), diagnostics...), summary: summary}, nil
}

func summarizeSourceActivity(records []SourceActivityRecord, findings []SourceActivityFinding) SourceActivitySummary {
	counts := map[SourceActivityStatus]int{}
	summary := SourceActivitySummary{Sources: len(records), Findings: len(findings)}
	for _, record := range records {
		counts[record.Status]++
		if record.Status != SourceActivityNotEligible {
			summary.Eligible++
		}
		if record.Evidence.ActivityObserved {
			summary.ActivityObserved++
		}
		if record.Truncated {
			summary.Truncated++
		}
	}
	for _, status := range sourceActivityStatusOrder() {
		if count := counts[status]; count > 0 {
			summary.Statuses = append(summary.Statuses, SourceActivityStatusCount{Status: status, Sources: count})
		}
	}
	return summary
}

func sourceActivityStatusOrder() []SourceActivityStatus {
	return []SourceActivityStatus{SourceActivitySuccess, SourceActivityStale, SourceActivityFuture, SourceActivityConflicting, SourceActivityUnavailable, SourceActivityRateLimited, SourceActivityMalformed, SourceActivityFailed, SourceActivityTimeout, SourceActivityCanceled, SourceActivityNotEligible, SourceActivityNotEvaluated}
}

func sortSourceActivityFindings(values []SourceActivityFinding) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].RecordID != values[j].RecordID {
			return values[i].RecordID < values[j].RecordID
		}
		return values[i].Code < values[j].Code
	})
}
func sortSourceActivityDiagnostics(values []SourceActivityDiagnostic) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].RecordID != values[j].RecordID {
			return values[i].RecordID < values[j].RecordID
		}
		return values[i].Code < values[j].Code
	})
}

func cloneSourceActivityRecords(values []SourceActivityRecord) []SourceActivityRecord {
	result := make([]SourceActivityRecord, len(values))
	for index, value := range values {
		value.CandidateIDs = append([]AnalysisID(nil), value.CandidateIDs...)
		value.EnrichmentAssertionIDs = append([]AnalysisID(nil), value.EnrichmentAssertionIDs...)
		value.EnrichmentConflictFields = append([]string(nil), value.EnrichmentConflictFields...)
		value.FindingIDs = append([]FindingID(nil), value.FindingIDs...)
		value.Evidence = cloneSourceActivityEvidence(value.Evidence)
		result[index] = value
	}
	return result
}

func cloneSourceActivityEvidence(value SourceActivityEvidence) SourceActivityEvidence {
	value.FirstSeen, value.LastSeen, value.UpdatedAt, value.ExpiresAt = cloneUTC(value.FirstSeen), cloneUTC(value.LastSeen), cloneUTC(value.UpdatedAt), cloneUTC(value.ExpiresAt)
	value.Metrics = append([]SourceActivityMetric(nil), value.Metrics...)
	value.Assertions = append([]SourceActivityNetworkAssertion(nil), value.Assertions...)
	value.ConflictFields = append([]string(nil), value.ConflictFields...)
	feeds := value.ThreatFeeds
	value.ThreatFeeds = make([]SourceActivityThreatFeed, len(feeds))
	for index, feed := range feeds {
		feed.FirstSeen, feed.LastSeen = cloneUTC(feed.FirstSeen), cloneUTC(feed.LastSeen)
		value.ThreatFeeds[index] = feed
	}
	return value
}

func cloneSourceActivityFindings(values []SourceActivityFinding) []SourceActivityFinding {
	result := make([]SourceActivityFinding, len(values))
	for index, value := range values {
		value.EvidenceIDs = append([]AnalysisID(nil), value.EvidenceIDs...)
		result[index] = value
	}
	return result
}
func cloneSourceActivitySummary(value SourceActivitySummary) SourceActivitySummary {
	value.Statuses = append([]SourceActivityStatusCount(nil), value.Statuses...)
	return value
}
func cloneUTC(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
}
func uniqueSortedAnalysisIDs(values []AnalysisID) []AnalysisID {
	seen := map[AnalysisID]struct{}{}
	result := []AnalysisID{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
func joinAnalysisIDs(values []AnalysisID) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = string(value)
	}
	return strings.Join(parts, "\x00")
}
