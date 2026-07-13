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
	"unicode"
	"unicode/utf8"
)

const (
	// SourceEnrichmentVersion identifies the current source-enrichment result
	// contract. It is independent of the Go module and output schemas.
	SourceEnrichmentVersion = "1"

	defaultSourceEnrichmentMaxConcurrency = 4
	defaultSourceEnrichmentLookupTimeout  = 5 * time.Second
	maxSourceEnrichmentAssertions         = 64
	maxSourceEnrichmentTextBytes          = 2048
)

var (
	// ErrInvalidSourceEnrichmentOptions identifies invalid limits, timestamps,
	// or a mismatched threat-candidate result.
	ErrInvalidSourceEnrichmentOptions = errors.New("invalid source-enrichment options")
	// ErrInvalidIPMetadata identifies malformed or internally inconsistent
	// caller-supplied enrichment metadata.
	ErrInvalidIPMetadata = errors.New("invalid IP metadata")
	// ErrIPMetadataUnavailable allows an enricher to distinguish a supported
	// lookup with no available metadata from an operational failure.
	ErrIPMetadataUnavailable = errors.New("IP metadata unavailable")
	// ErrSourceEnrichmentFailed identifies a fail-fast enrichment that stopped
	// after a provider failure.
	ErrSourceEnrichmentFailed = errors.New("source enrichment failed")
)

// SourceEnrichmentFailurePolicy controls whether independent IP lookups
// continue after a provider failure. Unavailable, stale, and conflicting data
// remain evidence states rather than provider failures.
type SourceEnrichmentFailurePolicy string

const (
	SourceEnrichmentCollectAll SourceEnrichmentFailurePolicy = "collect_all"
	SourceEnrichmentFailFast   SourceEnrichmentFailurePolicy = "fail_fast"
)

// SourceEnrichmentStatus records the outcome for one candidate.
type SourceEnrichmentStatus string

const (
	SourceEnrichmentNotEvaluated SourceEnrichmentStatus = "not_evaluated"
	SourceEnrichmentNotEligible  SourceEnrichmentStatus = "not_eligible"
	SourceEnrichmentSuccess      SourceEnrichmentStatus = "success"
	SourceEnrichmentUnavailable  SourceEnrichmentStatus = "unavailable"
	SourceEnrichmentStale        SourceEnrichmentStatus = "stale"
	SourceEnrichmentConflicting  SourceEnrichmentStatus = "conflicting"
	SourceEnrichmentFailed       SourceEnrichmentStatus = "failed"
	SourceEnrichmentCanceled     SourceEnrichmentStatus = "canceled"
	SourceEnrichmentTimeout      SourceEnrichmentStatus = "timeout"
)

// SourceEnrichmentFreshness records whether one provider assertion is current
// at the source-enrichment result timestamp.
type SourceEnrichmentFreshness string

const (
	SourceEnrichmentFreshnessUnknown SourceEnrichmentFreshness = "unknown"
	SourceEnrichmentFreshnessFresh   SourceEnrichmentFreshness = "fresh"
	SourceEnrichmentFreshnessStale   SourceEnrichmentFreshness = "stale"
)

// IPMetadataConfidence preserves whether a provider supplied confidence and,
// when available, its value from zero through one hundred.
type IPMetadataConfidence struct {
	Available bool `json:"available"`
	Value     int  `json:"value,omitempty"`
}

// IPMetadataProvenance identifies the caller-selected provider and dataset.
// Provider, Source, and ReferenceID are untrusted data and must never become
// generated instructions or be interpolated into library-generated prose.
type IPMetadataProvenance struct {
	Provider    string               `json:"provider"`
	Source      string               `json:"source,omitempty"`
	LookupAt    time.Time            `json:"lookup_at"`
	ExpiresAt   *time.Time           `json:"expires_at,omitempty"`
	Confidence  IPMetadataConfidence `json:"confidence"`
	ReferenceID string               `json:"reference_id,omitempty"`
}

// IPMetadataAssertion is one normalized provider assertion about an address.
// CountryCode is intentionally coarse; exact geolocation is outside this
// library. Freshness and ID are assigned by EnrichThreatCandidates.
type IPMetadataAssertion struct {
	ID            AnalysisID                `json:"id"`
	ASN           uint32                    `json:"asn,omitempty"`
	ASNName       string                    `json:"asn_name,omitempty"`
	NetworkPrefix string                    `json:"network_prefix,omitempty"`
	Organization  string                    `json:"organization,omitempty"`
	CountryCode   string                    `json:"country_code,omitempty"`
	Provenance    IPMetadataProvenance      `json:"provenance"`
	Freshness     SourceEnrichmentFreshness `json:"freshness"`
	Sensitivity   Sensitivity               `json:"sensitivity"`
}

// IPMetadata contains one or more independent provider assertions. Multiple
// non-zero ASNs or country codes are preserved and marked as conflicts rather
// than collapsed into a preferred answer.
type IPMetadata struct {
	Assertions     []IPMetadataAssertion `json:"assertions"`
	ConflictFields []string              `json:"conflict_fields"`
}

// IPEnricher is the only source-enrichment side-effect boundary. Implementations
// must honor context cancellation and must never ping, scan, open a socket to,
// or otherwise contact the subject IP. A network-backed implementation may
// contact only an explicitly configured third-party service. PTR lookup is a
// separately observable, opt-in operation and must not be hidden in this method.
// Offline or local datasets are preferred. Callers may wrap an implementation
// with their own cache; the library has no global cache.
type IPEnricher interface {
	EnrichIP(ctx context.Context, ip netip.Addr) (IPMetadata, error)
}

// IPEnrichmentBatchItem is one per-address response from BatchIPEnricher. Err
// is converted to a stable status and is never copied into result prose.
type IPEnrichmentBatchItem struct {
	IP       netip.Addr
	Metadata IPMetadata
	Err      error
}

// BatchIPEnricher optionally performs one caller-owned batch request. The
// library supplies canonical, deduplicated addresses in deterministic order.
// Implementations own and must bound any concurrency inside the batch call.
type BatchIPEnricher interface {
	EnrichIPs(ctx context.Context, ips []netip.Addr) ([]IPEnrichmentBatchItem, error)
}

// SourceEnrichmentOptions bounds the explicitly invoked enrichment stage.
// Zero values select safe defaults. There are no retries: each deduplicated IP
// is supplied to the selected enricher at most once per invocation.
type SourceEnrichmentOptions struct {
	MaxConcurrency int
	LookupTimeout  time.Duration
	FailurePolicy  SourceEnrichmentFailurePolicy
	Clock          Clock
}

// EnrichedThreatCandidate is a defensive candidate copy plus optional metadata.
// Successful non-stale, non-conflicting enrichment replaces the prior
// unenriched confidence cap with a provider-confidence cap. It never changes
// Score, ReviewEligible, PromotionEligible, exclusions, or recommended usage.
type EnrichedThreatCandidate struct {
	Candidate ThreatCandidate        `json:"candidate"`
	Status    SourceEnrichmentStatus `json:"status"`
	Metadata  IPMetadata             `json:"metadata"`
}

// ASNEnrichment is a deterministic ASN rollup that retains every underlying
// source IP, candidate, and metadata assertion. Conflicting IPs appear in each
// asserted ASN rather than being hidden by a preferred value.
type ASNEnrichment struct {
	ID                   AnalysisID   `json:"id"`
	ASN                  uint32       `json:"asn"`
	Names                []string     `json:"names"`
	Organizations        []string     `json:"organizations"`
	NetworkPrefixes      []string     `json:"network_prefixes"`
	CountryCodes         []string     `json:"country_codes"`
	Providers            []string     `json:"providers"`
	SourceIPs            []string     `json:"source_ips"`
	CandidateIDs         []AnalysisID `json:"candidate_ids"`
	AssertionIDs         []AnalysisID `json:"assertion_ids"`
	StaleSourceIPs       []string     `json:"stale_source_ips"`
	ConflictingSourceIPs []string     `json:"conflicting_source_ips"`
	Sensitivity          Sensitivity  `json:"sensitivity"`
}

// SourceEnrichmentDiagnostic is value-safe. Message is fixed library text and
// never includes provider errors or metadata strings.
type SourceEnrichmentDiagnostic struct {
	Code         DiagnosticCode  `json:"code"`
	Severity     FindingSeverity `json:"severity"`
	SourceIP     string          `json:"source_ip,omitempty"`
	CandidateIDs []AnalysisID    `json:"candidate_ids"`
	Message      string          `json:"message"`
}

// SourceEnrichmentStatusCount is one deterministic status rollup.
type SourceEnrichmentStatusCount struct {
	Status     SourceEnrichmentStatus `json:"status"`
	Candidates int                    `json:"candidates"`
}

// SourceEnrichmentSummary describes candidate coverage and ASN aggregation.
type SourceEnrichmentSummary struct {
	Candidates int                           `json:"candidates"`
	Eligible   int                           `json:"eligible"`
	ASNs       int                           `json:"asns"`
	Statuses   []SourceEnrichmentStatusCount `json:"statuses"`
}

// SourceEnrichmentResult is an immutable result from the explicitly invoked
// source-enrichment stage.
type SourceEnrichmentResult struct {
	metadata              ResultMetadata
	version               string
	organizationID        string
	threatCandidateDigest AnalysisID
	digest                AnalysisID
	complete              bool
	candidates            []EnrichedThreatCandidate
	asns                  []ASNEnrichment
	diagnostics           []SourceEnrichmentDiagnostic
	summary               SourceEnrichmentSummary
}

func (result SourceEnrichmentResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result SourceEnrichmentResult) Version() string                { return result.version }
func (result SourceEnrichmentResult) OrganizationID() string         { return result.organizationID }
func (result SourceEnrichmentResult) ThreatCandidateDigest() AnalysisID {
	return result.threatCandidateDigest
}
func (result SourceEnrichmentResult) Digest() AnalysisID { return result.digest }
func (result SourceEnrichmentResult) Complete() bool     { return result.complete }
func (result SourceEnrichmentResult) Candidates() []EnrichedThreatCandidate {
	return cloneEnrichedThreatCandidates(result.candidates)
}
func (result SourceEnrichmentResult) ASNs() []ASNEnrichment {
	return cloneASNEnrichments(result.asns)
}
func (result SourceEnrichmentResult) Diagnostics() []SourceEnrichmentDiagnostic {
	return cloneSourceEnrichmentDiagnostics(result.diagnostics)
}
func (result SourceEnrichmentResult) Summary() SourceEnrichmentSummary {
	return cloneSourceEnrichmentSummary(result.summary)
}

// SourceEnrichmentError retains cancellation or the stable fail-fast sentinel
// without exposing provider-controlled error text.
type SourceEnrichmentError struct {
	cause error
}

func (err *SourceEnrichmentError) Error() string {
	if errors.Is(err.cause, context.Canceled) {
		return "source enrichment canceled"
	}
	if errors.Is(err.cause, context.DeadlineExceeded) {
		return "source enrichment deadline exceeded"
	}
	return ErrSourceEnrichmentFailed.Error()
}

func (err *SourceEnrichmentError) Unwrap() error { return err.cause }

type sourceEnrichmentOutcome struct {
	ip       netip.Addr
	metadata IPMetadata
	status   SourceEnrichmentStatus
	failed   bool
	code     DiagnosticCode
	severity FindingSeverity
	message  string
}

// EnrichThreatCandidates explicitly enriches review-eligible, non-excluded
// threat candidates through a caller-supplied dependency. Passing nil is a
// supported no-op that returns not-evaluated coverage and performs no clock or
// network access. The function never performs DNS, PTR, HTTP, SMTP, ICMP, or
// direct source-IP activity itself.
func EnrichThreatCandidates(ctx context.Context, candidates ThreatCandidateResult, enricher IPEnricher, options SourceEnrichmentOptions) (SourceEnrichmentResult, error) {
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return SourceEnrichmentResult{}, err
	}
	options, err := normalizeSourceEnrichmentOptions(options, !nilIPEnricher(enricher))
	if err != nil {
		return SourceEnrichmentResult{}, err
	}
	values := candidates.Candidates()
	if nilIPEnricher(enricher) {
		entries := make([]EnrichedThreatCandidate, len(values))
		for index, candidate := range values {
			candidate.Enrichment = Evaluation{State: EvaluationStateNotEvaluated, Reason: "No IP enricher was supplied."}
			entries[index] = EnrichedThreatCandidate{Candidate: candidate, Status: SourceEnrichmentNotEvaluated, Metadata: emptyIPMetadata()}
		}
		return newSourceEnrichmentResult(candidates, candidates.ResultMetadata().GeneratedAt, Evaluation{State: EvaluationStateNotEvaluated, Reason: "No IP enricher was supplied."}, false, entries, []ASNEnrichment{}, []SourceEnrichmentDiagnostic{})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	generatedAt := options.Clock.Now().UTC()
	if generatedAt.IsZero() || generatedAt.Before(candidates.ResultMetadata().GeneratedAt) {
		return SourceEnrichmentResult{}, ErrInvalidSourceEnrichmentOptions
	}

	eligibleIPs, candidateIDs, err := sourceEnrichmentPlan(values)
	if err != nil {
		return SourceEnrichmentResult{}, err
	}
	outcomes := map[string]sourceEnrichmentOutcome{}
	complete := true
	var stageErr error
	if len(eligibleIPs) > 0 {
		if batch, ok := enricher.(BatchIPEnricher); ok {
			outcomes, complete, stageErr = collectBatchIPEnrichment(ctx, batch, eligibleIPs, generatedAt, options)
		} else {
			outcomes, complete, stageErr = collectIPEnrichment(ctx, enricher, eligibleIPs, generatedAt, options)
		}
		if stageErr != nil {
			complete = false
		}
	}

	entries := make([]EnrichedThreatCandidate, len(values))
	diagnostics := make([]SourceEnrichmentDiagnostic, 0)
	for index, candidate := range values {
		if !sourceEnrichmentEligible(candidate) {
			candidate.Enrichment = Evaluation{State: EvaluationStateNotApplicable, Reason: "The candidate is not eligible for source enrichment."}
			entries[index] = EnrichedThreatCandidate{Candidate: candidate, Status: SourceEnrichmentNotEligible, Metadata: emptyIPMetadata()}
			continue
		}
		outcome, ok := outcomes[candidate.SourceIP]
		if !ok {
			ip := netip.MustParseAddr(candidate.SourceIP)
			if errors.Is(stageErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				outcome = sourceEnrichmentTimeoutOutcome(ip)
			} else {
				outcome = sourceEnrichmentCanceledOutcome(ip)
			}
			complete = false
		}
		candidate, err = applySourceEnrichmentOutcome(candidate, candidates.Profile(), outcome)
		if err != nil {
			return SourceEnrichmentResult{}, err
		}
		entries[index] = EnrichedThreatCandidate{Candidate: candidate, Status: outcome.status, Metadata: cloneIPMetadata(outcome.metadata)}
		if outcome.code != "" {
			diagnostics = append(diagnostics, SourceEnrichmentDiagnostic{
				Code: outcome.code, Severity: outcome.severity, SourceIP: candidate.SourceIP,
				CandidateIDs: append([]AnalysisID{}, candidateIDs[candidate.SourceIP]...), Message: outcome.message,
			})
		}
	}
	sortSourceEnrichmentDiagnostics(diagnostics)
	asns := buildASNEnrichments(entries)
	result, err := newSourceEnrichmentResult(candidates, generatedAt, Evaluation{State: EvaluationStateEvaluated}, complete, entries, asns, diagnostics)
	if err != nil {
		return SourceEnrichmentResult{}, err
	}
	if stageErr != nil {
		return result, &SourceEnrichmentError{cause: stageErr}
	}
	return result, nil
}

func validateSourceEnrichmentInput(result ThreatCandidateResult) error {
	metadata := result.ResultMetadata()
	if result.Digest() == "" || result.OrganizationID() == "" || result.Version() != ThreatCandidateScoringVersion ||
		metadata.ContractVersion != AnalysisContractVersion || metadata.Mode != AnalysisModeThreatCandidates || metadata.Evaluation.State != EvaluationStateEvaluated {
		return ErrInvalidAnalysisResult
	}
	if err := validateThreatCandidateProfile(result.Profile()); err != nil {
		return ErrInvalidAnalysisResult
	}
	for _, candidate := range result.Candidates() {
		ip, err := netip.ParseAddr(candidate.SourceIP)
		if err != nil || ip != ip.Unmap() || candidate.ID == "" || candidate.ScoringVersion != ThreatCandidateScoringVersion || candidate.PromotionEligible {
			return ErrInvalidAnalysisResult
		}
		if ip.Is4() != (candidate.IPType == ThreatCandidateIPv4) || ip.Is6() != (candidate.IPType == ThreatCandidateIPv6) {
			return ErrInvalidAnalysisResult
		}
	}
	return nil
}

func normalizeSourceEnrichmentOptions(options SourceEnrichmentOptions, requireClock bool) (SourceEnrichmentOptions, error) {
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = defaultSourceEnrichmentMaxConcurrency
	}
	if options.LookupTimeout == 0 {
		options.LookupTimeout = defaultSourceEnrichmentLookupTimeout
	}
	if options.FailurePolicy == "" {
		options.FailurePolicy = SourceEnrichmentCollectAll
	}
	if options.MaxConcurrency < 1 || options.MaxConcurrency > 256 || options.LookupTimeout < 0 ||
		(options.FailurePolicy != SourceEnrichmentCollectAll && options.FailurePolicy != SourceEnrichmentFailFast) {
		return SourceEnrichmentOptions{}, ErrInvalidSourceEnrichmentOptions
	}
	if requireClock && options.Clock == nil {
		options.Clock = ClockFunc(time.Now)
	}
	return options, nil
}

func nilIPEnricher(enricher IPEnricher) bool {
	if enricher == nil {
		return true
	}
	value := reflect.ValueOf(enricher)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func sourceEnrichmentEligible(candidate ThreatCandidate) bool {
	return candidate.Evaluation.State == EvaluationStateEvaluated && candidate.ReviewEligible && !candidate.Excluded
}

func sourceEnrichmentPlan(candidates []ThreatCandidate) ([]netip.Addr, map[string][]AnalysisID, error) {
	byIP := map[string]netip.Addr{}
	candidateIDs := map[string][]AnalysisID{}
	for _, candidate := range candidates {
		if !sourceEnrichmentEligible(candidate) {
			continue
		}
		ip, err := netip.ParseAddr(candidate.SourceIP)
		if err != nil || ip != ip.Unmap() {
			return nil, nil, ErrInvalidAnalysisResult
		}
		byIP[ip.String()] = ip
		candidateIDs[ip.String()] = append(candidateIDs[ip.String()], candidate.ID)
	}
	result := make([]netip.Addr, 0, len(byIP))
	for _, ip := range byIP {
		result = append(result, ip)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	for ip := range candidateIDs {
		sort.Slice(candidateIDs[ip], func(i, j int) bool { return candidateIDs[ip][i] < candidateIDs[ip][j] })
	}
	return result, candidateIDs, nil
}

func collectIPEnrichment(ctx context.Context, enricher IPEnricher, ips []netip.Addr, generatedAt time.Time, options SourceEnrichmentOptions) (map[string]sourceEnrichmentOutcome, bool, error) {
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan netip.Addr)
	results := make(chan sourceEnrichmentOutcome, len(ips))
	workerCount := min(options.MaxConcurrency, len(ips))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ip := range jobs {
				if workCtx.Err() != nil {
					continue
				}
				outcome := lookupIPMetadata(workCtx, enricher, ip, generatedAt, options.LookupTimeout)
				if outcome.failed && options.FailurePolicy == SourceEnrichmentFailFast {
					cancel()
				}
				results <- outcome
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case jobs <- ip:
			case <-workCtx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	outcomes := make(map[string]sourceEnrichmentOutcome, len(ips))
	failure := false
	for outcome := range results {
		outcomes[outcome.ip.String()] = outcome
		failure = failure || outcome.failed
	}
	complete := len(outcomes) == len(ips)
	if err := ctx.Err(); err != nil {
		return outcomes, complete, err
	}
	if failure && options.FailurePolicy == SourceEnrichmentFailFast {
		return outcomes, complete, ErrSourceEnrichmentFailed
	}
	return outcomes, complete, nil
}

func collectBatchIPEnrichment(ctx context.Context, enricher BatchIPEnricher, ips []netip.Addr, generatedAt time.Time, options SourceEnrichmentOptions) (map[string]sourceEnrichmentOutcome, bool, error) {
	if err := ctx.Err(); err != nil {
		outcomes := make(map[string]sourceEnrichmentOutcome, len(ips))
		for _, ip := range ips {
			if errors.Is(err, context.DeadlineExceeded) {
				outcomes[ip.String()] = sourceEnrichmentTimeoutOutcome(ip)
			} else {
				outcomes[ip.String()] = sourceEnrichmentCanceledOutcome(ip)
			}
		}
		return outcomes, false, err
	}
	lookupCtx, cancel := context.WithTimeout(ctx, options.LookupTimeout)
	defer cancel()
	items, batchErr := enricher.EnrichIPs(lookupCtx, append([]netip.Addr{}, ips...))
	if lookupErr := lookupCtx.Err(); lookupErr != nil {
		outcomes := make(map[string]sourceEnrichmentOutcome, len(ips))
		for _, ip := range ips {
			if errors.Is(lookupErr, context.DeadlineExceeded) {
				outcomes[ip.String()] = sourceEnrichmentTimeoutOutcome(ip)
			} else {
				outcomes[ip.String()] = sourceEnrichmentCanceledOutcome(ip)
			}
		}
		if err := ctx.Err(); err != nil {
			return outcomes, false, err
		}
		if errors.Is(lookupErr, context.DeadlineExceeded) && options.FailurePolicy == SourceEnrichmentFailFast {
			return outcomes, true, ErrSourceEnrichmentFailed
		}
		return outcomes, true, nil
	}
	requested := make(map[string]netip.Addr, len(ips))
	for _, ip := range ips {
		requested[ip.String()] = ip
	}
	outcomes := make(map[string]sourceEnrichmentOutcome, len(ips))
	duplicates := map[string]struct{}{}
	invalidResponse := false
	for _, item := range items {
		ip := item.IP.Unmap()
		requestedIP, ok := requested[ip.String()]
		if !item.IP.IsValid() || !ok {
			invalidResponse = true
			continue
		}
		if _, exists := outcomes[ip.String()]; exists {
			duplicates[ip.String()] = struct{}{}
			continue
		}
		outcomes[ip.String()] = classifyIPMetadata(requestedIP, item.Metadata, item.Err, generatedAt, ctx)
	}
	for ip := range duplicates {
		outcomes[ip] = sourceEnrichmentInvalidMetadataOutcome(requested[ip])
		invalidResponse = true
	}
	for _, ip := range ips {
		if _, ok := outcomes[ip.String()]; ok {
			continue
		}
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			outcomes[ip.String()] = sourceEnrichmentCanceledOutcome(ip)
		case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(lookupCtx.Err(), context.DeadlineExceeded):
			outcomes[ip.String()] = sourceEnrichmentTimeoutOutcome(ip)
		case errors.Is(lookupCtx.Err(), context.Canceled), errors.Is(batchErr, context.Canceled):
			outcomes[ip.String()] = sourceEnrichmentCanceledOutcome(ip)
		case errors.Is(batchErr, context.DeadlineExceeded):
			outcomes[ip.String()] = sourceEnrichmentTimeoutOutcome(ip)
		case batchErr != nil:
			outcomes[ip.String()] = sourceEnrichmentFailedOutcome(ip)
		default:
			outcomes[ip.String()] = sourceEnrichmentInvalidMetadataOutcome(ip)
			invalidResponse = true
		}
	}
	complete := !invalidResponse && batchErr == nil
	if err := ctx.Err(); err != nil {
		return outcomes, complete, err
	}
	failure := batchErr != nil || invalidResponse
	for _, outcome := range outcomes {
		failure = failure || outcome.failed
	}
	if failure && options.FailurePolicy == SourceEnrichmentFailFast {
		return outcomes, complete, ErrSourceEnrichmentFailed
	}
	return outcomes, complete, nil
}

func lookupIPMetadata(ctx context.Context, enricher IPEnricher, ip netip.Addr, generatedAt time.Time, timeout time.Duration) sourceEnrichmentOutcome {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	metadata, err := enricher.EnrichIP(lookupCtx, ip)
	if contextErr := lookupCtx.Err(); contextErr != nil {
		err = contextErr
	}
	return classifyIPMetadata(ip, metadata, err, generatedAt, ctx)
}

func classifyIPMetadata(ip netip.Addr, metadata IPMetadata, lookupErr error, generatedAt time.Time, parent context.Context) sourceEnrichmentOutcome {
	switch {
	case parent != nil && errors.Is(parent.Err(), context.Canceled):
		return sourceEnrichmentCanceledOutcome(ip)
	case parent != nil && errors.Is(parent.Err(), context.DeadlineExceeded):
		return sourceEnrichmentTimeoutOutcome(ip)
	case errors.Is(lookupErr, context.Canceled):
		return sourceEnrichmentCanceledOutcome(ip)
	case errors.Is(lookupErr, context.DeadlineExceeded):
		return sourceEnrichmentTimeoutOutcome(ip)
	case errors.Is(lookupErr, ErrIPMetadataUnavailable):
		return sourceEnrichmentUnavailableOutcome(ip)
	case lookupErr != nil:
		return sourceEnrichmentFailedOutcome(ip)
	}
	normalized, err := normalizeIPMetadata(ip, metadata, generatedAt)
	if err != nil {
		return sourceEnrichmentInvalidMetadataOutcome(ip)
	}
	if len(normalized.Assertions) == 0 {
		return sourceEnrichmentUnavailableOutcome(ip)
	}
	if len(normalized.ConflictFields) > 0 {
		return sourceEnrichmentOutcome{ip: ip, metadata: normalized, status: SourceEnrichmentConflicting, code: "source_enrichment.conflicting", severity: FindingSeverityMedium, message: "Caller-supplied enrichment assertions conflict."}
	}
	allStale := true
	for _, assertion := range normalized.Assertions {
		allStale = allStale && assertion.Freshness == SourceEnrichmentFreshnessStale
	}
	if allStale {
		return sourceEnrichmentOutcome{ip: ip, metadata: normalized, status: SourceEnrichmentStale, code: "source_enrichment.stale", severity: FindingSeverityLow, message: "All caller-supplied enrichment assertions are stale."}
	}
	return sourceEnrichmentOutcome{ip: ip, metadata: normalized, status: SourceEnrichmentSuccess}
}

func sourceEnrichmentUnavailableOutcome(ip netip.Addr) sourceEnrichmentOutcome {
	return sourceEnrichmentOutcome{ip: ip, metadata: emptyIPMetadata(), status: SourceEnrichmentUnavailable, code: "source_enrichment.unavailable", severity: FindingSeverityInfo, message: "The caller-supplied enricher returned no metadata."}
}

func sourceEnrichmentFailedOutcome(ip netip.Addr) sourceEnrichmentOutcome {
	return sourceEnrichmentOutcome{ip: ip, metadata: emptyIPMetadata(), status: SourceEnrichmentFailed, failed: true, code: "source_enrichment.failed", severity: FindingSeverityLow, message: "The caller-supplied enricher failed."}
}

func sourceEnrichmentInvalidMetadataOutcome(ip netip.Addr) sourceEnrichmentOutcome {
	return sourceEnrichmentOutcome{ip: ip, metadata: emptyIPMetadata(), status: SourceEnrichmentFailed, failed: true, code: "source_enrichment.invalid_metadata", severity: FindingSeverityMedium, message: "The caller-supplied enricher returned invalid metadata."}
}

func sourceEnrichmentCanceledOutcome(ip netip.Addr) sourceEnrichmentOutcome {
	return sourceEnrichmentOutcome{ip: ip, metadata: emptyIPMetadata(), status: SourceEnrichmentCanceled, code: "source_enrichment.canceled", severity: FindingSeverityInfo, message: "Source enrichment was canceled before a result was available."}
}

func sourceEnrichmentTimeoutOutcome(ip netip.Addr) sourceEnrichmentOutcome {
	return sourceEnrichmentOutcome{ip: ip, metadata: emptyIPMetadata(), status: SourceEnrichmentTimeout, failed: true, code: "source_enrichment.timeout", severity: FindingSeverityLow, message: "The caller-supplied enrichment lookup exceeded its deadline."}
}

func normalizeIPMetadata(ip netip.Addr, metadata IPMetadata, generatedAt time.Time) (IPMetadata, error) {
	if len(metadata.Assertions) > maxSourceEnrichmentAssertions {
		return IPMetadata{}, ErrInvalidIPMetadata
	}
	assertions := make([]IPMetadataAssertion, 0, len(metadata.Assertions))
	seen := map[AnalysisID]struct{}{}
	for _, assertion := range metadata.Assertions {
		assertion.ASNName = strings.TrimSpace(assertion.ASNName)
		assertion.Organization = strings.TrimSpace(assertion.Organization)
		assertion.CountryCode = strings.ToUpper(strings.TrimSpace(assertion.CountryCode))
		assertion.Provenance.Provider = strings.TrimSpace(assertion.Provenance.Provider)
		assertion.Provenance.Source = strings.TrimSpace(assertion.Provenance.Source)
		assertion.Provenance.ReferenceID = strings.TrimSpace(assertion.Provenance.ReferenceID)
		assertion.Provenance.LookupAt = assertion.Provenance.LookupAt.UTC()
		assertion.Provenance.ExpiresAt = cloneTimePointer(assertion.Provenance.ExpiresAt)
		if assertion.Provenance.ExpiresAt != nil {
			value := assertion.Provenance.ExpiresAt.UTC()
			assertion.Provenance.ExpiresAt = &value
		}
		if assertion.Provenance.Provider == "" || assertion.Provenance.LookupAt.IsZero() ||
			!sourceEnrichmentTimeMarshalable(assertion.Provenance.LookupAt) ||
			!validSourceEnrichmentText(assertion.ASNName) || !validSourceEnrichmentText(assertion.NetworkPrefix) ||
			!validSourceEnrichmentText(assertion.Organization) || !validSourceEnrichmentText(assertion.CountryCode) ||
			!validSourceEnrichmentText(assertion.Provenance.Provider) || !validSourceEnrichmentText(assertion.Provenance.Source) ||
			!validSourceEnrichmentText(assertion.Provenance.ReferenceID) ||
			assertion.Provenance.Confidence.Value < 0 || assertion.Provenance.Confidence.Value > 100 ||
			(!assertion.Provenance.Confidence.Available && assertion.Provenance.Confidence.Value != 0) ||
			(assertion.Provenance.ExpiresAt != nil && (!sourceEnrichmentTimeMarshalable(*assertion.Provenance.ExpiresAt) ||
				assertion.Provenance.ExpiresAt.Before(assertion.Provenance.LookupAt))) ||
			(assertion.ASN == 0 && assertion.ASNName == "" && strings.TrimSpace(assertion.NetworkPrefix) == "" && assertion.Organization == "" && assertion.CountryCode == "") ||
			(assertion.CountryCode != "" && !validCountryCode(assertion.CountryCode)) {
			return IPMetadata{}, ErrInvalidIPMetadata
		}
		if strings.TrimSpace(assertion.NetworkPrefix) != "" {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(assertion.NetworkPrefix))
			if err != nil {
				return IPMetadata{}, ErrInvalidIPMetadata
			}
			prefix = prefix.Masked()
			if !prefix.Contains(ip) {
				return IPMetadata{}, ErrInvalidIPMetadata
			}
			assertion.NetworkPrefix = prefix.String()
		} else {
			assertion.NetworkPrefix = ""
		}
		switch {
		case assertion.Provenance.ExpiresAt == nil:
			assertion.Freshness = SourceEnrichmentFreshnessUnknown
		case !assertion.Provenance.ExpiresAt.After(generatedAt):
			assertion.Freshness = SourceEnrichmentFreshnessStale
		default:
			assertion.Freshness = SourceEnrichmentFreshnessFresh
		}
		assertion.Sensitivity = SensitivityRestricted
		assertion.ID = sourceEnrichmentAssertionID(ip, assertion)
		if _, ok := seen[assertion.ID]; ok {
			continue
		}
		seen[assertion.ID] = struct{}{}
		assertions = append(assertions, assertion)
	}
	sort.Slice(assertions, func(i, j int) bool { return assertions[i].ID < assertions[j].ID })
	return IPMetadata{Assertions: assertions, ConflictFields: sourceEnrichmentConflictFields(assertions)}, nil
}

func sourceEnrichmentTimeMarshalable(value time.Time) bool {
	_, err := value.MarshalJSON()
	return err == nil
}

func validSourceEnrichmentText(value string) bool {
	return len(value) <= maxSourceEnrichmentTextBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validCountryCode(value string) bool {
	if len(value) != 2 {
		return false
	}
	return value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func sourceEnrichmentAssertionID(ip netip.Addr, assertion IPMetadataAssertion) AnalysisID {
	expiresAt := ""
	if assertion.Provenance.ExpiresAt != nil {
		expiresAt = assertion.Provenance.ExpiresAt.Format(time.RFC3339Nano)
	}
	return StableAnalysisID("ip_metadata_assertion", ip.String(), fmt.Sprint(assertion.ASN), assertion.ASNName,
		assertion.NetworkPrefix, assertion.Organization, assertion.CountryCode, assertion.Provenance.Provider,
		assertion.Provenance.Source, assertion.Provenance.LookupAt.Format(time.RFC3339Nano), expiresAt,
		fmt.Sprint(assertion.Provenance.Confidence.Available), fmt.Sprint(assertion.Provenance.Confidence.Value), assertion.Provenance.ReferenceID)
}

func sourceEnrichmentConflictFields(assertions []IPMetadataAssertion) []string {
	asns := map[uint32]struct{}{}
	countries := map[string]struct{}{}
	for _, assertion := range assertions {
		if assertion.ASN != 0 {
			asns[assertion.ASN] = struct{}{}
		}
		if assertion.CountryCode != "" {
			countries[assertion.CountryCode] = struct{}{}
		}
	}
	result := []string{}
	if len(asns) > 1 {
		result = append(result, "asn")
	}
	if len(countries) > 1 {
		result = append(result, "country_code")
	}
	return result
}

func applySourceEnrichmentOutcome(candidate ThreatCandidate, profile ThreatCandidateScoringProfile, outcome sourceEnrichmentOutcome) (ThreatCandidate, error) {
	switch outcome.status {
	case SourceEnrichmentSuccess:
		candidate.Enrichment = Evaluation{State: EvaluationStateEvaluated}
		code, maximum, message := sourceEnrichmentConfidenceCap(outcome.metadata, profile)
		adjustments := append([]ThreatCandidateConfidenceAdjustment{}, candidate.ConfidenceAdjustments...)
		for index := range adjustments {
			if adjustments[index].Code == "threat_candidate.unenriched" {
				adjustments[index].Code = code
				adjustments[index].Maximum = maximum
				adjustments[index].Message = message
			}
		}
		candidate.Confidence = 100
		for index := range adjustments {
			adjustments[index].Before = candidate.Confidence
			candidate.Confidence = min(candidate.Confidence, adjustments[index].Maximum)
			adjustments[index].After = candidate.Confidence
		}
		candidate.ConfidenceAdjustments = adjustments
		candidate.ConfidenceLevel = threatCandidateConfidence(candidate.Confidence)
		candidate.Severity = threatCandidateSeverity(min(candidate.Score, candidate.Confidence), profile)
		if confidence, err := RecomputeThreatCandidateConfidence(candidate); err != nil || confidence != candidate.Confidence {
			return ThreatCandidate{}, ErrInvalidAnalysisResult
		}
	case SourceEnrichmentNotEligible:
		candidate.Enrichment = Evaluation{State: EvaluationStateNotApplicable, Reason: "The candidate is not eligible for source enrichment."}
	case SourceEnrichmentNotEvaluated:
		candidate.Enrichment = Evaluation{State: EvaluationStateNotEvaluated, Reason: "No IP enricher was supplied."}
	case SourceEnrichmentUnavailable:
		candidate.Enrichment = Evaluation{State: EvaluationStateUnknown, Reason: "The caller-supplied enricher returned no metadata."}
	case SourceEnrichmentStale:
		candidate.Enrichment = Evaluation{State: EvaluationStateUnknown, Reason: "All caller-supplied enrichment assertions are stale."}
	case SourceEnrichmentConflicting:
		candidate.Enrichment = Evaluation{State: EvaluationStateUnknown, Reason: "Caller-supplied enrichment assertions conflict."}
	case SourceEnrichmentFailed:
		candidate.Enrichment = Evaluation{State: EvaluationStateUnknown, Reason: "The caller-supplied enricher failed."}
	case SourceEnrichmentCanceled:
		candidate.Enrichment = Evaluation{State: EvaluationStateUnknown, Reason: "Source enrichment was canceled before a result was available."}
	case SourceEnrichmentTimeout:
		candidate.Enrichment = Evaluation{State: EvaluationStateUnknown, Reason: "The caller-supplied enrichment lookup exceeded its deadline."}
	default:
		return ThreatCandidate{}, ErrInvalidAnalysisResult
	}
	candidate.PromotionEligible = false
	return candidate, nil
}

func sourceEnrichmentConfidenceCap(metadata IPMetadata, profile ThreatCandidateScoringProfile) (FindingCode, int, string) {
	maximum := 100
	for _, assertion := range metadata.Assertions {
		if !assertion.Provenance.Confidence.Available {
			return "threat_candidate.enrichment_confidence_unknown", profile.UnenrichedConfidenceCap, "Caller-supplied enrichment did not provide complete confidence evidence."
		}
		maximum = min(maximum, assertion.Provenance.Confidence.Value)
	}
	return "threat_candidate.enrichment_provider_confidence", maximum, "Caller-supplied enrichment confidence limits candidate confidence."
}

type asnEnrichmentAccumulator struct {
	names, organizations, prefixes, countries, providers map[string]struct{}
	sourceIPs, staleIPs, conflictingIPs                  map[string]struct{}
	candidateIDs, assertionIDs                           map[AnalysisID]struct{}
}

func buildASNEnrichments(candidates []EnrichedThreatCandidate) []ASNEnrichment {
	byASN := map[uint32]*asnEnrichmentAccumulator{}
	for _, enriched := range candidates {
		for _, assertion := range enriched.Metadata.Assertions {
			if assertion.ASN == 0 {
				continue
			}
			accumulator := byASN[assertion.ASN]
			if accumulator == nil {
				accumulator = &asnEnrichmentAccumulator{
					names: map[string]struct{}{}, organizations: map[string]struct{}{}, prefixes: map[string]struct{}{}, countries: map[string]struct{}{}, providers: map[string]struct{}{},
					sourceIPs: map[string]struct{}{}, staleIPs: map[string]struct{}{}, conflictingIPs: map[string]struct{}{}, candidateIDs: map[AnalysisID]struct{}{}, assertionIDs: map[AnalysisID]struct{}{},
				}
				byASN[assertion.ASN] = accumulator
			}
			addNonEmptyString(accumulator.names, assertion.ASNName)
			addNonEmptyString(accumulator.organizations, assertion.Organization)
			addNonEmptyString(accumulator.prefixes, assertion.NetworkPrefix)
			addNonEmptyString(accumulator.countries, assertion.CountryCode)
			addNonEmptyString(accumulator.providers, assertion.Provenance.Provider)
			accumulator.sourceIPs[enriched.Candidate.SourceIP] = struct{}{}
			accumulator.candidateIDs[enriched.Candidate.ID] = struct{}{}
			accumulator.assertionIDs[assertion.ID] = struct{}{}
			if assertion.Freshness == SourceEnrichmentFreshnessStale {
				accumulator.staleIPs[enriched.Candidate.SourceIP] = struct{}{}
			}
			if enriched.Status == SourceEnrichmentConflicting {
				accumulator.conflictingIPs[enriched.Candidate.SourceIP] = struct{}{}
			}
		}
	}
	asns := make([]uint32, 0, len(byASN))
	for asn := range byASN {
		asns = append(asns, asn)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	result := make([]ASNEnrichment, 0, len(asns))
	for _, asn := range asns {
		value := byASN[asn]
		result = append(result, ASNEnrichment{
			ID: StableAnalysisID("asn_enrichment", fmt.Sprint(asn), strings.Join(sortedStringSet(value.sourceIPs), "\x00")), ASN: asn,
			Names: sortedStringSet(value.names), Organizations: sortedStringSet(value.organizations), NetworkPrefixes: sortedStringSet(value.prefixes),
			CountryCodes: sortedStringSet(value.countries), Providers: sortedStringSet(value.providers), SourceIPs: sortedStringSet(value.sourceIPs),
			CandidateIDs: sortedAnalysisIDSet(value.candidateIDs), AssertionIDs: sortedAnalysisIDSet(value.assertionIDs),
			StaleSourceIPs: sortedStringSet(value.staleIPs), ConflictingSourceIPs: sortedStringSet(value.conflictingIPs), Sensitivity: SensitivityRestricted,
		})
	}
	return result
}

func addNonEmptyString(values map[string]struct{}, value string) {
	if value != "" {
		values[value] = struct{}{}
	}
}

func newSourceEnrichmentResult(candidates ThreatCandidateResult, generatedAt time.Time, evaluation Evaluation, complete bool, enriched []EnrichedThreatCandidate, asns []ASNEnrichment, diagnostics []SourceEnrichmentDiagnostic) (SourceEnrichmentResult, error) {
	statusCounts := map[SourceEnrichmentStatus]int{}
	eligible := 0
	for _, value := range enriched {
		statusCounts[value.Status]++
		if sourceEnrichmentEligible(value.Candidate) {
			eligible++
		}
	}
	summary := SourceEnrichmentSummary{Candidates: len(enriched), Eligible: eligible, ASNs: len(asns), Statuses: []SourceEnrichmentStatusCount{}}
	for _, status := range sourceEnrichmentStatusOrder() {
		if count := statusCounts[status]; count > 0 {
			summary.Statuses = append(summary.Statuses, SourceEnrichmentStatusCount{Status: status, Candidates: count})
		}
	}
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeSourceEnrichment, GeneratedAt: generatedAt, Evaluation: evaluation}
	canonical, err := json.Marshal(struct {
		Metadata              ResultMetadata               `json:"metadata"`
		Version               string                       `json:"version"`
		OrganizationID        string                       `json:"organization_id"`
		ThreatCandidateDigest AnalysisID                   `json:"threat_candidate_digest"`
		Complete              bool                         `json:"complete"`
		Candidates            []EnrichedThreatCandidate    `json:"candidates"`
		ASNs                  []ASNEnrichment              `json:"asns"`
		Diagnostics           []SourceEnrichmentDiagnostic `json:"diagnostics"`
		Summary               SourceEnrichmentSummary      `json:"summary"`
	}{metadata, SourceEnrichmentVersion, candidates.OrganizationID(), candidates.Digest(), complete, enriched, asns, diagnostics, summary})
	if err != nil {
		return SourceEnrichmentResult{}, errors.Join(ErrInvalidSourceEnrichmentOptions, err)
	}
	return SourceEnrichmentResult{
		metadata: metadata, version: SourceEnrichmentVersion, organizationID: candidates.OrganizationID(), threatCandidateDigest: candidates.Digest(),
		digest: StableAnalysisID("source_enrichment", string(canonical)), complete: complete,
		candidates: cloneEnrichedThreatCandidates(enriched), asns: cloneASNEnrichments(asns), diagnostics: cloneSourceEnrichmentDiagnostics(diagnostics), summary: cloneSourceEnrichmentSummary(summary),
	}, nil
}

func sourceEnrichmentStatusOrder() []SourceEnrichmentStatus {
	return []SourceEnrichmentStatus{
		SourceEnrichmentSuccess, SourceEnrichmentConflicting, SourceEnrichmentStale, SourceEnrichmentUnavailable,
		SourceEnrichmentFailed, SourceEnrichmentTimeout, SourceEnrichmentCanceled, SourceEnrichmentNotEligible, SourceEnrichmentNotEvaluated,
	}
}

func sortSourceEnrichmentDiagnostics(values []SourceEnrichmentDiagnostic) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].SourceIP != values[j].SourceIP {
			left, leftErr := netip.ParseAddr(values[i].SourceIP)
			right, rightErr := netip.ParseAddr(values[j].SourceIP)
			if leftErr == nil && rightErr == nil {
				return left.Compare(right) < 0
			}
			return values[i].SourceIP < values[j].SourceIP
		}
		return values[i].Code < values[j].Code
	})
}

func emptyIPMetadata() IPMetadata {
	return IPMetadata{Assertions: []IPMetadataAssertion{}, ConflictFields: []string{}}
}

func cloneIPMetadata(value IPMetadata) IPMetadata {
	value.Assertions = append([]IPMetadataAssertion{}, value.Assertions...)
	for index := range value.Assertions {
		value.Assertions[index].Provenance.ExpiresAt = cloneTimePointer(value.Assertions[index].Provenance.ExpiresAt)
	}
	value.ConflictFields = cloneStrings(value.ConflictFields)
	return value
}

func cloneEnrichedThreatCandidates(values []EnrichedThreatCandidate) []EnrichedThreatCandidate {
	result := make([]EnrichedThreatCandidate, len(values))
	for index, value := range values {
		value.Candidate = cloneThreatCandidates([]ThreatCandidate{value.Candidate})[0]
		value.Metadata = cloneIPMetadata(value.Metadata)
		result[index] = value
	}
	return result
}

func cloneASNEnrichments(values []ASNEnrichment) []ASNEnrichment {
	result := make([]ASNEnrichment, len(values))
	for index, value := range values {
		value.Names = cloneStrings(value.Names)
		value.Organizations = cloneStrings(value.Organizations)
		value.NetworkPrefixes = cloneStrings(value.NetworkPrefixes)
		value.CountryCodes = cloneStrings(value.CountryCodes)
		value.Providers = cloneStrings(value.Providers)
		value.SourceIPs = cloneStrings(value.SourceIPs)
		value.CandidateIDs = append([]AnalysisID{}, value.CandidateIDs...)
		value.AssertionIDs = append([]AnalysisID{}, value.AssertionIDs...)
		value.StaleSourceIPs = cloneStrings(value.StaleSourceIPs)
		value.ConflictingSourceIPs = cloneStrings(value.ConflictingSourceIPs)
		result[index] = value
	}
	return result
}

func cloneSourceEnrichmentDiagnostics(values []SourceEnrichmentDiagnostic) []SourceEnrichmentDiagnostic {
	result := make([]SourceEnrichmentDiagnostic, len(values))
	for index, value := range values {
		value.CandidateIDs = append([]AnalysisID{}, value.CandidateIDs...)
		result[index] = value
	}
	return result
}

func cloneSourceEnrichmentSummary(value SourceEnrichmentSummary) SourceEnrichmentSummary {
	value.Statuses = append([]SourceEnrichmentStatusCount{}, value.Statuses...)
	return value
}
