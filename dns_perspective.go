package dmarcgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// DNSPerspectiveVersion identifies the normalized DNS-perspective result
	// contract. It is independent of the Go module and output schemas.
	DNSPerspectiveVersion = "1"

	defaultDNSPerspectiveMaxQueries               = 64
	defaultDNSPerspectiveMaxConcurrency           = 1
	defaultDNSPerspectiveLookupTimeout            = 10 * time.Second
	defaultDNSPerspectiveMaxObservationsPerQuery  = 256
	defaultDNSPerspectiveMaxAnswersPerObservation = 32
	defaultDNSPerspectiveMaxTextBytes             = 4096
	defaultDNSPerspectiveMaxTotalTextBytes        = 1024 * 1024
	defaultDNSPerspectiveMaxRetryAfter            = time.Hour
	maxDNSPerspectiveQueries                      = 256
	maxDNSPerspectiveConcurrency                  = 4
	maxDNSPerspectiveLookupTimeout                = 5 * time.Minute
	maxDNSPerspectiveObservationsPerQuery         = 1024
	maxDNSPerspectiveAnswersPerObservation        = 256
	maxDNSPerspectiveTextBytes                    = 64 * 1024
	maxDNSPerspectiveTotalTextBytes               = 8 * 1024 * 1024
	maxDNSPerspectiveRetryAfter                   = 7 * 24 * time.Hour
)

var (
	// ErrInvalidDNSPerspectiveOptions identifies invalid selection, limits, or
	// mismatched portfolio/snapshot inputs.
	ErrInvalidDNSPerspectiveOptions = errors.New("invalid DNS perspective options")
	// ErrInvalidDNSPerspectiveResponse identifies structurally unsafe or
	// internally inconsistent provider evidence.
	ErrInvalidDNSPerspectiveResponse = errors.New("invalid DNS perspective response")
	// ErrDNSPerspectiveRateLimited lets providers expose a stable rate-limit
	// outcome without copying an HTTP response body into normalized evidence.
	ErrDNSPerspectiveRateLimited = errors.New("DNS perspective provider rate limited")
	// ErrDNSPerspectiveUnavailable identifies a supported lookup for which the
	// provider supplied no usable evidence.
	ErrDNSPerspectiveUnavailable = errors.New("DNS perspective unavailable")
	// ErrDNSPerspectiveMalformed identifies a provider response that the adapter
	// could not safely normalize.
	ErrDNSPerspectiveMalformed = errors.New("DNS perspective response malformed")
)

// DNSPerspectiveRecordType is the provider-neutral DNS RR type. The Phase 15
// planner emits TXT only; the interface can represent later explicitly scoped
// standard-record features without changing its method signature.
type DNSPerspectiveRecordType string

const (
	DNSPerspectiveTXT DNSPerspectiveRecordType = "TXT"
)

// DNSPerspectiveOutcome is a stable normalized provider or stage outcome.
type DNSPerspectiveOutcome string

const (
	DNSPerspectiveNotEvaluated DNSPerspectiveOutcome = "not_evaluated"
	DNSPerspectiveSuccess      DNSPerspectiveOutcome = "success"
	DNSPerspectiveNoAnswer     DNSPerspectiveOutcome = "no_answer"
	DNSPerspectiveFailed       DNSPerspectiveOutcome = "failed"
	DNSPerspectiveRateLimited  DNSPerspectiveOutcome = "rate_limited"
	DNSPerspectiveMalformed    DNSPerspectiveOutcome = "malformed"
	DNSPerspectiveUnavailable  DNSPerspectiveOutcome = "unavailable"
	DNSPerspectiveCanceled     DNSPerspectiveOutcome = "canceled"
)

// DNSPerspectiveAgreement describes answer-set comparison without claiming
// that any remote perspective is authoritative.
type DNSPerspectiveAgreement string

const (
	DNSPerspectiveAgreementNotEvaluated DNSPerspectiveAgreement = "not_evaluated"
	DNSPerspectiveAgreementUnknown      DNSPerspectiveAgreement = "unknown"
	DNSPerspectiveAnswersAgree          DNSPerspectiveAgreement = "agreement"
	DNSPerspectiveAnswersDisagree       DNSPerspectiveAgreement = "disagreement"
)

// DNSPerspectiveQuery contains only the explicitly disclosed owner name and RR
// type. Portfolio ownership and other organization metadata are not sent to a
// provider.
type DNSPerspectiveQuery struct {
	Name string                   `json:"name"`
	Type DNSPerspectiveRecordType `json:"type"`
}

// DNSPerspectiveAnswer preserves one provider-supplied answer. TXT adapters
// should supply Fragments when they can recover DNS character-string
// boundaries; Joined is the complete TXT value used for answer-set comparison.
type DNSPerspectiveAnswer struct {
	Fragments          []string    `json:"fragments"`
	FragmentsAvailable bool        `json:"fragments_available"`
	Joined             string      `json:"joined"`
	Sensitivity        Sensitivity `json:"sensitivity"`
}

// DNSPerspectiveProviderObservation is one independently identified resolver
// or provider perspective. PerspectiveID must be stable and unique within one
// response. Perspective and Status are untrusted provider-controlled data.
type DNSPerspectiveProviderObservation struct {
	PerspectiveID string                 `json:"perspective_id"`
	Perspective   string                 `json:"perspective,omitempty"`
	Status        string                 `json:"status,omitempty"`
	Outcome       DNSPerspectiveOutcome  `json:"outcome"`
	Answers       []DNSPerspectiveAnswer `json:"answers"`
}

// DNSPerspectiveResponse is returned by a caller-supplied provider. Provider,
// Dataset, ReferenceID, observations, and answers are untrusted data. A
// positive RetryAfter is normalized and capped for caller policy; the library
// never sleeps or retries automatically.
type DNSPerspectiveResponse struct {
	Provider     string                              `json:"provider"`
	Dataset      string                              `json:"dataset"`
	ReferenceID  string                              `json:"reference_id,omitempty"`
	Observations []DNSPerspectiveProviderObservation `json:"observations"`
	RetryAfter   time.Duration                       `json:"-"`
	Truncated    bool                                `json:"truncated"`
}

// DNSPerspectiveProvider is the only side-effect boundary used by perspective
// collection. Implementations must honor context cancellation, enforce a
// bounded raw response size, contact only their configured third-party
// service, and never contact an observed source IP. Redirect and destination
// policy remain implementation or caller responsibilities. Each query is
// supplied at most once per collection invocation.
type DNSPerspectiveProvider interface {
	LookupDNSPerspective(context.Context, DNSPerspectiveQuery) (DNSPerspectiveResponse, error)
}

// DNSPerspectiveSelection explicitly chooses which normalized portfolio owner
// names may be disclosed. Names and Roles are unioned. The Phase 15 planner
// always requests TXT.
type DNSPerspectiveSelection struct {
	Names []string
	Roles []DNSRecordType
}

// DNSPerspectiveOptions bounds explicitly invoked collection. Zero values use
// conservative defaults. There are no retries, sleeps, polling, discovery, or
// hidden lookups.
type DNSPerspectiveOptions struct {
	Selection                DNSPerspectiveSelection
	MaxQueries               int
	MaxConcurrency           int
	LookupTimeout            time.Duration
	MaxObservationsPerQuery  int
	MaxAnswersPerObservation int
	MaxTextBytes             int
	MaxTotalTextBytes        int
	MaxRetryAfter            time.Duration
	Clock                    Clock
}

// DNSPerspectiveRetryAfter is bounded metadata for caller-owned scheduling.
type DNSPerspectiveRetryAfter struct {
	Available bool  `json:"available"`
	Seconds   int64 `json:"seconds,omitempty"`
	Capped    bool  `json:"capped"`
}

// DNSPerspectiveProvenance identifies the caller-selected provider and data
// contract. All strings are untrusted structured data.
type DNSPerspectiveProvenance struct {
	Provider    string      `json:"provider"`
	Dataset     string      `json:"dataset"`
	ReferenceID string      `json:"reference_id,omitempty"`
	CollectedAt time.Time   `json:"collected_at"`
	Sensitivity Sensitivity `json:"sensitivity"`
}

// DNSPerspectiveSnapshotReference ties a query back to the trusted snapshot
// without treating the remote result as authoritative DNS evidence.
type DNSPerspectiveSnapshotReference struct {
	SnapshotDigest    AnalysisID           `json:"snapshot_digest"`
	ObservedAt        time.Time            `json:"observed_at"`
	ObservationName   string               `json:"observation_name"`
	Status            DNSObservationStatus `json:"status"`
	AnswerFingerprint AnalysisID           `json:"answer_fingerprint,omitempty"`
	References        []DNSRecordReference `json:"references"`
	Sensitivity       Sensitivity          `json:"sensitivity"`
}

// DNSPerspectiveObservation is one normalized provider perspective.
type DNSPerspectiveObservation struct {
	ID                AnalysisID             `json:"id"`
	PerspectiveID     string                 `json:"perspective_id"`
	Perspective       string                 `json:"perspective,omitempty"`
	ProviderStatus    string                 `json:"provider_status,omitempty"`
	Outcome           DNSPerspectiveOutcome  `json:"outcome"`
	Answers           []DNSPerspectiveAnswer `json:"answers"`
	AnswerFingerprint AnalysisID             `json:"answer_fingerprint,omitempty"`
	Sensitivity       Sensitivity            `json:"sensitivity"`
}

// DNSPerspectiveQueryResult contains supplemental resolver-consistency
// evidence for one selected authentication record name.
type DNSPerspectiveQueryResult struct {
	ID                     AnalysisID                      `json:"id"`
	Query                  DNSPerspectiveQuery             `json:"query"`
	Snapshot               DNSPerspectiveSnapshotReference `json:"snapshot"`
	Provenance             DNSPerspectiveProvenance        `json:"provenance"`
	Outcome                DNSPerspectiveOutcome           `json:"outcome"`
	Observations           []DNSPerspectiveObservation     `json:"observations"`
	SuccessfulPerspectives int                             `json:"successful_perspectives"`
	NoAnswerPerspectives   int                             `json:"no_answer_perspectives"`
	FailedPerspectives     int                             `json:"failed_perspectives"`
	PerspectiveAgreement   DNSPerspectiveAgreement         `json:"perspective_agreement"`
	SnapshotAgreement      DNSPerspectiveAgreement         `json:"snapshot_agreement"`
	RetryAfter             DNSPerspectiveRetryAfter        `json:"retry_after"`
	Truncated              bool                            `json:"truncated"`
	Sensitivity            Sensitivity                     `json:"sensitivity"`
}

// DNSPerspectiveFinding uses only fixed library-controlled prose. Query names
// and provider evidence stay in structured fields and evidence identifiers.
type DNSPerspectiveFinding struct {
	ID             FindingID       `json:"id"`
	Code           FindingCode     `json:"code"`
	Severity       FindingSeverity `json:"severity"`
	QueryID        AnalysisID      `json:"query_id"`
	EvidenceIDs    []AnalysisID    `json:"evidence_ids"`
	Title          string          `json:"title"`
	Explanation    string          `json:"explanation"`
	Recommendation string          `json:"recommendation"`
	Sensitivity    Sensitivity     `json:"sensitivity"`
}

// DNSPerspectiveDiagnostic is value-safe. Message never includes provider
// errors, status strings, answer text, or other untrusted data.
type DNSPerspectiveDiagnostic struct {
	Code     DiagnosticCode        `json:"code"`
	Severity FindingSeverity       `json:"severity"`
	QueryID  AnalysisID            `json:"query_id"`
	Outcome  DNSPerspectiveOutcome `json:"outcome"`
	Message  string                `json:"message"`
}

// DNSPerspectiveOutcomeCount is one deterministic query-outcome rollup.
type DNSPerspectiveOutcomeCount struct {
	Outcome DNSPerspectiveOutcome `json:"outcome"`
	Queries int                   `json:"queries"`
}

// DNSPerspectiveSummary describes selected-query coverage without changing DNS
// health or maturity scores.
type DNSPerspectiveSummary struct {
	Queries                int                          `json:"queries"`
	Perspectives           int                          `json:"perspectives"`
	SuccessfulPerspectives int                          `json:"successful_perspectives"`
	NoAnswerPerspectives   int                          `json:"no_answer_perspectives"`
	FailedPerspectives     int                          `json:"failed_perspectives"`
	TruncatedQueries       int                          `json:"truncated_queries"`
	Findings               int                          `json:"findings"`
	Outcomes               []DNSPerspectiveOutcomeCount `json:"outcomes"`
}

// DNSPerspectiveResult is an immutable result from the explicitly invoked
// remote-perspective stage.
type DNSPerspectiveResult struct {
	metadata        ResultMetadata
	version         string
	portfolioDigest AnalysisID
	snapshotDigest  AnalysisID
	digest          AnalysisID
	complete        bool
	queries         []DNSPerspectiveQueryResult
	findings        []DNSPerspectiveFinding
	diagnostics     []DNSPerspectiveDiagnostic
	summary         DNSPerspectiveSummary
}

func (result DNSPerspectiveResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result DNSPerspectiveResult) Version() string                { return result.version }
func (result DNSPerspectiveResult) PortfolioDigest() AnalysisID    { return result.portfolioDigest }
func (result DNSPerspectiveResult) SnapshotDigest() AnalysisID     { return result.snapshotDigest }
func (result DNSPerspectiveResult) Digest() AnalysisID             { return result.digest }

// Complete reports whether every selected query reached a terminal outcome.
// It does not mean that every remote perspective returned a successful answer.
func (result DNSPerspectiveResult) Complete() bool { return result.complete }
func (result DNSPerspectiveResult) Queries() []DNSPerspectiveQueryResult {
	return cloneDNSPerspectiveQueryResults(result.queries)
}
func (result DNSPerspectiveResult) Findings() []DNSPerspectiveFinding {
	return cloneDNSPerspectiveFindings(result.findings)
}
func (result DNSPerspectiveResult) Diagnostics() []DNSPerspectiveDiagnostic {
	return append([]DNSPerspectiveDiagnostic(nil), result.diagnostics...)
}
func (result DNSPerspectiveResult) Summary() DNSPerspectiveSummary {
	value := result.summary
	value.Outcomes = append([]DNSPerspectiveOutcomeCount(nil), value.Outcomes...)
	return value
}

// DNSPerspectiveError retains cancellation without exposing provider errors.
type DNSPerspectiveError struct{ cause error }

func (err *DNSPerspectiveError) Error() string {
	if errors.Is(err.cause, context.DeadlineExceeded) {
		return "DNS perspective collection deadline exceeded"
	}
	return "DNS perspective collection canceled"
}

func (err *DNSPerspectiveError) Unwrap() error { return err.cause }

type dnsPerspectivePlanItem struct {
	query    DNSPerspectiveQuery
	snapshot DNSPerspectiveSnapshotReference
}

type dnsPerspectiveLookupOutcome struct {
	index       int
	result      DNSPerspectiveQueryResult
	findings    []DNSPerspectiveFinding
	diagnostics []DNSPerspectiveDiagnostic
	complete    bool
}

// CollectDNSPerspectives explicitly requests supplemental DNS resolver
// perspectives for selected authentication TXT owner names. Passing nil is a
// supported no-op that does not consult a clock or perform network access.
// Remote evidence never mutates the supplied snapshot or DNS health scores.
func CollectDNSPerspectives(ctx context.Context, portfolio Portfolio, snapshot DNSSnapshot, provider DNSPerspectiveProvider, options DNSPerspectiveOptions) (DNSPerspectiveResult, error) {
	if err := validateDNSPerspectiveInputs(portfolio, snapshot); err != nil {
		return DNSPerspectiveResult{}, err
	}
	providerAvailable := !nilDNSPerspectiveProvider(provider)
	options, err := normalizeDNSPerspectiveOptions(options, providerAvailable)
	if err != nil {
		return DNSPerspectiveResult{}, err
	}
	plan, err := buildDNSPerspectivePlan(portfolio, snapshot, options.Selection)
	if err != nil {
		return DNSPerspectiveResult{}, err
	}
	if len(plan) > options.MaxQueries {
		return DNSPerspectiveResult{}, fmt.Errorf("%w: selected query count exceeds the configured limit", ErrInvalidDNSPerspectiveOptions)
	}
	if !providerAvailable {
		queries := make([]DNSPerspectiveQueryResult, len(plan))
		for index, item := range plan {
			queries[index] = emptyDNSPerspectiveQueryResult(item, DNSPerspectiveNotEvaluated)
		}
		return newDNSPerspectiveResult(portfolio, snapshot, snapshot.ObservedAt(), Evaluation{
			State: EvaluationStateNotEvaluated, Reason: "No DNS perspective provider was supplied.",
		}, false, queries, []DNSPerspectiveFinding{}, []DNSPerspectiveDiagnostic{})
	}
	if len(plan) == 0 {
		return newDNSPerspectiveResult(portfolio, snapshot, snapshot.ObservedAt(), Evaluation{State: EvaluationStateEvaluated}, true,
			[]DNSPerspectiveQueryResult{}, []DNSPerspectiveFinding{}, []DNSPerspectiveDiagnostic{})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	generatedAt := options.Clock.Now().UTC()
	if generatedAt.IsZero() || !sourceEnrichmentTimeMarshalable(generatedAt) || generatedAt.Before(snapshot.ObservedAt()) {
		return DNSPerspectiveResult{}, ErrInvalidDNSPerspectiveOptions
	}

	outcomes := collectDNSPerspectiveQueries(ctx, provider, plan, generatedAt, options)
	queries := make([]DNSPerspectiveQueryResult, len(plan))
	findings := make([]DNSPerspectiveFinding, 0)
	diagnostics := make([]DNSPerspectiveDiagnostic, 0)
	complete := true
	for index, item := range plan {
		outcome, ok := outcomes[index]
		if !ok {
			outcome = canceledDNSPerspectiveOutcome(index, item, ctx.Err())
		}
		queries[index] = outcome.result
		findings = append(findings, outcome.findings...)
		diagnostics = append(diagnostics, outcome.diagnostics...)
		complete = complete && outcome.complete
	}
	sortDNSPerspectiveFindings(findings)
	sortDNSPerspectiveDiagnostics(diagnostics)
	result, err := newDNSPerspectiveResult(portfolio, snapshot, generatedAt, Evaluation{State: EvaluationStateEvaluated}, complete, queries, findings, diagnostics)
	if err != nil {
		return DNSPerspectiveResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return result, &DNSPerspectiveError{cause: err}
	}
	return result, nil
}

func validateDNSPerspectiveInputs(portfolio Portfolio, snapshot DNSSnapshot) error {
	metadata := snapshot.ResultMetadata()
	if portfolio.Digest() == "" || snapshot.Digest() == "" || snapshot.PortfolioDigest() != portfolio.Digest() || !snapshot.Complete() ||
		metadata.ContractVersion != AnalysisContractVersion || metadata.Mode != AnalysisModeDNSSnapshot || metadata.Evaluation.State != EvaluationStateEvaluated ||
		snapshot.ObservedAt().IsZero() || !sourceEnrichmentTimeMarshalable(snapshot.ObservedAt()) {
		return ErrInvalidAnalysisResult
	}
	plan := buildDNSQueryPlan(portfolio)
	observations := snapshot.Observations()
	if len(plan) != len(observations) {
		return ErrInvalidAnalysisResult
	}
	for index := range plan {
		if plan[index].name != observations[index].Name || !reflect.DeepEqual(plan[index].references, observations[index].References) {
			return ErrInvalidAnalysisResult
		}
	}
	return nil
}

func normalizeDNSPerspectiveOptions(options DNSPerspectiveOptions, requireClock bool) (DNSPerspectiveOptions, error) {
	if options.MaxQueries == 0 {
		options.MaxQueries = defaultDNSPerspectiveMaxQueries
	}
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = defaultDNSPerspectiveMaxConcurrency
	}
	if options.LookupTimeout == 0 {
		options.LookupTimeout = defaultDNSPerspectiveLookupTimeout
	}
	if options.MaxObservationsPerQuery == 0 {
		options.MaxObservationsPerQuery = defaultDNSPerspectiveMaxObservationsPerQuery
	}
	if options.MaxAnswersPerObservation == 0 {
		options.MaxAnswersPerObservation = defaultDNSPerspectiveMaxAnswersPerObservation
	}
	if options.MaxTextBytes == 0 {
		options.MaxTextBytes = defaultDNSPerspectiveMaxTextBytes
	}
	if options.MaxTotalTextBytes == 0 {
		options.MaxTotalTextBytes = defaultDNSPerspectiveMaxTotalTextBytes
	}
	if options.MaxRetryAfter == 0 {
		options.MaxRetryAfter = defaultDNSPerspectiveMaxRetryAfter
	}
	if options.MaxQueries < 1 || options.MaxQueries > maxDNSPerspectiveQueries ||
		options.MaxConcurrency < 1 || options.MaxConcurrency > maxDNSPerspectiveConcurrency ||
		options.LookupTimeout < 1 || options.LookupTimeout > maxDNSPerspectiveLookupTimeout ||
		options.MaxObservationsPerQuery < 1 || options.MaxObservationsPerQuery > maxDNSPerspectiveObservationsPerQuery ||
		options.MaxAnswersPerObservation < 1 || options.MaxAnswersPerObservation > maxDNSPerspectiveAnswersPerObservation ||
		options.MaxTextBytes < 1 || options.MaxTextBytes > maxDNSPerspectiveTextBytes ||
		options.MaxTotalTextBytes < 1 || options.MaxTotalTextBytes > maxDNSPerspectiveTotalTextBytes ||
		options.MaxRetryAfter < 0 || options.MaxRetryAfter > maxDNSPerspectiveRetryAfter {
		return DNSPerspectiveOptions{}, ErrInvalidDNSPerspectiveOptions
	}
	if requireClock && options.Clock == nil {
		options.Clock = ClockFunc(time.Now)
	}
	return options, nil
}

func buildDNSPerspectivePlan(portfolio Portfolio, snapshot DNSSnapshot, selection DNSPerspectiveSelection) ([]dnsPerspectivePlanItem, error) {
	if len(selection.Names) == 0 && len(selection.Roles) == 0 {
		return nil, fmt.Errorf("%w: an explicit name or role selection is required", ErrInvalidDNSPerspectiveOptions)
	}
	selectedNames := map[string]struct{}{}
	for _, value := range selection.Names {
		name := normalizeDNSDisplayName(value)
		if name == "" {
			return nil, fmt.Errorf("%w: selected owner name is invalid", ErrInvalidDNSPerspectiveOptions)
		}
		selectedNames[name] = struct{}{}
	}
	selectedRoles := map[DNSRecordType]struct{}{}
	for _, role := range selection.Roles {
		if role != DNSRecordSPF && role != DNSRecordDKIM && role != DNSRecordDMARC {
			return nil, fmt.Errorf("%w: selected record role is invalid", ErrInvalidDNSPerspectiveOptions)
		}
		selectedRoles[role] = struct{}{}
	}
	basePlan := buildDNSQueryPlan(portfolio)
	knownNames := make(map[string]struct{}, len(basePlan))
	observations := snapshot.Observations()
	byName := make(map[string]DNSObservation, len(observations))
	for _, observation := range observations {
		byName[observation.Name] = observation
	}
	result := make([]dnsPerspectivePlanItem, 0, len(basePlan))
	for _, item := range basePlan {
		knownNames[item.name] = struct{}{}
		_, nameSelected := selectedNames[item.name]
		roleSelected := false
		for _, reference := range item.references {
			if _, ok := selectedRoles[reference.Type]; ok {
				roleSelected = true
				break
			}
		}
		if !nameSelected && !roleSelected {
			continue
		}
		observation, ok := byName[item.name]
		if !ok {
			return nil, ErrInvalidAnalysisResult
		}
		result = append(result, dnsPerspectivePlanItem{
			query: DNSPerspectiveQuery{Name: item.name, Type: DNSPerspectiveTXT},
			snapshot: DNSPerspectiveSnapshotReference{
				SnapshotDigest: snapshot.Digest(), ObservedAt: snapshot.ObservedAt(), ObservationName: item.name, Status: observation.Status,
				AnswerFingerprint: dnsSnapshotAnswerFingerprint(observation), References: cloneDNSReferences(item.references),
				Sensitivity: SensitivityOperational,
			},
		})
	}
	for name := range selectedNames {
		if _, ok := knownNames[name]; !ok {
			return nil, fmt.Errorf("%w: selected owner name is not in the portfolio snapshot", ErrInvalidDNSPerspectiveOptions)
		}
	}
	return result, nil
}

func collectDNSPerspectiveQueries(ctx context.Context, provider DNSPerspectiveProvider, plan []dnsPerspectivePlanItem, generatedAt time.Time, options DNSPerspectiveOptions) map[int]dnsPerspectiveLookupOutcome {
	if ctx.Err() != nil {
		return map[int]dnsPerspectiveLookupOutcome{}
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	results := make(chan dnsPerspectiveLookupOutcome, len(plan))
	workerCount := min(options.MaxConcurrency, len(plan))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if workCtx.Err() != nil {
					continue
				}
				results <- lookupDNSPerspective(workCtx, provider, index, plan[index], generatedAt, options)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range plan {
			select {
			case jobs <- index:
			case <-workCtx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	outcomes := make(map[int]dnsPerspectiveLookupOutcome, len(plan))
	for outcome := range results {
		outcomes[outcome.index] = outcome
	}
	return outcomes
}

func lookupDNSPerspective(ctx context.Context, provider DNSPerspectiveProvider, index int, item dnsPerspectivePlanItem, generatedAt time.Time, options DNSPerspectiveOptions) dnsPerspectiveLookupOutcome {
	if err := ctx.Err(); err != nil {
		return canceledDNSPerspectiveOutcome(index, item, err)
	}
	lookupCtx := ctx
	cancel := func() {}
	if options.LookupTimeout > 0 {
		lookupCtx, cancel = context.WithTimeout(ctx, options.LookupTimeout)
	}
	response, lookupErr := provider.LookupDNSPerspective(lookupCtx, item.query)
	lookupContextErr := lookupCtx.Err()
	cancel()
	if lookupContextErr != nil {
		lookupErr = lookupContextErr
	}
	if lookupErr != nil {
		return failedDNSPerspectiveOutcome(index, item, response, lookupErr, ctx, options)
	}
	result, findings, diagnostics, complete, err := normalizeDNSPerspectiveResponse(item, response, generatedAt, options)
	if err != nil {
		return failedDNSPerspectiveOutcome(index, item, response, ErrDNSPerspectiveMalformed, ctx, options)
	}
	return dnsPerspectiveLookupOutcome{index: index, result: result, findings: findings, diagnostics: diagnostics, complete: complete}
}

func normalizeDNSPerspectiveResponse(item dnsPerspectivePlanItem, response DNSPerspectiveResponse, generatedAt time.Time, options DNSPerspectiveOptions) (DNSPerspectiveQueryResult, []DNSPerspectiveFinding, []DNSPerspectiveDiagnostic, bool, error) {
	response.Provider = strings.TrimSpace(response.Provider)
	response.Dataset = strings.TrimSpace(response.Dataset)
	response.ReferenceID = strings.TrimSpace(response.ReferenceID)
	if response.Provider == "" || response.Dataset == "" ||
		!validDNSPerspectiveText(response.Provider, options.MaxTextBytes) || !validDNSPerspectiveText(response.Dataset, options.MaxTextBytes) ||
		!validDNSPerspectiveText(response.ReferenceID, options.MaxTextBytes) || len(response.Observations) > options.MaxObservationsPerQuery {
		return DNSPerspectiveQueryResult{}, nil, nil, false, ErrInvalidDNSPerspectiveResponse
	}
	textBytes := len(response.Provider) + len(response.Dataset) + len(response.ReferenceID)
	retryAfter, err := normalizeDNSPerspectiveRetryAfter(response.RetryAfter, options.MaxRetryAfter)
	if err != nil {
		return DNSPerspectiveQueryResult{}, nil, nil, false, err
	}
	observations := make([]DNSPerspectiveObservation, 0, len(response.Observations))
	seen := map[string]struct{}{}
	for _, raw := range response.Observations {
		raw.PerspectiveID = strings.TrimSpace(raw.PerspectiveID)
		raw.Perspective = strings.TrimSpace(raw.Perspective)
		raw.Status = strings.TrimSpace(raw.Status)
		if raw.PerspectiveID == "" || !validDNSPerspectiveText(raw.PerspectiveID, options.MaxTextBytes) ||
			!validDNSPerspectiveText(raw.Perspective, options.MaxTextBytes) || !validDNSPerspectiveText(raw.Status, options.MaxTextBytes) ||
			!validProviderDNSPerspectiveOutcome(raw.Outcome) {
			return DNSPerspectiveQueryResult{}, nil, nil, false, ErrInvalidDNSPerspectiveResponse
		}
		textBytes += len(raw.PerspectiveID) + len(raw.Perspective) + len(raw.Status)
		if textBytes > options.MaxTotalTextBytes {
			return DNSPerspectiveQueryResult{}, nil, nil, false, ErrInvalidDNSPerspectiveResponse
		}
		if _, ok := seen[raw.PerspectiveID]; ok {
			return DNSPerspectiveQueryResult{}, nil, nil, false, ErrInvalidDNSPerspectiveResponse
		}
		seen[raw.PerspectiveID] = struct{}{}
		answers, err := normalizeDNSPerspectiveAnswers(raw.Answers, raw.Outcome, options)
		if err != nil {
			return DNSPerspectiveQueryResult{}, nil, nil, false, err
		}
		for _, answer := range answers {
			textBytes += len(answer.Joined)
			for _, fragment := range answer.Fragments {
				textBytes += len(fragment)
			}
			if textBytes > options.MaxTotalTextBytes {
				return DNSPerspectiveQueryResult{}, nil, nil, false, ErrInvalidDNSPerspectiveResponse
			}
		}
		fingerprint := AnalysisID("")
		if raw.Outcome == DNSPerspectiveSuccess {
			fingerprint = dnsPerspectiveAnswerFingerprint(answers)
		}
		observation := DNSPerspectiveObservation{
			PerspectiveID: raw.PerspectiveID, Perspective: raw.Perspective, ProviderStatus: raw.Status,
			Outcome: raw.Outcome, Answers: answers, AnswerFingerprint: fingerprint, Sensitivity: SensitivityOperational,
		}
		observation.ID = StableAnalysisID("dns_perspective_observation", response.Provider, response.Dataset, response.ReferenceID,
			item.query.Name, string(item.query.Type), raw.PerspectiveID, string(raw.Outcome), string(fingerprint), raw.Perspective, raw.Status)
		observations = append(observations, observation)
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].PerspectiveID < observations[j].PerspectiveID })
	result := emptyDNSPerspectiveQueryResult(item, DNSPerspectiveNoAnswer)
	result.Provenance = DNSPerspectiveProvenance{
		Provider: response.Provider, Dataset: response.Dataset, ReferenceID: response.ReferenceID,
		CollectedAt: generatedAt, Sensitivity: SensitivityOperational,
	}
	result.Observations = observations
	result.RetryAfter = retryAfter
	result.Truncated = response.Truncated
	result.PerspectiveAgreement = dnsPerspectiveAgreement(observations)
	result.SnapshotAgreement = dnsPerspectiveSnapshotAgreement(item.snapshot, observations)
	for _, observation := range observations {
		switch observation.Outcome {
		case DNSPerspectiveSuccess:
			result.SuccessfulPerspectives++
		case DNSPerspectiveNoAnswer:
			result.NoAnswerPerspectives++
		default:
			result.FailedPerspectives++
		}
	}
	result.Outcome = dnsPerspectiveQueryOutcome(observations)
	complete := true
	findings := dnsPerspectiveFindings(result)
	diagnostics := dnsPerspectiveResponseDiagnostics(result)
	return result, findings, diagnostics, complete, nil
}

func normalizeDNSPerspectiveAnswers(values []DNSPerspectiveAnswer, outcome DNSPerspectiveOutcome, options DNSPerspectiveOptions) ([]DNSPerspectiveAnswer, error) {
	if len(values) > options.MaxAnswersPerObservation || (outcome == DNSPerspectiveSuccess && len(values) == 0) ||
		(outcome != DNSPerspectiveSuccess && len(values) != 0) {
		return nil, ErrInvalidDNSPerspectiveResponse
	}
	result := make([]DNSPerspectiveAnswer, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value.Fragments = append([]string(nil), value.Fragments...)
		if value.FragmentsAvailable {
			if len(value.Fragments) == 0 {
				return nil, ErrInvalidDNSPerspectiveResponse
			}
			for _, fragment := range value.Fragments {
				if !validDNSPerspectiveText(fragment, options.MaxTextBytes) {
					return nil, ErrInvalidDNSPerspectiveResponse
				}
			}
			joined := strings.Join(value.Fragments, "")
			if value.Joined != "" && value.Joined != joined {
				return nil, ErrInvalidDNSPerspectiveResponse
			}
			value.Joined = joined
		} else {
			if len(value.Fragments) != 0 || !validDNSPerspectiveText(value.Joined, options.MaxTextBytes) {
				return nil, ErrInvalidDNSPerspectiveResponse
			}
			value.Fragments = []string{}
		}
		if !validDNSPerspectiveText(value.Joined, options.MaxTextBytes) {
			return nil, ErrInvalidDNSPerspectiveResponse
		}
		value.Sensitivity = SensitivityOperational
		key := value.Joined + "\x00" + strings.Join(value.Fragments, "\x00") + fmt.Sprint(value.FragmentsAvailable)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Joined != result[j].Joined {
			return result[i].Joined < result[j].Joined
		}
		return strings.Join(result[i].Fragments, "\x00") < strings.Join(result[j].Fragments, "\x00")
	})
	return result, nil
}

func failedDNSPerspectiveOutcome(index int, item dnsPerspectivePlanItem, response DNSPerspectiveResponse, lookupErr error, parent context.Context, options DNSPerspectiveOptions) dnsPerspectiveLookupOutcome {
	status := DNSPerspectiveFailed
	code := DiagnosticCode("dns_perspective.failed")
	message := "The caller-supplied DNS perspective provider failed."
	severity := FindingSeverityLow
	switch {
	case parent != nil && errors.Is(parent.Err(), context.Canceled), errors.Is(lookupErr, context.Canceled):
		status, code, message, severity = DNSPerspectiveCanceled, "dns_perspective.canceled", "DNS perspective collection was canceled before evidence was available.", FindingSeverityInfo
	case parent != nil && errors.Is(parent.Err(), context.DeadlineExceeded):
		status, code, message = DNSPerspectiveCanceled, "dns_perspective.deadline_exceeded", "DNS perspective collection exceeded its caller deadline."
	case errors.Is(lookupErr, context.DeadlineExceeded):
		status, code, message = DNSPerspectiveFailed, "dns_perspective.timeout", "The DNS perspective provider lookup exceeded its deadline."
	case errors.Is(lookupErr, ErrDNSPerspectiveRateLimited):
		status, code, message = DNSPerspectiveRateLimited, "dns_perspective.rate_limited", "The DNS perspective provider rate limited the lookup."
	case errors.Is(lookupErr, ErrDNSPerspectiveUnavailable):
		status, code, message, severity = DNSPerspectiveUnavailable, "dns_perspective.unavailable", "The DNS perspective provider returned no usable evidence.", FindingSeverityInfo
	case errors.Is(lookupErr, ErrDNSPerspectiveMalformed), errors.Is(lookupErr, ErrInvalidDNSPerspectiveResponse):
		status, code, message, severity = DNSPerspectiveMalformed, "dns_perspective.malformed", "The DNS perspective provider returned malformed evidence.", FindingSeverityMedium
	}
	result := emptyDNSPerspectiveQueryResult(item, status)
	if retryAfter, err := normalizeDNSPerspectiveRetryAfter(response.RetryAfter, options.MaxRetryAfter); err == nil {
		result.RetryAfter = retryAfter
	}
	diagnostic := DNSPerspectiveDiagnostic{Code: code, Severity: severity, QueryID: result.ID, Outcome: status, Message: message}
	complete := status != DNSPerspectiveCanceled
	return dnsPerspectiveLookupOutcome{index: index, result: result, diagnostics: []DNSPerspectiveDiagnostic{diagnostic}, complete: complete}
}

func canceledDNSPerspectiveOutcome(index int, item dnsPerspectivePlanItem, err error) dnsPerspectiveLookupOutcome {
	result := emptyDNSPerspectiveQueryResult(item, DNSPerspectiveCanceled)
	message := "DNS perspective collection was canceled before evidence was available."
	code := DiagnosticCode("dns_perspective.canceled")
	if errors.Is(err, context.DeadlineExceeded) {
		message = "DNS perspective collection exceeded its caller deadline."
		code = "dns_perspective.deadline_exceeded"
	}
	return dnsPerspectiveLookupOutcome{index: index, result: result, diagnostics: []DNSPerspectiveDiagnostic{{
		Code: code, Severity: FindingSeverityInfo, QueryID: result.ID, Outcome: DNSPerspectiveCanceled, Message: message,
	}}, complete: false}
}

func emptyDNSPerspectiveQueryResult(item dnsPerspectivePlanItem, outcome DNSPerspectiveOutcome) DNSPerspectiveQueryResult {
	agreement := DNSPerspectiveAgreementUnknown
	if outcome == DNSPerspectiveNotEvaluated {
		agreement = DNSPerspectiveAgreementNotEvaluated
	}
	return DNSPerspectiveQueryResult{
		ID: StableAnalysisID("dns_perspective_query", item.query.Name, string(item.query.Type)), Query: item.query,
		Snapshot: cloneDNSPerspectiveSnapshotReference(item.snapshot), Outcome: outcome,
		Observations: []DNSPerspectiveObservation{}, PerspectiveAgreement: agreement,
		SnapshotAgreement: agreement, Sensitivity: SensitivityOperational,
	}
}

func dnsPerspectiveFindings(result DNSPerspectiveQueryResult) []DNSPerspectiveFinding {
	findings := make([]DNSPerspectiveFinding, 0, 2)
	evidenceIDs := make([]AnalysisID, 0, len(result.Observations))
	for _, observation := range result.Observations {
		if observation.Outcome == DNSPerspectiveSuccess {
			evidenceIDs = append(evidenceIDs, observation.ID)
		}
	}
	if result.PerspectiveAgreement == DNSPerspectiveAnswersDisagree {
		findings = append(findings, newDNSPerspectiveFinding(result.ID, "dns_perspective.answer_disagreement", FindingSeverityInfo, evidenceIDs,
			"Remote DNS perspectives returned different answer sets.",
			"Successful resolver perspectives did not all return the same TXT answer set. This is supplemental consistency evidence, not authoritative proof that the record is broken.",
			"Review the trusted recursive and authoritative DNS evidence before deciding whether any DNS change is needed."))
	}
	if result.SnapshotAgreement == DNSPerspectiveAnswersDisagree {
		findings = append(findings, newDNSPerspectiveFinding(result.ID, "dns_perspective.snapshot_disagreement", FindingSeverityInfo, evidenceIDs,
			"Remote DNS evidence differs from the trusted snapshot.",
			"At least one successful resolver perspective returned a TXT answer set different from the supplied DNS snapshot. Observation times and resolver behavior may differ.",
			"Recheck the authoritative record and trusted resolvers, considering TTL and negative-cache evidence before changing DNS."))
	}
	return findings
}

func newDNSPerspectiveFinding(queryID AnalysisID, code FindingCode, severity FindingSeverity, evidenceIDs []AnalysisID, title, explanation, recommendation string) DNSPerspectiveFinding {
	return DNSPerspectiveFinding{
		ID: FindingID(StableAnalysisID("dns_perspective_finding", string(code), string(queryID))), Code: code, Severity: severity,
		QueryID: queryID, EvidenceIDs: append([]AnalysisID(nil), evidenceIDs...), Title: title, Explanation: explanation,
		Recommendation: recommendation, Sensitivity: SensitivityOperational,
	}
}

func dnsPerspectiveResponseDiagnostics(result DNSPerspectiveQueryResult) []DNSPerspectiveDiagnostic {
	diagnostics := make([]DNSPerspectiveDiagnostic, 0, 2)
	if result.Truncated {
		diagnostics = append(diagnostics, DNSPerspectiveDiagnostic{
			Code: "dns_perspective.provider_truncated", Severity: FindingSeverityLow, QueryID: result.ID,
			Outcome: result.Outcome, Message: "The provider reported that DNS perspective evidence was truncated.",
		})
	}
	if result.NoAnswerPerspectives > 0 || result.FailedPerspectives > 0 {
		diagnostics = append(diagnostics, DNSPerspectiveDiagnostic{
			Code: "dns_perspective.incomplete_coverage", Severity: FindingSeverityInfo, QueryID: result.ID,
			Outcome: result.Outcome, Message: "One or more provider perspectives did not return usable answer evidence.",
		})
	}
	if len(result.Observations) == 0 {
		diagnostics = append(diagnostics, DNSPerspectiveDiagnostic{
			Code: "dns_perspective.no_perspectives", Severity: FindingSeverityInfo, QueryID: result.ID,
			Outcome: result.Outcome, Message: "The provider returned no resolver perspectives for the selected DNS name.",
		})
	}
	return diagnostics
}

func dnsPerspectiveAgreement(observations []DNSPerspectiveObservation) DNSPerspectiveAgreement {
	seen := map[AnalysisID]struct{}{}
	success := 0
	for _, observation := range observations {
		if observation.Outcome == DNSPerspectiveSuccess {
			success++
			seen[observation.AnswerFingerprint] = struct{}{}
		}
	}
	if success < 2 {
		return DNSPerspectiveAgreementUnknown
	}
	if len(seen) == 1 {
		return DNSPerspectiveAnswersAgree
	}
	return DNSPerspectiveAnswersDisagree
}

func dnsPerspectiveSnapshotAgreement(snapshot DNSPerspectiveSnapshotReference, observations []DNSPerspectiveObservation) DNSPerspectiveAgreement {
	if snapshot.Status != DNSObservationSuccess || snapshot.AnswerFingerprint == "" {
		return DNSPerspectiveAgreementUnknown
	}
	success := 0
	for _, observation := range observations {
		if observation.Outcome != DNSPerspectiveSuccess {
			continue
		}
		success++
		if observation.AnswerFingerprint != snapshot.AnswerFingerprint {
			return DNSPerspectiveAnswersDisagree
		}
	}
	if success == 0 {
		return DNSPerspectiveAgreementUnknown
	}
	return DNSPerspectiveAnswersAgree
}

func dnsPerspectiveQueryOutcome(observations []DNSPerspectiveObservation) DNSPerspectiveOutcome {
	if len(observations) == 0 {
		return DNSPerspectiveUnavailable
	}
	priority := []DNSPerspectiveOutcome{
		DNSPerspectiveSuccess, DNSPerspectiveRateLimited, DNSPerspectiveMalformed, DNSPerspectiveFailed,
		DNSPerspectiveCanceled, DNSPerspectiveUnavailable, DNSPerspectiveNoAnswer,
	}
	for _, candidate := range priority {
		for _, observation := range observations {
			if observation.Outcome == candidate {
				return candidate
			}
		}
	}
	return DNSPerspectiveMalformed
}

func dnsSnapshotAnswerFingerprint(observation DNSObservation) AnalysisID {
	if observation.Status != DNSObservationSuccess || len(observation.Records) == 0 {
		return ""
	}
	answers := make([]DNSPerspectiveAnswer, len(observation.Records))
	for index, record := range observation.Records {
		answers[index] = DNSPerspectiveAnswer{
			Fragments: append([]string(nil), record.Fragments...), FragmentsAvailable: record.FragmentsAvailable,
			Joined: record.Joined, Sensitivity: SensitivityOperational,
		}
	}
	return dnsPerspectiveAnswerFingerprint(answers)
}

func dnsPerspectiveAnswerFingerprint(answers []DNSPerspectiveAnswer) AnalysisID {
	values := make([]string, 0, len(answers))
	seen := map[string]struct{}{}
	for _, answer := range answers {
		if _, ok := seen[answer.Joined]; ok {
			continue
		}
		seen[answer.Joined] = struct{}{}
		values = append(values, answer.Joined)
	}
	sort.Strings(values)
	return StableAnalysisID("dns_perspective_answer_set", values...)
}

func normalizeDNSPerspectiveRetryAfter(value, maximum time.Duration) (DNSPerspectiveRetryAfter, error) {
	if value < 0 {
		return DNSPerspectiveRetryAfter{}, ErrInvalidDNSPerspectiveResponse
	}
	if value == 0 {
		return DNSPerspectiveRetryAfter{}, nil
	}
	result := DNSPerspectiveRetryAfter{Available: true}
	if maximum > 0 && value > maximum {
		value = maximum
		result.Capped = true
	}
	seconds := (value + time.Second - 1) / time.Second
	result.Seconds = int64(seconds)
	return result, nil
}

func validProviderDNSPerspectiveOutcome(value DNSPerspectiveOutcome) bool {
	switch value {
	case DNSPerspectiveSuccess, DNSPerspectiveNoAnswer, DNSPerspectiveFailed, DNSPerspectiveRateLimited,
		DNSPerspectiveMalformed, DNSPerspectiveUnavailable, DNSPerspectiveCanceled:
		return true
	default:
		return false
	}
}

func validDNSPerspectiveText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func nilDNSPerspectiveProvider(provider DNSPerspectiveProvider) bool {
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

func newDNSPerspectiveResult(portfolio Portfolio, snapshot DNSSnapshot, generatedAt time.Time, evaluation Evaluation, complete bool, queries []DNSPerspectiveQueryResult, findings []DNSPerspectiveFinding, diagnostics []DNSPerspectiveDiagnostic) (DNSPerspectiveResult, error) {
	summary := summarizeDNSPerspectives(queries, findings)
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeDNSPerspectives, GeneratedAt: generatedAt.UTC(), Evaluation: evaluation}
	canonical, err := json.Marshal(struct {
		Metadata        ResultMetadata              `json:"metadata"`
		Version         string                      `json:"version"`
		PortfolioDigest AnalysisID                  `json:"portfolio_digest"`
		SnapshotDigest  AnalysisID                  `json:"snapshot_digest"`
		Complete        bool                        `json:"complete"`
		Queries         []DNSPerspectiveQueryResult `json:"queries"`
		Findings        []DNSPerspectiveFinding     `json:"findings"`
		Diagnostics     []DNSPerspectiveDiagnostic  `json:"diagnostics"`
		Summary         DNSPerspectiveSummary       `json:"summary"`
	}{metadata, DNSPerspectiveVersion, portfolio.Digest(), snapshot.Digest(), complete, queries, findings, diagnostics, summary})
	if err != nil {
		return DNSPerspectiveResult{}, errors.Join(ErrInvalidDNSPerspectiveOptions, err)
	}
	return DNSPerspectiveResult{
		metadata: metadata, version: DNSPerspectiveVersion, portfolioDigest: portfolio.Digest(), snapshotDigest: snapshot.Digest(),
		digest: StableAnalysisID("dns_perspectives", string(canonical)), complete: complete,
		queries: cloneDNSPerspectiveQueryResults(queries), findings: cloneDNSPerspectiveFindings(findings),
		diagnostics: append([]DNSPerspectiveDiagnostic(nil), diagnostics...), summary: summary,
	}, nil
}

func summarizeDNSPerspectives(queries []DNSPerspectiveQueryResult, findings []DNSPerspectiveFinding) DNSPerspectiveSummary {
	counts := map[DNSPerspectiveOutcome]int{}
	summary := DNSPerspectiveSummary{Queries: len(queries), Findings: len(findings)}
	for _, query := range queries {
		counts[query.Outcome]++
		summary.Perspectives += len(query.Observations)
		summary.SuccessfulPerspectives += query.SuccessfulPerspectives
		summary.NoAnswerPerspectives += query.NoAnswerPerspectives
		summary.FailedPerspectives += query.FailedPerspectives
		if query.Truncated {
			summary.TruncatedQueries++
		}
	}
	for _, outcome := range dnsPerspectiveOutcomeOrder() {
		summary.Outcomes = append(summary.Outcomes, DNSPerspectiveOutcomeCount{Outcome: outcome, Queries: counts[outcome]})
	}
	return summary
}

func dnsPerspectiveOutcomeOrder() []DNSPerspectiveOutcome {
	return []DNSPerspectiveOutcome{
		DNSPerspectiveSuccess, DNSPerspectiveNoAnswer, DNSPerspectiveFailed, DNSPerspectiveRateLimited,
		DNSPerspectiveMalformed, DNSPerspectiveUnavailable, DNSPerspectiveCanceled, DNSPerspectiveNotEvaluated,
	}
}

func sortDNSPerspectiveFindings(values []DNSPerspectiveFinding) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].QueryID != values[j].QueryID {
			return values[i].QueryID < values[j].QueryID
		}
		return values[i].Code < values[j].Code
	})
}

func sortDNSPerspectiveDiagnostics(values []DNSPerspectiveDiagnostic) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].QueryID != values[j].QueryID {
			return values[i].QueryID < values[j].QueryID
		}
		return values[i].Code < values[j].Code
	})
}

func cloneDNSPerspectiveQueryResults(values []DNSPerspectiveQueryResult) []DNSPerspectiveQueryResult {
	result := make([]DNSPerspectiveQueryResult, len(values))
	for index, value := range values {
		value.Snapshot = cloneDNSPerspectiveSnapshotReference(value.Snapshot)
		value.Observations = cloneDNSPerspectiveObservations(value.Observations)
		result[index] = value
	}
	return result
}

func cloneDNSPerspectiveSnapshotReference(value DNSPerspectiveSnapshotReference) DNSPerspectiveSnapshotReference {
	value.References = cloneDNSReferences(value.References)
	return value
}

func cloneDNSPerspectiveObservations(values []DNSPerspectiveObservation) []DNSPerspectiveObservation {
	result := make([]DNSPerspectiveObservation, len(values))
	for index, value := range values {
		value.Answers = make([]DNSPerspectiveAnswer, len(values[index].Answers))
		for answerIndex, answer := range values[index].Answers {
			answer.Fragments = append([]string(nil), answer.Fragments...)
			value.Answers[answerIndex] = answer
		}
		result[index] = value
	}
	return result
}

func cloneDNSPerspectiveFindings(values []DNSPerspectiveFinding) []DNSPerspectiveFinding {
	result := make([]DNSPerspectiveFinding, len(values))
	for index, value := range values {
		value.EvidenceIDs = append([]AnalysisID(nil), value.EvidenceIDs...)
		result[index] = value
	}
	return result
}
