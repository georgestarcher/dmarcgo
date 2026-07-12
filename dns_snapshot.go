package dmarcgo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultDNSMaxConcurrency = 4
	defaultDNSMaxAttempts    = 2
	defaultDNSQueryTimeout   = 5 * time.Second
	defaultDNSRetryDelay     = 100 * time.Millisecond
)

var (
	// ErrDNSCollectionFailed identifies a fail-fast collection that stopped
	// after a DNS observation failed.
	ErrDNSCollectionFailed = errors.New("DNS snapshot collection failed")
	// ErrInvalidDNSCollectionOptions identifies invalid collection limits or policy.
	ErrInvalidDNSCollectionOptions = errors.New("invalid DNS collection options")
	// ErrDNSNXDOMAIN allows resolvers to identify an authoritative name error.
	ErrDNSNXDOMAIN = errors.New("DNS name does not exist")
	// ErrDNSNoData allows resolvers to identify an existing name without TXT data.
	ErrDNSNoData = errors.New("DNS name has no TXT data")
	// ErrDNSTemporary allows resolvers to identify a retryable DNS failure.
	ErrDNSTemporary = errors.New("temporary DNS failure")
	// ErrDNSMalformedResponse allows resolvers to identify unusable DNS evidence.
	ErrDNSMalformedResponse = errors.New("malformed DNS response")
)

// DNSObservationStatus classifies one planned TXT lookup without relying on
// resolver-specific error strings.
type DNSObservationStatus string

const (
	DNSObservationSuccess          DNSObservationStatus = "success"
	DNSObservationNXDOMAIN         DNSObservationStatus = "nxdomain"
	DNSObservationNoData           DNSObservationStatus = "no_data"
	DNSObservationNotFound         DNSObservationStatus = "not_found"
	DNSObservationTimeout          DNSObservationStatus = "timeout"
	DNSObservationTemporaryFailure DNSObservationStatus = "temporary_failure"
	DNSObservationMalformed        DNSObservationStatus = "malformed_response"
	DNSObservationCanceled         DNSObservationStatus = "canceled"
)

// DNSFailurePolicy controls whether independent planned lookups continue after
// one observation fails.
type DNSFailurePolicy string

const (
	DNSFailureCollectAll DNSFailurePolicy = "collect_all"
	DNSFailureFailFast   DNSFailurePolicy = "fail_fast"
)

// DNSRecordType identifies why a TXT owner name is monitored.
type DNSRecordType string

const (
	DNSRecordSPF   DNSRecordType = "spf"
	DNSRecordDKIM  DNSRecordType = "dkim"
	DNSRecordDMARC DNSRecordType = "dmarc"
)

// DNSAnswerSource identifies whether TTL evidence came from an authoritative
// or recursive answer. Unknown is used by limited adapters such as net.Resolver.
type DNSAnswerSource string

const (
	DNSAnswerSourceUnknown       DNSAnswerSource = "unknown"
	DNSAnswerSourceRecursive     DNSAnswerSource = "recursive"
	DNSAnswerSourceAuthoritative DNSAnswerSource = "authoritative"
)

// DNSDurationEvidence represents a DNS TTL without inventing a value when the
// resolver API cannot expose one.
type DNSDurationEvidence struct {
	Available bool   `json:"available"`
	Seconds   uint32 `json:"seconds,omitempty"`
}

// DNSRCodeEvidence represents a DNS response code without conflating NOERROR
// (zero) with an adapter that cannot expose response codes.
type DNSRCodeEvidence struct {
	Available bool `json:"available"`
	Value     int  `json:"value,omitempty"`
}

// DNSSOAEvidence preserves the fields used to explain negative-cache evidence.
type DNSSOAEvidence struct {
	Name    string `json:"name"`
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
	TTL     uint32 `json:"ttl"`
}

// TXTRecord preserves one TXT resource record, received TTL, and its normalized
// joined representation. FragmentsAvailable is false when a limited resolver
// cannot recover the original DNS character-string boundaries.
type TXTRecord struct {
	Fragments          []string            `json:"fragments"`
	FragmentsAvailable bool                `json:"fragments_available"`
	Joined             string              `json:"joined"`
	TTL                DNSDurationEvidence `json:"ttl"`
}

// TXTLookupResult is returned by a TXTResolver. Resolver implementations may
// supply status and DNS-message evidence even when they also return an error.
type TXTLookupResult struct {
	Name          string               `json:"name"`
	Status        DNSObservationStatus `json:"status,omitempty"`
	Records       []TXTRecord          `json:"records"`
	TTL           DNSDurationEvidence  `json:"ttl"`
	NegativeTTL   DNSDurationEvidence  `json:"negative_ttl"`
	SOA           *DNSSOAEvidence      `json:"soa,omitempty"`
	Resolver      string               `json:"resolver,omitempty"`
	AnswerSource  DNSAnswerSource      `json:"answer_source"`
	RCode         DNSRCodeEvidence     `json:"rcode"`
	CanonicalName string               `json:"canonical_name,omitempty"`
	CNAMEPath     []string             `json:"cname_path"`
}

// TXTResolver is the only DNS side-effect boundary used by snapshot collection.
// Implementations must honor context cancellation.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) (TXTLookupResult, error)
}

// DNSRecordReference maps one deduplicated owner-name lookup back to every
// configured organizational scope that depends on it.
type DNSRecordReference struct {
	EntityID string        `json:"entity_id"`
	Domain   string        `json:"domain"`
	Owner    string        `json:"owner,omitempty"`
	Type     DNSRecordType `json:"type"`
}

// DNSObservation is immutable once copied out of a completed DNSSnapshot.
type DNSObservation struct {
	Name          string               `json:"name"`
	References    []DNSRecordReference `json:"references"`
	Status        DNSObservationStatus `json:"status"`
	Records       []TXTRecord          `json:"records"`
	TTL           DNSDurationEvidence  `json:"ttl"`
	NegativeTTL   DNSDurationEvidence  `json:"negative_ttl"`
	SOA           *DNSSOAEvidence      `json:"soa,omitempty"`
	Resolver      string               `json:"resolver,omitempty"`
	AnswerSource  DNSAnswerSource      `json:"answer_source"`
	RCode         DNSRCodeEvidence     `json:"rcode"`
	CanonicalName string               `json:"canonical_name,omitempty"`
	CNAMEPath     []string             `json:"cname_path"`
	Attempts      int                  `json:"attempts"`
}

// DNSCollectionDiagnostic is value-safe: Message is library-generated and
// never copies resolver error text or returned TXT data.
type DNSCollectionDiagnostic struct {
	Code     DiagnosticCode  `json:"code"`
	Severity FindingSeverity `json:"severity"`
	Name     string          `json:"name"`
	Attempts int             `json:"attempts"`
	Message  string          `json:"message"`
}

// DNSSnapshot is a completed, reusable DNS evidence value. Accessors return
// defensive copies and never perform DNS or other I/O.
type DNSSnapshot struct {
	metadata     ResultMetadata
	portfolioID  AnalysisID
	digest       AnalysisID
	complete     bool
	observations []DNSObservation
	diagnostics  []DNSCollectionDiagnostic
}

// ResultMetadata returns the shared result metadata without performing work.
func (snapshot DNSSnapshot) ResultMetadata() ResultMetadata { return snapshot.metadata }

// ObservedAt returns the reproducible timestamp assigned to the snapshot.
func (snapshot DNSSnapshot) ObservedAt() time.Time { return snapshot.metadata.GeneratedAt }

// PortfolioDigest identifies the normalized configuration used to plan lookups.
func (snapshot DNSSnapshot) PortfolioDigest() AnalysisID { return snapshot.portfolioID }

// Digest identifies the complete canonical snapshot contents.
func (snapshot DNSSnapshot) Digest() AnalysisID { return snapshot.digest }

// Complete reports whether every planned owner name reached a terminal result.
func (snapshot DNSSnapshot) Complete() bool { return snapshot.complete }

// Observations returns owner-name observations in deterministic name order.
func (snapshot DNSSnapshot) Observations() []DNSObservation {
	return cloneDNSObservations(snapshot.observations)
}

// Diagnostics returns deterministic value-safe collection diagnostics.
func (snapshot DNSSnapshot) Diagnostics() []DNSCollectionDiagnostic {
	return append([]DNSCollectionDiagnostic(nil), snapshot.diagnostics...)
}

// DNSCollectionOptions bounds explicit DNS collection. Zero values select safe
// defaults; Clock defaults to time.Now only for this networked collection stage.
type DNSCollectionOptions struct {
	MaxConcurrency int
	MaxAttempts    int
	QueryTimeout   time.Duration
	RetryDelay     time.Duration
	FailurePolicy  DNSFailurePolicy
	Clock          Clock
	ResolverID     string
}

// DNSCollectionError retains the underlying cancellation or stable collection
// sentinel without exposing resolver-controlled text.
type DNSCollectionError struct {
	cause error
}

func (err *DNSCollectionError) Error() string {
	if errors.Is(err.cause, context.Canceled) {
		return "DNS snapshot collection canceled"
	}
	if errors.Is(err.cause, context.DeadlineExceeded) {
		return "DNS snapshot collection deadline exceeded"
	}
	return ErrDNSCollectionFailed.Error()
}

// Unwrap supports errors.Is for context cancellation and collection failure.
func (err *DNSCollectionError) Unwrap() error { return err.cause }

type dnsQueryPlan struct {
	name       string
	references []DNSRecordReference
}

type dnsLookupOutcome struct {
	index       int
	observation DNSObservation
	diagnostic  *DNSCollectionDiagnostic
	failed      bool
	fatal       bool
}

type txtResolverValidator interface {
	validateTXTResolver() error
}

// CollectDNSSnapshot explicitly resolves all configured SPF, DKIM, and DMARC
// TXT owner names through resolver. It never loads reports or performs health
// evaluation. Collect-all returns failures as observations and diagnostics;
// fail-fast also returns ErrDNSCollectionFailed with the immutable partial snapshot.
func CollectDNSSnapshot(ctx context.Context, portfolio Portfolio, resolver TXTResolver, options DNSCollectionOptions) (DNSSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	options, err := normalizeDNSCollectionOptions(options)
	if err != nil {
		return DNSSnapshot{}, err
	}
	if nilTXTResolver(resolver) {
		return DNSSnapshot{}, fmt.Errorf("%w: resolver is required", ErrInvalidDNSCollectionOptions)
	}
	if validator, ok := resolver.(txtResolverValidator); ok {
		if err := validator.validateTXTResolver(); err != nil {
			return DNSSnapshot{}, err
		}
	}

	observedAt := options.Clock.Now().UTC()
	plan := buildDNSQueryPlan(portfolio)
	if len(plan) == 0 {
		return newDNSSnapshot(observedAt, portfolio.Digest(), []DNSObservation{}, []DNSCollectionDiagnostic{}), nil
	}
	if options.FailurePolicy == DNSFailureFailFast {
		return collectDNSSnapshotFailFast(ctx, portfolio.Digest(), observedAt, plan, resolver, options)
	}
	observations := make([]DNSObservation, len(plan))
	completed := make([]bool, len(plan))
	for index, query := range plan {
		observations[index] = DNSObservation{
			Name: query.name, References: cloneDNSReferences(query.references), Status: DNSObservationCanceled,
			Records: []TXTRecord{}, CNAMEPath: []string{}, AnswerSource: DNSAnswerSourceUnknown,
		}
	}
	diagnostics := make([]DNSCollectionDiagnostic, 0)
	preflight := collectDNSObservation(ctx, plan[0], resolver, options)
	if preflight.fatal {
		return DNSSnapshot{}, fmt.Errorf("%w: resolver failed during collection", ErrInvalidDNSCollectionOptions)
	}
	observations[0] = preflight.observation
	completed[0] = true
	if preflight.diagnostic != nil {
		diagnostics = append(diagnostics, *preflight.diagnostic)
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	results := make(chan dnsLookupOutcome, len(plan))
	var workers sync.WaitGroup
	workerCount := options.MaxConcurrency
	if workerCount > len(plan)-1 {
		workerCount = len(plan) - 1
	}
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				outcome := collectDNSObservation(workCtx, plan[index], resolver, options)
				outcome.index = index
				if outcome.fatal {
					cancel()
				}
				results <- outcome
			}
		}()
	}

	go func() {
		defer close(jobs)
		for index := 1; index < len(plan); index++ {
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

	fatal := false
	for outcome := range results {
		observations[outcome.index] = outcome.observation
		completed[outcome.index] = true
		if outcome.diagnostic != nil {
			diagnostics = append(diagnostics, *outcome.diagnostic)
		}
		fatal = fatal || outcome.fatal
	}
	for index := range observations {
		if !completed[index] {
			diagnostics = append(diagnostics, diagnosticForObservation(observations[index]))
		}
	}
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].Name != diagnostics[j].Name {
			return diagnostics[i].Name < diagnostics[j].Name
		}
		return diagnostics[i].Code < diagnostics[j].Code
	})

	snapshot := newDNSSnapshot(observedAt, portfolio.Digest(), observations, diagnostics)
	if err := ctx.Err(); err != nil {
		return snapshot, &DNSCollectionError{cause: err}
	}
	if fatal {
		return DNSSnapshot{}, fmt.Errorf("%w: resolver failed during collection", ErrInvalidDNSCollectionOptions)
	}
	return snapshot, nil
}

func nilTXTResolver(resolver TXTResolver) bool {
	if resolver == nil {
		return true
	}
	value := reflect.ValueOf(resolver)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func collectDNSSnapshotFailFast(ctx context.Context, portfolioID AnalysisID, observedAt time.Time, plan []dnsQueryPlan, resolver TXTResolver, options DNSCollectionOptions) (DNSSnapshot, error) {
	observations := make([]DNSObservation, len(plan))
	for index, query := range plan {
		observations[index] = DNSObservation{
			Name: query.name, References: cloneDNSReferences(query.references), Status: DNSObservationCanceled,
			Records: []TXTRecord{}, CNAMEPath: []string{}, AnswerSource: DNSAnswerSourceUnknown,
		}
	}
	diagnostics := make([]DNSCollectionDiagnostic, 0)
	completed := 0
	for index, query := range plan {
		if err := ctx.Err(); err != nil {
			break
		}
		outcome := collectDNSObservation(ctx, query, resolver, options)
		if outcome.fatal {
			return DNSSnapshot{}, fmt.Errorf("%w: resolver failed during collection", ErrInvalidDNSCollectionOptions)
		}
		observations[index] = outcome.observation
		completed = index + 1
		if outcome.diagnostic != nil {
			diagnostics = append(diagnostics, *outcome.diagnostic)
		}
		if outcome.failed {
			break
		}
	}
	for index := completed; index < len(observations); index++ {
		diagnostics = append(diagnostics, diagnosticForObservation(observations[index]))
	}
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].Name != diagnostics[j].Name {
			return diagnostics[i].Name < diagnostics[j].Name
		}
		return diagnostics[i].Code < diagnostics[j].Code
	})
	snapshot := newDNSSnapshot(observedAt, portfolioID, observations, diagnostics)
	if err := ctx.Err(); err != nil {
		return snapshot, &DNSCollectionError{cause: err}
	}
	if completed < len(plan) || observations[completed-1].Status != DNSObservationSuccess {
		return snapshot, &DNSCollectionError{cause: ErrDNSCollectionFailed}
	}
	return snapshot, nil
}

func normalizeDNSCollectionOptions(options DNSCollectionOptions) (DNSCollectionOptions, error) {
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = defaultDNSMaxConcurrency
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = defaultDNSMaxAttempts
	}
	if options.QueryTimeout == 0 {
		options.QueryTimeout = defaultDNSQueryTimeout
	}
	if options.RetryDelay == 0 {
		options.RetryDelay = defaultDNSRetryDelay
	}
	if options.FailurePolicy == "" {
		options.FailurePolicy = DNSFailureCollectAll
	}
	if options.Clock == nil {
		options.Clock = ClockFunc(time.Now)
	}
	options.ResolverID = strings.TrimSpace(options.ResolverID)
	if options.MaxConcurrency < 1 || options.MaxConcurrency > 256 || options.MaxAttempts < 1 || options.MaxAttempts > 10 || options.QueryTimeout < 0 || options.RetryDelay < 0 {
		return options, fmt.Errorf("%w: limits are outside supported bounds", ErrInvalidDNSCollectionOptions)
	}
	if options.FailurePolicy != DNSFailureCollectAll && options.FailurePolicy != DNSFailureFailFast {
		return options, fmt.Errorf("%w: unsupported failure policy", ErrInvalidDNSCollectionOptions)
	}
	return options, nil
}

func buildDNSQueryPlan(portfolio Portfolio) []dnsQueryPlan {
	byName := map[string][]DNSRecordReference{}
	for _, entity := range portfolio.Entities() {
		for _, domain := range entity.Domains {
			addDNSPlanReferences(byName, entity, domain, DNSRecordSPF, domain.Records.SPF)
			addDNSPlanReferences(byName, entity, domain, DNSRecordDKIM, domain.Records.DKIM)
			addDNSPlanReferences(byName, entity, domain, DNSRecordDMARC, domain.Records.DMARC)
		}
	}
	plan := make([]dnsQueryPlan, 0, len(byName))
	for name, references := range byName {
		sortDNSReferences(references)
		plan = append(plan, dnsQueryPlan{name: name, references: references})
	}
	sort.Slice(plan, func(i, j int) bool { return plan[i].name < plan[j].name })
	return plan
}

func addDNSPlanReferences(byName map[string][]DNSRecordReference, entity Entity, domain MonitoredDomain, recordType DNSRecordType, names []string) {
	for _, name := range names {
		reference := DNSRecordReference{EntityID: entity.ID, Domain: domain.Name, Owner: domain.Owner, Type: recordType}
		duplicate := false
		for _, existing := range byName[name] {
			if existing == reference {
				duplicate = true
				break
			}
		}
		if !duplicate {
			byName[name] = append(byName[name], reference)
		}
	}
}

func collectDNSObservation(ctx context.Context, query dnsQueryPlan, resolver TXTResolver, options DNSCollectionOptions) dnsLookupOutcome {
	observation := DNSObservation{
		Name: query.name, References: cloneDNSReferences(query.references), Status: DNSObservationCanceled,
		Records: []TXTRecord{}, CNAMEPath: []string{}, AnswerSource: DNSAnswerSourceUnknown,
	}
	var result TXTLookupResult
	var lookupErr error
	for attempt := 1; attempt <= options.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			observation.Attempts = attempt - 1
			break
		}
		attemptCtx := ctx
		cancel := func() {}
		if options.QueryTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, options.QueryTimeout)
		}
		result, lookupErr = resolver.LookupTXT(attemptCtx, query.name)
		attemptErr := attemptCtx.Err()
		cancel()
		observation.Attempts = attempt
		if errors.Is(lookupErr, ErrInvalidDNSCollectionOptions) {
			return dnsLookupOutcome{observation: observation, failed: true, fatal: true}
		}
		status := classifyDNSLookup(result, lookupErr, attemptErr, ctx.Err())
		if !retryDNSStatus(status) || attempt == options.MaxAttempts {
			observation = observationFromLookup(query, result, status, attempt, options.ResolverID)
			break
		}
		if !waitDNSRetry(ctx, options.RetryDelay) {
			observation.Status = DNSObservationCanceled
			break
		}
	}
	failed := observation.Status != DNSObservationSuccess
	if !failed {
		return dnsLookupOutcome{observation: observation}
	}
	diagnostic := diagnosticForObservation(observation)
	return dnsLookupOutcome{observation: observation, diagnostic: &diagnostic, failed: true}
}

func classifyDNSLookup(result TXTLookupResult, lookupErr, attemptErr, parentErr error) DNSObservationStatus {
	if parentErr != nil || errors.Is(lookupErr, context.Canceled) {
		return DNSObservationCanceled
	}
	if errors.Is(attemptErr, context.DeadlineExceeded) || errors.Is(lookupErr, context.DeadlineExceeded) {
		return DNSObservationTimeout
	}
	if result.Status != "" && result.Status != DNSObservationSuccess {
		if !validDNSObservationStatus(result.Status) {
			return DNSObservationMalformed
		}
		return result.Status
	}
	switch {
	case lookupErr == nil && len(result.Records) == 0:
		return DNSObservationNoData
	case lookupErr == nil:
		return DNSObservationSuccess
	case errors.Is(lookupErr, ErrDNSNXDOMAIN):
		return DNSObservationNXDOMAIN
	case errors.Is(lookupErr, ErrDNSNoData):
		return DNSObservationNoData
	case errors.Is(lookupErr, ErrDNSMalformedResponse):
		return DNSObservationMalformed
	case errors.Is(lookupErr, ErrDNSTemporary):
		return DNSObservationTemporaryFailure
	}
	var dnsErr *net.DNSError
	if errors.As(lookupErr, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return DNSObservationTimeout
		case dnsErr.IsTemporary:
			return DNSObservationTemporaryFailure
		case dnsErr.IsNotFound:
			return DNSObservationNotFound
		}
	}
	var networkErr net.Error
	if errors.As(lookupErr, &networkErr) && networkErr.Timeout() {
		return DNSObservationTimeout
	}
	return DNSObservationTemporaryFailure
}

func retryDNSStatus(status DNSObservationStatus) bool {
	return status == DNSObservationTimeout || status == DNSObservationTemporaryFailure
}

func validDNSObservationStatus(status DNSObservationStatus) bool {
	switch status {
	case DNSObservationSuccess, DNSObservationNXDOMAIN, DNSObservationNoData, DNSObservationNotFound,
		DNSObservationTimeout, DNSObservationTemporaryFailure, DNSObservationMalformed, DNSObservationCanceled:
		return true
	default:
		return false
	}
}

func waitDNSRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func observationFromLookup(query dnsQueryPlan, result TXTLookupResult, status DNSObservationStatus, attempts int, fallbackResolver string) DNSObservation {
	resolverID := strings.TrimSpace(result.Resolver)
	if resolverID == "" {
		resolverID = fallbackResolver
	}
	observation := DNSObservation{
		Name: query.name, References: cloneDNSReferences(query.references), Status: status,
		Records: cloneTXTRecords(result.Records), TTL: result.TTL, NegativeTTL: result.NegativeTTL,
		SOA: cloneSOA(result.SOA), Resolver: resolverID, AnswerSource: result.AnswerSource,
		RCode: result.RCode, CanonicalName: normalizeDNSDisplayName(result.CanonicalName),
		CNAMEPath: normalizeDNSDisplayNames(result.CNAMEPath), Attempts: attempts,
	}
	if observation.AnswerSource == "" {
		observation.AnswerSource = DNSAnswerSourceUnknown
	}
	if result.Name != "" && normalizeDNSDisplayName(result.Name) != query.name {
		observation.Status = DNSObservationMalformed
	}
	for index := range observation.Records {
		record := &observation.Records[index]
		if len(record.Fragments) > 0 {
			record.FragmentsAvailable = true
			record.Joined = strings.Join(record.Fragments, "")
			continue
		}
		if record.FragmentsAvailable || record.Joined == "" {
			observation.Status = DNSObservationMalformed
		}
	}
	sort.Slice(observation.Records, func(i, j int) bool {
		if observation.Records[i].Joined != observation.Records[j].Joined {
			return observation.Records[i].Joined < observation.Records[j].Joined
		}
		return strings.Join(observation.Records[i].Fragments, "\x00") < strings.Join(observation.Records[j].Fragments, "\x00")
	})
	if observation.Status == DNSObservationSuccess && len(observation.Records) == 0 {
		observation.Status = DNSObservationNoData
	}
	if observation.Status != DNSObservationSuccess {
		observation.Records = []TXTRecord{}
		observation.TTL = DNSDurationEvidence{}
		if observation.Status != DNSObservationNXDOMAIN && observation.Status != DNSObservationNoData {
			observation.NegativeTTL = DNSDurationEvidence{}
			observation.SOA = nil
		}
	}
	return observation
}

func diagnosticForObservation(observation DNSObservation) DNSCollectionDiagnostic {
	code := DiagnosticCode("dns.lookup." + string(observation.Status))
	message := "The DNS TXT lookup did not return usable evidence."
	severity := FindingSeverityLow
	switch observation.Status {
	case DNSObservationNXDOMAIN:
		message = "The DNS owner name does not exist."
	case DNSObservationNoData:
		message = "The DNS owner name has no TXT data."
	case DNSObservationNotFound:
		message = "The limited resolver reported that the DNS owner name was not found."
	case DNSObservationTimeout:
		message = "The DNS TXT lookup timed out."
		severity = FindingSeverityMedium
	case DNSObservationTemporaryFailure:
		message = "The DNS TXT lookup failed temporarily."
		severity = FindingSeverityMedium
	case DNSObservationMalformed:
		message = "The resolver returned malformed DNS evidence."
		severity = FindingSeverityMedium
	case DNSObservationCanceled:
		message = "The DNS TXT lookup was canceled before completion."
	}
	return DNSCollectionDiagnostic{Code: code, Severity: severity, Name: observation.Name, Attempts: observation.Attempts, Message: message}
}

func newDNSSnapshot(observedAt time.Time, portfolioID AnalysisID, observations []DNSObservation, diagnostics []DNSCollectionDiagnostic) DNSSnapshot {
	complete := true
	for _, observation := range observations {
		if observation.Status == DNSObservationCanceled {
			complete = false
			break
		}
	}
	canonical := struct {
		ObservedAt   time.Time                 `json:"observed_at"`
		PortfolioID  AnalysisID                `json:"portfolio_id"`
		Observations []DNSObservation          `json:"observations"`
		Diagnostics  []DNSCollectionDiagnostic `json:"diagnostics"`
	}{observedAt, portfolioID, observations, diagnostics}
	payload, _ := json.Marshal(canonical)
	hash := sha256.Sum256(payload)
	digest := AnalysisID("dns_snapshot:" + hex.EncodeToString(hash[:]))
	return DNSSnapshot{
		metadata:    ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeDNSSnapshot, GeneratedAt: observedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}},
		portfolioID: portfolioID, digest: digest, complete: complete,
		observations: cloneDNSObservations(observations), diagnostics: append([]DNSCollectionDiagnostic(nil), diagnostics...),
	}
}

func normalizeDNSDisplayName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func normalizeDNSDisplayNames(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = normalizeDNSDisplayName(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func sortDNSReferences(references []DNSRecordReference) {
	sort.Slice(references, func(i, j int) bool {
		if references[i].EntityID != references[j].EntityID {
			return references[i].EntityID < references[j].EntityID
		}
		if references[i].Domain != references[j].Domain {
			return references[i].Domain < references[j].Domain
		}
		if references[i].Type != references[j].Type {
			return references[i].Type < references[j].Type
		}
		return references[i].Owner < references[j].Owner
	})
}

func cloneDNSReferences(values []DNSRecordReference) []DNSRecordReference {
	return append([]DNSRecordReference(nil), values...)
}

func cloneTXTRecords(values []TXTRecord) []TXTRecord {
	result := make([]TXTRecord, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Fragments = cloneStrings(value.Fragments)
	}
	return result
}

func cloneSOA(value *DNSSOAEvidence) *DNSSOAEvidence {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneDNSObservations(values []DNSObservation) []DNSObservation {
	result := make([]DNSObservation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].References = cloneDNSReferences(value.References)
		result[index].Records = cloneTXTRecords(value.Records)
		result[index].SOA = cloneSOA(value.SOA)
		result[index].CNAMEPath = cloneStrings(value.CNAMEPath)
	}
	return result
}
