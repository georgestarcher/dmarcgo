package dmarcgo

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// DNSReportCorrelationVersion identifies the current correlation algorithm.
const DNSReportCorrelationVersion = "1"

const correlationStandardReference = "https://www.rfc-editor.org/rfc/rfc9989.html#section-5.1.5"

var (
	// ErrInvalidDNSReportCorrelationOptions identifies invalid thresholds,
	// timestamps, prior results, or mismatched completed inputs.
	ErrInvalidDNSReportCorrelationOptions = errors.New("invalid DNS/report correlation options")
)

// DNSReportTemporalRelationship compares the current DNS observation time to
// historical report-period bounds. It never asserts that one caused the other.
type DNSReportTemporalRelationship string

const (
	DNSReportTimeUnknown      DNSReportTemporalRelationship = "unknown"
	DNSReportDNSBeforeReports DNSReportTemporalRelationship = "dns_before_reports"
	DNSReportDNSDuringReports DNSReportTemporalRelationship = "dns_during_reports"
	DNSReportDNSAfterReports  DNSReportTemporalRelationship = "dns_after_reports"
)

// SenderCandidateBasis explains why an expected sender is a candidate for an
// observed stream. Selector and unambiguous monitored-SPF matches are direct
// stream-to-inventory evidence; provider context alone never creates a match.
type SenderCandidateBasis string

const (
	SenderCandidateNone          SenderCandidateBasis = "none"
	SenderCandidateSelectorMatch SenderCandidateBasis = "selector_match"
	SenderCandidateSPFMatch      SenderCandidateBasis = "spf_identity_match"
)

// DNSReportCorrelationClassification is a stable machine category. None of
// these values is a malicious-attribution or safe-to-block verdict.
type DNSReportCorrelationClassification string

const (
	CorrelationExpectedSenderHealthy        DNSReportCorrelationClassification = "expected_sender_healthy"
	CorrelationExpectedSenderFailure        DNSReportCorrelationClassification = "expected_sender_configuration_failure"
	CorrelationProbableOnboardingGap        DNSReportCorrelationClassification = "probable_onboarding_gap"
	CorrelationUnknownSourceFailure         DNSReportCorrelationClassification = "unknown_source_authentication_failure"
	CorrelationUnknownPassingStream         DNSReportCorrelationClassification = "unknown_passing_stream"
	CorrelationNewSelector                  DNSReportCorrelationClassification = "new_selector"
	CorrelationNewSigningDomain             DNSReportCorrelationClassification = "new_signing_domain"
	CorrelationNewSPFIdentity               DNSReportCorrelationClassification = "new_spf_identity"
	CorrelationNewSource                    DNSReportCorrelationClassification = "new_source"
	CorrelationNewSubdomain                 DNSReportCorrelationClassification = "new_subdomain"
	CorrelationConfiguredSelectorNotSeen    DNSReportCorrelationClassification = "configured_selector_not_observed"
	CorrelationRetiredConfigurationObserved DNSReportCorrelationClassification = "retired_configuration_observed"
	CorrelationExpectedSenderBeganFailing   DNSReportCorrelationClassification = "expected_sender_began_failing"
	CorrelationCurrentDNSHistoricalVariance DNSReportCorrelationClassification = "current_dns_historical_variance"
	CorrelationInsufficientEvidence         DNSReportCorrelationClassification = "insufficient_evidence"
)

// DNSReportCorrelationThresholds controls when an observed stream can produce
// a substantive classification. Zero count thresholds select the safe default
// of one. Zero duration and age disable those two constraints.
type DNSReportCorrelationThresholds struct {
	MinMessages  int64         `json:"min_messages"`
	MinReports   int           `json:"min_reports"`
	MinReporters int           `json:"min_reporters"`
	MinDuration  time.Duration `json:"min_duration"`
	MaxReportAge time.Duration `json:"max_report_age"`
}

// DNSReportCorrelationOptions controls pure correlation. GeneratedAt defaults
// to the later completed-input timestamp. Previous is optional caller-supplied
// prior analysis used only for drift comparisons; the library adds no storage.
type DNSReportCorrelationOptions struct {
	GeneratedAt time.Time
	Thresholds  DNSReportCorrelationThresholds
	Previous    *DNSReportCorrelationResult
}

// DNSReportCorrelationInventory is the effective declared intent for one
// normalized entity/domain scope at correlation time.
type DNSReportCorrelationInventory struct {
	ID                  AnalysisID  `json:"id"`
	EntityID            string      `json:"entity_id"`
	Domain              string      `json:"domain"`
	Owner               string      `json:"owner,omitempty"`
	IncludeSubdomains   bool        `json:"include_subdomains"`
	ExpectedSenderIDs   []string    `json:"expected_sender_ids"`
	ExpectedSelectors   []string    `json:"expected_selectors"`
	MonitoredSPFNames   []string    `json:"monitored_spf_names"`
	MonitoredDKIMNames  []string    `json:"monitored_dkim_names"`
	MonitoredSelectors  []string    `json:"monitored_selectors"`
	DKIMDomains         []string    `json:"dkim_domains"`
	DeclaredProviderIDs []string    `json:"declared_provider_ids"`
	Sensitivity         Sensitivity `json:"sensitivity"`
}

// DNSReportCorrelationStream aggregates one observed source and authentication
// identity tuple. FirstSeen and LastSeen are report bounds, not message times.
type DNSReportCorrelationStream struct {
	ID                    AnalysisID                    `json:"id"`
	EntityID              string                        `json:"entity_id,omitempty"`
	Domain                string                        `json:"domain,omitempty"`
	Owner                 string                        `json:"owner,omitempty"`
	InheritedScope        bool                          `json:"inherited_scope"`
	TargetDomain          string                        `json:"target_domain,omitempty"`
	AuthorDomain          string                        `json:"author_domain,omitempty"`
	SourceIP              string                        `json:"source_ip,omitempty"`
	SPFDomain             string                        `json:"spf_domain,omitempty"`
	DKIMDomain            string                        `json:"dkim_domain,omitempty"`
	DKIMSelector          string                        `json:"dkim_selector,omitempty"`
	ExpectedSenderIDs     []string                      `json:"expected_sender_ids"`
	CandidateBasis        SenderCandidateBasis          `json:"candidate_basis"`
	DeclaredProviderIDs   []string                      `json:"declared_provider_ids"`
	ProviderContextIDs    []AnalysisID                  `json:"provider_context_ids"`
	SharedProviderContext bool                          `json:"shared_provider_context"`
	ObservationIDs        []EvidenceID                  `json:"observation_ids"`
	ReportEvidenceIDs     []EvidenceID                  `json:"report_evidence_ids"`
	DNSFindingIDs         []FindingID                   `json:"dns_finding_ids"`
	Messages              int64                         `json:"messages"`
	Reports               int                           `json:"reports"`
	ReporterDiversity     int                           `json:"reporter_diversity"`
	FirstSeen             ReportEvidenceTimestamp       `json:"first_seen"`
	LastSeen              ReportEvidenceTimestamp       `json:"last_seen"`
	Combined              ReportEvidenceOutcomeTotals   `json:"combined"`
	DKIM                  ReportEvidenceOutcomeTotals   `json:"dkim"`
	SPF                   ReportEvidenceOutcomeTotals   `json:"spf"`
	ThresholdEvaluation   Evaluation                    `json:"threshold_evaluation"`
	TemporalRelationship  DNSReportTemporalRelationship `json:"temporal_relationship"`
	Sensitivity           Sensitivity                   `json:"sensitivity"`
}

// DNSReportCorrelationFinding is one explainable, evidence-linked conclusion.
// Summary and Recommendation are library-controlled and never interpolate
// report, DNS, portfolio, provider, owner, or other untrusted values.
type DNSReportCorrelationFinding struct {
	ID                    FindingID                          `json:"id"`
	Code                  FindingCode                        `json:"code"`
	Classification        DNSReportCorrelationClassification `json:"classification"`
	Severity              FindingSeverity                    `json:"severity"`
	Confidence            FindingConfidence                  `json:"confidence"`
	EntityID              string                             `json:"entity_id,omitempty"`
	Domain                string                             `json:"domain,omitempty"`
	Owner                 string                             `json:"owner,omitempty"`
	ExpectedSenderIDs     []string                           `json:"expected_sender_ids"`
	DeclaredProviderIDs   []string                           `json:"declared_provider_ids"`
	ProviderContextIDs    []AnalysisID                       `json:"provider_context_ids"`
	SharedProviderContext bool                               `json:"shared_provider_context"`
	StreamIDs             []AnalysisID                       `json:"stream_ids"`
	ObservationIDs        []EvidenceID                       `json:"observation_ids"`
	DNSFindingIDs         []FindingID                        `json:"dns_finding_ids"`
	PreviousDigest        AnalysisID                         `json:"previous_correlation_digest,omitempty"`
	SourceIPs             []string                           `json:"source_ips"`
	AuthorDomains         []string                           `json:"author_domains"`
	SPFDomains            []string                           `json:"spf_domains"`
	DKIMDomains           []string                           `json:"dkim_domains"`
	DKIMSelectors         []string                           `json:"dkim_selectors"`
	Messages              int64                              `json:"messages"`
	Reports               int                                `json:"reports"`
	ReporterDiversity     int                                `json:"reporter_diversity"`
	FirstSeen             ReportEvidenceTimestamp            `json:"first_seen"`
	LastSeen              ReportEvidenceTimestamp            `json:"last_seen"`
	DNSObservedAt         time.Time                          `json:"dns_observed_at"`
	TemporalRelationship  DNSReportTemporalRelationship      `json:"temporal_relationship"`
	Evaluation            Evaluation                         `json:"evaluation"`
	Summary               string                             `json:"summary"`
	Recommendation        string                             `json:"recommendation,omitempty"`
	Standard              string                             `json:"standard"`
	Sensitivity           Sensitivity                        `json:"sensitivity"`
}

// DNSReportCorrelationClassificationCount is a deterministic summary count.
type DNSReportCorrelationClassificationCount struct {
	Classification DNSReportCorrelationClassification `json:"classification"`
	Findings       int                                `json:"findings"`
}

// DNSReportCorrelationSummary summarizes distinct report evidence and
// correlation products without summing expanded multi-DKIM streams twice.
type DNSReportCorrelationSummary struct {
	Messages              int64                                     `json:"messages"`
	Reports               int                                       `json:"reports"`
	ReporterDiversity     int                                       `json:"reporter_diversity"`
	Streams               int                                       `json:"streams"`
	ThresholdedStreams    int                                       `json:"thresholded_streams"`
	ExpectedSenderStreams int                                       `json:"expected_sender_streams"`
	UnknownSourceStreams  int                                       `json:"unknown_source_streams"`
	Findings              int                                       `json:"findings"`
	FirstSeen             ReportEvidenceTimestamp                   `json:"first_seen"`
	LastSeen              ReportEvidenceTimestamp                   `json:"last_seen"`
	Classifications       []DNSReportCorrelationClassificationCount `json:"classifications"`
}

// DNSReportCorrelationResult is an immutable pure-correlation result.
type DNSReportCorrelationResult struct {
	metadata              ResultMetadata
	version               string
	organizationID        string
	portfolioDigest       AnalysisID
	dnsHealthDigest       AnalysisID
	dnsSnapshotDigest     AnalysisID
	authenticationDigest  AnalysisID
	providerCatalogDigest AnalysisID
	providerProvenance    ProviderCatalogProvenance
	reportEvidenceDigest  AnalysisID
	previousDigest        AnalysisID
	digest                AnalysisID
	dnsObservedAt         time.Time
	thresholds            DNSReportCorrelationThresholds
	inventory             []DNSReportCorrelationInventory
	streams               []DNSReportCorrelationStream
	findings              []DNSReportCorrelationFinding
	summary               DNSReportCorrelationSummary
}

func (result DNSReportCorrelationResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result DNSReportCorrelationResult) Version() string                { return result.version }
func (result DNSReportCorrelationResult) OrganizationID() string         { return result.organizationID }
func (result DNSReportCorrelationResult) PortfolioDigest() AnalysisID    { return result.portfolioDigest }
func (result DNSReportCorrelationResult) DNSHealthDigest() AnalysisID    { return result.dnsHealthDigest }
func (result DNSReportCorrelationResult) DNSSnapshotDigest() AnalysisID {
	return result.dnsSnapshotDigest
}
func (result DNSReportCorrelationResult) AuthenticationDigest() AnalysisID {
	return result.authenticationDigest
}
func (result DNSReportCorrelationResult) ProviderCatalogDigest() AnalysisID {
	return result.providerCatalogDigest
}
func (result DNSReportCorrelationResult) ProviderCatalogProvenance() ProviderCatalogProvenance {
	return cloneProviderCatalogProvenance(result.providerProvenance)
}
func (result DNSReportCorrelationResult) ReportEvidenceDigest() AnalysisID {
	return result.reportEvidenceDigest
}
func (result DNSReportCorrelationResult) PreviousDigest() AnalysisID { return result.previousDigest }
func (result DNSReportCorrelationResult) Digest() AnalysisID         { return result.digest }
func (result DNSReportCorrelationResult) DNSObservedAt() time.Time   { return result.dnsObservedAt }
func (result DNSReportCorrelationResult) Thresholds() DNSReportCorrelationThresholds {
	return result.thresholds
}
func (result DNSReportCorrelationResult) Inventory() []DNSReportCorrelationInventory {
	return cloneDNSReportCorrelationInventory(result.inventory)
}
func (result DNSReportCorrelationResult) Streams() []DNSReportCorrelationStream {
	return cloneDNSReportCorrelationStreams(result.streams)
}
func (result DNSReportCorrelationResult) Findings() []DNSReportCorrelationFinding {
	return cloneDNSReportCorrelationFindings(result.findings)
}
func (result DNSReportCorrelationResult) Summary() DNSReportCorrelationSummary {
	return cloneDNSReportCorrelationSummary(result.summary)
}

type correlationScope struct {
	entity             Entity
	domain             MonitoredDomain
	inventory          DNSReportCorrelationInventory
	senders            map[string]ExpectedSender
	providerContextIDs []AnalysisID
	providerContexts   []DNSHealthProviderContext
	dnsFindingIDs      []FindingID
	mechanisms         DNSHealthMechanismScores
}

type correlationDKIMIdentity struct {
	domain   string
	selector string
	outcome  ReportAuthenticationOutcome
}

type correlationStreamAccumulator struct {
	value        DNSReportCorrelationStream
	observations map[EvidenceID]struct{}
	reports      map[EvidenceID]struct{}
	reporters    map[string]struct{}
}

type correlationCoverage struct {
	messages     int64
	reports      map[EvidenceID]struct{}
	reporters    map[string]struct{}
	observations map[EvidenceID]struct{}
	firstSeen    ReportEvidenceTimestamp
	lastSeen     ReportEvidenceTimestamp
}

type correlationPolicyState uint8

const (
	correlationPolicyUnknown correlationPolicyState = iota
	correlationPolicyPass
	correlationPolicyFail
)

// CorrelateReportEvidence compares declared portfolio intent, a completed
// current DNS-health result, and completed historical report evidence. It
// performs no DNS, report parsing, filesystem, enrichment, clock, or other I/O.
func CorrelateReportEvidence(portfolio Portfolio, dnsHealth DNSHealthResult, reportEvidence ReportEvidenceResult, options DNSReportCorrelationOptions) (DNSReportCorrelationResult, error) {
	thresholds, err := normalizeCorrelationThresholds(options.Thresholds)
	if err != nil {
		return DNSReportCorrelationResult{}, err
	}
	dnsMetadata := dnsHealth.ResultMetadata()
	reportMetadata := reportEvidence.ResultMetadata()
	dnsObservedAt := dnsHealth.ObservedAt().UTC()
	if portfolio.Digest() == "" || dnsHealth.Digest() == "" || reportEvidence.Digest() == "" ||
		dnsMetadata.ContractVersion != AnalysisContractVersion || dnsMetadata.Mode != AnalysisModeDNSHealth || dnsMetadata.Evaluation.State != EvaluationStateEvaluated ||
		reportMetadata.ContractVersion != AnalysisContractVersion || reportMetadata.Mode != AnalysisModeReportEvidence || reportMetadata.Evaluation.State != EvaluationStateEvaluated ||
		dnsHealth.PortfolioDigest() != portfolio.Digest() || dnsObservedAt.IsZero() || dnsObservedAt.After(dnsMetadata.GeneratedAt) {
		return DNSReportCorrelationResult{}, ErrInvalidAnalysisResult
	}
	generatedAt := options.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = laterTime(dnsMetadata.GeneratedAt, reportMetadata.GeneratedAt)
	}
	if generatedAt.Before(dnsMetadata.GeneratedAt) || generatedAt.Before(reportMetadata.GeneratedAt) {
		return DNSReportCorrelationResult{}, errors.Join(ErrInvalidDNSReportCorrelationOptions, errors.New("generation time predates a completed input"))
	}
	organizationID := portfolio.Organization().ID
	var previousDigest AnalysisID
	if options.Previous != nil {
		previous := options.Previous
		metadata := previous.ResultMetadata()
		if previous.Digest() == "" || metadata.ContractVersion != AnalysisContractVersion || metadata.Mode != AnalysisModeDNSReportCorrelation ||
			metadata.Evaluation.State != EvaluationStateEvaluated || metadata.GeneratedAt.After(generatedAt) || previous.OrganizationID() != organizationID {
			return DNSReportCorrelationResult{}, errors.Join(ErrInvalidDNSReportCorrelationOptions, errors.New("previous correlation result is invalid, newer than this evaluation, or belongs to another organization"))
		}
		previousDigest = previous.Digest()
	}

	scopes, inventory := buildCorrelationScopes(portfolio, dnsHealth)
	streams, coverage, err := buildCorrelationStreams(organizationID, scopes, reportEvidence.Observations(), thresholds, generatedAt, dnsObservedAt)
	if err != nil {
		return DNSReportCorrelationResult{}, err
	}
	previousStreams, previousInventory, previousSources := previousCorrelationIndexes(options.Previous)
	findings := buildCorrelationFindings(scopes, inventory, streams, coverage, previousStreams, previousInventory, previousSources, previousDigest, thresholds, generatedAt, dnsObservedAt)
	sortCorrelationFindings(findings)
	summary := buildCorrelationSummary(reportEvidence.Summary(), streams, findings)

	canonical, err := json.Marshal(struct {
		Version               string                          `json:"version"`
		OrganizationID        string                          `json:"organization_id"`
		PortfolioDigest       AnalysisID                      `json:"portfolio_digest"`
		DNSHealthDigest       AnalysisID                      `json:"dns_health_digest"`
		DNSSnapshotDigest     AnalysisID                      `json:"dns_snapshot_digest"`
		AuthenticationDigest  AnalysisID                      `json:"authentication_digest"`
		ProviderCatalogDigest AnalysisID                      `json:"provider_catalog_digest"`
		ProviderProvenance    ProviderCatalogProvenance       `json:"provider_provenance"`
		ReportEvidenceDigest  AnalysisID                      `json:"report_evidence_digest"`
		PreviousDigest        AnalysisID                      `json:"previous_digest,omitempty"`
		GeneratedAt           time.Time                       `json:"generated_at"`
		DNSObservedAt         time.Time                       `json:"dns_observed_at"`
		Thresholds            DNSReportCorrelationThresholds  `json:"thresholds"`
		Inventory             []DNSReportCorrelationInventory `json:"inventory"`
		Streams               []DNSReportCorrelationStream    `json:"streams"`
		Findings              []DNSReportCorrelationFinding   `json:"findings"`
		Summary               DNSReportCorrelationSummary     `json:"summary"`
	}{DNSReportCorrelationVersion, organizationID, portfolio.Digest(), dnsHealth.Digest(), dnsHealth.SnapshotDigest(), dnsHealth.AuthenticationDigest(), dnsHealth.ProviderCatalogDigest(), dnsHealth.ProviderCatalogProvenance(), reportEvidence.Digest(), previousDigest, generatedAt, dnsObservedAt, thresholds, inventory, streams, findings, summary})
	if err != nil {
		return DNSReportCorrelationResult{}, errors.Join(ErrInvalidAnalysisResult, err)
	}
	return DNSReportCorrelationResult{
		metadata: ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeDNSReportCorrelation, GeneratedAt: generatedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}},
		version:  DNSReportCorrelationVersion, organizationID: organizationID, portfolioDigest: portfolio.Digest(), dnsHealthDigest: dnsHealth.Digest(), dnsSnapshotDigest: dnsHealth.SnapshotDigest(),
		authenticationDigest: dnsHealth.AuthenticationDigest(), providerCatalogDigest: dnsHealth.ProviderCatalogDigest(), providerProvenance: dnsHealth.ProviderCatalogProvenance(),
		reportEvidenceDigest: reportEvidence.Digest(), previousDigest: previousDigest,
		digest: StableAnalysisID("dns_report_correlation", string(canonical)), dnsObservedAt: dnsObservedAt, thresholds: thresholds,
		inventory: cloneDNSReportCorrelationInventory(inventory), streams: cloneDNSReportCorrelationStreams(streams), findings: cloneDNSReportCorrelationFindings(findings), summary: cloneDNSReportCorrelationSummary(summary),
	}, nil
}

func normalizeCorrelationThresholds(value DNSReportCorrelationThresholds) (DNSReportCorrelationThresholds, error) {
	if value.MinMessages < 0 || value.MinReports < 0 || value.MinReporters < 0 || value.MinDuration < 0 || value.MaxReportAge < 0 {
		return DNSReportCorrelationThresholds{}, errors.Join(ErrInvalidDNSReportCorrelationOptions, errors.New("negative correlation threshold"))
	}
	if value.MinMessages == 0 {
		value.MinMessages = 1
	}
	if value.MinReports == 0 {
		value.MinReports = 1
	}
	if value.MinReporters == 0 {
		value.MinReporters = 1
	}
	return value, nil
}

func laterTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right.UTC()
	}
	return left.UTC()
}

func buildCorrelationScopes(portfolio Portfolio, dnsHealth DNSHealthResult) ([]correlationScope, []DNSReportCorrelationInventory) {
	organizationID := portfolio.Organization().ID
	senderIndex := map[string]ExpectedSender{}
	for _, sender := range portfolio.ExpectedSenders() {
		senderIndex[sender.ID] = sender
	}
	contextIndex := map[string][]DNSHealthProviderContext{}
	for _, value := range dnsHealth.ProviderContexts() {
		key := correlationScopeKey(value.EntityID, value.Domain)
		contextIndex[key] = append(contextIndex[key], value)
	}
	dnsFindingIndex := map[string][]DNSHealthFinding{}
	for _, value := range dnsHealth.Findings() {
		if value.EntityID == "" || value.Domain == "" {
			continue
		}
		key := correlationScopeKey(value.EntityID, value.Domain)
		dnsFindingIndex[key] = append(dnsFindingIndex[key], value)
	}
	domainHealthIndex := map[string]DNSDomainHealth{}
	for _, value := range dnsHealth.Domains() {
		domainHealthIndex[correlationScopeKey(value.EntityID, value.Domain)] = value
	}

	scopes := make([]correlationScope, 0)
	inventory := make([]DNSReportCorrelationInventory, 0)
	for _, entity := range portfolio.Entities() {
		for _, domain := range entity.Domains {
			scopeSenders := map[string]ExpectedSender{}
			providers := make([]string, 0)
			expectedSelectors := make([]string, 0)
			for _, senderID := range domain.ExpectedSenders {
				if sender, ok := senderIndex[senderID]; ok {
					scopeSenders[senderID] = sender
					expectedSelectors = append(expectedSelectors, sender.Policy.AllowedSelectors...)
					if sender.Provider != "" {
						providers = append(providers, sender.Provider)
					}
				}
			}
			monitoredSelectors, dkimDomains := monitoredDKIMInventory(domain.Records.DKIM)
			value := DNSReportCorrelationInventory{
				ID: StableAnalysisID("dns_report_inventory", organizationID, entity.ID, domain.Name), EntityID: entity.ID, Domain: domain.Name, Owner: domain.Owner,
				IncludeSubdomains: domain.IncludeSubdomains, ExpectedSenderIDs: compactSortedStrings(domain.ExpectedSenders), ExpectedSelectors: compactSortedStrings(expectedSelectors),
				MonitoredSPFNames: compactSortedStrings(domain.Records.SPF), MonitoredDKIMNames: compactSortedStrings(domain.Records.DKIM),
				MonitoredSelectors: monitoredSelectors, DKIMDomains: dkimDomains, DeclaredProviderIDs: compactSortedStrings(providers), Sensitivity: SensitivityOperational,
			}
			key := correlationScopeKey(entity.ID, domain.Name)
			providerContextIDs := make([]AnalysisID, 0)
			for _, context := range contextIndex[key] {
				providerContextIDs = append(providerContextIDs, context.ID)
			}
			dnsFindingIDs := make([]FindingID, 0)
			for _, finding := range dnsFindingIndex[key] {
				dnsFindingIDs = append(dnsFindingIDs, finding.ID)
			}
			health := domainHealthIndex[key]
			scopes = append(scopes, correlationScope{
				entity: entity, domain: domain, inventory: value, senders: scopeSenders,
				providerContextIDs: compactSortedAnalysisIDs(providerContextIDs), providerContexts: append([]DNSHealthProviderContext(nil), contextIndex[key]...),
				dnsFindingIDs: compactSortedFindingIDs(dnsFindingIDs), mechanisms: health.Mechanisms,
			})
			inventory = append(inventory, value)
		}
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].domain.Name != scopes[j].domain.Name {
			return scopes[i].domain.Name < scopes[j].domain.Name
		}
		return scopes[i].entity.ID < scopes[j].entity.ID
	})
	sort.Slice(inventory, func(i, j int) bool {
		if inventory[i].Domain != inventory[j].Domain {
			return inventory[i].Domain < inventory[j].Domain
		}
		return inventory[i].EntityID < inventory[j].EntityID
	})
	return scopes, inventory
}

func monitoredDKIMInventory(names []string) ([]string, []string) {
	selectors := make([]string, 0)
	domains := make([]string, 0)
	for _, name := range names {
		selector, domain, ok := strings.Cut(name, "._domainkey.")
		if !ok || selector == "" || domain == "" {
			continue
		}
		selectors = append(selectors, selector)
		domains = append(domains, domain)
	}
	return compactSortedStrings(selectors), compactSortedStrings(domains)
}

func buildCorrelationStreams(organizationID string, scopes []correlationScope, observations []ReportEvidenceObservation, thresholds DNSReportCorrelationThresholds, generatedAt, dnsObservedAt time.Time) ([]DNSReportCorrelationStream, map[string]*correlationCoverage, error) {
	accumulators := map[string]*correlationStreamAccumulator{}
	coverage := map[string]*correlationCoverage{}
	for _, observation := range observations {
		scope, inherited, resolved := resolveCorrelationScope(scopes, observation.AuthorDomain.Value)
		entityID, domain, owner := "", "", ""
		if resolved {
			entityID, domain, owner = scope.entity.ID, scope.domain.Name, scope.domain.Owner
			if err := addCorrelationCoverage(coverage, correlationScopeKey(entityID, domain), observation); err != nil {
				return nil, nil, err
			}
		}
		identities := correlationDKIMIdentities(observation)
		for _, identity := range identities {
			value := DNSReportCorrelationStream{
				EntityID: entityID, Domain: domain, Owner: owner, InheritedScope: inherited,
				TargetDomain: observation.TargetDomain.Value, AuthorDomain: observation.AuthorDomain.Value, SourceIP: observation.SourceIP.Value,
				SPFDomain: observation.SPF.Domain.Value, DKIMDomain: identity.domain, DKIMSelector: identity.selector,
				CandidateBasis: SenderCandidateNone, DeclaredProviderIDs: []string{}, ProviderContextIDs: []AnalysisID{}, ObservationIDs: []EvidenceID{}, ReportEvidenceIDs: []EvidenceID{}, DNSFindingIDs: []FindingID{},
				Sensitivity: SensitivityRestricted,
			}
			key := correlationStreamKey(value)
			accumulator, ok := accumulators[key]
			if !ok {
				value.ID = StableAnalysisID("dns_report_stream", organizationID, key)
				accumulator = &correlationStreamAccumulator{value: value, observations: map[EvidenceID]struct{}{}, reports: map[EvidenceID]struct{}{}, reporters: map[string]struct{}{}}
				accumulators[key] = accumulator
			}
			if err := accumulator.add(observation, identity.outcome); err != nil {
				return nil, nil, err
			}
		}
	}
	streams := make([]DNSReportCorrelationStream, 0, len(accumulators))
	for _, accumulator := range accumulators {
		value := accumulator.finish()
		if scope, ok := findCorrelationScope(scopes, value.EntityID, value.Domain); ok {
			applyCorrelationScope(&value, scope)
		}
		value.ThresholdEvaluation = evaluateCorrelationThresholds(value.Messages, value.Reports, value.ReporterDiversity, value.FirstSeen, value.LastSeen, thresholds, generatedAt)
		value.TemporalRelationship = correlationTemporalRelationship(dnsObservedAt, value.FirstSeen, value.LastSeen)
		streams = append(streams, value)
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].ID < streams[j].ID })
	return streams, coverage, nil
}

func resolveCorrelationScope(scopes []correlationScope, authorDomain string) (correlationScope, bool, bool) {
	if authorDomain == "" {
		return correlationScope{}, false, false
	}
	var best *correlationScope
	bestLength := -1
	for index := range scopes {
		candidate := &scopes[index]
		if authorDomain == candidate.domain.Name {
			if len(candidate.domain.Name) > bestLength {
				best, bestLength = candidate, len(candidate.domain.Name)
			}
			continue
		}
		if candidate.domain.IncludeSubdomains && strings.HasSuffix(authorDomain, "."+candidate.domain.Name) && len(candidate.domain.Name) > bestLength {
			best, bestLength = candidate, len(candidate.domain.Name)
		}
	}
	if best == nil {
		return correlationScope{}, false, false
	}
	return *best, authorDomain != best.domain.Name, true
}

func correlationDKIMIdentities(observation ReportEvidenceObservation) []correlationDKIMIdentity {
	type identityState struct {
		domain, selector string
		pass, fail       bool
	}
	states := map[string]*identityState{}
	for _, value := range observation.DKIM {
		key := value.Domain.Value + "\x00" + value.Selector.Value
		state, ok := states[key]
		if !ok {
			state = &identityState{domain: value.Domain.Value, selector: value.Selector.Value}
			states[key] = state
		}
		switch normalizedPolicyOutcome(value.Result) {
		case ReportAuthenticationPass:
			state.pass = true
		case ReportAuthenticationFail:
			state.fail = true
		}
	}
	if len(states) == 0 {
		return []correlationDKIMIdentity{{outcome: observation.PolicyOutcome.DKIM}}
	}
	passingIdentities := 0
	for _, state := range states {
		if state.pass {
			passingIdentities++
		}
	}
	identities := make([]correlationDKIMIdentity, 0, len(states))
	for _, state := range states {
		authenticationOutcome := ReportAuthenticationUnknown
		if state.pass {
			authenticationOutcome = ReportAuthenticationPass
		} else if state.fail {
			authenticationOutcome = ReportAuthenticationFail
		}
		identities = append(identities, correlationDKIMIdentity{
			domain: state.domain, selector: state.selector,
			outcome: correlationIdentityDKIMOutcome(observation.PolicyOutcome.DKIM, authenticationOutcome,
				state.domain != "" && state.domain == observation.AuthorDomain.Value, passingIdentities),
		})
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].domain != identities[j].domain {
			return identities[i].domain < identities[j].domain
		}
		return identities[i].selector < identities[j].selector
	})
	return identities
}

func correlationIdentityDKIMOutcome(policyOutcome, authenticationOutcome ReportAuthenticationOutcome, exactAlignment bool, passingIdentities int) ReportAuthenticationOutcome {
	switch policyOutcome {
	case ReportAuthenticationFail:
		return ReportAuthenticationFail
	case ReportAuthenticationPass:
		if authenticationOutcome != ReportAuthenticationPass {
			return authenticationOutcome
		}
		if passingIdentities == 1 || exactAlignment {
			return ReportAuthenticationPass
		}
	}
	return ReportAuthenticationUnknown
}

func correlationCombinedOutcome(dkim, spf ReportAuthenticationOutcome) ReportAuthenticationOutcome {
	if dkim == ReportAuthenticationPass || spf == ReportAuthenticationPass {
		return ReportAuthenticationPass
	}
	if dkim == ReportAuthenticationFail && spf == ReportAuthenticationFail {
		return ReportAuthenticationFail
	}
	return ReportAuthenticationUnknown
}

func correlationStreamKey(value DNSReportCorrelationStream) string {
	return strings.Join([]string{value.EntityID, value.Domain, value.TargetDomain, value.AuthorDomain, value.SourceIP, value.SPFDomain, value.DKIMDomain, value.DKIMSelector}, "\x00")
}

func (accumulator *correlationStreamAccumulator) add(observation ReportEvidenceObservation, dkimOutcome ReportAuthenticationOutcome) error {
	accumulator.observations[observation.ID] = struct{}{}
	accumulator.reports[observation.ReportEvidenceID] = struct{}{}
	if observation.Reporter.Value != "" {
		accumulator.reporters[observation.Reporter.Value] = struct{}{}
	}
	updateCorrelationPeriod(&accumulator.value.FirstSeen, &accumulator.value.LastSeen, observation.Period)
	if !observation.Count.Available {
		return nil
	}
	var err error
	accumulator.value.Messages, err = checkedEvidenceAdd(accumulator.value.Messages, observation.Count.Value)
	if err != nil {
		return err
	}
	if err = addReportEvidenceOutcome(&accumulator.value.Combined, correlationCombinedOutcome(dkimOutcome, observation.PolicyOutcome.SPF), observation.Count.Value); err != nil {
		return err
	}
	if err = addReportEvidenceOutcome(&accumulator.value.DKIM, dkimOutcome, observation.Count.Value); err != nil {
		return err
	}
	return addReportEvidenceOutcome(&accumulator.value.SPF, observation.PolicyOutcome.SPF, observation.Count.Value)
}

func (accumulator *correlationStreamAccumulator) finish() DNSReportCorrelationStream {
	value := accumulator.value
	value.ObservationIDs = sortedEvidenceIDSet(accumulator.observations)
	value.ReportEvidenceIDs = sortedEvidenceIDSet(accumulator.reports)
	value.Reports = len(accumulator.reports)
	value.ReporterDiversity = len(accumulator.reporters)
	return value
}

func addCorrelationCoverage(index map[string]*correlationCoverage, key string, observation ReportEvidenceObservation) error {
	value, ok := index[key]
	if !ok {
		value = &correlationCoverage{reports: map[EvidenceID]struct{}{}, reporters: map[string]struct{}{}, observations: map[EvidenceID]struct{}{}}
		index[key] = value
	}
	value.reports[observation.ReportEvidenceID] = struct{}{}
	value.observations[observation.ID] = struct{}{}
	if observation.Reporter.Value != "" {
		value.reporters[observation.Reporter.Value] = struct{}{}
	}
	updateCorrelationPeriod(&value.firstSeen, &value.lastSeen, observation.Period)
	if !observation.Count.Available {
		return nil
	}
	var err error
	value.messages, err = checkedEvidenceAdd(value.messages, observation.Count.Value)
	return err
}

func updateCorrelationPeriod(first, last *ReportEvidenceTimestamp, period ReportEvidencePeriod) {
	if period.Evaluation.State != EvaluationStateEvaluated || !period.Begin.Available || !period.End.Available {
		return
	}
	if !first.Available || period.Begin.Value.Before(first.Value) {
		*first = ReportEvidenceTimestamp{Available: true, Value: period.Begin.Value}
	}
	if !last.Available || period.End.Value.After(last.Value) {
		*last = ReportEvidenceTimestamp{Available: true, Value: period.End.Value}
	}
}

func findCorrelationScope(scopes []correlationScope, entityID, domain string) (correlationScope, bool) {
	for _, scope := range scopes {
		if scope.entity.ID == entityID && scope.domain.Name == domain {
			return scope, true
		}
	}
	return correlationScope{}, false
}

func applyCorrelationScope(value *DNSReportCorrelationStream, scope correlationScope) {
	value.ProviderContextIDs = cloneAnalysisIDs(scope.providerContextIDs)
	value.DNSFindingIDs = cloneFindingIDs(scope.dnsFindingIDs)
	selectorMatches := make([]string, 0)
	for senderID, sender := range scope.senders {
		if value.DKIMSelector != "" && containsString(sender.Policy.AllowedSelectors, value.DKIMSelector) {
			selectorMatches = append(selectorMatches, senderID)
		}
	}
	if len(selectorMatches) > 0 {
		value.ExpectedSenderIDs = compactSortedStrings(selectorMatches)
		value.CandidateBasis = SenderCandidateSelectorMatch
	} else {
		spfMatches := make([]string, 0)
		if value.SPFDomain != "" && containsString(scope.inventory.MonitoredSPFNames, value.SPFDomain) {
			for senderID, sender := range scope.senders {
				if sender.Policy.RequireSPF || sender.Policy.RequireEither {
					spfMatches = append(spfMatches, senderID)
				}
			}
		}
		if len(spfMatches) == 1 {
			value.ExpectedSenderIDs = spfMatches
			value.CandidateBasis = SenderCandidateSPFMatch
		}
	}
	applyCorrelationProviderContext(value, scope)
}

func applyCorrelationProviderContext(value *DNSReportCorrelationStream, scope correlationScope) {
	providers := make([]string, 0)
	for _, senderID := range value.ExpectedSenderIDs {
		if sender, ok := scope.senders[senderID]; ok && sender.Provider != "" {
			providers = append(providers, sender.Provider)
		}
	}
	for _, context := range scope.providerContexts {
		if !hasStringIntersection(value.ExpectedSenderIDs, context.ExpectedSenderIDs) {
			continue
		}
		value.SharedProviderContext = value.SharedProviderContext || context.Provider.SharedInfrastructure
	}
	value.DeclaredProviderIDs = compactSortedStrings(providers)
}

func hasStringIntersection(left, right []string) bool {
	for _, value := range left {
		if containsString(right, value) {
			return true
		}
	}
	return false
}

func evaluateCorrelationThresholds(messages int64, reports, reporters int, first, last ReportEvidenceTimestamp, thresholds DNSReportCorrelationThresholds, generatedAt time.Time) Evaluation {
	if messages < thresholds.MinMessages || reports < thresholds.MinReports || reporters < thresholds.MinReporters {
		return Evaluation{State: EvaluationStateNotEvaluated, Reason: "The observed stream does not meet the configured count thresholds."}
	}
	if thresholds.MinDuration > 0 {
		if !first.Available || !last.Available || last.Value.Sub(first.Value) < thresholds.MinDuration {
			return Evaluation{State: EvaluationStateNotEvaluated, Reason: "The observed stream does not meet the configured duration threshold."}
		}
	}
	if thresholds.MaxReportAge > 0 {
		if !last.Available || generatedAt.Sub(last.Value) > thresholds.MaxReportAge {
			return Evaluation{State: EvaluationStateNotEvaluated, Reason: "The observed stream is outside the configured recency window."}
		}
	}
	return Evaluation{State: EvaluationStateEvaluated}
}

func correlationTemporalRelationship(dnsObservedAt time.Time, first, last ReportEvidenceTimestamp) DNSReportTemporalRelationship {
	if dnsObservedAt.IsZero() || !first.Available || !last.Available {
		return DNSReportTimeUnknown
	}
	if dnsObservedAt.Before(first.Value) {
		return DNSReportDNSBeforeReports
	}
	if dnsObservedAt.After(last.Value) {
		return DNSReportDNSAfterReports
	}
	return DNSReportDNSDuringReports
}

func previousCorrelationIndexes(previous *DNSReportCorrelationResult) (map[AnalysisID]DNSReportCorrelationStream, map[string]DNSReportCorrelationInventory, map[string]struct{}) {
	streams := map[AnalysisID]DNSReportCorrelationStream{}
	inventory := map[string]DNSReportCorrelationInventory{}
	sources := map[string]struct{}{}
	if previous == nil {
		return streams, inventory, sources
	}
	for _, stream := range previous.Streams() {
		streams[stream.ID] = stream
		if stream.SourceIP != "" {
			sources[correlationSourceKey(stream.EntityID, stream.Domain, stream.SourceIP)] = struct{}{}
		}
	}
	for _, value := range previous.Inventory() {
		inventory[correlationScopeKey(value.EntityID, value.Domain)] = value
	}
	return streams, inventory, sources
}

func buildCorrelationFindings(scopes []correlationScope, inventory []DNSReportCorrelationInventory, streams []DNSReportCorrelationStream, coverage map[string]*correlationCoverage, previousStreams map[AnalysisID]DNSReportCorrelationStream, previousInventory map[string]DNSReportCorrelationInventory, previousSources map[string]struct{}, previousDigest AnalysisID, thresholds DNSReportCorrelationThresholds, generatedAt, dnsObservedAt time.Time) []DNSReportCorrelationFinding {
	findings := make([]DNSReportCorrelationFinding, 0)
	observedSelectors := map[string]map[string]struct{}{}
	for _, stream := range streams {
		key := correlationScopeKey(stream.EntityID, stream.Domain)
		if stream.DKIMSelector != "" {
			if observedSelectors[key] == nil {
				observedSelectors[key] = map[string]struct{}{}
			}
			observedSelectors[key][stream.DKIMSelector] = struct{}{}
		}
		scope, scoped := findCorrelationScope(scopes, stream.EntityID, stream.Domain)
		findings = append(findings, classifyCorrelationStream(stream, scope, scoped, previousStreams[stream.ID], previousInventory[key], previousSources, previousDigest, dnsObservedAt)...)
	}
	for _, value := range inventory {
		key := correlationScopeKey(value.EntityID, value.Domain)
		covered := coverage[key]
		if covered == nil {
			continue
		}
		evaluation := evaluateCorrelationThresholds(covered.messages, len(covered.reports), len(covered.reporters), covered.firstSeen, covered.lastSeen, thresholds, generatedAt)
		if evaluation.State != EvaluationStateEvaluated {
			continue
		}
		selectors := compactSortedStrings(append(cloneStrings(value.ExpectedSelectors), value.MonitoredSelectors...))
		for _, selector := range selectors {
			if _, ok := observedSelectors[key][selector]; ok {
				continue
			}
			finding := newCorrelationInventoryFinding("correlation.configured_selector_not_observed", CorrelationConfiguredSelectorNotSeen, FindingSeverityLow, FindingConfidenceMedium, value, selector, covered, dnsObservedAt)
			findings = append(findings, finding)
		}
	}
	return findings
}

func classifyCorrelationStream(stream DNSReportCorrelationStream, scope correlationScope, scoped bool, previous DNSReportCorrelationStream, previousInventory DNSReportCorrelationInventory, previousSources map[string]struct{}, previousDigest AnalysisID, dnsObservedAt time.Time) []DNSReportCorrelationFinding {
	findings := make([]DNSReportCorrelationFinding, 0)
	if !scoped || stream.AuthorDomain == "" {
		return append(findings, newCorrelationStreamFinding("correlation.insufficient_domain_evidence", CorrelationInsufficientEvidence, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
	}
	if stream.ThresholdEvaluation.State != EvaluationStateEvaluated {
		return append(findings, newCorrelationStreamFinding("correlation.threshold_not_met", CorrelationInsufficientEvidence, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
	}

	selectorKnown := stream.DKIMSelector == "" || containsString(scope.inventory.ExpectedSelectors, stream.DKIMSelector) || containsString(scope.inventory.MonitoredSelectors, stream.DKIMSelector)
	dkimDomainKnown := stream.DKIMDomain == "" || containsString(scope.inventory.DKIMDomains, stream.DKIMDomain)
	spfKnown := stream.SPFDomain == "" || containsString(scope.inventory.MonitoredSPFNames, stream.SPFDomain)
	policyState := evaluateCandidatePolicies(stream, scope)
	directCandidate := stream.CandidateBasis == SenderCandidateSelectorMatch || stream.CandidateBasis == SenderCandidateSPFMatch

	if stream.SourceIP == "" {
		findings = append(findings, newCorrelationStreamFinding("correlation.source_evidence_incomplete", CorrelationInsufficientEvidence, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
	} else {
		switch {
		case directCandidate && policyState == correlationPolicyPass:
			findings = append(findings, newCorrelationStreamFinding("correlation.expected_sender_healthy", CorrelationExpectedSenderHealthy, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
		case directCandidate && policyState == correlationPolicyFail:
			classification := CorrelationExpectedSenderFailure
			code := FindingCode("correlation.expected_sender_authentication_failure")
			if !selectorKnown || !dkimDomainKnown || !spfKnown || !correlationDNSHealthyForCandidates(stream, scope) {
				classification = CorrelationProbableOnboardingGap
				code = "correlation.probable_onboarding_gap"
			}
			findings = append(findings, newCorrelationStreamFinding(code, classification, FindingSeverityHigh, FindingConfidenceHigh, stream, dnsObservedAt))
		case stream.CandidateBasis != SenderCandidateNone && policyState == correlationPolicyFail:
			findings = append(findings, newCorrelationStreamFinding("correlation.probable_onboarding_gap", CorrelationProbableOnboardingGap, FindingSeverityHigh, FindingConfidenceMedium, stream, dnsObservedAt))
		case stream.CandidateBasis != SenderCandidateNone && policyState == correlationPolicyPass:
			findings = append(findings, newCorrelationStreamFinding("correlation.unknown_passing_stream", CorrelationUnknownPassingStream, FindingSeverityInfo, FindingConfidenceMedium, stream, dnsObservedAt))
		case stream.Combined.Fail > 0:
			confidence := FindingConfidenceHigh
			if stream.Combined.Pass > 0 {
				confidence = FindingConfidenceMedium
			}
			findings = append(findings, newCorrelationStreamFinding("correlation.unknown_source_authentication_failure", CorrelationUnknownSourceFailure, FindingSeverityMedium, confidence, stream, dnsObservedAt))
		case stream.Combined.Pass > 0:
			findings = append(findings, newCorrelationStreamFinding("correlation.unknown_passing_stream", CorrelationUnknownPassingStream, FindingSeverityInfo, FindingConfidenceMedium, stream, dnsObservedAt))
		default:
			findings = append(findings, newCorrelationStreamFinding("correlation.authentication_evidence_incomplete", CorrelationInsufficientEvidence, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
		}
	}

	if stream.DKIMSelector != "" && !selectorKnown {
		findings = append(findings, newCorrelationStreamFinding("correlation.new_selector", CorrelationNewSelector, FindingSeverityMedium, FindingConfidenceHigh, stream, dnsObservedAt))
	}
	if stream.DKIMDomain != "" && !dkimDomainKnown {
		findings = append(findings, newCorrelationStreamFinding("correlation.new_signing_domain", CorrelationNewSigningDomain, FindingSeverityMedium, FindingConfidenceHigh, stream, dnsObservedAt))
	}
	if stream.SPFDomain != "" && !spfKnown {
		findings = append(findings, newCorrelationStreamFinding("correlation.new_spf_identity", CorrelationNewSPFIdentity, FindingSeverityMedium, FindingConfidenceHigh, stream, dnsObservedAt))
	}
	if stream.InheritedScope {
		findings = append(findings, newCorrelationStreamFinding("correlation.new_subdomain", CorrelationNewSubdomain, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
	}
	if previousDigest != "" && stream.SourceIP != "" {
		if _, ok := previousSources[correlationSourceKey(stream.EntityID, stream.Domain, stream.SourceIP)]; !ok {
			finding := newCorrelationStreamFinding("correlation.new_source", CorrelationNewSource, FindingSeverityLow, FindingConfidenceHigh, stream, dnsObservedAt)
			finding.PreviousDigest = previousDigest
			findings = append(findings, finding)
		}
	}
	if previous.ID != "" && expectedSenderBeganFailing(stream, previous, scope) {
		finding := newCorrelationStreamFinding("correlation.expected_sender_began_failing", CorrelationExpectedSenderBeganFailing, FindingSeverityHigh, FindingConfidenceHigh, stream, dnsObservedAt)
		finding.PreviousDigest = previousDigest
		findings = append(findings, finding)
	}
	if stream.DKIMSelector != "" && containsString(append(previousInventory.ExpectedSelectors, previousInventory.MonitoredSelectors...), stream.DKIMSelector) &&
		!containsString(append(scope.inventory.ExpectedSelectors, scope.inventory.MonitoredSelectors...), stream.DKIMSelector) {
		finding := newCorrelationStreamFinding("correlation.retired_configuration_observed", CorrelationRetiredConfigurationObserved, FindingSeverityMedium, FindingConfidenceHigh, stream, dnsObservedAt)
		finding.PreviousDigest = previousDigest
		findings = append(findings, finding)
	}
	if stream.Combined.Fail > 0 && correlationDNSHealthyForCandidates(stream, scope) && stream.TemporalRelationship == DNSReportDNSAfterReports {
		findings = append(findings, newCorrelationStreamFinding("correlation.current_dns_historical_variance", CorrelationCurrentDNSHistoricalVariance, FindingSeverityInfo, FindingConfidenceHigh, stream, dnsObservedAt))
	}
	return findings
}

func correlationDNSHealthyForCandidates(stream DNSReportCorrelationStream, scope correlationScope) bool {
	if len(stream.ExpectedSenderIDs) == 0 {
		return false
	}
	for _, senderID := range stream.ExpectedSenderIDs {
		sender, ok := scope.senders[senderID]
		if !ok {
			continue
		}
		policy := sender.Policy
		spfHealthy := dnsHealthScoreMaximum(scope.mechanisms.SPF)
		dkimHealthy := dnsHealthScoreMaximum(scope.mechanisms.DKIM)
		if len(policy.AllowedSelectors) > 0 {
			dkimHealthy = dkimHealthy && stream.DKIMSelector != "" && containsString(scope.inventory.MonitoredSelectors, stream.DKIMSelector)
		}
		if policy.RequireEither && (spfHealthy || dkimHealthy) {
			return true
		}
		if !policy.RequireEither && (!policy.RequireSPF || spfHealthy) && (!policy.RequireDKIM || dkimHealthy) && (policy.RequireSPF || policy.RequireDKIM) {
			return true
		}
	}
	return false
}

func dnsHealthScoreMaximum(value DNSHealthScore) bool {
	return value.Available && value.Value == value.Maximum && value.Evaluation.State == EvaluationStateEvaluated
}

func evaluateCandidatePolicies(stream DNSReportCorrelationStream, scope correlationScope) correlationPolicyState {
	if len(stream.ExpectedSenderIDs) == 0 {
		return correlationPolicyUnknown
	}
	seenFailure := false
	for _, senderID := range stream.ExpectedSenderIDs {
		sender, ok := scope.senders[senderID]
		if !ok {
			continue
		}
		state := evaluateSenderPolicy(stream, sender.Policy)
		if state == correlationPolicyPass {
			return state
		}
		if state == correlationPolicyFail {
			seenFailure = true
		}
	}
	if seenFailure {
		return correlationPolicyFail
	}
	return correlationPolicyUnknown
}

func expectedSenderBeganFailing(current, previous DNSReportCorrelationStream, scope correlationScope) bool {
	if current.CandidateBasis == SenderCandidateNone || previous.CandidateBasis == SenderCandidateNone ||
		current.ThresholdEvaluation.State != EvaluationStateEvaluated || previous.ThresholdEvaluation.State != EvaluationStateEvaluated {
		return false
	}
	for _, senderID := range current.ExpectedSenderIDs {
		if !containsString(previous.ExpectedSenderIDs, senderID) {
			continue
		}
		sender, ok := scope.senders[senderID]
		if ok && evaluateSenderPolicy(previous, sender.Policy) == correlationPolicyPass && evaluateSenderPolicy(current, sender.Policy) == correlationPolicyFail {
			return true
		}
	}
	return false
}

func evaluateSenderPolicy(stream DNSReportCorrelationStream, policy AuthenticationPolicy) correlationPolicyState {
	if policy.RequireEither {
		if stream.Combined.Fail > 0 {
			return correlationPolicyFail
		}
		if stream.Combined.Unknown > 0 || stream.Combined.Pass != stream.Messages {
			return correlationPolicyUnknown
		}
		if stream.SPF.Pass == stream.Messages {
			return correlationPolicyPass
		}
		selectorAllowed := len(policy.AllowedSelectors) == 0 || (stream.DKIMSelector != "" && containsString(policy.AllowedSelectors, stream.DKIMSelector))
		if selectorAllowed && stream.DKIM.Pass == stream.Messages {
			return correlationPolicyPass
		}
		if selectorAllowed {
			return correlationPolicyPass
		}
		return correlationPolicyFail
	}
	states := make([]correlationPolicyState, 0, 2)
	if policy.RequireDKIM {
		if len(policy.AllowedSelectors) > 0 {
			if stream.DKIMSelector == "" {
				return correlationPolicyUnknown
			}
			if !containsString(policy.AllowedSelectors, stream.DKIMSelector) {
				return correlationPolicyFail
			}
		}
		states = append(states, outcomeTotalsState(stream.DKIM))
	}
	if policy.RequireSPF {
		states = append(states, outcomeTotalsState(stream.SPF))
	}
	if len(states) == 0 {
		return correlationPolicyUnknown
	}
	for _, state := range states {
		if state == correlationPolicyFail {
			return state
		}
	}
	for _, state := range states {
		if state != correlationPolicyPass {
			return correlationPolicyUnknown
		}
	}
	return correlationPolicyPass
}

func outcomeTotalsState(value ReportEvidenceOutcomeTotals) correlationPolicyState {
	if value.Fail > 0 {
		return correlationPolicyFail
	}
	if value.Pass > 0 && value.Unknown == 0 {
		return correlationPolicyPass
	}
	return correlationPolicyUnknown
}

func newCorrelationStreamFinding(code FindingCode, classification DNSReportCorrelationClassification, severity FindingSeverity, confidence FindingConfidence, stream DNSReportCorrelationStream, dnsObservedAt time.Time) DNSReportCorrelationFinding {
	summary, recommendation := correlationFindingText(classification)
	evaluation := Evaluation{State: EvaluationStateEvaluated}
	if code == "correlation.threshold_not_met" {
		evaluation = stream.ThresholdEvaluation
	} else if classification == CorrelationInsufficientEvidence {
		evaluation = Evaluation{State: EvaluationStateUnknown, Reason: "The supplied evidence does not support a stronger classification."}
	}
	return DNSReportCorrelationFinding{
		ID: FindingID(StableAnalysisID("dns_report_finding", string(code), string(stream.ID))), Code: code, Classification: classification,
		Severity: severity, Confidence: confidence, EntityID: stream.EntityID, Domain: stream.Domain, Owner: stream.Owner,
		ExpectedSenderIDs: cloneStrings(stream.ExpectedSenderIDs), DeclaredProviderIDs: cloneStrings(stream.DeclaredProviderIDs), ProviderContextIDs: cloneAnalysisIDs(stream.ProviderContextIDs), SharedProviderContext: stream.SharedProviderContext, StreamIDs: []AnalysisID{stream.ID},
		ObservationIDs: cloneEvidenceIDs(stream.ObservationIDs), DNSFindingIDs: cloneFindingIDs(stream.DNSFindingIDs),
		SourceIPs: compactNonEmptyStrings(stream.SourceIP), AuthorDomains: compactNonEmptyStrings(stream.AuthorDomain), SPFDomains: compactNonEmptyStrings(stream.SPFDomain),
		DKIMDomains: compactNonEmptyStrings(stream.DKIMDomain), DKIMSelectors: compactNonEmptyStrings(stream.DKIMSelector),
		Messages: stream.Messages, Reports: stream.Reports, ReporterDiversity: stream.ReporterDiversity, FirstSeen: stream.FirstSeen, LastSeen: stream.LastSeen,
		DNSObservedAt: dnsObservedAt, TemporalRelationship: stream.TemporalRelationship, Evaluation: evaluation,
		Summary: summary, Recommendation: recommendation, Standard: correlationStandardReference, Sensitivity: SensitivityRestricted,
	}
}

func newCorrelationInventoryFinding(code FindingCode, classification DNSReportCorrelationClassification, severity FindingSeverity, confidence FindingConfidence, inventory DNSReportCorrelationInventory, selector string, coverage *correlationCoverage, dnsObservedAt time.Time) DNSReportCorrelationFinding {
	summary, recommendation := correlationFindingText(classification)
	return DNSReportCorrelationFinding{
		ID: FindingID(StableAnalysisID("dns_report_finding", string(code), string(inventory.ID), selector)), Code: code, Classification: classification,
		Severity: severity, Confidence: confidence, EntityID: inventory.EntityID, Domain: inventory.Domain, Owner: inventory.Owner,
		ExpectedSenderIDs: cloneStrings(inventory.ExpectedSenderIDs), DeclaredProviderIDs: cloneStrings(inventory.DeclaredProviderIDs), ProviderContextIDs: []AnalysisID{}, StreamIDs: []AnalysisID{},
		ObservationIDs: sortedEvidenceIDSet(coverage.observations), DNSFindingIDs: []FindingID{}, SourceIPs: []string{}, AuthorDomains: []string{}, SPFDomains: []string{}, DKIMDomains: []string{}, DKIMSelectors: []string{selector},
		Messages: coverage.messages, Reports: len(coverage.reports), ReporterDiversity: len(coverage.reporters), FirstSeen: coverage.firstSeen, LastSeen: coverage.lastSeen,
		DNSObservedAt: dnsObservedAt, TemporalRelationship: correlationTemporalRelationship(dnsObservedAt, coverage.firstSeen, coverage.lastSeen), Evaluation: Evaluation{State: EvaluationStateEvaluated},
		Summary: summary, Recommendation: recommendation, Standard: correlationStandardReference, Sensitivity: SensitivityOperational,
	}
}

func correlationFindingText(classification DNSReportCorrelationClassification) (string, string) {
	switch classification {
	case CorrelationExpectedSenderHealthy:
		return "Observed authentication satisfies a declared sender policy for this stream.", "Continue monitoring the declared stream for authentication drift."
	case CorrelationExpectedSenderFailure:
		return "A stream linked by declared authentication identity evidence does not consistently satisfy its expected authentication policy.", "Review the sender configuration and the separately observed DNS and report evidence."
	case CorrelationProbableOnboardingGap:
		return "Observed sender evidence is consistent with an incomplete or drifting onboarding configuration.", "Confirm the service owner and complete the declared SPF or DKIM onboarding sequence before changing enforcement."
	case CorrelationUnknownSourceFailure:
		return "An unattributed source failed both policy-evaluated SPF and DKIM for the observed stream.", "Review the source and authentication evidence; do not infer malicious ownership from DMARC failure alone."
	case CorrelationUnknownPassingStream:
		return "An unattributed stream passed at least one policy-evaluated authentication path.", "Determine whether the passing stream should be added to the expected-sender inventory."
	case CorrelationNewSelector:
		return "The observed DKIM selector is absent from the effective monitored selector inventory.", "Confirm whether the selector is an intended rotation or onboarding value and update monitored record names if authorized."
	case CorrelationNewSigningDomain:
		return "The observed DKIM signing domain is absent from the effective monitored signing-domain inventory.", "Confirm the signing-domain relationship with the service owner before updating inventory."
	case CorrelationNewSPFIdentity:
		return "The observed SPF identity is absent from the effective monitored SPF-name inventory.", "Confirm the MAIL FROM identity and declare its record name only when it is an intended stream."
	case CorrelationNewSource:
		return "The source address was not present in the caller-supplied prior correlation result.", "Review the new source in context; source novelty alone is not a malicious verdict."
	case CorrelationNewSubdomain:
		return "Report evidence resolved through an inherited parent scope rather than an explicit domain entry.", "Confirm whether the subdomain should remain inherited or become an explicitly owned scope."
	case CorrelationConfiguredSelectorNotSeen:
		return "A configured selector was not observed in the supplied report corpus for this domain scope.", "Confirm corpus coverage and whether the selector is inactive, retired, or reserved for a separate stream."
	case CorrelationRetiredConfigurationObserved:
		return "A selector present in prior declared inventory is still observed after removal from current inventory.", "Confirm whether the sender is intentionally retired and whether residual traffic remains authorized."
	case CorrelationExpectedSenderBeganFailing:
		return "A stream that passed in the caller-supplied prior result now includes authentication failure.", "Review recent sender and DNS changes while preserving the separate observation times."
	case CorrelationCurrentDNSHistoricalVariance:
		return "Current DNS health is strong while older report evidence contains authentication failure.", "Do not treat current DNS as proof of the historical cause; compare with time-matched evidence when available."
	case CorrelationInsufficientEvidence:
		return "The supplied evidence is insufficient for a stronger sender or authentication classification.", "Collect or supply additional bounded evidence without converting unknown values into failures."
	default:
		return "The supplied evidence produced a correlation finding.", "Review the structured evidence and temporal relationship before taking action."
	}
}

func buildCorrelationSummary(evidence ReportEvidenceAggregate, streams []DNSReportCorrelationStream, findings []DNSReportCorrelationFinding) DNSReportCorrelationSummary {
	result := DNSReportCorrelationSummary{
		Messages: evidence.Messages, Reports: evidence.Reports, ReporterDiversity: evidence.ReporterDiversity, Streams: len(streams), Findings: len(findings),
		FirstSeen: evidence.FirstSeen, LastSeen: evidence.LastSeen, Classifications: []DNSReportCorrelationClassificationCount{},
	}
	for _, stream := range streams {
		if stream.ThresholdEvaluation.State == EvaluationStateEvaluated {
			result.ThresholdedStreams++
		}
		if stream.CandidateBasis == SenderCandidateNone {
			result.UnknownSourceStreams++
		} else {
			result.ExpectedSenderStreams++
		}
	}
	counts := map[DNSReportCorrelationClassification]int{}
	for _, finding := range findings {
		counts[finding.Classification]++
	}
	classifications := make([]DNSReportCorrelationClassification, 0, len(counts))
	for classification := range counts {
		classifications = append(classifications, classification)
	}
	sort.Slice(classifications, func(i, j int) bool { return classifications[i] < classifications[j] })
	for _, classification := range classifications {
		result.Classifications = append(result.Classifications, DNSReportCorrelationClassificationCount{Classification: classification, Findings: counts[classification]})
	}
	return result
}

func sortCorrelationFindings(values []DNSReportCorrelationFinding) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Code != values[j].Code {
			return values[i].Code < values[j].Code
		}
		if values[i].Domain != values[j].Domain {
			return values[i].Domain < values[j].Domain
		}
		return values[i].ID < values[j].ID
	})
}

func correlationScopeKey(entityID, domain string) string { return entityID + "\x00" + domain }
func correlationSourceKey(entityID, domain, sourceIP string) string {
	return correlationScopeKey(entityID, domain) + "\x00" + sourceIP
}

func compactNonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return compactSortedStrings(result)
}

func compactSortedAnalysisIDs(values []AnalysisID) []AnalysisID {
	result := append([]AnalysisID(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	write := 0
	for _, value := range result {
		if value == "" || (write > 0 && result[write-1] == value) {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}

func sortedEvidenceIDSet(values map[EvidenceID]struct{}) []EvidenceID {
	result := make([]EvidenceID, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func cloneAnalysisIDs(values []AnalysisID) []AnalysisID { return append([]AnalysisID(nil), values...) }
func cloneEvidenceIDs(values []EvidenceID) []EvidenceID { return append([]EvidenceID(nil), values...) }
func cloneFindingIDs(values []FindingID) []FindingID    { return append([]FindingID(nil), values...) }

func cloneDNSReportCorrelationInventory(values []DNSReportCorrelationInventory) []DNSReportCorrelationInventory {
	result := append([]DNSReportCorrelationInventory(nil), values...)
	for index := range result {
		result[index].ExpectedSenderIDs = cloneStrings(result[index].ExpectedSenderIDs)
		result[index].DeclaredProviderIDs = cloneStrings(result[index].DeclaredProviderIDs)
		result[index].ExpectedSelectors = cloneStrings(result[index].ExpectedSelectors)
		result[index].MonitoredSPFNames = cloneStrings(result[index].MonitoredSPFNames)
		result[index].MonitoredDKIMNames = cloneStrings(result[index].MonitoredDKIMNames)
		result[index].MonitoredSelectors = cloneStrings(result[index].MonitoredSelectors)
		result[index].DKIMDomains = cloneStrings(result[index].DKIMDomains)
	}
	return result
}

func cloneDNSReportCorrelationStreams(values []DNSReportCorrelationStream) []DNSReportCorrelationStream {
	result := append([]DNSReportCorrelationStream(nil), values...)
	for index := range result {
		result[index].ExpectedSenderIDs = cloneStrings(result[index].ExpectedSenderIDs)
		result[index].DeclaredProviderIDs = cloneStrings(result[index].DeclaredProviderIDs)
		result[index].ProviderContextIDs = cloneAnalysisIDs(result[index].ProviderContextIDs)
		result[index].ObservationIDs = cloneEvidenceIDs(result[index].ObservationIDs)
		result[index].ReportEvidenceIDs = cloneEvidenceIDs(result[index].ReportEvidenceIDs)
		result[index].DNSFindingIDs = cloneFindingIDs(result[index].DNSFindingIDs)
	}
	return result
}

func cloneDNSReportCorrelationFindings(values []DNSReportCorrelationFinding) []DNSReportCorrelationFinding {
	result := append([]DNSReportCorrelationFinding(nil), values...)
	for index := range result {
		value := &result[index]
		value.ExpectedSenderIDs = cloneStrings(value.ExpectedSenderIDs)
		value.DeclaredProviderIDs = cloneStrings(value.DeclaredProviderIDs)
		value.ProviderContextIDs = cloneAnalysisIDs(value.ProviderContextIDs)
		value.StreamIDs = cloneAnalysisIDs(value.StreamIDs)
		value.ObservationIDs = cloneEvidenceIDs(value.ObservationIDs)
		value.DNSFindingIDs = cloneFindingIDs(value.DNSFindingIDs)
		value.SourceIPs = cloneStrings(value.SourceIPs)
		value.AuthorDomains = cloneStrings(value.AuthorDomains)
		value.SPFDomains = cloneStrings(value.SPFDomains)
		value.DKIMDomains = cloneStrings(value.DKIMDomains)
		value.DKIMSelectors = cloneStrings(value.DKIMSelectors)
	}
	return result
}

func cloneDNSReportCorrelationSummary(value DNSReportCorrelationSummary) DNSReportCorrelationSummary {
	value.Classifications = append([]DNSReportCorrelationClassificationCount(nil), value.Classifications...)
	return value
}
