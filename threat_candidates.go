package dmarcgo

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// ThreatCandidateScoringVersion identifies the current suspicious-source
// scoring algorithm. It is independent of the Go module and output schemas.
const ThreatCandidateScoringVersion = "1"

var (
	// ErrInvalidThreatCandidateOptions identifies an invalid scoring profile,
	// timestamp, or mismatched completed input.
	ErrInvalidThreatCandidateOptions = errors.New("invalid threat-candidate options")
	// ErrThreatCandidateOverflow identifies evidence counts that cannot be
	// represented safely by this scoring contract.
	ErrThreatCandidateOverflow = errors.New("threat-candidate count overflow")
)

// ThreatCandidateProfileName identifies an inspectable scoring policy.
type ThreatCandidateProfileName string

const (
	ThreatCandidateProfileConservative ThreatCandidateProfileName = "conservative"
	ThreatCandidateProfileBalanced     ThreatCandidateProfileName = "balanced"
	ThreatCandidateProfileSensitive    ThreatCandidateProfileName = "sensitive"
	ThreatCandidateProfileCustom       ThreatCandidateProfileName = "custom"
)

// ThreatCandidateScoringProfile contains all thresholds, weights, deductions,
// and confidence caps used by ScoreThreatCandidates. Custom profiles must use
// Name custom and the current scoring version.
type ThreatCandidateScoringProfile struct {
	Name                            ThreatCandidateProfileName `json:"name"`
	Version                         string                     `json:"version"`
	DualFailureWeight               int                        `json:"dual_failure_weight"`
	RepeatedReportsWeight           int                        `json:"repeated_reports_weight"`
	PersistenceWeight               int                        `json:"persistence_weight"`
	VolumeWeight                    int                        `json:"volume_weight"`
	ReporterDiversityWeight         int                        `json:"reporter_diversity_weight"`
	DispositionWeight               int                        `json:"disposition_weight"`
	DomainDiversityWeight           int                        `json:"domain_diversity_weight"`
	MixedPassingDeduction           int                        `json:"mixed_passing_deduction"`
	ExpectedSenderDeduction         int                        `json:"expected_sender_deduction"`
	SharedProviderDeduction         int                        `json:"shared_provider_deduction"`
	IndirectMailDeduction           int                        `json:"indirect_mail_deduction"`
	IncompleteEvidenceDeduction     int                        `json:"incomplete_evidence_deduction"`
	LowVolumeDeduction              int                        `json:"low_volume_deduction"`
	StaleEvidenceDeduction          int                        `json:"stale_evidence_deduction"`
	VolumeThreshold                 int64                      `json:"volume_threshold"`
	LowVolumeThreshold              int64                      `json:"low_volume_threshold"`
	PersistenceThreshold            time.Duration              `json:"persistence_threshold"`
	StaleAfter                      time.Duration              `json:"stale_after"`
	ReviewThreshold                 int                        `json:"review_threshold"`
	LowSeverityThreshold            int                        `json:"low_severity_threshold"`
	MediumSeverityThreshold         int                        `json:"medium_severity_threshold"`
	HighSeverityThreshold           int                        `json:"high_severity_threshold"`
	SingleReportConfidenceCap       int                        `json:"single_report_confidence_cap"`
	SingleReporterConfidenceCap     int                        `json:"single_reporter_confidence_cap"`
	UnenrichedConfidenceCap         int                        `json:"unenriched_confidence_cap"`
	MixedPassingConfidenceCap       int                        `json:"mixed_passing_confidence_cap"`
	ExpectedSenderConfidenceCap     int                        `json:"expected_sender_confidence_cap"`
	SharedProviderConfidenceCap     int                        `json:"shared_provider_confidence_cap"`
	IndirectMailConfidenceCap       int                        `json:"indirect_mail_confidence_cap"`
	IncompleteEvidenceConfidenceCap int                        `json:"incomplete_evidence_confidence_cap"`
	LowVolumeConfidenceCap          int                        `json:"low_volume_confidence_cap"`
	StaleEvidenceConfidenceCap      int                        `json:"stale_evidence_confidence_cap"`
}

// ThreatCandidateOptions controls pure candidate scoring. GeneratedAt defaults
// to the later completed-input timestamp. Expected sender failures are omitted
// unless IncludeExpectedSenders is explicitly set.
type ThreatCandidateOptions struct {
	GeneratedAt            time.Time
	Profile                ThreatCandidateProfileName
	CustomProfile          *ThreatCandidateScoringProfile
	IncludeExpectedSenders bool
}

// ThreatCandidateIPType distinguishes canonical address families.
type ThreatCandidateIPType string

const (
	ThreatCandidateIPv4 ThreatCandidateIPType = "ipv4"
	ThreatCandidateIPv6 ThreatCandidateIPType = "ipv6"
)

// ThreatCandidateAdjustmentKind distinguishes supporting evidence from
// false-positive-sensitive counter-evidence.
type ThreatCandidateAdjustmentKind string

const (
	ThreatCandidateSupport   ThreatCandidateAdjustmentKind = "support"
	ThreatCandidateDeduction ThreatCandidateAdjustmentKind = "deduction"
)

// ThreatCandidateScoreAdjustment is one reproducible score operation. Message
// is fixed library text and never interpolates supplied evidence.
type ThreatCandidateScoreAdjustment struct {
	Code        FindingCode                   `json:"code"`
	Kind        ThreatCandidateAdjustmentKind `json:"kind"`
	Points      int                           `json:"points"`
	Before      int                           `json:"before"`
	After       int                           `json:"after"`
	Message     string                        `json:"message"`
	EvidenceIDs []EvidenceID                  `json:"evidence_ids"`
}

// ThreatCandidateConfidenceAdjustment records one applied confidence cap.
// Message is fixed library text and never interpolates supplied evidence.
type ThreatCandidateConfidenceAdjustment struct {
	Code        FindingCode  `json:"code"`
	Maximum     int          `json:"maximum"`
	Before      int          `json:"before"`
	After       int          `json:"after"`
	Message     string       `json:"message"`
	EvidenceIDs []EvidenceID `json:"evidence_ids"`
}

// ThreatCandidateExclusion records an exclusion evaluated for a candidate.
// Reason is caller-owned restricted data and is never copied into generated prose.
type ThreatCandidateExclusion struct {
	ID              string         `json:"id"`
	Owner           string         `json:"owner"`
	Reason          string         `json:"reason"`
	Scope           ExclusionScope `json:"scope"`
	Target          string         `json:"target,omitempty"`
	EntityID        string         `json:"entity_id"`
	PortfolioDomain string         `json:"portfolio_domain"`
	CreatedAt       time.Time      `json:"created_at"`
	ExpiresAt       *time.Time     `json:"expires_at,omitempty"`
	Matched         bool           `json:"matched"`
	Active          bool           `json:"active"`
	Expired         bool           `json:"expired"`
}

// ThreatCandidateRecommendedUsage is deliberately advisory. No value permits
// blocking, enforcement, or malicious attribution.
type ThreatCandidateRecommendedUsage string

const (
	ThreatCandidateUsageReviewOnly     ThreatCandidateRecommendedUsage = "review_only"
	ThreatCandidateUsageMonitorOnly    ThreatCandidateRecommendedUsage = "monitor_only"
	ThreatCandidateUsageRetainEvidence ThreatCandidateRecommendedUsage = "retain_evidence_only"
)

// ThreatCandidate is an explainable source-review candidate. It is observed
// authentication evidence, not an IOC, ownership assertion, or safe-to-block verdict.
type ThreatCandidate struct {
	ID                            AnalysisID                            `json:"id"`
	SourceIP                      string                                `json:"source_ip"`
	IPType                        ThreatCandidateIPType                 `json:"ip_type"`
	ScoringVersion                string                                `json:"scoring_version"`
	Profile                       ThreatCandidateProfileName            `json:"profile"`
	Score                         int                                   `json:"score"`
	Confidence                    int                                   `json:"confidence"`
	ConfidenceLevel               FindingConfidence                     `json:"confidence_level"`
	Severity                      FindingSeverity                       `json:"severity"`
	Evaluation                    Evaluation                            `json:"evaluation"`
	Messages                      int64                                 `json:"messages"`
	DualFailureMessages           int64                                 `json:"dual_failure_messages"`
	ExpectedSenderFailureMessages int64                                 `json:"expected_sender_failure_messages"`
	PassingMessages               int64                                 `json:"passing_messages"`
	UnknownMessages               int64                                 `json:"unknown_messages"`
	Reports                       int                                   `json:"reports"`
	ReporterDiversity             int                                   `json:"reporter_diversity"`
	FirstSeen                     ReportEvidenceTimestamp               `json:"first_seen"`
	LastSeen                      ReportEvidenceTimestamp               `json:"last_seen"`
	Domains                       []string                              `json:"domains"`
	EntityIDs                     []string                              `json:"entity_ids"`
	Dispositions                  []ReportEvidenceDispositionCount      `json:"dispositions"`
	PolicyOverrideTypes           []string                              `json:"policy_override_types"`
	ExpectedSenderIDs             []string                              `json:"expected_sender_ids"`
	ProviderContextIDs            []AnalysisID                          `json:"provider_context_ids"`
	SharedProviderContext         bool                                  `json:"shared_provider_context"`
	IncompleteEvidence            bool                                  `json:"incomplete_evidence"`
	StaleEvidence                 bool                                  `json:"stale_evidence"`
	Enrichment                    Evaluation                            `json:"enrichment"`
	ScoreAdjustments              []ThreatCandidateScoreAdjustment      `json:"score_adjustments"`
	ConfidenceAdjustments         []ThreatCandidateConfidenceAdjustment `json:"confidence_adjustments"`
	ExclusionsConsidered          []ThreatCandidateExclusion            `json:"exclusions_considered"`
	Excluded                      bool                                  `json:"excluded"`
	ReviewEligible                bool                                  `json:"review_eligible"`
	PromotionEligible             bool                                  `json:"promotion_eligible"`
	RecommendedUsage              ThreatCandidateRecommendedUsage       `json:"recommended_usage"`
	ObservationIDs                []EvidenceID                          `json:"observation_ids"`
	ReportEvidenceIDs             []EvidenceID                          `json:"report_evidence_ids"`
	CorrelationFindingIDs         []FindingID                           `json:"correlation_finding_ids"`
	Sensitivity                   Sensitivity                           `json:"sensitivity"`
}

// ThreatCandidateSeverityCount is one deterministic severity rollup.
type ThreatCandidateSeverityCount struct {
	Severity   FindingSeverity `json:"severity"`
	Candidates int             `json:"candidates"`
}

// ThreatCandidateSummary describes candidate coverage without counting
// expected-sender-only failures as threat candidates by default.
type ThreatCandidateSummary struct {
	SourcesObserved               int                            `json:"sources_observed"`
	Candidates                    int                            `json:"candidates"`
	ReviewEligible                int                            `json:"review_eligible"`
	Excluded                      int                            `json:"excluded"`
	ExpectedSenderSourcesOmitted  int                            `json:"expected_sender_sources_omitted"`
	ExpectedSenderMessagesOmitted int64                          `json:"expected_sender_messages_omitted"`
	Severities                    []ThreatCandidateSeverityCount `json:"severities"`
}

// ThreatCandidateResult is an immutable pure-scoring result.
type ThreatCandidateResult struct {
	metadata             ResultMetadata
	version              string
	organizationID       string
	portfolioDigest      AnalysisID
	reportEvidenceDigest AnalysisID
	correlationDigest    AnalysisID
	digest               AnalysisID
	profile              ThreatCandidateScoringProfile
	candidates           []ThreatCandidate
	summary              ThreatCandidateSummary
}

func (result ThreatCandidateResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result ThreatCandidateResult) Version() string                { return result.version }
func (result ThreatCandidateResult) OrganizationID() string         { return result.organizationID }
func (result ThreatCandidateResult) PortfolioDigest() AnalysisID    { return result.portfolioDigest }
func (result ThreatCandidateResult) ReportEvidenceDigest() AnalysisID {
	return result.reportEvidenceDigest
}
func (result ThreatCandidateResult) CorrelationDigest() AnalysisID          { return result.correlationDigest }
func (result ThreatCandidateResult) Digest() AnalysisID                     { return result.digest }
func (result ThreatCandidateResult) Profile() ThreatCandidateScoringProfile { return result.profile }
func (result ThreatCandidateResult) Candidates() []ThreatCandidate {
	return cloneThreatCandidates(result.candidates)
}
func (result ThreatCandidateResult) Summary() ThreatCandidateSummary {
	return cloneThreatCandidateSummary(result.summary)
}

// ThreatCandidateScoringProfiles returns defensive copies of the built-in
// profiles in stable conservative, balanced, and sensitive order.
func ThreatCandidateScoringProfiles() []ThreatCandidateScoringProfile {
	return []ThreatCandidateScoringProfile{
		builtinThreatCandidateProfile(ThreatCandidateProfileConservative),
		builtinThreatCandidateProfile(ThreatCandidateProfileBalanced),
		builtinThreatCandidateProfile(ThreatCandidateProfileSensitive),
	}
}

// ThreatCandidateScoringProfileForName returns one built-in profile.
func ThreatCandidateScoringProfileForName(name ThreatCandidateProfileName) (ThreatCandidateScoringProfile, bool) {
	profile := builtinThreatCandidateProfile(name)
	if profile.Name == "" {
		return ThreatCandidateScoringProfile{}, false
	}
	return profile, true
}

func builtinThreatCandidateProfile(name ThreatCandidateProfileName) ThreatCandidateScoringProfile {
	base := ThreatCandidateScoringProfile{
		Name: name, Version: ThreatCandidateScoringVersion,
		VolumeThreshold: 100, LowVolumeThreshold: 10, PersistenceThreshold: 24 * time.Hour, StaleAfter: 30 * 24 * time.Hour,
		LowSeverityThreshold: 20, MediumSeverityThreshold: 45, HighSeverityThreshold: 70,
	}
	switch name {
	case ThreatCandidateProfileConservative:
		base.DualFailureWeight, base.RepeatedReportsWeight, base.PersistenceWeight = 20, 10, 10
		base.VolumeWeight, base.ReporterDiversityWeight, base.DispositionWeight, base.DomainDiversityWeight = 10, 10, 5, 5
		base.MixedPassingDeduction, base.ExpectedSenderDeduction, base.SharedProviderDeduction = 25, 35, 20
		base.IndirectMailDeduction, base.IncompleteEvidenceDeduction, base.LowVolumeDeduction, base.StaleEvidenceDeduction = 25, 20, 10, 10
		base.ReviewThreshold = 35
		base.SingleReportConfidenceCap, base.SingleReporterConfidenceCap, base.UnenrichedConfidenceCap = 35, 45, 60
		base.MixedPassingConfidenceCap, base.ExpectedSenderConfidenceCap, base.SharedProviderConfidenceCap = 45, 30, 45
		base.IndirectMailConfidenceCap, base.IncompleteEvidenceConfidenceCap, base.LowVolumeConfidenceCap, base.StaleEvidenceConfidenceCap = 35, 40, 40, 45
	case ThreatCandidateProfileBalanced:
		base.DualFailureWeight, base.RepeatedReportsWeight, base.PersistenceWeight = 30, 15, 10
		base.VolumeWeight, base.ReporterDiversityWeight, base.DispositionWeight, base.DomainDiversityWeight = 15, 10, 10, 10
		base.MixedPassingDeduction, base.ExpectedSenderDeduction, base.SharedProviderDeduction = 20, 30, 15
		base.IndirectMailDeduction, base.IncompleteEvidenceDeduction, base.LowVolumeDeduction, base.StaleEvidenceDeduction = 20, 15, 5, 10
		base.ReviewThreshold = 30
		base.SingleReportConfidenceCap, base.SingleReporterConfidenceCap, base.UnenrichedConfidenceCap = 45, 55, 70
		base.MixedPassingConfidenceCap, base.ExpectedSenderConfidenceCap, base.SharedProviderConfidenceCap = 55, 40, 55
		base.IndirectMailConfidenceCap, base.IncompleteEvidenceConfidenceCap, base.LowVolumeConfidenceCap, base.StaleEvidenceConfidenceCap = 45, 50, 50, 55
	case ThreatCandidateProfileSensitive:
		base.DualFailureWeight, base.RepeatedReportsWeight, base.PersistenceWeight = 40, 15, 10
		base.VolumeWeight, base.ReporterDiversityWeight, base.DispositionWeight, base.DomainDiversityWeight = 15, 10, 10, 10
		base.MixedPassingDeduction, base.ExpectedSenderDeduction, base.SharedProviderDeduction = 15, 25, 10
		base.IndirectMailDeduction, base.IncompleteEvidenceDeduction, base.LowVolumeDeduction, base.StaleEvidenceDeduction = 15, 10, 0, 5
		base.ReviewThreshold = 25
		base.SingleReportConfidenceCap, base.SingleReporterConfidenceCap, base.UnenrichedConfidenceCap = 55, 65, 80
		base.MixedPassingConfidenceCap, base.ExpectedSenderConfidenceCap, base.SharedProviderConfidenceCap = 65, 50, 65
		base.IndirectMailConfidenceCap, base.IncompleteEvidenceConfidenceCap, base.LowVolumeConfidenceCap, base.StaleEvidenceConfidenceCap = 55, 60, 60, 65
	default:
		return ThreatCandidateScoringProfile{}
	}
	return base
}

type threatCandidateObservationContext struct {
	entityIDs             map[string]struct{}
	portfolioDomains      map[string]struct{}
	expectedSenderIDs     map[string]struct{}
	providerContextIDs    map[AnalysisID]struct{}
	correlationFindingIDs map[FindingID]struct{}
	unattributedFailure   bool
	sharedProvider        bool
	incomplete            bool
}

type threatCandidateAccumulator struct {
	sourceIP        string
	ipType          ThreatCandidateIPType
	observations    []ReportEvidenceObservation
	contexts        map[EvidenceID]*threatCandidateObservationContext
	allMessages     int64
	passingMessages int64
	unknownMessages int64
	incomplete      bool
}

// ScoreThreatCandidates derives neutral, review-only candidates from completed
// normalized evidence and correlation values. It performs no DNS, report
// parsing, enrichment, filesystem, clock, or other I/O. Observed source
// addresses are inert evidence and must never be contacted by this stage.
func ScoreThreatCandidates(portfolio Portfolio, evidence ReportEvidenceResult, correlation DNSReportCorrelationResult, options ThreatCandidateOptions) (ThreatCandidateResult, error) {
	profile, err := normalizedThreatCandidateProfile(options)
	if err != nil {
		return ThreatCandidateResult{}, err
	}
	evidenceMetadata := evidence.ResultMetadata()
	correlationMetadata := correlation.ResultMetadata()
	if portfolio.Digest() == "" || evidence.Digest() == "" || correlation.Digest() == "" ||
		evidenceMetadata.ContractVersion != AnalysisContractVersion || evidenceMetadata.Mode != AnalysisModeReportEvidence || evidenceMetadata.Evaluation.State != EvaluationStateEvaluated ||
		correlationMetadata.ContractVersion != AnalysisContractVersion || correlationMetadata.Mode != AnalysisModeDNSReportCorrelation || correlationMetadata.Evaluation.State != EvaluationStateEvaluated ||
		correlation.PortfolioDigest() != portfolio.Digest() || correlation.ReportEvidenceDigest() != evidence.Digest() ||
		correlation.OrganizationID() != portfolio.Organization().ID {
		return ThreatCandidateResult{}, ErrInvalidAnalysisResult
	}
	generatedAt := options.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = evidenceMetadata.GeneratedAt
		if correlationMetadata.GeneratedAt.After(generatedAt) {
			generatedAt = correlationMetadata.GeneratedAt
		}
	}
	if generatedAt.Before(evidenceMetadata.GeneratedAt) || generatedAt.Before(correlationMetadata.GeneratedAt) {
		return ThreatCandidateResult{}, ErrInvalidThreatCandidateOptions
	}

	contexts := threatCandidateContexts(correlation)
	bySource := map[string]*threatCandidateAccumulator{}
	for _, observation := range evidence.Observations() {
		if observation.SourceIP.Evaluation.State != EvaluationStateEvaluated {
			continue
		}
		address, parseErr := netip.ParseAddr(observation.SourceIP.Value)
		if parseErr != nil || address.Zone() != "" {
			return ThreatCandidateResult{}, ErrInvalidAnalysisResult
		}
		accumulator := bySource[observation.SourceIP.Value]
		if accumulator == nil {
			ipType := ThreatCandidateIPv6
			if address.Is4() {
				ipType = ThreatCandidateIPv4
			}
			accumulator = &threatCandidateAccumulator{sourceIP: observation.SourceIP.Value, ipType: ipType, contexts: contexts}
			bySource[observation.SourceIP.Value] = accumulator
		}
		accumulator.observations = append(accumulator.observations, observation)
		if !observation.Count.Available {
			accumulator.incomplete = true
			continue
		}
		if accumulator.allMessages, err = checkedThreatCandidateAdd(accumulator.allMessages, observation.Count.Value); err != nil {
			return ThreatCandidateResult{}, err
		}
		switch observation.PolicyOutcome.Combined {
		case ReportAuthenticationPass:
			accumulator.passingMessages, err = checkedThreatCandidateAdd(accumulator.passingMessages, observation.Count.Value)
		case ReportAuthenticationUnknown:
			accumulator.unknownMessages, err = checkedThreatCandidateAdd(accumulator.unknownMessages, observation.Count.Value)
		}
		if err != nil {
			return ThreatCandidateResult{}, err
		}
		if observation.Period.Evaluation.State != EvaluationStateEvaluated || observation.AuthorDomain.Evaluation.State != EvaluationStateEvaluated ||
			observation.Reporter.Evaluation.State != EvaluationStateEvaluated || observation.PolicyOutcome.Combined == ReportAuthenticationUnknown {
			accumulator.incomplete = true
		}
	}

	sources := make([]string, 0, len(bySource))
	for source := range bySource {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		left, _ := netip.ParseAddr(sources[i])
		right, _ := netip.ParseAddr(sources[j])
		return left.Compare(right) < 0
	})

	candidates := make([]ThreatCandidate, 0, len(sources))
	summary := ThreatCandidateSummary{SourcesObserved: len(sources), Severities: []ThreatCandidateSeverityCount{}}
	for _, source := range sources {
		candidate, expectedOnly, omittedMessages, buildErr := buildThreatCandidate(portfolio, bySource[source], profile, generatedAt, options.IncludeExpectedSenders)
		if buildErr != nil {
			return ThreatCandidateResult{}, buildErr
		}
		if omittedMessages > 0 {
			summary.ExpectedSenderMessagesOmitted, err = checkedThreatCandidateAdd(summary.ExpectedSenderMessagesOmitted, omittedMessages)
			if err != nil {
				return ThreatCandidateResult{}, err
			}
		}
		if expectedOnly {
			summary.ExpectedSenderSourcesOmitted++
			continue
		}
		if candidate.ID == "" {
			continue
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		if candidates[i].Confidence != candidates[j].Confidence {
			return candidates[i].Confidence > candidates[j].Confidence
		}
		left, _ := netip.ParseAddr(candidates[i].SourceIP)
		right, _ := netip.ParseAddr(candidates[j].SourceIP)
		return left.Compare(right) < 0
	})
	summary.Candidates = len(candidates)
	severityCounts := map[FindingSeverity]int{}
	for _, candidate := range candidates {
		severityCounts[candidate.Severity]++
		if candidate.ReviewEligible {
			summary.ReviewEligible++
		}
		if candidate.Excluded {
			summary.Excluded++
		}
	}
	for _, severity := range []FindingSeverity{FindingSeverityInfo, FindingSeverityLow, FindingSeverityMedium, FindingSeverityHigh} {
		if count := severityCounts[severity]; count > 0 {
			summary.Severities = append(summary.Severities, ThreatCandidateSeverityCount{Severity: severity, Candidates: count})
		}
	}
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeThreatCandidates, GeneratedAt: generatedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
	canonical, err := json.Marshal(struct {
		Metadata             ResultMetadata                `json:"metadata"`
		Version              string                        `json:"version"`
		OrganizationID       string                        `json:"organization_id"`
		PortfolioDigest      AnalysisID                    `json:"portfolio_digest"`
		ReportEvidenceDigest AnalysisID                    `json:"report_evidence_digest"`
		CorrelationDigest    AnalysisID                    `json:"correlation_digest"`
		Profile              ThreatCandidateScoringProfile `json:"profile"`
		Candidates           []ThreatCandidate             `json:"candidates"`
		Summary              ThreatCandidateSummary        `json:"summary"`
	}{metadata, ThreatCandidateScoringVersion, portfolio.Organization().ID, portfolio.Digest(), evidence.Digest(), correlation.Digest(), profile, candidates, summary})
	if err != nil {
		return ThreatCandidateResult{}, errors.Join(ErrInvalidThreatCandidateOptions, err)
	}
	return ThreatCandidateResult{
		metadata: metadata, version: ThreatCandidateScoringVersion, organizationID: portfolio.Organization().ID,
		portfolioDigest: portfolio.Digest(), reportEvidenceDigest: evidence.Digest(), correlationDigest: correlation.Digest(),
		digest: StableAnalysisID("threat_candidates", string(canonical)), profile: profile,
		candidates: cloneThreatCandidates(candidates), summary: cloneThreatCandidateSummary(summary),
	}, nil
}

func normalizedThreatCandidateProfile(options ThreatCandidateOptions) (ThreatCandidateScoringProfile, error) {
	if options.CustomProfile != nil {
		profile := *options.CustomProfile
		if options.Profile != "" && options.Profile != ThreatCandidateProfileCustom || profile.Name != ThreatCandidateProfileCustom {
			return ThreatCandidateScoringProfile{}, ErrInvalidThreatCandidateOptions
		}
		if err := validateThreatCandidateProfile(profile); err != nil {
			return ThreatCandidateScoringProfile{}, err
		}
		return profile, nil
	}
	if options.Profile == ThreatCandidateProfileCustom {
		return ThreatCandidateScoringProfile{}, ErrInvalidThreatCandidateOptions
	}
	name := options.Profile
	if name == "" {
		name = ThreatCandidateProfileBalanced
	}
	profile, ok := ThreatCandidateScoringProfileForName(name)
	if !ok {
		return ThreatCandidateScoringProfile{}, ErrInvalidThreatCandidateOptions
	}
	return profile, validateThreatCandidateProfile(profile)
}

func validateThreatCandidateProfile(profile ThreatCandidateScoringProfile) error {
	if profile.Version != ThreatCandidateScoringVersion || profile.Name == "" || profile.VolumeThreshold <= 0 || profile.LowVolumeThreshold <= 0 ||
		profile.LowVolumeThreshold > profile.VolumeThreshold || profile.PersistenceThreshold < 0 || profile.StaleAfter < 0 ||
		profile.ReviewThreshold < 0 || profile.ReviewThreshold > 100 || profile.LowSeverityThreshold < 0 ||
		profile.LowSeverityThreshold > profile.MediumSeverityThreshold || profile.MediumSeverityThreshold > profile.HighSeverityThreshold || profile.HighSeverityThreshold > 100 {
		return ErrInvalidThreatCandidateOptions
	}
	weights := []int{
		profile.DualFailureWeight, profile.RepeatedReportsWeight, profile.PersistenceWeight, profile.VolumeWeight,
		profile.ReporterDiversityWeight, profile.DispositionWeight, profile.DomainDiversityWeight,
		profile.MixedPassingDeduction, profile.ExpectedSenderDeduction, profile.SharedProviderDeduction,
		profile.IndirectMailDeduction, profile.IncompleteEvidenceDeduction, profile.LowVolumeDeduction, profile.StaleEvidenceDeduction,
		profile.SingleReportConfidenceCap, profile.SingleReporterConfidenceCap, profile.UnenrichedConfidenceCap,
		profile.MixedPassingConfidenceCap, profile.ExpectedSenderConfidenceCap, profile.SharedProviderConfidenceCap,
		profile.IndirectMailConfidenceCap, profile.IncompleteEvidenceConfidenceCap, profile.LowVolumeConfidenceCap, profile.StaleEvidenceConfidenceCap,
	}
	for _, value := range weights {
		if value < 0 || value > 100 {
			return ErrInvalidThreatCandidateOptions
		}
	}
	return nil
}

func threatCandidateContexts(correlation DNSReportCorrelationResult) map[EvidenceID]*threatCandidateObservationContext {
	contexts := map[EvidenceID]*threatCandidateObservationContext{}
	get := func(id EvidenceID) *threatCandidateObservationContext {
		context := contexts[id]
		if context == nil {
			context = &threatCandidateObservationContext{
				entityIDs: map[string]struct{}{}, portfolioDomains: map[string]struct{}{}, expectedSenderIDs: map[string]struct{}{},
				providerContextIDs: map[AnalysisID]struct{}{}, correlationFindingIDs: map[FindingID]struct{}{},
			}
			contexts[id] = context
		}
		return context
	}
	for _, stream := range correlation.Streams() {
		for _, observationID := range stream.ObservationIDs {
			context := get(observationID)
			if stream.EntityID != "" {
				context.entityIDs[stream.EntityID] = struct{}{}
			}
			if stream.Domain != "" {
				context.portfolioDomains[stream.Domain] = struct{}{}
			}
			for _, id := range stream.ExpectedSenderIDs {
				context.expectedSenderIDs[id] = struct{}{}
			}
			for _, id := range stream.ProviderContextIDs {
				context.providerContextIDs[id] = struct{}{}
			}
			if stream.Combined.Fail > 0 && len(stream.ExpectedSenderIDs) == 0 {
				context.unattributedFailure = true
			}
			context.sharedProvider = context.sharedProvider || stream.SharedProviderContext
			context.incomplete = context.incomplete || stream.ThresholdEvaluation.State != EvaluationStateEvaluated
		}
	}
	for _, finding := range correlation.Findings() {
		for _, observationID := range finding.ObservationIDs {
			get(observationID).correlationFindingIDs[finding.ID] = struct{}{}
		}
	}
	return contexts
}

func threatCandidateExpectedSenderOnly(context *threatCandidateObservationContext) bool {
	return context != nil && len(context.expectedSenderIDs) > 0 && !context.unattributedFailure
}

func buildThreatCandidate(portfolio Portfolio, accumulator *threatCandidateAccumulator, profile ThreatCandidateScoringProfile, generatedAt time.Time, includeExpected bool) (ThreatCandidate, bool, int64, error) {
	failureObservations := make([]ReportEvidenceObservation, 0)
	allFailureObservations := make([]ReportEvidenceObservation, 0)
	expectedFailureMessages := int64(0)
	allFailureMessages := int64(0)
	for _, observation := range accumulator.observations {
		if !observation.Count.Available || observation.PolicyOutcome.DKIM != ReportAuthenticationFail || observation.PolicyOutcome.SPF != ReportAuthenticationFail {
			continue
		}
		var err error
		allFailureMessages, err = checkedThreatCandidateAdd(allFailureMessages, observation.Count.Value)
		if err != nil {
			return ThreatCandidate{}, false, 0, err
		}
		allFailureObservations = append(allFailureObservations, observation)
		context := accumulator.contexts[observation.ID]
		expectedOnly := threatCandidateExpectedSenderOnly(context)
		if expectedOnly {
			expectedFailureMessages, err = checkedThreatCandidateAdd(expectedFailureMessages, observation.Count.Value)
			if err != nil {
				return ThreatCandidate{}, false, 0, err
			}
		}
		if includeExpected || !expectedOnly {
			failureObservations = append(failureObservations, observation)
		}
	}
	if len(allFailureObservations) == 0 {
		return ThreatCandidate{}, false, 0, nil
	}
	if len(failureObservations) == 0 {
		return ThreatCandidate{}, true, allFailureMessages, nil
	}

	candidate := ThreatCandidate{
		ID: StableAnalysisID("threat_candidate", portfolio.Organization().ID, accumulator.sourceIP), SourceIP: accumulator.sourceIP,
		IPType: accumulator.ipType, ScoringVersion: ThreatCandidateScoringVersion, Profile: profile.Name,
		Evaluation: Evaluation{State: EvaluationStateEvaluated}, Messages: accumulator.allMessages,
		ExpectedSenderFailureMessages: expectedFailureMessages, PassingMessages: accumulator.passingMessages, UnknownMessages: accumulator.unknownMessages,
		Enrichment:        Evaluation{State: EvaluationStateNotEvaluated, Reason: "Source enrichment was not supplied to this stage."},
		PromotionEligible: false, Sensitivity: SensitivityRestricted,
	}
	reports, reporters, domains, entityIDs := map[EvidenceID]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	expectedSenderIDs, providerContextIDs := map[string]struct{}{}, map[AnalysisID]struct{}{}
	observationIDs, failedObservationIDs, passingObservationIDs := map[EvidenceID]struct{}{}, map[EvidenceID]struct{}{}, map[EvidenceID]struct{}{}
	expectedObservationIDs, sharedProviderObservationIDs := map[EvidenceID]struct{}{}, map[EvidenceID]struct{}{}
	indirectObservationIDs, incompleteObservationIDs := map[EvidenceID]struct{}{}, map[EvidenceID]struct{}{}
	correlationFindingIDs := map[FindingID]struct{}{}
	reportEvidenceIDs := map[EvidenceID]struct{}{}
	dispositions := map[string]int64{}
	overrideTypes := map[string]struct{}{}
	sharedProvider := false
	incomplete := accumulator.incomplete
	for _, observation := range accumulator.observations {
		observationIDs[observation.ID] = struct{}{}
		reportEvidenceIDs[observation.ReportEvidenceID] = struct{}{}
		if observation.Count.Available && observation.PolicyOutcome.Combined == ReportAuthenticationPass {
			passingObservationIDs[observation.ID] = struct{}{}
		}
		observationIncomplete := !observation.Count.Available || observation.Period.Evaluation.State != EvaluationStateEvaluated ||
			observation.AuthorDomain.Evaluation.State != EvaluationStateEvaluated || observation.Reporter.Evaluation.State != EvaluationStateEvaluated ||
			observation.PolicyOutcome.Combined == ReportAuthenticationUnknown
		context := accumulator.contexts[observation.ID]
		if context == nil {
			observationIncomplete = true
		} else {
			for value := range context.providerContextIDs {
				providerContextIDs[value] = struct{}{}
			}
			for value := range context.correlationFindingIDs {
				correlationFindingIDs[value] = struct{}{}
			}
			if context.sharedProvider {
				sharedProvider = true
				sharedProviderObservationIDs[observation.ID] = struct{}{}
			}
			observationIncomplete = observationIncomplete || context.incomplete
			if observation.PolicyOutcome.DKIM == ReportAuthenticationFail && observation.PolicyOutcome.SPF == ReportAuthenticationFail && len(context.expectedSenderIDs) > 0 {
				expectedObservationIDs[observation.ID] = struct{}{}
				for value := range context.expectedSenderIDs {
					expectedSenderIDs[value] = struct{}{}
				}
			}
		}
		if observationIncomplete {
			incomplete = true
			incompleteObservationIDs[observation.ID] = struct{}{}
		}
	}
	for _, observation := range failureObservations {
		var err error
		candidate.DualFailureMessages, err = checkedThreatCandidateAdd(candidate.DualFailureMessages, observation.Count.Value)
		if err != nil {
			return ThreatCandidate{}, false, 0, err
		}
		reports[observation.ReportEvidenceID] = struct{}{}
		failedObservationIDs[observation.ID] = struct{}{}
		if observation.Reporter.Value != "" {
			reporters[observation.Reporter.Value] = struct{}{}
		}
		if observation.AuthorDomain.Value != "" {
			domains[observation.AuthorDomain.Value] = struct{}{}
		}
		if observation.Disposition != "" {
			dispositions[observation.Disposition], err = checkedThreatCandidateAdd(dispositions[observation.Disposition], observation.Count.Value)
			if err != nil {
				return ThreatCandidate{}, false, 0, err
			}
		}
		for _, value := range observation.PolicyOverrideTypes {
			overrideTypes[value] = struct{}{}
			if value == "mailing_list" || value == "trusted_forwarder" {
				indirectObservationIDs[observation.ID] = struct{}{}
			}
		}
		if observation.Period.Evaluation.State == EvaluationStateEvaluated {
			if !candidate.FirstSeen.Available || observation.Period.Begin.Value.Before(candidate.FirstSeen.Value) {
				candidate.FirstSeen = observation.Period.Begin
			}
			if !candidate.LastSeen.Available || observation.Period.End.Value.After(candidate.LastSeen.Value) {
				candidate.LastSeen = observation.Period.End
			}
		} else {
			incomplete = true
		}
		context := accumulator.contexts[observation.ID]
		if context == nil {
			incomplete = true
			continue
		}
		for value := range context.entityIDs {
			entityIDs[value] = struct{}{}
		}
		incomplete = incomplete || context.incomplete
	}
	candidate.Reports, candidate.ReporterDiversity = len(reports), len(reporters)
	candidate.Domains, candidate.EntityIDs = sortedStringSet(domains), sortedStringSet(entityIDs)
	candidate.ExpectedSenderIDs = sortedStringSet(expectedSenderIDs)
	candidate.ProviderContextIDs = sortedAnalysisIDSet(providerContextIDs)
	candidate.ObservationIDs, candidate.ReportEvidenceIDs = sortedEvidenceIDSet(observationIDs), sortedEvidenceIDSet(reportEvidenceIDs)
	candidate.CorrelationFindingIDs = sortedFindingIDSet(correlationFindingIDs)
	candidate.PolicyOverrideTypes = sortedStringSet(overrideTypes)
	candidate.SharedProviderContext, candidate.IncompleteEvidence = sharedProvider, incomplete
	for _, disposition := range sortedMapKeys(dispositions) {
		candidate.Dispositions = append(candidate.Dispositions, ReportEvidenceDispositionCount{Disposition: disposition, Messages: dispositions[disposition]})
	}
	candidate.StaleEvidence = candidate.LastSeen.Available && profile.StaleAfter > 0 && generatedAt.Sub(candidate.LastSeen.Value) > profile.StaleAfter
	indirect := containsString(candidate.PolicyOverrideTypes, "mailing_list") || containsString(candidate.PolicyOverrideTypes, "trusted_forwarder")
	rejectedOrQuarantined := dispositions["reject"] > 0 || dispositions["quarantine"] > 0
	// A single report window does not prove that messages occurred throughout
	// that window, so persistence requires observations from multiple reports.
	persistent := candidate.Reports > 1 && candidate.FirstSeen.Available && candidate.LastSeen.Available && profile.PersistenceThreshold > 0 && candidate.LastSeen.Value.Sub(candidate.FirstSeen.Value) >= profile.PersistenceThreshold
	lowVolume := candidate.DualFailureMessages < profile.LowVolumeThreshold

	addScore := func(code FindingCode, kind ThreatCandidateAdjustmentKind, points int, message string, ids []EvidenceID) {
		if points == 0 {
			return
		}
		if kind == ThreatCandidateDeduction {
			points = -points
		}
		before := candidate.Score
		candidate.Score = clampThreatCandidateScore(candidate.Score + points)
		candidate.ScoreAdjustments = append(candidate.ScoreAdjustments, ThreatCandidateScoreAdjustment{
			Code: code, Kind: kind, Points: points, Before: before, After: candidate.Score, Message: message, EvidenceIDs: append([]EvidenceID{}, ids...),
		})
	}
	failedIDs := sortedEvidenceIDSet(failedObservationIDs)
	passingIDs := sortedEvidenceIDSet(passingObservationIDs)
	expectedIDs := sortedEvidenceIDSet(expectedObservationIDs)
	sharedProviderIDs := sortedEvidenceIDSet(sharedProviderObservationIDs)
	indirectIDs := sortedEvidenceIDSet(indirectObservationIDs)
	incompleteIDs := sortedEvidenceIDSet(incompleteObservationIDs)
	addScore("threat_candidate.aligned_dual_failure", ThreatCandidateSupport, profile.DualFailureWeight, "Policy-evaluated DKIM and SPF both failed.", failedIDs)
	if candidate.Reports > 1 {
		addScore("threat_candidate.repeated_reports", ThreatCandidateSupport, profile.RepeatedReportsWeight, "Aligned dual failures were observed in multiple reports.", failedIDs)
	}
	if persistent {
		addScore("threat_candidate.persistent_failure", ThreatCandidateSupport, profile.PersistenceWeight, "Aligned dual failures persisted across the configured observation duration.", failedIDs)
	}
	if candidate.DualFailureMessages >= profile.VolumeThreshold {
		addScore("threat_candidate.failure_volume", ThreatCandidateSupport, profile.VolumeWeight, "Aligned dual-failure volume reached the configured threshold.", failedIDs)
	}
	if candidate.ReporterDiversity > 1 {
		addScore("threat_candidate.reporter_diversity", ThreatCandidateSupport, profile.ReporterDiversityWeight, "Aligned dual failures were observed by multiple reporters.", failedIDs)
	}
	if rejectedOrQuarantined {
		addScore("threat_candidate.enforcing_disposition", ThreatCandidateSupport, profile.DispositionWeight, "Receivers reported reject or quarantine dispositions for aligned dual failures.", failedIDs)
	}
	if len(candidate.Domains) > 1 {
		addScore("threat_candidate.domain_diversity", ThreatCandidateSupport, profile.DomainDiversityWeight, "The same source produced aligned dual failures for multiple author domains.", failedIDs)
	}
	if candidate.PassingMessages > 0 {
		addScore("threat_candidate.mixed_passing", ThreatCandidateDeduction, profile.MixedPassingDeduction, "The source also produced DMARC-passing traffic.", passingIDs)
	}
	if includeExpected && candidate.ExpectedSenderFailureMessages > 0 {
		addScore("threat_candidate.expected_sender", ThreatCandidateDeduction, profile.ExpectedSenderDeduction, "Some aligned dual failures were attributed to declared expected senders.", expectedIDs)
	}
	if candidate.SharedProviderContext {
		addScore("threat_candidate.shared_provider", ThreatCandidateDeduction, profile.SharedProviderDeduction, "Prepared correlation identified shared-provider context.", sharedProviderIDs)
	}
	if indirect {
		addScore("threat_candidate.indirect_mail", ThreatCandidateDeduction, profile.IndirectMailDeduction, "Reporter-supplied policy overrides indicate forwarding or mailing-list handling.", indirectIDs)
	}
	if candidate.IncompleteEvidence {
		addScore("threat_candidate.incomplete_evidence", ThreatCandidateDeduction, profile.IncompleteEvidenceDeduction, "Some source evidence was incomplete or below prepared correlation thresholds.", incompleteIDs)
	}
	if lowVolume {
		addScore("threat_candidate.low_volume", ThreatCandidateDeduction, profile.LowVolumeDeduction, "Aligned dual-failure volume remained below the configured low-volume threshold.", failedIDs)
	}
	if candidate.StaleEvidence {
		addScore("threat_candidate.stale_evidence", ThreatCandidateDeduction, profile.StaleEvidenceDeduction, "The latest report period is older than the configured evidence-age threshold.", failedIDs)
	}

	candidate.Confidence = 100
	applyCap := func(code FindingCode, maximum int, message string, ids []EvidenceID) {
		before := candidate.Confidence
		if maximum < candidate.Confidence {
			candidate.Confidence = maximum
		}
		candidate.ConfidenceAdjustments = append(candidate.ConfidenceAdjustments, ThreatCandidateConfidenceAdjustment{
			Code: code, Maximum: maximum, Before: before, After: candidate.Confidence, Message: message, EvidenceIDs: append([]EvidenceID{}, ids...),
		})
	}
	applyCap("threat_candidate.unenriched", profile.UnenrichedConfidenceCap, "No caller-supplied source enrichment was evaluated.", failedIDs)
	if candidate.Reports == 1 {
		applyCap("threat_candidate.single_report", profile.SingleReportConfidenceCap, "Aligned dual failures were observed in only one report.", failedIDs)
	}
	if candidate.ReporterDiversity <= 1 {
		applyCap("threat_candidate.single_reporter", profile.SingleReporterConfidenceCap, "Aligned dual failures were observed by at most one reporter.", failedIDs)
	}
	if candidate.PassingMessages > 0 {
		applyCap("threat_candidate.mixed_passing", profile.MixedPassingConfidenceCap, "The source also produced DMARC-passing traffic.", passingIDs)
	}
	if includeExpected && candidate.ExpectedSenderFailureMessages > 0 {
		applyCap("threat_candidate.expected_sender", profile.ExpectedSenderConfidenceCap, "Some aligned dual failures were attributed to declared expected senders.", expectedIDs)
	}
	if candidate.SharedProviderContext {
		applyCap("threat_candidate.shared_provider", profile.SharedProviderConfidenceCap, "Prepared correlation identified shared-provider context.", sharedProviderIDs)
	}
	if indirect {
		applyCap("threat_candidate.indirect_mail", profile.IndirectMailConfidenceCap, "Reporter-supplied policy overrides indicate forwarding or mailing-list handling.", indirectIDs)
	}
	if candidate.IncompleteEvidence {
		applyCap("threat_candidate.incomplete_evidence", profile.IncompleteEvidenceConfidenceCap, "Some source evidence was incomplete or below prepared correlation thresholds.", incompleteIDs)
	}
	if lowVolume {
		applyCap("threat_candidate.low_volume", profile.LowVolumeConfidenceCap, "Aligned dual-failure volume remained below the configured low-volume threshold.", failedIDs)
	}
	if candidate.StaleEvidence {
		applyCap("threat_candidate.stale_evidence", profile.StaleEvidenceConfidenceCap, "The latest report period is older than the configured evidence-age threshold.", failedIDs)
	}
	candidate.ConfidenceLevel = threatCandidateConfidence(candidate.Confidence)
	candidate.Severity = threatCandidateSeverity(min(candidate.Score, candidate.Confidence), profile)
	candidate.ExclusionsConsidered, candidate.Excluded = threatCandidateExclusions(portfolio, candidate, accumulator.contexts, failureObservations, generatedAt)
	candidate.ReviewEligible = candidate.Score >= profile.ReviewThreshold && !candidate.Excluded
	switch {
	case candidate.Excluded:
		candidate.RecommendedUsage = ThreatCandidateUsageRetainEvidence
	case candidate.ReviewEligible:
		candidate.RecommendedUsage = ThreatCandidateUsageReviewOnly
	default:
		candidate.RecommendedUsage = ThreatCandidateUsageMonitorOnly
	}
	omittedMessages := int64(0)
	if !includeExpected {
		omittedMessages = expectedFailureMessages
	}
	return candidate, false, omittedMessages, nil
}

func threatCandidateExclusions(portfolio Portfolio, candidate ThreatCandidate, contexts map[EvidenceID]*threatCandidateObservationContext, observations []ReportEvidenceObservation, generatedAt time.Time) ([]ThreatCandidateExclusion, bool) {
	type scopeKey struct{ entity, domain string }
	scopes := map[scopeKey]MonitoredDomain{}
	for _, entity := range portfolio.Entities() {
		for _, domain := range entity.Domains {
			scopes[scopeKey{entity.ID, domain.Name}] = domain
		}
	}
	relevantScopes := map[scopeKey]map[string]struct{}{}
	scopeObservations := map[scopeKey]map[string]map[EvidenceID]struct{}{}
	scopeSenders := map[scopeKey]map[string]map[string]map[EvidenceID]struct{}{}
	for _, observation := range observations {
		context := contexts[observation.ID]
		if context == nil || observation.AuthorDomain.Value == "" {
			continue
		}
		for entity := range context.entityIDs {
			for domain := range context.portfolioDomains {
				key := scopeKey{entity, domain}
				if _, ok := scopes[key]; ok {
					if relevantScopes[key] == nil {
						relevantScopes[key] = map[string]struct{}{}
					}
					relevantScopes[key][observation.AuthorDomain.Value] = struct{}{}
					if scopeObservations[key] == nil {
						scopeObservations[key] = map[string]map[EvidenceID]struct{}{}
					}
					if scopeObservations[key][observation.AuthorDomain.Value] == nil {
						scopeObservations[key][observation.AuthorDomain.Value] = map[EvidenceID]struct{}{}
					}
					scopeObservations[key][observation.AuthorDomain.Value][observation.ID] = struct{}{}
					if !threatCandidateExpectedSenderOnly(context) {
						continue
					}
					if scopeSenders[key] == nil {
						scopeSenders[key] = map[string]map[string]map[EvidenceID]struct{}{}
					}
					for senderID := range context.expectedSenderIDs {
						if scopeSenders[key][senderID] == nil {
							scopeSenders[key][senderID] = map[string]map[EvidenceID]struct{}{}
						}
						if scopeSenders[key][senderID][observation.AuthorDomain.Value] == nil {
							scopeSenders[key][senderID][observation.AuthorDomain.Value] = map[EvidenceID]struct{}{}
						}
						scopeSenders[key][senderID][observation.AuthorDomain.Value][observation.ID] = struct{}{}
					}
				}
			}
		}
	}
	keys := make([]scopeKey, 0, len(relevantScopes))
	for key := range relevantScopes {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].entity != keys[j].entity {
			return keys[i].entity < keys[j].entity
		}
		return keys[i].domain < keys[j].domain
	})
	values := make([]ThreatCandidateExclusion, 0)
	coveredDomains := map[string]struct{}{}
	for _, key := range keys {
		domain := scopes[key]
		scopedCandidateDomains := relevantScopes[key]
		for _, exclusion := range domain.Exclusions {
			value := ThreatCandidateExclusion{
				ID: exclusion.ID, Owner: exclusion.Owner, Reason: exclusion.Reason, Scope: exclusion.Scope, Target: exclusion.Target,
				EntityID: key.entity, PortfolioDomain: key.domain, CreatedAt: exclusion.CreatedAt, ExpiresAt: cloneTimePointer(exclusion.ExpiresAt),
			}
			value.Expired = value.ExpiresAt != nil && !value.ExpiresAt.After(generatedAt)
			value.Active = !value.CreatedAt.After(generatedAt) && !value.Expired
			switch exclusion.Scope {
			case ExclusionScopeDomain:
				for candidateDomain := range scopedCandidateDomains {
					if candidateDomain == key.domain {
						value.Matched = true
						if value.Active {
							coveredDomains[candidateDomain] = struct{}{}
						}
					}
				}
			case ExclusionScopeSubdomains:
				for candidateDomain := range scopedCandidateDomains {
					if candidateDomain == key.domain || strings.HasSuffix(candidateDomain, "."+key.domain) {
						value.Matched = true
						if value.Active {
							coveredDomains[candidateDomain] = struct{}{}
						}
					}
				}
			case ExclusionScopeSender:
				matchedDomains := map[string]struct{}{}
				for candidateDomain, senderObservations := range scopeSenders[key][exclusion.Target] {
					if len(senderObservations) > 0 && len(senderObservations) == len(scopeObservations[key][candidateDomain]) {
						matchedDomains[candidateDomain] = struct{}{}
					}
				}
				value.Matched = len(matchedDomains) > 0
				if value.Active {
					for candidateDomain := range matchedDomains {
						coveredDomains[candidateDomain] = struct{}{}
					}
				}
			case ExclusionScopeSource:
				value.Matched = sourceExclusionMatches(exclusion.Target, candidate.SourceIP)
				if value.Matched && value.Active {
					for candidateDomain := range scopedCandidateDomains {
						coveredDomains[candidateDomain] = struct{}{}
					}
				}
			}
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].EntityID != values[j].EntityID {
			return values[i].EntityID < values[j].EntityID
		}
		if values[i].PortfolioDomain != values[j].PortfolioDomain {
			return values[i].PortfolioDomain < values[j].PortfolioDomain
		}
		return values[i].ID < values[j].ID
	})
	fullyDomainExcluded := len(candidate.Domains) > 0 && len(coveredDomains) == len(candidate.Domains)
	return values, fullyDomainExcluded
}

func sourceExclusionMatches(target, source string) bool {
	address, err := netip.ParseAddr(source)
	if err != nil {
		return false
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Contains(address)
	}
	targetAddress, err := netip.ParseAddr(target)
	return err == nil && targetAddress == address
}

// RecomputeThreatCandidateScore validates and recomputes an explained score.
func RecomputeThreatCandidateScore(candidate ThreatCandidate) (int, error) {
	value := 0
	for _, adjustment := range candidate.ScoreAdjustments {
		validSupport := adjustment.Kind == ThreatCandidateSupport && adjustment.Points > 0 && adjustment.Points <= 100
		validDeduction := adjustment.Kind == ThreatCandidateDeduction && adjustment.Points < 0 && adjustment.Points >= -100
		if adjustment.Before != value || adjustment.Before < 0 || adjustment.Before > 100 || !validSupport && !validDeduction {
			return 0, ErrInvalidAnalysisResult
		}
		value = clampThreatCandidateScore(value + adjustment.Points)
		if adjustment.After != value {
			return 0, ErrInvalidAnalysisResult
		}
	}
	if value != candidate.Score {
		return 0, ErrInvalidAnalysisResult
	}
	return value, nil
}

// RecomputeThreatCandidateConfidence validates and recomputes explained caps.
func RecomputeThreatCandidateConfidence(candidate ThreatCandidate) (int, error) {
	value := 100
	for _, adjustment := range candidate.ConfidenceAdjustments {
		if adjustment.Before != value || adjustment.Maximum < 0 || adjustment.Maximum > 100 {
			return 0, ErrInvalidAnalysisResult
		}
		if adjustment.Maximum < value {
			value = adjustment.Maximum
		}
		if adjustment.After != value {
			return 0, ErrInvalidAnalysisResult
		}
	}
	if value != candidate.Confidence {
		return 0, ErrInvalidAnalysisResult
	}
	return value, nil
}

func checkedThreatCandidateAdd(left, right int64) (int64, error) {
	if right < 0 || left > math.MaxInt64-right {
		return 0, ErrThreatCandidateOverflow
	}
	return left + right, nil
}

func clampThreatCandidateScore(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func threatCandidateConfidence(value int) FindingConfidence {
	switch {
	case value >= 80:
		return FindingConfidenceHigh
	case value >= 50:
		return FindingConfidenceMedium
	default:
		return FindingConfidenceLow
	}
}

func threatCandidateSeverity(value int, profile ThreatCandidateScoringProfile) FindingSeverity {
	switch {
	case value >= profile.HighSeverityThreshold:
		return FindingSeverityHigh
	case value >= profile.MediumSeverityThreshold:
		return FindingSeverityMedium
	case value >= profile.LowSeverityThreshold:
		return FindingSeverityLow
	default:
		return FindingSeverityInfo
	}
}

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedAnalysisIDSet(values map[AnalysisID]struct{}) []AnalysisID {
	result := make([]AnalysisID, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func sortedFindingIDSet(values map[FindingID]struct{}) []FindingID {
	result := make([]FindingID, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneThreatCandidates(values []ThreatCandidate) []ThreatCandidate {
	result := make([]ThreatCandidate, len(values))
	for index, value := range values {
		value.Domains = cloneStrings(value.Domains)
		value.EntityIDs = cloneStrings(value.EntityIDs)
		value.Dispositions = append([]ReportEvidenceDispositionCount{}, value.Dispositions...)
		value.PolicyOverrideTypes = cloneStrings(value.PolicyOverrideTypes)
		value.ExpectedSenderIDs = cloneStrings(value.ExpectedSenderIDs)
		value.ProviderContextIDs = append([]AnalysisID{}, value.ProviderContextIDs...)
		value.ObservationIDs = append([]EvidenceID{}, value.ObservationIDs...)
		value.ReportEvidenceIDs = append([]EvidenceID{}, value.ReportEvidenceIDs...)
		value.CorrelationFindingIDs = append([]FindingID{}, value.CorrelationFindingIDs...)
		value.ScoreAdjustments = append([]ThreatCandidateScoreAdjustment{}, value.ScoreAdjustments...)
		for adjustmentIndex := range value.ScoreAdjustments {
			value.ScoreAdjustments[adjustmentIndex].EvidenceIDs = append([]EvidenceID{}, value.ScoreAdjustments[adjustmentIndex].EvidenceIDs...)
		}
		value.ConfidenceAdjustments = append([]ThreatCandidateConfidenceAdjustment{}, value.ConfidenceAdjustments...)
		for adjustmentIndex := range value.ConfidenceAdjustments {
			value.ConfidenceAdjustments[adjustmentIndex].EvidenceIDs = append([]EvidenceID{}, value.ConfidenceAdjustments[adjustmentIndex].EvidenceIDs...)
		}
		value.ExclusionsConsidered = append([]ThreatCandidateExclusion{}, value.ExclusionsConsidered...)
		for exclusionIndex := range value.ExclusionsConsidered {
			value.ExclusionsConsidered[exclusionIndex].ExpiresAt = cloneTimePointer(value.ExclusionsConsidered[exclusionIndex].ExpiresAt)
		}
		result[index] = value
	}
	return result
}

func cloneThreatCandidateSummary(value ThreatCandidateSummary) ThreatCandidateSummary {
	value.Severities = append([]ThreatCandidateSeverityCount{}, value.Severities...)
	return value
}
