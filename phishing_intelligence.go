package dmarcgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// PhishingIntelligenceVersion identifies the normalized snapshot and
	// correlation contract. It is independent of the Go module and output
	// schema versions.
	PhishingIntelligenceVersion = "1"

	maxPhishingIntelligenceSnapshots    = 32
	maxPhishingIntelligenceIndicators   = 100_000
	maxPhishingIntelligenceTotalItems   = 250_000
	maxPhishingIntelligenceContextItems = 1_024
	maxPhishingIntelligenceMatches      = 250_000
	maxPhishingIntelligenceTextBytes    = 4096
	maxPhishingIntelligenceTotalBytes   = 32 * 1024 * 1024
	defaultPhishingIntelligenceMatches  = 100_000
)

var (
	// ErrInvalidPhishingIntelligenceSnapshot identifies unsafe, unsupported,
	// or internally inconsistent caller-supplied intelligence.
	ErrInvalidPhishingIntelligenceSnapshot = errors.New("invalid phishing-intelligence snapshot")
	// ErrInvalidPhishingIntelligenceOptions identifies invalid result timing,
	// freshness, or match limits.
	ErrInvalidPhishingIntelligenceOptions = errors.New("invalid phishing-intelligence options")
)

// PhishingIntelligenceIndicatorType is a canonical identifier that this
// release can compare with completed DMARC evidence.
type PhishingIntelligenceIndicatorType string

const (
	PhishingIntelligenceSourceIP PhishingIntelligenceIndicatorType = "source_ip"
	PhishingIntelligenceDomain   PhishingIntelligenceIndicatorType = "domain"
)

// PhishingIntelligenceIndicatorState preserves the caller's provider state.
// Unknown is not interpreted as active.
type PhishingIntelligenceIndicatorState string

const (
	PhishingIntelligenceIndicatorActive    PhishingIntelligenceIndicatorState = "active"
	PhishingIntelligenceIndicatorWithdrawn PhishingIntelligenceIndicatorState = "withdrawn"
	PhishingIntelligenceIndicatorUnknown   PhishingIntelligenceIndicatorState = "unknown"
)

// PhishingIntelligenceUsagePolicy records caller-reviewed license handling.
// The library preserves the value but does not interpret legal permission.
type PhishingIntelligenceUsagePolicy string

const (
	PhishingIntelligenceUsageUnknown    PhishingIntelligenceUsagePolicy = "unknown"
	PhishingIntelligenceUsagePermitted  PhishingIntelligenceUsagePolicy = "permitted"
	PhishingIntelligenceUsageRestricted PhishingIntelligenceUsagePolicy = "restricted"
	PhishingIntelligenceUsageProhibited PhishingIntelligenceUsagePolicy = "prohibited"
)

// PhishingIntelligenceLicense preserves caller-reviewed terms metadata.
// Name and TermsURI are untrusted structured data, not legal advice.
type PhishingIntelligenceLicense struct {
	Name           string                          `json:"name"`
	TermsURI       string                          `json:"terms_uri,omitempty"`
	CommercialUse  PhishingIntelligenceUsagePolicy `json:"commercial_use"`
	Redistribution PhishingIntelligenceUsagePolicy `json:"redistribution"`
	Sensitivity    Sensitivity                     `json:"sensitivity"`
}

// PhishingIntelligenceConfidence preserves an optional provider confidence.
// It never changes candidate score, confidence, severity, or eligibility.
type PhishingIntelligenceConfidence struct {
	Available bool `json:"available"`
	Value     int  `json:"value,omitempty"`
}

// PhishingIntelligenceContext is non-matching provider context. None of these
// values can create or strengthen a match.
type PhishingIntelligenceContext struct {
	ASNs                    []uint32    `json:"asns"`
	CountryCodes            []string    `json:"country_codes"`
	InfrastructureProviders []string    `json:"infrastructure_providers"`
	Brands                  []string    `json:"brands"`
	Sectors                 []string    `json:"sectors"`
	Sensitivity             Sensitivity `json:"sensitivity"`
}

// PhishingIntelligenceIndicatorConfig is mutable snapshot input.
type PhishingIntelligenceIndicatorConfig struct {
	Type               PhishingIntelligenceIndicatorType  `json:"type"`
	Value              string                             `json:"value"`
	State              PhishingIntelligenceIndicatorState `json:"state"`
	FirstSeen          *time.Time                         `json:"first_seen,omitempty"`
	LastSeen           *time.Time                         `json:"last_seen,omitempty"`
	ExpiresAt          *time.Time                         `json:"expires_at,omitempty"`
	ProviderConfidence PhishingIntelligenceConfidence     `json:"provider_confidence"`
	Category           string                             `json:"category,omitempty"`
	ReferenceID        string                             `json:"reference_id,omitempty"`
	Context            PhishingIntelligenceContext        `json:"context"`
}

// PhishingIntelligenceSnapshotConfig is mutable, caller-owned intelligence.
// dmarcgo does not download, discover, refresh, or persist it.
type PhishingIntelligenceSnapshotConfig struct {
	Provider      string                                `json:"provider"`
	Dataset       string                                `json:"dataset"`
	SchemaVersion string                                `json:"schema_version"`
	CollectedAt   time.Time                             `json:"collected_at"`
	AsOf          time.Time                             `json:"as_of"`
	ExpiresAt     *time.Time                            `json:"expires_at,omitempty"`
	License       PhishingIntelligenceLicense           `json:"license"`
	Indicators    []PhishingIntelligenceIndicatorConfig `json:"indicators"`
}

// PhishingIntelligenceIndicator is one immutable, canonical provider record.
type PhishingIntelligenceIndicator struct {
	ID                 AnalysisID                         `json:"id"`
	Type               PhishingIntelligenceIndicatorType  `json:"type"`
	Value              string                             `json:"value"`
	State              PhishingIntelligenceIndicatorState `json:"state"`
	FirstSeen          *time.Time                         `json:"first_seen,omitempty"`
	LastSeen           *time.Time                         `json:"last_seen,omitempty"`
	ExpiresAt          *time.Time                         `json:"expires_at,omitempty"`
	ProviderConfidence PhishingIntelligenceConfidence     `json:"provider_confidence"`
	Category           string                             `json:"category,omitempty"`
	ReferenceID        string                             `json:"reference_id,omitempty"`
	Context            PhishingIntelligenceContext        `json:"context"`
	Sensitivity        Sensitivity                        `json:"sensitivity"`
}

// PhishingIntelligenceSnapshot is an immutable, normalized offline snapshot.
type PhishingIntelligenceSnapshot struct {
	id            AnalysisID
	digest        AnalysisID
	version       string
	provider      string
	dataset       string
	schemaVersion string
	collectedAt   time.Time
	asOf          time.Time
	expiresAt     *time.Time
	license       PhishingIntelligenceLicense
	indicators    []PhishingIntelligenceIndicator
}

func (snapshot PhishingIntelligenceSnapshot) ID() AnalysisID         { return snapshot.id }
func (snapshot PhishingIntelligenceSnapshot) Digest() AnalysisID     { return snapshot.digest }
func (snapshot PhishingIntelligenceSnapshot) Version() string        { return snapshot.version }
func (snapshot PhishingIntelligenceSnapshot) Provider() string       { return snapshot.provider }
func (snapshot PhishingIntelligenceSnapshot) Dataset() string        { return snapshot.dataset }
func (snapshot PhishingIntelligenceSnapshot) SchemaVersion() string  { return snapshot.schemaVersion }
func (snapshot PhishingIntelligenceSnapshot) CollectedAt() time.Time { return snapshot.collectedAt }
func (snapshot PhishingIntelligenceSnapshot) AsOf() time.Time        { return snapshot.asOf }
func (snapshot PhishingIntelligenceSnapshot) ExpiresAt() *time.Time {
	return cloneTimePointer(snapshot.expiresAt)
}
func (snapshot PhishingIntelligenceSnapshot) License() PhishingIntelligenceLicense {
	return snapshot.license
}
func (snapshot PhishingIntelligenceSnapshot) Indicators() []PhishingIntelligenceIndicator {
	return clonePhishingIntelligenceIndicators(snapshot.indicators)
}

// PhishingIntelligenceOptions controls pure correlation. GeneratedAt defaults
// deterministically to the latest completed-input timestamp. StaleAfter is
// disabled when zero. MaxMatches bounds retained exact-identifier relations.
type PhishingIntelligenceOptions struct {
	GeneratedAt time.Time
	StaleAfter  time.Duration
	MaxMatches  int
}

// PhishingIntelligenceSnapshotFreshness describes snapshot usability at the
// correlation timestamp.
type PhishingIntelligenceSnapshotFreshness string

const (
	PhishingIntelligenceFresh   PhishingIntelligenceSnapshotFreshness = "fresh"
	PhishingIntelligenceStale   PhishingIntelligenceSnapshotFreshness = "stale"
	PhishingIntelligenceExpired PhishingIntelligenceSnapshotFreshness = "expired"
	PhishingIntelligenceFuture  PhishingIntelligenceSnapshotFreshness = "future"
)

// PhishingIntelligenceEvidenceRole retains the exact DMARC evidence role that
// caused an identifier comparison.
type PhishingIntelligenceEvidenceRole string

const (
	PhishingIntelligenceRoleSourceIP     PhishingIntelligenceEvidenceRole = "source_ip"
	PhishingIntelligenceRoleTargetDomain PhishingIntelligenceEvidenceRole = "target_domain"
	PhishingIntelligenceRoleAuthorDomain PhishingIntelligenceEvidenceRole = "author_domain"
	PhishingIntelligenceRoleSPFDomain    PhishingIntelligenceEvidenceRole = "spf_domain"
	PhishingIntelligenceRoleDKIMDomain   PhishingIntelligenceEvidenceRole = "dkim_domain"
)

// PhishingIntelligenceTemporalRelationship compares report-period bounds with
// an indicator's available observation window.
type PhishingIntelligenceTemporalRelationship string

const (
	PhishingIntelligenceTemporalUnknown       PhishingIntelligenceTemporalRelationship = "unknown"
	PhishingIntelligenceTemporalOverlaps      PhishingIntelligenceTemporalRelationship = "overlaps"
	PhishingIntelligenceTemporalBeforeReports PhishingIntelligenceTemporalRelationship = "before_reports"
	PhishingIntelligenceTemporalAfterReports  PhishingIntelligenceTemporalRelationship = "after_reports"
)

// PhishingIntelligenceMatchStatus keeps exact-value equality separate from
// freshness, provider state, and temporal applicability.
type PhishingIntelligenceMatchStatus string

const (
	PhishingIntelligenceActiveMatch      PhishingIntelligenceMatchStatus = "active_match"
	PhishingIntelligenceTimeUnknown      PhishingIntelligenceMatchStatus = "time_unknown"
	PhishingIntelligenceNotOverlapping   PhishingIntelligenceMatchStatus = "not_overlapping"
	PhishingIntelligenceWithdrawn        PhishingIntelligenceMatchStatus = "withdrawn"
	PhishingIntelligenceIndicatorExpired PhishingIntelligenceMatchStatus = "expired"
	PhishingIntelligenceMatchStale       PhishingIntelligenceMatchStatus = "stale"
	PhishingIntelligenceMatchFuture      PhishingIntelligenceMatchStatus = "future"
	PhishingIntelligenceStateUnknown     PhishingIntelligenceMatchStatus = "state_unknown"
)

// PhishingIntelligenceCandidateStatus summarizes retained matches without
// changing the underlying threat-candidate result.
type PhishingIntelligenceCandidateStatus string

const (
	PhishingIntelligenceCandidateNotEvaluated PhishingIntelligenceCandidateStatus = "not_evaluated"
	PhishingIntelligenceCandidateNotEligible  PhishingIntelligenceCandidateStatus = "not_eligible"
	PhishingIntelligenceCandidateNoMatch      PhishingIntelligenceCandidateStatus = "no_match"
	PhishingIntelligenceCandidateMatch        PhishingIntelligenceCandidateStatus = "match"
	PhishingIntelligenceCandidateUnknown      PhishingIntelligenceCandidateStatus = "unknown"
	PhishingIntelligenceCandidateNoOverlap    PhishingIntelligenceCandidateStatus = "no_temporal_match"
	PhishingIntelligenceCandidateWithdrawn    PhishingIntelligenceCandidateStatus = "withdrawn"
	PhishingIntelligenceCandidateExpired      PhishingIntelligenceCandidateStatus = "expired"
	PhishingIntelligenceCandidateStale        PhishingIntelligenceCandidateStatus = "stale"
	PhishingIntelligenceCandidateFuture       PhishingIntelligenceCandidateStatus = "future"
	PhishingIntelligenceCandidateConflicting  PhishingIntelligenceCandidateStatus = "conflicting"
)

// PhishingIntelligenceSource preserves snapshot provenance and caller-reviewed
// terms metadata. Provider-controlled strings remain untrusted data.
type PhishingIntelligenceSource struct {
	SnapshotID     AnalysisID                            `json:"snapshot_id"`
	SnapshotDigest AnalysisID                            `json:"snapshot_digest"`
	Provider       string                                `json:"provider"`
	Dataset        string                                `json:"dataset"`
	SchemaVersion  string                                `json:"schema_version"`
	CollectedAt    time.Time                             `json:"collected_at"`
	AsOf           time.Time                             `json:"as_of"`
	ExpiresAt      *time.Time                            `json:"expires_at,omitempty"`
	Freshness      PhishingIntelligenceSnapshotFreshness `json:"freshness"`
	License        PhishingIntelligenceLicense           `json:"license"`
	Indicators     int                                   `json:"indicators"`
	Sensitivity    Sensitivity                           `json:"sensitivity"`
}

// PhishingIntelligenceMatch is one exact source-IP or exact domain-role
// relation. Context fields are retained but never participate in matching.
type PhishingIntelligenceMatch struct {
	ID                   AnalysisID                               `json:"id"`
	CandidateID          AnalysisID                               `json:"candidate_id"`
	ObservationIDs       []EvidenceID                             `json:"observation_ids"`
	SnapshotID           AnalysisID                               `json:"snapshot_id"`
	IndicatorID          AnalysisID                               `json:"indicator_id"`
	Type                 PhishingIntelligenceIndicatorType        `json:"type"`
	Value                string                                   `json:"value"`
	Role                 PhishingIntelligenceEvidenceRole         `json:"role"`
	Status               PhishingIntelligenceMatchStatus          `json:"status"`
	IndicatorState       PhishingIntelligenceIndicatorState       `json:"indicator_state"`
	SnapshotFreshness    PhishingIntelligenceSnapshotFreshness    `json:"snapshot_freshness"`
	TemporalRelationship PhishingIntelligenceTemporalRelationship `json:"temporal_relationship"`
	FirstSeen            *time.Time                               `json:"first_seen,omitempty"`
	LastSeen             *time.Time                               `json:"last_seen,omitempty"`
	ExpiresAt            *time.Time                               `json:"expires_at,omitempty"`
	ProviderConfidence   PhishingIntelligenceConfidence           `json:"provider_confidence"`
	Category             string                                   `json:"category,omitempty"`
	ReferenceID          string                                   `json:"reference_id,omitempty"`
	Context              PhishingIntelligenceContext              `json:"context"`
	Sensitivity          Sensitivity                              `json:"sensitivity"`
}

// PhishingIntelligenceCandidate records correlation status for one immutable
// threat candidate. It does not duplicate or mutate score fields.
type PhishingIntelligenceCandidate struct {
	CandidateID AnalysisID                          `json:"candidate_id"`
	SourceIP    string                              `json:"source_ip"`
	Status      PhishingIntelligenceCandidateStatus `json:"status"`
	MatchIDs    []AnalysisID                        `json:"match_ids"`
	FindingIDs  []FindingID                         `json:"finding_ids"`
	Sensitivity Sensitivity                         `json:"sensitivity"`
}

// PhishingIntelligenceFinding uses only fixed library-controlled prose.
type PhishingIntelligenceFinding struct {
	ID             FindingID       `json:"id"`
	Code           FindingCode     `json:"code"`
	Severity       FindingSeverity `json:"severity"`
	CandidateID    AnalysisID      `json:"candidate_id"`
	MatchIDs       []AnalysisID    `json:"match_ids"`
	Title          string          `json:"title"`
	Explanation    string          `json:"explanation"`
	Recommendation string          `json:"recommendation"`
	Sensitivity    Sensitivity     `json:"sensitivity"`
}

// PhishingIntelligenceStatusCount is one deterministic candidate rollup.
type PhishingIntelligenceStatusCount struct {
	Status     PhishingIntelligenceCandidateStatus `json:"status"`
	Candidates int                                 `json:"candidates"`
}

// PhishingIntelligenceSummary describes offline correlation coverage.
type PhishingIntelligenceSummary struct {
	Sources       int                               `json:"sources"`
	Indicators    int                               `json:"indicators"`
	Candidates    int                               `json:"candidates"`
	ExactMatches  int                               `json:"exact_matches"`
	ActiveMatches int                               `json:"active_matches"`
	Findings      int                               `json:"findings"`
	Statuses      []PhishingIntelligenceStatusCount `json:"statuses"`
}

// PhishingIntelligenceResult is an immutable pure-correlation result.
type PhishingIntelligenceResult struct {
	metadata              ResultMetadata
	version               string
	organizationID        string
	threatCandidateDigest AnalysisID
	reportEvidenceDigest  AnalysisID
	snapshotDigests       []AnalysisID
	digest                AnalysisID
	sources               []PhishingIntelligenceSource
	candidates            []PhishingIntelligenceCandidate
	matches               []PhishingIntelligenceMatch
	findings              []PhishingIntelligenceFinding
	summary               PhishingIntelligenceSummary
}

func (result PhishingIntelligenceResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result PhishingIntelligenceResult) Version() string                { return result.version }
func (result PhishingIntelligenceResult) OrganizationID() string         { return result.organizationID }
func (result PhishingIntelligenceResult) ThreatCandidateDigest() AnalysisID {
	return result.threatCandidateDigest
}
func (result PhishingIntelligenceResult) ReportEvidenceDigest() AnalysisID {
	return result.reportEvidenceDigest
}
func (result PhishingIntelligenceResult) SnapshotDigests() []AnalysisID {
	return append([]AnalysisID(nil), result.snapshotDigests...)
}
func (result PhishingIntelligenceResult) Digest() AnalysisID { return result.digest }
func (result PhishingIntelligenceResult) Sources() []PhishingIntelligenceSource {
	return clonePhishingIntelligenceSources(result.sources)
}
func (result PhishingIntelligenceResult) Candidates() []PhishingIntelligenceCandidate {
	return clonePhishingIntelligenceCandidates(result.candidates)
}
func (result PhishingIntelligenceResult) Matches() []PhishingIntelligenceMatch {
	return clonePhishingIntelligenceMatches(result.matches)
}
func (result PhishingIntelligenceResult) Findings() []PhishingIntelligenceFinding {
	return clonePhishingIntelligenceFindings(result.findings)
}
func (result PhishingIntelligenceResult) Summary() PhishingIntelligenceSummary {
	return clonePhishingIntelligenceSummary(result.summary)
}

// NormalizePhishingIntelligenceSnapshot validates mutable caller data and
// returns an immutable offline snapshot. It performs no file, DNS, HTTP,
// credential, environment, clock, or subject-IP access.
func NormalizePhishingIntelligenceSnapshot(config PhishingIntelligenceSnapshotConfig) (PhishingIntelligenceSnapshot, error) {
	config.Provider = strings.TrimSpace(config.Provider)
	config.Dataset = strings.TrimSpace(config.Dataset)
	config.SchemaVersion = strings.TrimSpace(config.SchemaVersion)
	config.CollectedAt = config.CollectedAt.UTC()
	config.AsOf = config.AsOf.UTC()
	config.ExpiresAt = normalizedPhishingTimePointer(config.ExpiresAt)
	if config.Provider == "" || config.Dataset == "" || config.SchemaVersion == "" ||
		!validPhishingIntelligenceText(config.Provider) || !validPhishingIntelligenceText(config.Dataset) || !validPhishingIntelligenceText(config.SchemaVersion) ||
		config.CollectedAt.IsZero() || config.AsOf.IsZero() || !sourceEnrichmentTimeMarshalable(config.CollectedAt) ||
		!sourceEnrichmentTimeMarshalable(config.AsOf) || config.AsOf.After(config.CollectedAt) || len(config.Indicators) > maxPhishingIntelligenceIndicators {
		return PhishingIntelligenceSnapshot{}, ErrInvalidPhishingIntelligenceSnapshot
	}
	if config.ExpiresAt != nil && (!sourceEnrichmentTimeMarshalable(*config.ExpiresAt) || !config.ExpiresAt.After(config.AsOf)) {
		return PhishingIntelligenceSnapshot{}, ErrInvalidPhishingIntelligenceSnapshot
	}
	license, textBytes, err := normalizePhishingIntelligenceLicense(config.License)
	if err != nil {
		return PhishingIntelligenceSnapshot{}, err
	}
	textBytes += len(config.Provider) + len(config.Dataset) + len(config.SchemaVersion)
	indicators := make([]PhishingIntelligenceIndicator, 0, len(config.Indicators))
	seen := map[AnalysisID]struct{}{}
	for _, input := range config.Indicators {
		indicator, size, normalizeErr := normalizePhishingIntelligenceIndicator(input)
		if normalizeErr != nil {
			return PhishingIntelligenceSnapshot{}, normalizeErr
		}
		textBytes += size
		if textBytes > maxPhishingIntelligenceTotalBytes {
			return PhishingIntelligenceSnapshot{}, ErrInvalidPhishingIntelligenceSnapshot
		}
		if _, duplicate := seen[indicator.ID]; duplicate {
			continue
		}
		seen[indicator.ID] = struct{}{}
		indicators = append(indicators, indicator)
	}
	sort.Slice(indicators, func(i, j int) bool {
		if indicators[i].Type != indicators[j].Type {
			return indicators[i].Type < indicators[j].Type
		}
		if indicators[i].Value != indicators[j].Value {
			return indicators[i].Value < indicators[j].Value
		}
		return indicators[i].ID < indicators[j].ID
	})
	canonical, err := json.Marshal(struct {
		Version       string                          `json:"version"`
		Provider      string                          `json:"provider"`
		Dataset       string                          `json:"dataset"`
		SchemaVersion string                          `json:"schema_version"`
		CollectedAt   time.Time                       `json:"collected_at"`
		AsOf          time.Time                       `json:"as_of"`
		ExpiresAt     *time.Time                      `json:"expires_at,omitempty"`
		License       PhishingIntelligenceLicense     `json:"license"`
		Indicators    []PhishingIntelligenceIndicator `json:"indicators"`
	}{PhishingIntelligenceVersion, config.Provider, config.Dataset, config.SchemaVersion, config.CollectedAt, config.AsOf, config.ExpiresAt, license, indicators})
	if err != nil {
		return PhishingIntelligenceSnapshot{}, errors.Join(ErrInvalidPhishingIntelligenceSnapshot, err)
	}
	digest := StableAnalysisID("phishing_intelligence_snapshot", string(canonical))
	return PhishingIntelligenceSnapshot{
		id: digest, digest: digest, version: PhishingIntelligenceVersion, provider: config.Provider, dataset: config.Dataset,
		schemaVersion: config.SchemaVersion, collectedAt: config.CollectedAt, asOf: config.AsOf,
		expiresAt: cloneTimePointer(config.ExpiresAt), license: license, indicators: clonePhishingIntelligenceIndicators(indicators),
	}, nil
}

// CorrelatePhishingIntelligence performs pure, exact, offline correlation.
// It never downloads intelligence, submits evidence, contacts a source IP,
// changes candidate scoring, or authorizes automatic action.
func CorrelatePhishingIntelligence(candidates ThreatCandidateResult, evidence ReportEvidenceResult, snapshots []PhishingIntelligenceSnapshot, options PhishingIntelligenceOptions) (PhishingIntelligenceResult, error) {
	if err := validatePhishingIntelligenceInputs(candidates, evidence, snapshots); err != nil {
		return PhishingIntelligenceResult{}, err
	}
	generatedAt := options.GeneratedAt.UTC()
	baseTime := candidates.ResultMetadata().GeneratedAt
	if evidence.ResultMetadata().GeneratedAt.After(baseTime) {
		baseTime = evidence.ResultMetadata().GeneratedAt
	}
	if options.GeneratedAt.IsZero() {
		generatedAt = baseTime
	}
	if options.MaxMatches == 0 {
		options.MaxMatches = defaultPhishingIntelligenceMatches
	}
	if generatedAt.IsZero() || !sourceEnrichmentTimeMarshalable(generatedAt) || generatedAt.Before(baseTime) ||
		options.StaleAfter < 0 || options.MaxMatches < 1 || options.MaxMatches > maxPhishingIntelligenceMatches {
		return PhishingIntelligenceResult{}, ErrInvalidPhishingIntelligenceOptions
	}

	sources, index := phishingIntelligenceIndex(snapshots, generatedAt, options.StaleAfter)
	observationByID := make(map[EvidenceID]ReportEvidenceObservation, len(evidence.observations))
	for _, observation := range evidence.observations {
		observationByID[observation.ID] = observation
	}
	values := candidates.Candidates()
	resultCandidates := make([]PhishingIntelligenceCandidate, 0, len(values))
	matches := make([]PhishingIntelligenceMatch, 0)
	findings := make([]PhishingIntelligenceFinding, 0)
	for _, candidate := range values {
		record := PhishingIntelligenceCandidate{CandidateID: candidate.ID, SourceIP: candidate.SourceIP, MatchIDs: []AnalysisID{}, FindingIDs: []FindingID{}, Sensitivity: SensitivityRestricted}
		if len(snapshots) == 0 {
			record.Status = PhishingIntelligenceCandidateNotEvaluated
			resultCandidates = append(resultCandidates, record)
			continue
		}
		if !candidate.ReviewEligible || candidate.Excluded {
			record.Status = PhishingIntelligenceCandidateNotEligible
			resultCandidates = append(resultCandidates, record)
			continue
		}
		identifiers, err := phishingIntelligenceCandidateIdentifiers(candidate, observationByID)
		if err != nil {
			return PhishingIntelligenceResult{}, err
		}
		candidateMatches := make([]PhishingIntelligenceMatch, 0)
		for _, identifier := range identifiers {
			for _, indexed := range index[phishingIntelligenceIndexKey(identifier.indicatorType, identifier.value)] {
				candidateMatches = append(candidateMatches, newPhishingIntelligenceMatch(candidate, identifier, indexed, generatedAt))
				if len(matches)+len(candidateMatches) > options.MaxMatches {
					return PhishingIntelligenceResult{}, fmt.Errorf("%w: exact match count exceeds the configured limit", ErrInvalidPhishingIntelligenceOptions)
				}
			}
		}
		sortPhishingIntelligenceMatches(candidateMatches)
		record.Status = phishingIntelligenceCandidateStatus(candidateMatches)
		for _, match := range candidateMatches {
			record.MatchIDs = append(record.MatchIDs, match.ID)
		}
		if finding := newPhishingIntelligenceFinding(record); finding != nil {
			record.FindingIDs = []FindingID{finding.ID}
			findings = append(findings, *finding)
		}
		matches = append(matches, candidateMatches...)
		resultCandidates = append(resultCandidates, record)
	}
	sort.Slice(resultCandidates, func(i, j int) bool {
		if resultCandidates[i].SourceIP != resultCandidates[j].SourceIP {
			return resultCandidates[i].SourceIP < resultCandidates[j].SourceIP
		}
		return resultCandidates[i].CandidateID < resultCandidates[j].CandidateID
	})
	sortPhishingIntelligenceMatches(matches)
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	evaluation := Evaluation{State: EvaluationStateEvaluated}
	if len(snapshots) == 0 {
		evaluation = Evaluation{State: EvaluationStateNotEvaluated, Reason: "No phishing-intelligence snapshots were supplied."}
	}
	return newPhishingIntelligenceResult(candidates, evidence, snapshots, generatedAt, evaluation, sources, resultCandidates, matches, findings)
}

type phishingIntelligenceIndexedIndicator struct {
	snapshot  PhishingIntelligenceSnapshot
	indicator PhishingIntelligenceIndicator
	freshness PhishingIntelligenceSnapshotFreshness
}

type phishingIntelligenceCandidateIdentifier struct {
	indicatorType  PhishingIntelligenceIndicatorType
	value          string
	role           PhishingIntelligenceEvidenceRole
	observationIDs []EvidenceID
}

func normalizePhishingIntelligenceLicense(value PhishingIntelligenceLicense) (PhishingIntelligenceLicense, int, error) {
	value.Name = strings.TrimSpace(value.Name)
	value.TermsURI = strings.TrimSpace(value.TermsURI)
	if value.CommercialUse == "" {
		value.CommercialUse = PhishingIntelligenceUsageUnknown
	}
	if value.Redistribution == "" {
		value.Redistribution = PhishingIntelligenceUsageUnknown
	}
	value.Sensitivity = SensitivityRestricted
	if value.Name == "" || !validPhishingIntelligenceText(value.Name) || !validPhishingIntelligenceUsage(value.CommercialUse) ||
		!validPhishingIntelligenceUsage(value.Redistribution) || (value.TermsURI != "" &&
		(!validPhishingIntelligenceText(value.TermsURI) || !validPhishingIntelligenceTermsURI(value.TermsURI))) {
		return PhishingIntelligenceLicense{}, 0, ErrInvalidPhishingIntelligenceSnapshot
	}
	return value, len(value.Name) + len(value.TermsURI), nil
}

func normalizePhishingIntelligenceIndicator(input PhishingIntelligenceIndicatorConfig) (PhishingIntelligenceIndicator, int, error) {
	value := PhishingIntelligenceIndicator{
		Type: input.Type, State: input.State, FirstSeen: normalizedPhishingTimePointer(input.FirstSeen),
		LastSeen: normalizedPhishingTimePointer(input.LastSeen), ExpiresAt: normalizedPhishingTimePointer(input.ExpiresAt),
		ProviderConfidence: input.ProviderConfidence, Category: strings.TrimSpace(input.Category), ReferenceID: strings.TrimSpace(input.ReferenceID),
		Sensitivity: SensitivityRestricted,
	}
	switch value.Type {
	case PhishingIntelligenceSourceIP:
		addr, err := netip.ParseAddr(strings.TrimSpace(input.Value))
		if err != nil || addr.Zone() != "" {
			return PhishingIntelligenceIndicator{}, 0, ErrInvalidPhishingIntelligenceSnapshot
		}
		value.Value = addr.Unmap().String()
	case PhishingIntelligenceDomain:
		domain, err := normalizeDomainName(input.Value)
		if err != nil {
			return PhishingIntelligenceIndicator{}, 0, ErrInvalidPhishingIntelligenceSnapshot
		}
		value.Value = domain
	default:
		return PhishingIntelligenceIndicator{}, 0, ErrInvalidPhishingIntelligenceSnapshot
	}
	if value.State == "" {
		value.State = PhishingIntelligenceIndicatorUnknown
	}
	if !validPhishingIntelligenceIndicatorState(value.State) || !validPhishingIntelligenceConfidence(value.ProviderConfidence) ||
		!validPhishingIntelligenceText(value.Category) || !validPhishingIntelligenceText(value.ReferenceID) ||
		!validPhishingIntelligenceWindow(value.FirstSeen, value.LastSeen, value.ExpiresAt) {
		return PhishingIntelligenceIndicator{}, 0, ErrInvalidPhishingIntelligenceSnapshot
	}
	context, size, err := normalizePhishingIntelligenceContext(input.Context)
	if err != nil {
		return PhishingIntelligenceIndicator{}, 0, err
	}
	value.Context = context
	canonical, err := json.Marshal(struct {
		Type               PhishingIntelligenceIndicatorType  `json:"type"`
		Value              string                             `json:"value"`
		State              PhishingIntelligenceIndicatorState `json:"state"`
		FirstSeen          *time.Time                         `json:"first_seen,omitempty"`
		LastSeen           *time.Time                         `json:"last_seen,omitempty"`
		ExpiresAt          *time.Time                         `json:"expires_at,omitempty"`
		ProviderConfidence PhishingIntelligenceConfidence     `json:"provider_confidence"`
		Category           string                             `json:"category,omitempty"`
		ReferenceID        string                             `json:"reference_id,omitempty"`
		Context            PhishingIntelligenceContext        `json:"context"`
	}{value.Type, value.Value, value.State, value.FirstSeen, value.LastSeen, value.ExpiresAt, value.ProviderConfidence, value.Category, value.ReferenceID, value.Context})
	if err != nil {
		return PhishingIntelligenceIndicator{}, 0, errors.Join(ErrInvalidPhishingIntelligenceSnapshot, err)
	}
	value.ID = StableAnalysisID("phishing_intelligence_indicator", string(canonical))
	return value, size + len(value.Value) + len(value.Category) + len(value.ReferenceID), nil
}

func normalizePhishingIntelligenceContext(input PhishingIntelligenceContext) (PhishingIntelligenceContext, int, error) {
	if len(input.ASNs) > maxPhishingIntelligenceContextItems || len(input.CountryCodes) > maxPhishingIntelligenceContextItems ||
		len(input.InfrastructureProviders) > maxPhishingIntelligenceContextItems || len(input.Brands) > maxPhishingIntelligenceContextItems ||
		len(input.Sectors) > maxPhishingIntelligenceContextItems {
		return PhishingIntelligenceContext{}, 0, ErrInvalidPhishingIntelligenceSnapshot
	}
	result := PhishingIntelligenceContext{ASNs: append([]uint32(nil), input.ASNs...), Sensitivity: SensitivityRestricted}
	for _, asn := range result.ASNs {
		if asn == 0 {
			return PhishingIntelligenceContext{}, 0, ErrInvalidPhishingIntelligenceSnapshot
		}
	}
	sort.Slice(result.ASNs, func(i, j int) bool { return result.ASNs[i] < result.ASNs[j] })
	result.ASNs = compactUint32s(result.ASNs)
	var err error
	if result.CountryCodes, err = normalizePhishingCountryCodes(input.CountryCodes); err != nil {
		return PhishingIntelligenceContext{}, 0, err
	}
	if result.InfrastructureProviders, err = normalizePhishingTextList(input.InfrastructureProviders); err != nil {
		return PhishingIntelligenceContext{}, 0, err
	}
	if result.Brands, err = normalizePhishingTextList(input.Brands); err != nil {
		return PhishingIntelligenceContext{}, 0, err
	}
	if result.Sectors, err = normalizePhishingTextList(input.Sectors); err != nil {
		return PhishingIntelligenceContext{}, 0, err
	}
	size := len(result.ASNs)*4 + stringListBytes(result.CountryCodes) + stringListBytes(result.InfrastructureProviders) + stringListBytes(result.Brands) + stringListBytes(result.Sectors)
	return result, size, nil
}

func normalizePhishingCountryCodes(values []string) ([]string, error) {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.ToUpper(strings.TrimSpace(value))
		if !validISO3166Alpha2Code(result[index]) {
			return nil, ErrInvalidPhishingIntelligenceSnapshot
		}
	}
	sort.Strings(result)
	return compactStrings(result), nil
}

func normalizePhishingTextList(values []string) ([]string, error) {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.TrimSpace(value)
		if result[index] == "" || !validPhishingIntelligenceText(result[index]) {
			return nil, ErrInvalidPhishingIntelligenceSnapshot
		}
	}
	sort.Strings(result)
	return compactStrings(result), nil
}

func validatePhishingIntelligenceInputs(candidates ThreatCandidateResult, evidence ReportEvidenceResult, snapshots []PhishingIntelligenceSnapshot) error {
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return ErrInvalidAnalysisResult
	}
	evidenceMetadata := evidence.ResultMetadata()
	if evidence.Digest() == "" || evidenceMetadata.ContractVersion != AnalysisContractVersion || evidenceMetadata.Mode != AnalysisModeReportEvidence ||
		evidenceMetadata.Evaluation.State != EvaluationStateEvaluated || candidates.ReportEvidenceDigest() != evidence.Digest() ||
		len(snapshots) > maxPhishingIntelligenceSnapshots {
		return ErrInvalidAnalysisResult
	}
	seen := map[AnalysisID]struct{}{}
	totalIndicators := 0
	for _, snapshot := range snapshots {
		if snapshot.id == "" || snapshot.digest == "" || snapshot.id != snapshot.digest || snapshot.version != PhishingIntelligenceVersion ||
			snapshot.provider == "" || snapshot.dataset == "" || snapshot.schemaVersion == "" || len(snapshot.indicators) > maxPhishingIntelligenceIndicators {
			return ErrInvalidAnalysisResult
		}
		if len(snapshot.indicators) > maxPhishingIntelligenceTotalItems-totalIndicators {
			return ErrInvalidAnalysisResult
		}
		totalIndicators += len(snapshot.indicators)
		if _, duplicate := seen[snapshot.digest]; duplicate {
			return ErrInvalidAnalysisResult
		}
		seen[snapshot.digest] = struct{}{}
	}
	return nil
}

func phishingIntelligenceIndex(snapshots []PhishingIntelligenceSnapshot, generatedAt time.Time, staleAfter time.Duration) ([]PhishingIntelligenceSource, map[string][]phishingIntelligenceIndexedIndicator) {
	ordered := append([]PhishingIntelligenceSnapshot(nil), snapshots...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].digest < ordered[j].digest })
	sources := make([]PhishingIntelligenceSource, 0, len(ordered))
	index := map[string][]phishingIntelligenceIndexedIndicator{}
	for _, snapshot := range ordered {
		freshness := phishingIntelligenceSnapshotFreshness(snapshot, generatedAt, staleAfter)
		sources = append(sources, PhishingIntelligenceSource{
			SnapshotID: snapshot.id, SnapshotDigest: snapshot.digest, Provider: snapshot.provider, Dataset: snapshot.dataset,
			SchemaVersion: snapshot.schemaVersion, CollectedAt: snapshot.collectedAt, AsOf: snapshot.asOf,
			ExpiresAt: cloneTimePointer(snapshot.expiresAt), Freshness: freshness, License: snapshot.license,
			Indicators: len(snapshot.indicators), Sensitivity: SensitivityRestricted,
		})
		for _, indicator := range snapshot.indicators {
			key := phishingIntelligenceIndexKey(indicator.Type, indicator.Value)
			index[key] = append(index[key], phishingIntelligenceIndexedIndicator{snapshot: snapshot, indicator: indicator, freshness: freshness})
		}
	}
	for key := range index {
		sort.Slice(index[key], func(i, j int) bool {
			if index[key][i].snapshot.id != index[key][j].snapshot.id {
				return index[key][i].snapshot.id < index[key][j].snapshot.id
			}
			return index[key][i].indicator.ID < index[key][j].indicator.ID
		})
	}
	return sources, index
}

func phishingIntelligenceCandidateIdentifiers(candidate ThreatCandidate, observations map[EvidenceID]ReportEvidenceObservation) ([]phishingIntelligenceCandidateIdentifier, error) {
	values := map[string]*phishingIntelligenceCandidateIdentifier{}
	add := func(indicatorType PhishingIntelligenceIndicatorType, value string, role PhishingIntelligenceEvidenceRole, observationID EvidenceID) {
		if value == "" {
			return
		}
		key := phishingIntelligenceIndexKey(indicatorType, value) + "\x00" + string(role)
		entry := values[key]
		if entry == nil {
			entry = &phishingIntelligenceCandidateIdentifier{indicatorType: indicatorType, value: value, role: role}
			values[key] = entry
		}
		if observationID != "" {
			entry.observationIDs = append(entry.observationIDs, observationID)
		}
	}
	for _, observationID := range candidate.ObservationIDs {
		add(PhishingIntelligenceSourceIP, candidate.SourceIP, PhishingIntelligenceRoleSourceIP, observationID)
	}
	for _, observationID := range candidate.ObservationIDs {
		observation, ok := observations[observationID]
		if !ok || observation.SourceIP.Evaluation.State != EvaluationStateEvaluated || observation.SourceIP.Value != candidate.SourceIP {
			return nil, ErrInvalidAnalysisResult
		}
		addEvaluatedPhishingDomain := func(value ReportEvidenceValue, role PhishingIntelligenceEvidenceRole) {
			if value.Evaluation.State == EvaluationStateEvaluated {
				add(PhishingIntelligenceDomain, value.Value, role, observationID)
			}
		}
		addEvaluatedPhishingDomain(observation.TargetDomain, PhishingIntelligenceRoleTargetDomain)
		addEvaluatedPhishingDomain(observation.AuthorDomain, PhishingIntelligenceRoleAuthorDomain)
		if observation.SPF.Evaluation.State == EvaluationStateEvaluated {
			addEvaluatedPhishingDomain(observation.SPF.Domain, PhishingIntelligenceRoleSPFDomain)
		}
		for _, dkim := range observation.DKIM {
			addEvaluatedPhishingDomain(dkim.Domain, PhishingIntelligenceRoleDKIMDomain)
		}
	}
	result := make([]phishingIntelligenceCandidateIdentifier, 0, len(values))
	for _, value := range values {
		sort.Slice(value.observationIDs, func(i, j int) bool { return value.observationIDs[i] < value.observationIDs[j] })
		value.observationIDs = compactSortedEvidenceIDs(value.observationIDs)
		result = append(result, *value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].indicatorType != result[j].indicatorType {
			return result[i].indicatorType < result[j].indicatorType
		}
		if result[i].value != result[j].value {
			return result[i].value < result[j].value
		}
		return result[i].role < result[j].role
	})
	return result, nil
}

func newPhishingIntelligenceMatch(candidate ThreatCandidate, identifier phishingIntelligenceCandidateIdentifier, indexed phishingIntelligenceIndexedIndicator, generatedAt time.Time) PhishingIntelligenceMatch {
	indicator := indexed.indicator
	temporal := phishingIntelligenceTemporalRelationship(candidate.FirstSeen, candidate.LastSeen, indicator.FirstSeen, indicator.LastSeen)
	status := phishingIntelligenceMatchStatus(indexed.freshness, indicator, temporal, generatedAt)
	match := PhishingIntelligenceMatch{
		CandidateID: candidate.ID, ObservationIDs: append([]EvidenceID(nil), identifier.observationIDs...), SnapshotID: indexed.snapshot.id,
		IndicatorID: indicator.ID, Type: indicator.Type, Value: indicator.Value, Role: identifier.role, Status: status,
		IndicatorState: indicator.State, SnapshotFreshness: indexed.freshness, TemporalRelationship: temporal,
		FirstSeen: cloneTimePointer(indicator.FirstSeen), LastSeen: cloneTimePointer(indicator.LastSeen), ExpiresAt: cloneTimePointer(indicator.ExpiresAt),
		ProviderConfidence: indicator.ProviderConfidence, Category: indicator.Category, ReferenceID: indicator.ReferenceID,
		Context: clonePhishingIntelligenceContext(indicator.Context), Sensitivity: SensitivityRestricted,
	}
	parts := []string{string(candidate.ID), string(indexed.snapshot.id), string(indicator.ID), string(identifier.role), string(status), string(temporal)}
	for _, id := range match.ObservationIDs {
		parts = append(parts, string(id))
	}
	match.ID = StableAnalysisID("phishing_intelligence_match", parts...)
	return match
}

func phishingIntelligenceMatchStatus(freshness PhishingIntelligenceSnapshotFreshness, indicator PhishingIntelligenceIndicator, temporal PhishingIntelligenceTemporalRelationship, generatedAt time.Time) PhishingIntelligenceMatchStatus {
	if freshness == PhishingIntelligenceFuture || phishingIndicatorHasFutureTime(indicator, generatedAt) {
		return PhishingIntelligenceMatchFuture
	}
	if freshness == PhishingIntelligenceExpired || (indicator.ExpiresAt != nil && !indicator.ExpiresAt.After(generatedAt)) {
		return PhishingIntelligenceIndicatorExpired
	}
	if freshness == PhishingIntelligenceStale {
		return PhishingIntelligenceMatchStale
	}
	if temporal == PhishingIntelligenceTemporalBeforeReports || temporal == PhishingIntelligenceTemporalAfterReports {
		return PhishingIntelligenceNotOverlapping
	}
	if indicator.State == PhishingIntelligenceIndicatorWithdrawn {
		return PhishingIntelligenceWithdrawn
	}
	if indicator.State == PhishingIntelligenceIndicatorUnknown {
		return PhishingIntelligenceStateUnknown
	}
	if temporal == PhishingIntelligenceTemporalUnknown {
		return PhishingIntelligenceTimeUnknown
	}
	return PhishingIntelligenceActiveMatch
}

func phishingIntelligenceCandidateStatus(matches []PhishingIntelligenceMatch) PhishingIntelligenceCandidateStatus {
	if len(matches) == 0 {
		return PhishingIntelligenceCandidateNoMatch
	}
	activeByKey, withdrawnByKey := map[string]bool{}, map[string]bool{}
	statuses := map[PhishingIntelligenceMatchStatus]bool{}
	for _, match := range matches {
		statuses[match.Status] = true
		key := string(match.Type) + "\x00" + match.Value + "\x00" + string(match.Role)
		activeByKey[key] = activeByKey[key] || match.IndicatorState == PhishingIntelligenceIndicatorActive
		withdrawnByKey[key] = withdrawnByKey[key] || match.IndicatorState == PhishingIntelligenceIndicatorWithdrawn
	}
	for key := range activeByKey {
		if activeByKey[key] && withdrawnByKey[key] {
			return PhishingIntelligenceCandidateConflicting
		}
	}
	if statuses[PhishingIntelligenceActiveMatch] {
		return PhishingIntelligenceCandidateMatch
	}
	if statuses[PhishingIntelligenceMatchFuture] {
		return PhishingIntelligenceCandidateFuture
	}
	if statuses[PhishingIntelligenceTimeUnknown] || statuses[PhishingIntelligenceStateUnknown] {
		return PhishingIntelligenceCandidateUnknown
	}
	if statuses[PhishingIntelligenceMatchStale] {
		return PhishingIntelligenceCandidateStale
	}
	if statuses[PhishingIntelligenceIndicatorExpired] {
		return PhishingIntelligenceCandidateExpired
	}
	if statuses[PhishingIntelligenceWithdrawn] {
		return PhishingIntelligenceCandidateWithdrawn
	}
	return PhishingIntelligenceCandidateNoOverlap
}

func newPhishingIntelligenceFinding(candidate PhishingIntelligenceCandidate) *PhishingIntelligenceFinding {
	code, severity, title, explanation, recommendation := phishingIntelligenceFindingText(candidate.Status)
	if code == "" {
		return nil
	}
	parts := []string{string(code), string(candidate.CandidateID)}
	for _, id := range candidate.MatchIDs {
		parts = append(parts, string(id))
	}
	return &PhishingIntelligenceFinding{
		ID: FindingID(StableAnalysisID("phishing_intelligence_finding", parts...)), Code: code, Severity: severity,
		CandidateID: candidate.CandidateID, MatchIDs: append([]AnalysisID(nil), candidate.MatchIDs...), Title: title,
		Explanation: explanation, Recommendation: recommendation, Sensitivity: SensitivityRestricted,
	}
}

func phishingIntelligenceFindingText(status PhishingIntelligenceCandidateStatus) (FindingCode, FindingSeverity, string, string, string) {
	switch status {
	case PhishingIntelligenceCandidateMatch:
		return "phishing_intelligence.exact_match", FindingSeverityInfo, "Exact phishing-intelligence context matched", "A canonical source or domain identifier appeared in caller-supplied phishing intelligence with an overlapping evidence window. This does not prove malicious email behavior, ownership, compromise, or control.", "Review the structured evidence, provider terms, time bounds, and infrastructure-reuse limitations before making any decision."
	case PhishingIntelligenceCandidateConflicting:
		return "phishing_intelligence.conflicting", FindingSeverityInfo, "Phishing-intelligence providers disagreed", "Caller-supplied intelligence contained active and withdrawn assertions for the same exact identifier and evidence role. No provider was preferred.", "Retain the conflicting assertions and resolve the disagreement through human review."
	case PhishingIntelligenceCandidateUnknown:
		return "phishing_intelligence.temporal_or_state_unknown", FindingSeverityInfo, "Phishing-intelligence applicability is unknown", "An exact identifier appeared in caller-supplied intelligence, but provider state or temporal overlap could not be established.", "Treat the relation as incomplete context and obtain better time or state evidence before relying on it."
	case PhishingIntelligenceCandidateNoOverlap:
		return "phishing_intelligence.window_not_overlapping", FindingSeverityInfo, "Phishing-intelligence window did not overlap", "An exact identifier appeared in caller-supplied intelligence, but its available observation window did not overlap the aggregate-report period.", "Retain the relation as historical context without implying relevance to the reviewed reports."
	case PhishingIntelligenceCandidateWithdrawn:
		return "phishing_intelligence.withdrawn", FindingSeverityInfo, "Phishing-intelligence assertion was withdrawn", "The exact identifier relation was present only in provider records marked withdrawn.", "Do not treat a withdrawn assertion as current evidence."
	case PhishingIntelligenceCandidateExpired:
		return "phishing_intelligence.expired", FindingSeverityInfo, "Phishing-intelligence evidence expired", "The exact identifier relation came only from expired snapshot or indicator evidence.", "Refresh the caller-owned intelligence before relying on the relation."
	case PhishingIntelligenceCandidateStale:
		return "phishing_intelligence.stale", FindingSeverityInfo, "Phishing-intelligence evidence is stale", "The exact identifier relation came only from intelligence older than the caller-selected freshness limit.", "Refresh the caller-owned intelligence or retain the relation as historical context."
	case PhishingIntelligenceCandidateFuture:
		return "phishing_intelligence.future", FindingSeverityLow, "Phishing-intelligence evidence is future-dated", "The exact identifier relation contains snapshot or indicator timestamps after the correlation timestamp.", "Review the source clock and snapshot construction before using the evidence."
	default:
		return "", "", "", "", ""
	}
}

func newPhishingIntelligenceResult(candidates ThreatCandidateResult, evidence ReportEvidenceResult, snapshots []PhishingIntelligenceSnapshot, generatedAt time.Time, evaluation Evaluation, sources []PhishingIntelligenceSource, candidateValues []PhishingIntelligenceCandidate, matches []PhishingIntelligenceMatch, findings []PhishingIntelligenceFinding) (PhishingIntelligenceResult, error) {
	snapshotDigests := make([]AnalysisID, len(snapshots))
	for index, snapshot := range snapshots {
		snapshotDigests[index] = snapshot.digest
	}
	sort.Slice(snapshotDigests, func(i, j int) bool { return snapshotDigests[i] < snapshotDigests[j] })
	summary := summarizePhishingIntelligence(sources, candidateValues, matches, findings)
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModePhishingIntelligence, GeneratedAt: generatedAt, Evaluation: evaluation}
	canonical, err := json.Marshal(struct {
		Metadata              ResultMetadata                  `json:"metadata"`
		Version               string                          `json:"version"`
		OrganizationID        string                          `json:"organization_id"`
		ThreatCandidateDigest AnalysisID                      `json:"threat_candidate_digest"`
		ReportEvidenceDigest  AnalysisID                      `json:"report_evidence_digest"`
		SnapshotDigests       []AnalysisID                    `json:"snapshot_digests"`
		Sources               []PhishingIntelligenceSource    `json:"sources"`
		Candidates            []PhishingIntelligenceCandidate `json:"candidates"`
		Matches               []PhishingIntelligenceMatch     `json:"matches"`
		Findings              []PhishingIntelligenceFinding   `json:"findings"`
		Summary               PhishingIntelligenceSummary     `json:"summary"`
	}{metadata, PhishingIntelligenceVersion, candidates.OrganizationID(), candidates.Digest(), evidence.Digest(), snapshotDigests, sources, candidateValues, matches, findings, summary})
	if err != nil {
		return PhishingIntelligenceResult{}, errors.Join(ErrInvalidPhishingIntelligenceOptions, err)
	}
	return PhishingIntelligenceResult{
		metadata: metadata, version: PhishingIntelligenceVersion, organizationID: candidates.OrganizationID(),
		threatCandidateDigest: candidates.Digest(), reportEvidenceDigest: evidence.Digest(), snapshotDigests: snapshotDigests,
		digest: StableAnalysisID("phishing_intelligence", string(canonical)), sources: clonePhishingIntelligenceSources(sources),
		candidates: clonePhishingIntelligenceCandidates(candidateValues), matches: clonePhishingIntelligenceMatches(matches),
		findings: clonePhishingIntelligenceFindings(findings), summary: summary,
	}, nil
}

func summarizePhishingIntelligence(sources []PhishingIntelligenceSource, candidates []PhishingIntelligenceCandidate, matches []PhishingIntelligenceMatch, findings []PhishingIntelligenceFinding) PhishingIntelligenceSummary {
	result := PhishingIntelligenceSummary{Sources: len(sources), Candidates: len(candidates), ExactMatches: len(matches), Findings: len(findings), Statuses: []PhishingIntelligenceStatusCount{}}
	for _, source := range sources {
		result.Indicators += source.Indicators
	}
	for _, match := range matches {
		if match.Status == PhishingIntelligenceActiveMatch {
			result.ActiveMatches++
		}
	}
	counts := map[PhishingIntelligenceCandidateStatus]int{}
	for _, candidate := range candidates {
		counts[candidate.Status]++
	}
	for _, status := range phishingIntelligenceCandidateStatusOrder() {
		if count := counts[status]; count > 0 {
			result.Statuses = append(result.Statuses, PhishingIntelligenceStatusCount{Status: status, Candidates: count})
		}
	}
	return result
}

func phishingIntelligenceSnapshotFreshness(snapshot PhishingIntelligenceSnapshot, generatedAt time.Time, staleAfter time.Duration) PhishingIntelligenceSnapshotFreshness {
	if snapshot.collectedAt.After(generatedAt) || snapshot.asOf.After(generatedAt) {
		return PhishingIntelligenceFuture
	}
	if snapshot.expiresAt != nil && !snapshot.expiresAt.After(generatedAt) {
		return PhishingIntelligenceExpired
	}
	if staleAfter > 0 && generatedAt.Sub(snapshot.asOf) > staleAfter {
		return PhishingIntelligenceStale
	}
	return PhishingIntelligenceFresh
}

func phishingIntelligenceTemporalRelationship(reportFirst, reportLast ReportEvidenceTimestamp, indicatorFirst, indicatorLast *time.Time) PhishingIntelligenceTemporalRelationship {
	if !reportFirst.Available || !reportLast.Available || (indicatorFirst == nil && indicatorLast == nil) {
		return PhishingIntelligenceTemporalUnknown
	}
	if indicatorLast != nil && indicatorLast.Before(reportFirst.Value) {
		return PhishingIntelligenceTemporalBeforeReports
	}
	if indicatorFirst != nil && indicatorFirst.After(reportLast.Value) {
		return PhishingIntelligenceTemporalAfterReports
	}
	return PhishingIntelligenceTemporalOverlaps
}

func phishingIndicatorHasFutureTime(indicator PhishingIntelligenceIndicator, generatedAt time.Time) bool {
	return (indicator.FirstSeen != nil && indicator.FirstSeen.After(generatedAt)) || (indicator.LastSeen != nil && indicator.LastSeen.After(generatedAt))
}

func phishingIntelligenceIndexKey(indicatorType PhishingIntelligenceIndicatorType, value string) string {
	return string(indicatorType) + "\x00" + value
}

func sortPhishingIntelligenceMatches(values []PhishingIntelligenceMatch) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].CandidateID != values[j].CandidateID {
			return values[i].CandidateID < values[j].CandidateID
		}
		if values[i].Type != values[j].Type {
			return values[i].Type < values[j].Type
		}
		if values[i].Value != values[j].Value {
			return values[i].Value < values[j].Value
		}
		if values[i].Role != values[j].Role {
			return values[i].Role < values[j].Role
		}
		if values[i].SnapshotID != values[j].SnapshotID {
			return values[i].SnapshotID < values[j].SnapshotID
		}
		return values[i].IndicatorID < values[j].IndicatorID
	})
}

func phishingIntelligenceCandidateStatusOrder() []PhishingIntelligenceCandidateStatus {
	return []PhishingIntelligenceCandidateStatus{
		PhishingIntelligenceCandidateMatch, PhishingIntelligenceCandidateConflicting, PhishingIntelligenceCandidateUnknown,
		PhishingIntelligenceCandidateNoOverlap, PhishingIntelligenceCandidateWithdrawn, PhishingIntelligenceCandidateExpired,
		PhishingIntelligenceCandidateStale, PhishingIntelligenceCandidateFuture, PhishingIntelligenceCandidateNoMatch,
		PhishingIntelligenceCandidateNotEligible, PhishingIntelligenceCandidateNotEvaluated,
	}
}

func validPhishingIntelligenceUsage(value PhishingIntelligenceUsagePolicy) bool {
	return value == PhishingIntelligenceUsageUnknown || value == PhishingIntelligenceUsagePermitted ||
		value == PhishingIntelligenceUsageRestricted || value == PhishingIntelligenceUsageProhibited
}

func validPhishingIntelligenceIndicatorState(value PhishingIntelligenceIndicatorState) bool {
	return value == PhishingIntelligenceIndicatorActive || value == PhishingIntelligenceIndicatorWithdrawn || value == PhishingIntelligenceIndicatorUnknown
}

func validPhishingIntelligenceConfidence(value PhishingIntelligenceConfidence) bool {
	if !value.Available {
		return value.Value == 0
	}
	return value.Value >= 0 && value.Value <= 100
}

func validPhishingIntelligenceWindow(first, last, expires *time.Time) bool {
	for _, value := range []*time.Time{first, last, expires} {
		if value != nil && (value.IsZero() || !sourceEnrichmentTimeMarshalable(*value)) {
			return false
		}
	}
	if first != nil && last != nil && last.Before(*first) {
		return false
	}
	if expires != nil && first != nil && !expires.After(*first) {
		return false
	}
	if expires != nil && last != nil && !expires.After(*last) {
		return false
	}
	return true
}

func validPhishingIntelligenceText(value string) bool {
	return len(value) <= maxPhishingIntelligenceTextBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validPhishingIntelligenceTermsURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func normalizedPhishingTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func compactUint32s(values []uint32) []uint32 {
	if len(values) == 0 {
		return []uint32{}
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func stringListBytes(values []string) int {
	total := 0
	for _, value := range values {
		total += len(value)
	}
	return total
}

func clonePhishingIntelligenceContext(value PhishingIntelligenceContext) PhishingIntelligenceContext {
	value.ASNs = append([]uint32(nil), value.ASNs...)
	value.CountryCodes = append([]string(nil), value.CountryCodes...)
	value.InfrastructureProviders = append([]string(nil), value.InfrastructureProviders...)
	value.Brands = append([]string(nil), value.Brands...)
	value.Sectors = append([]string(nil), value.Sectors...)
	return value
}

func clonePhishingIntelligenceIndicators(values []PhishingIntelligenceIndicator) []PhishingIntelligenceIndicator {
	result := make([]PhishingIntelligenceIndicator, len(values))
	for index, value := range values {
		value.FirstSeen = cloneTimePointer(value.FirstSeen)
		value.LastSeen = cloneTimePointer(value.LastSeen)
		value.ExpiresAt = cloneTimePointer(value.ExpiresAt)
		value.Context = clonePhishingIntelligenceContext(value.Context)
		result[index] = value
	}
	return result
}

func clonePhishingIntelligenceSources(values []PhishingIntelligenceSource) []PhishingIntelligenceSource {
	result := make([]PhishingIntelligenceSource, len(values))
	for index, value := range values {
		value.ExpiresAt = cloneTimePointer(value.ExpiresAt)
		result[index] = value
	}
	return result
}

func clonePhishingIntelligenceMatches(values []PhishingIntelligenceMatch) []PhishingIntelligenceMatch {
	result := make([]PhishingIntelligenceMatch, len(values))
	for index, value := range values {
		value.ObservationIDs = append([]EvidenceID(nil), value.ObservationIDs...)
		value.FirstSeen = cloneTimePointer(value.FirstSeen)
		value.LastSeen = cloneTimePointer(value.LastSeen)
		value.ExpiresAt = cloneTimePointer(value.ExpiresAt)
		value.Context = clonePhishingIntelligenceContext(value.Context)
		result[index] = value
	}
	return result
}

func clonePhishingIntelligenceCandidates(values []PhishingIntelligenceCandidate) []PhishingIntelligenceCandidate {
	result := make([]PhishingIntelligenceCandidate, len(values))
	for index, value := range values {
		value.MatchIDs = append([]AnalysisID(nil), value.MatchIDs...)
		value.FindingIDs = append([]FindingID(nil), value.FindingIDs...)
		result[index] = value
	}
	return result
}

func clonePhishingIntelligenceFindings(values []PhishingIntelligenceFinding) []PhishingIntelligenceFinding {
	result := make([]PhishingIntelligenceFinding, len(values))
	for index, value := range values {
		value.MatchIDs = append([]AnalysisID(nil), value.MatchIDs...)
		result[index] = value
	}
	return result
}

func clonePhishingIntelligenceSummary(value PhishingIntelligenceSummary) PhishingIntelligenceSummary {
	value.Statuses = append([]PhishingIntelligenceStatusCount(nil), value.Statuses...)
	return value
}
