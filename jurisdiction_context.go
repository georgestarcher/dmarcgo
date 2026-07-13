package dmarcgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// JurisdictionContextVersion identifies the jurisdiction-context result
	// contract. It is independent of the policy version and output schemas.
	JurisdictionContextVersion = "1"

	maxJurisdictionPolicySources = 16
	maxJurisdictionPolicyEntries = 512
	maxJurisdictionPolicyCodes   = 32
)

var (
	// ErrInvalidJurisdictionRiskPolicy identifies malformed, ambiguous, or
	// internally inconsistent caller-supplied policy data.
	ErrInvalidJurisdictionRiskPolicy = errors.New("invalid jurisdiction risk policy")
	// ErrInvalidJurisdictionContextOptions identifies an invalid result
	// timestamp or adjustment selection.
	ErrInvalidJurisdictionContextOptions = errors.New("invalid jurisdiction context options")
)

// JurisdictionRiskTier is a stable policy-owned tier code. A tier is review
// context, not a threat, actor, intent, nationality, or legal classification.
type JurisdictionRiskTier string

const (
	JurisdictionRiskTierExportControl JurisdictionRiskTier = "export_control_context"
	JurisdictionRiskTierArmsEmbargo   JurisdictionRiskTier = "arms_embargo_context"
	JurisdictionRiskTierEmbargo       JurisdictionRiskTier = "embargo_context"
)

// JurisdictionCategoryCode identifies one source category retained by a
// jurisdiction policy.
type JurisdictionCategoryCode string

const (
	JurisdictionCategoryBISCountryGroupD1 JurisdictionCategoryCode = "bis_country_group_d1"
	JurisdictionCategoryBISCountryGroupD2 JurisdictionCategoryCode = "bis_country_group_d2"
	JurisdictionCategoryBISCountryGroupD3 JurisdictionCategoryCode = "bis_country_group_d3"
	JurisdictionCategoryBISCountryGroupD4 JurisdictionCategoryCode = "bis_country_group_d4"
	JurisdictionCategoryBISCountryGroupD5 JurisdictionCategoryCode = "bis_country_group_d5"
	JurisdictionCategoryBISCountryGroupE1 JurisdictionCategoryCode = "bis_country_group_e1"
	JurisdictionCategoryBISCountryGroupE2 JurisdictionCategoryCode = "bis_country_group_e2"
)

// JurisdictionReasonCode records the documented reason associated with a
// source category. It remains structured data and is never generated prose.
type JurisdictionReasonCode string

const (
	JurisdictionReasonNationalSecurity             JurisdictionReasonCode = "national_security_controls"
	JurisdictionReasonNuclear                      JurisdictionReasonCode = "nuclear_controls"
	JurisdictionReasonChemicalBiological           JurisdictionReasonCode = "chemical_biological_controls"
	JurisdictionReasonMissileTechnology            JurisdictionReasonCode = "missile_technology_controls"
	JurisdictionReasonUSArmsEmbargo                JurisdictionReasonCode = "us_arms_embargo"
	JurisdictionReasonTerrorismSupportingCountries JurisdictionReasonCode = "terrorism_supporting_country_group"
	JurisdictionReasonUnilateralEmbargo            JurisdictionReasonCode = "unilateral_embargo"
)

// JurisdictionRiskPolicySource is one public provenance source for a policy.
// Title and URI are untrusted policy data and must not become generated prose.
type JurisdictionRiskPolicySource struct {
	Title string `json:"title"`
	URI   string `json:"uri"`
}

// JurisdictionRiskPolicyEntry is one normalized ISO 3166-1 alpha-2 entry.
// ReviewPriorityAdjustment is inert unless the caller explicitly enables it.
type JurisdictionRiskPolicyEntry struct {
	ID                       AnalysisID                 `json:"id"`
	CountryCode              string                     `json:"country_code"`
	Tier                     JurisdictionRiskTier       `json:"tier"`
	Categories               []JurisdictionCategoryCode `json:"categories"`
	Reasons                  []JurisdictionReasonCode   `json:"reasons"`
	ReviewPriorityAdjustment int                        `json:"review_priority_adjustment"`
}

// JurisdictionRiskPolicyConfig is mutable policy input. Normalize it before
// evaluation; normalization performs no I/O or environment access.
type JurisdictionRiskPolicyConfig struct {
	ID                          string
	Version                     string
	Name                        string
	Description                 string
	EffectiveAt                 time.Time
	AsOf                        time.Time
	ExpiresAt                   *time.Time
	Sources                     []JurisdictionRiskPolicySource
	Entries                     []JurisdictionRiskPolicyEntry
	MaxReviewPriorityAdjustment int
}

// JurisdictionRiskPolicy is an immutable, versioned jurisdiction-context
// policy. Accessors return defensive copies.
type JurisdictionRiskPolicy struct {
	id                          string
	version                     string
	name                        string
	description                 string
	effectiveAt                 time.Time
	asOf                        time.Time
	expiresAt                   *time.Time
	sources                     []JurisdictionRiskPolicySource
	entries                     []JurisdictionRiskPolicyEntry
	maxReviewPriorityAdjustment int
	digest                      AnalysisID
}

func (policy JurisdictionRiskPolicy) ID() string             { return policy.id }
func (policy JurisdictionRiskPolicy) Version() string        { return policy.version }
func (policy JurisdictionRiskPolicy) Name() string           { return policy.name }
func (policy JurisdictionRiskPolicy) Description() string    { return policy.description }
func (policy JurisdictionRiskPolicy) EffectiveAt() time.Time { return policy.effectiveAt }
func (policy JurisdictionRiskPolicy) AsOf() time.Time        { return policy.asOf }
func (policy JurisdictionRiskPolicy) MaxReviewPriorityAdjustment() int {
	return policy.maxReviewPriorityAdjustment
}
func (policy JurisdictionRiskPolicy) Digest() AnalysisID { return policy.digest }
func (policy JurisdictionRiskPolicy) ExpiresAt() *time.Time {
	return cloneTimePointer(policy.expiresAt)
}
func (policy JurisdictionRiskPolicy) Sources() []JurisdictionRiskPolicySource {
	return append([]JurisdictionRiskPolicySource{}, policy.sources...)
}
func (policy JurisdictionRiskPolicy) Entries() []JurisdictionRiskPolicyEntry {
	return cloneJurisdictionPolicyEntries(policy.entries)
}

// JurisdictionContextStatus records whether current, unambiguous enrichment
// could be evaluated against the selected policy.
type JurisdictionContextStatus string

const (
	JurisdictionContextMatch        JurisdictionContextStatus = "match"
	JurisdictionContextNoMatch      JurisdictionContextStatus = "no_match"
	JurisdictionContextUnknown      JurisdictionContextStatus = "unknown"
	JurisdictionContextStale        JurisdictionContextStatus = "stale"
	JurisdictionContextConflicting  JurisdictionContextStatus = "conflicting"
	JurisdictionContextNotEligible  JurisdictionContextStatus = "not_eligible"
	JurisdictionContextNotEvaluated JurisdictionContextStatus = "not_evaluated"
)

// JurisdictionContextAssertionReference links a context result to one
// normalized source-enrichment assertion without copying provider-controlled
// prose into a finding.
type JurisdictionContextAssertionReference struct {
	AssertionID AnalysisID                `json:"assertion_id"`
	CountryCode string                    `json:"country_code,omitempty"`
	Freshness   SourceEnrichmentFreshness `json:"freshness"`
}

// JurisdictionContextCandidate is one deterministic candidate evaluation.
// SourceIP and assertion references remain restricted operational data.
type JurisdictionContextCandidate struct {
	CandidateID              AnalysisID                              `json:"candidate_id"`
	SourceIP                 string                                  `json:"source_ip"`
	Status                   JurisdictionContextStatus               `json:"status"`
	AssertionReferences      []JurisdictionContextAssertionReference `json:"assertion_references"`
	CountryCodes             []string                                `json:"country_codes"`
	PolicyEntryIDs           []AnalysisID                            `json:"policy_entry_ids"`
	Tier                     JurisdictionRiskTier                    `json:"tier,omitempty"`
	Categories               []JurisdictionCategoryCode              `json:"categories"`
	Reasons                  []JurisdictionReasonCode                `json:"reasons"`
	ReviewPriorityAdjustment int                                     `json:"review_priority_adjustment"`
	FindingIDs               []FindingID                             `json:"finding_ids"`
	Sensitivity              Sensitivity                             `json:"sensitivity"`
}

// JurisdictionContextFinding is library-controlled prose plus structured
// policy and evidence references. Policy-provided strings are never
// interpolated into Message.
type JurisdictionContextFinding struct {
	ID                       FindingID                  `json:"id"`
	Code                     FindingCode                `json:"code"`
	Severity                 FindingSeverity            `json:"severity"`
	CandidateID              AnalysisID                 `json:"candidate_id"`
	AssertionIDs             []AnalysisID               `json:"assertion_ids"`
	PolicyEntryIDs           []AnalysisID               `json:"policy_entry_ids"`
	CountryCodes             []string                   `json:"country_codes"`
	Tier                     JurisdictionRiskTier       `json:"tier,omitempty"`
	Categories               []JurisdictionCategoryCode `json:"categories"`
	Reasons                  []JurisdictionReasonCode   `json:"reasons"`
	ReviewPriorityAdjustment int                        `json:"review_priority_adjustment"`
	Message                  string                     `json:"message"`
	Sensitivity              Sensitivity                `json:"sensitivity"`
}

// JurisdictionContextStatusCount is one deterministic status rollup.
type JurisdictionContextStatusCount struct {
	Status     JurisdictionContextStatus `json:"status"`
	Candidates int                       `json:"candidates"`
}

// JurisdictionContextSummary describes policy matches and optional priority
// adjustments without changing the upstream candidate score.
type JurisdictionContextSummary struct {
	Candidates               int                              `json:"candidates"`
	Matches                  int                              `json:"matches"`
	AdjustedCandidates       int                              `json:"adjusted_candidates"`
	MaximumAppliedAdjustment int                              `json:"maximum_applied_adjustment"`
	Statuses                 []JurisdictionContextStatusCount `json:"statuses"`
}

// JurisdictionContextOptions controls the pure evaluation stage. A zero
// GeneratedAt preserves the source-enrichment timestamp. Priority adjustment
// is disabled by default.
type JurisdictionContextOptions struct {
	GeneratedAt                    time.Time
	EnableReviewPriorityAdjustment bool
}

// JurisdictionContextResult is an immutable result from explicit, offline
// jurisdiction-context evaluation.
type JurisdictionContextResult struct {
	metadata               ResultMetadata
	version                string
	organizationID         string
	sourceEnrichmentDigest AnalysisID
	policy                 JurisdictionRiskPolicy
	policyFreshness        SourceEnrichmentFreshness
	digest                 AnalysisID
	candidates             []JurisdictionContextCandidate
	findings               []JurisdictionContextFinding
	summary                JurisdictionContextSummary
}

func (result JurisdictionContextResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result JurisdictionContextResult) Version() string                { return result.version }
func (result JurisdictionContextResult) OrganizationID() string         { return result.organizationID }
func (result JurisdictionContextResult) SourceEnrichmentDigest() AnalysisID {
	return result.sourceEnrichmentDigest
}
func (result JurisdictionContextResult) Policy() JurisdictionRiskPolicy { return result.policy }
func (result JurisdictionContextResult) PolicyFreshness() SourceEnrichmentFreshness {
	return result.policyFreshness
}
func (result JurisdictionContextResult) Digest() AnalysisID { return result.digest }
func (result JurisdictionContextResult) Candidates() []JurisdictionContextCandidate {
	return cloneJurisdictionContextCandidates(result.candidates)
}
func (result JurisdictionContextResult) Findings() []JurisdictionContextFinding {
	return cloneJurisdictionContextFindings(result.findings)
}
func (result JurisdictionContextResult) Summary() JurisdictionContextSummary {
	return cloneJurisdictionContextSummary(result.summary)
}

// NormalizeJurisdictionRiskPolicy validates mutable configuration and returns
// an immutable policy. It performs no DNS, HTTP, filesystem, environment,
// credential, or subject-IP access.
func NormalizeJurisdictionRiskPolicy(config JurisdictionRiskPolicyConfig) (JurisdictionRiskPolicy, error) {
	config.ID = normalizeJurisdictionCode(config.ID)
	config.Version = strings.TrimSpace(config.Version)
	config.Name = strings.TrimSpace(config.Name)
	config.Description = strings.TrimSpace(config.Description)
	config.EffectiveAt = config.EffectiveAt.UTC()
	config.AsOf = config.AsOf.UTC()
	config.ExpiresAt = cloneTimePointer(config.ExpiresAt)
	if config.ExpiresAt != nil {
		value := config.ExpiresAt.UTC()
		config.ExpiresAt = &value
	}
	if !validJurisdictionCode(config.ID) || !validJurisdictionVersion(config.Version) || config.Name == "" || config.Description == "" ||
		!validSourceEnrichmentText(config.Name) || !validSourceEnrichmentText(config.Description) ||
		config.EffectiveAt.IsZero() || config.AsOf.IsZero() || !sourceEnrichmentTimeMarshalable(config.EffectiveAt) ||
		!sourceEnrichmentTimeMarshalable(config.AsOf) || config.AsOf.Before(config.EffectiveAt) ||
		config.MaxReviewPriorityAdjustment < 0 || config.MaxReviewPriorityAdjustment > 10 ||
		len(config.Sources) == 0 || len(config.Sources) > maxJurisdictionPolicySources ||
		len(config.Entries) == 0 || len(config.Entries) > maxJurisdictionPolicyEntries {
		return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
	}
	if config.ExpiresAt != nil && (!sourceEnrichmentTimeMarshalable(*config.ExpiresAt) || !config.ExpiresAt.After(config.AsOf)) {
		return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
	}

	sources := append([]JurisdictionRiskPolicySource{}, config.Sources...)
	seenSources := map[string]struct{}{}
	for index := range sources {
		sources[index].Title = strings.TrimSpace(sources[index].Title)
		sources[index].URI = strings.TrimSpace(sources[index].URI)
		if sources[index].Title == "" || !validSourceEnrichmentText(sources[index].Title) || !validJurisdictionSourceURI(sources[index].URI) {
			return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
		}
		if _, exists := seenSources[sources[index].URI]; exists {
			return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
		}
		seenSources[sources[index].URI] = struct{}{}
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].URI != sources[j].URI {
			return sources[i].URI < sources[j].URI
		}
		return sources[i].Title < sources[j].Title
	})

	entries := cloneJurisdictionPolicyEntries(config.Entries)
	seenCountries := map[string]struct{}{}
	for index := range entries {
		entry := &entries[index]
		entry.ID = ""
		entry.CountryCode = strings.ToUpper(strings.TrimSpace(entry.CountryCode))
		entry.Tier = JurisdictionRiskTier(normalizeJurisdictionCode(string(entry.Tier)))
		entry.Categories = normalizeJurisdictionCategories(entry.Categories)
		entry.Reasons = normalizeJurisdictionReasons(entry.Reasons)
		if !validISO3166Alpha2Code(entry.CountryCode) || !validJurisdictionCode(string(entry.Tier)) ||
			len(entry.Categories) == 0 || len(entry.Categories) > maxJurisdictionPolicyCodes ||
			len(entry.Reasons) == 0 || len(entry.Reasons) > maxJurisdictionPolicyCodes ||
			entry.ReviewPriorityAdjustment < 0 || entry.ReviewPriorityAdjustment > config.MaxReviewPriorityAdjustment ||
			!uniqueJurisdictionCategories(entry.Categories) || !uniqueJurisdictionReasons(entry.Reasons) {
			return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
		}
		if _, exists := seenCountries[entry.CountryCode]; exists {
			return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
		}
		seenCountries[entry.CountryCode] = struct{}{}
		for _, code := range entry.Categories {
			if !validJurisdictionCode(string(code)) {
				return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
			}
		}
		for _, code := range entry.Reasons {
			if !validJurisdictionCode(string(code)) {
				return JurisdictionRiskPolicy{}, ErrInvalidJurisdictionRiskPolicy
			}
		}
		entry.ID = jurisdictionPolicyEntryID(config.ID, config.Version, *entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CountryCode < entries[j].CountryCode })

	canonical, err := json.Marshal(struct {
		ID                          string                         `json:"id"`
		Version                     string                         `json:"version"`
		Name                        string                         `json:"name"`
		Description                 string                         `json:"description"`
		EffectiveAt                 time.Time                      `json:"effective_at"`
		AsOf                        time.Time                      `json:"as_of"`
		ExpiresAt                   *time.Time                     `json:"expires_at,omitempty"`
		Sources                     []JurisdictionRiskPolicySource `json:"sources"`
		Entries                     []JurisdictionRiskPolicyEntry  `json:"entries"`
		MaxReviewPriorityAdjustment int                            `json:"max_review_priority_adjustment"`
	}{config.ID, config.Version, config.Name, config.Description, config.EffectiveAt, config.AsOf, config.ExpiresAt, sources, entries, config.MaxReviewPriorityAdjustment})
	if err != nil {
		return JurisdictionRiskPolicy{}, errors.Join(ErrInvalidJurisdictionRiskPolicy, err)
	}
	return JurisdictionRiskPolicy{
		id: config.ID, version: config.Version, name: config.Name, description: config.Description,
		effectiveAt: config.EffectiveAt, asOf: config.AsOf, expiresAt: cloneTimePointer(config.ExpiresAt),
		sources: sources, entries: entries, maxReviewPriorityAdjustment: config.MaxReviewPriorityAdjustment,
		digest: StableAnalysisID("jurisdiction_risk_policy", string(canonical)),
	}, nil
}

// EvaluateJurisdictionContext evaluates completed source-enrichment values
// against an explicit normalized policy. It is pure and offline. It never
// performs DNS, HTTP, PTR, WHOIS, GeoIP, environment, credential, filesystem,
// or direct subject-IP activity.
func EvaluateJurisdictionContext(enrichment SourceEnrichmentResult, policy JurisdictionRiskPolicy, options JurisdictionContextOptions) (JurisdictionContextResult, error) {
	if err := validateJurisdictionContextInput(enrichment, policy); err != nil {
		return JurisdictionContextResult{}, err
	}
	generatedAt := options.GeneratedAt.UTC()
	if options.GeneratedAt.IsZero() {
		generatedAt = enrichment.ResultMetadata().GeneratedAt
	}
	if generatedAt.IsZero() || !sourceEnrichmentTimeMarshalable(generatedAt) || generatedAt.Before(enrichment.ResultMetadata().GeneratedAt) {
		return JurisdictionContextResult{}, ErrInvalidJurisdictionContextOptions
	}

	policyFreshness := SourceEnrichmentFreshnessFresh
	if policy.ExpiresAt() == nil {
		policyFreshness = SourceEnrichmentFreshnessUnknown
	} else if !policy.ExpiresAt().After(generatedAt) {
		policyFreshness = SourceEnrichmentFreshnessStale
	}
	policyFuture := generatedAt.Before(policy.EffectiveAt())
	entryByCountry := make(map[string]JurisdictionRiskPolicyEntry, len(policy.entries))
	for _, entry := range policy.entries {
		entryByCountry[entry.CountryCode] = entry
	}

	values := enrichment.Candidates()
	candidates := make([]JurisdictionContextCandidate, 0, len(values))
	findings := make([]JurisdictionContextFinding, 0, len(values))
	for _, value := range values {
		candidate, finding := evaluateJurisdictionCandidate(value, entryByCountry, policyFreshness, policyFuture, options.EnableReviewPriorityAdjustment)
		if finding != nil {
			findings = append(findings, *finding)
			candidate.FindingIDs = []FindingID{finding.ID}
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].SourceIP != candidates[j].SourceIP {
			return candidates[i].SourceIP < candidates[j].SourceIP
		}
		return candidates[i].CandidateID < candidates[j].CandidateID
	})
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })

	evaluation := Evaluation{State: EvaluationStateEvaluated}
	if policyFuture {
		evaluation = Evaluation{State: EvaluationStateNotEvaluated, Reason: "The selected jurisdiction policy is not yet effective."}
	} else if enrichment.ResultMetadata().Evaluation.State == EvaluationStateNotEvaluated {
		evaluation = Evaluation{State: EvaluationStateNotEvaluated, Reason: "Source enrichment was not evaluated."}
	}
	return newJurisdictionContextResult(enrichment, policy, policyFreshness, generatedAt, evaluation, candidates, findings)
}

func validateJurisdictionContextInput(enrichment SourceEnrichmentResult, policy JurisdictionRiskPolicy) error {
	metadata := enrichment.ResultMetadata()
	if enrichment.Digest() == "" || enrichment.OrganizationID() == "" || enrichment.Version() != SourceEnrichmentVersion ||
		metadata.ContractVersion != AnalysisContractVersion || metadata.Mode != AnalysisModeSourceEnrichment ||
		(metadata.Evaluation.State != EvaluationStateEvaluated && metadata.Evaluation.State != EvaluationStateNotEvaluated) ||
		policy.Digest() == "" || policy.ID() == "" || policy.Version() == "" || len(policy.entries) == 0 {
		return ErrInvalidAnalysisResult
	}
	for _, value := range enrichment.Candidates() {
		if value.Candidate.ID == "" || value.Candidate.SourceIP == "" || value.Candidate.PromotionEligible {
			return ErrInvalidAnalysisResult
		}
	}
	return nil
}

func evaluateJurisdictionCandidate(value EnrichedThreatCandidate, entryByCountry map[string]JurisdictionRiskPolicyEntry, policyFreshness SourceEnrichmentFreshness, policyFuture, enableAdjustment bool) (JurisdictionContextCandidate, *JurisdictionContextFinding) {
	result := JurisdictionContextCandidate{
		CandidateID: value.Candidate.ID, SourceIP: value.Candidate.SourceIP,
		AssertionReferences: []JurisdictionContextAssertionReference{}, CountryCodes: []string{}, PolicyEntryIDs: []AnalysisID{},
		Categories: []JurisdictionCategoryCode{}, Reasons: []JurisdictionReasonCode{}, FindingIDs: []FindingID{}, Sensitivity: SensitivityRestricted,
	}
	countries := map[string]struct{}{}
	freshCountry := false
	for _, assertion := range value.Metadata.Assertions {
		result.AssertionReferences = append(result.AssertionReferences, JurisdictionContextAssertionReference{
			AssertionID: assertion.ID, CountryCode: assertion.CountryCode, Freshness: assertion.Freshness,
		})
		if assertion.CountryCode != "" {
			countries[assertion.CountryCode] = struct{}{}
			freshCountry = freshCountry || assertion.Freshness == SourceEnrichmentFreshnessFresh
		}
	}
	sort.Slice(result.AssertionReferences, func(i, j int) bool {
		return result.AssertionReferences[i].AssertionID < result.AssertionReferences[j].AssertionID
	})
	result.CountryCodes = sortedStringSet(countries)

	switch value.Status {
	case SourceEnrichmentNotEligible:
		result.Status = JurisdictionContextNotEligible
		return result, nil
	case SourceEnrichmentNotEvaluated:
		result.Status = JurisdictionContextNotEvaluated
		return result, nil
	}
	if policyFuture {
		result.Status = JurisdictionContextNotEvaluated
		return result, nil
	}
	if len(result.CountryCodes) > 1 {
		result.Status = JurisdictionContextConflicting
		return result, newJurisdictionContextFinding(result)
	}
	if len(result.CountryCodes) == 0 {
		result.Status = JurisdictionContextUnknown
		return result, newJurisdictionContextFinding(result)
	}
	if policyFreshness == SourceEnrichmentFreshnessStale || value.Status == SourceEnrichmentStale {
		result.Status = JurisdictionContextStale
		return result, newJurisdictionContextFinding(result)
	}
	if !freshCountry {
		result.Status = JurisdictionContextUnknown
		return result, newJurisdictionContextFinding(result)
	}

	entry, matched := entryByCountry[result.CountryCodes[0]]
	if !matched {
		result.Status = JurisdictionContextNoMatch
		return result, nil
	}
	result.Status = JurisdictionContextMatch
	result.PolicyEntryIDs = []AnalysisID{entry.ID}
	result.Tier = entry.Tier
	result.Categories = append([]JurisdictionCategoryCode{}, entry.Categories...)
	result.Reasons = append([]JurisdictionReasonCode{}, entry.Reasons...)
	if enableAdjustment {
		result.ReviewPriorityAdjustment = entry.ReviewPriorityAdjustment
	}
	return result, newJurisdictionContextFinding(result)
}

func newJurisdictionContextFinding(candidate JurisdictionContextCandidate) *JurisdictionContextFinding {
	code, message := jurisdictionContextFindingText(candidate.Status)
	if code == "" {
		return nil
	}
	assertionIDs := make([]AnalysisID, len(candidate.AssertionReferences))
	for index, reference := range candidate.AssertionReferences {
		assertionIDs[index] = reference.AssertionID
	}
	parts := []string{string(code), string(candidate.CandidateID), string(candidate.Tier), fmt.Sprint(candidate.ReviewPriorityAdjustment)}
	for _, value := range assertionIDs {
		parts = append(parts, string(value))
	}
	for _, value := range candidate.PolicyEntryIDs {
		parts = append(parts, string(value))
	}
	return &JurisdictionContextFinding{
		ID: FindingID(StableAnalysisID("jurisdiction_finding", parts...)), Code: code, Severity: FindingSeverityInfo,
		CandidateID: candidate.CandidateID, AssertionIDs: assertionIDs, PolicyEntryIDs: append([]AnalysisID{}, candidate.PolicyEntryIDs...),
		CountryCodes: cloneStrings(candidate.CountryCodes), Tier: candidate.Tier,
		Categories: append([]JurisdictionCategoryCode{}, candidate.Categories...), Reasons: append([]JurisdictionReasonCode{}, candidate.Reasons...),
		ReviewPriorityAdjustment: candidate.ReviewPriorityAdjustment, Message: message, Sensitivity: SensitivityRestricted,
	}
}

func jurisdictionContextFindingText(status JurisdictionContextStatus) (FindingCode, string) {
	switch status {
	case JurisdictionContextMatch:
		return "jurisdiction_context.match", "Coarse infrastructure geography matched the selected jurisdiction-context policy. Treat the structured match as review context only."
	case JurisdictionContextUnknown:
		return "jurisdiction_context.unknown", "Jurisdiction context could not be evaluated from current coarse geography evidence."
	case JurisdictionContextStale:
		return "jurisdiction_context.stale", "Jurisdiction context was not applied because the selected policy or all relevant geography evidence was stale."
	case JurisdictionContextConflicting:
		return "jurisdiction_context.conflicting", "Jurisdiction context was not applied because enrichment providers asserted conflicting country codes."
	default:
		return "", ""
	}
}

func newJurisdictionContextResult(enrichment SourceEnrichmentResult, policy JurisdictionRiskPolicy, policyFreshness SourceEnrichmentFreshness, generatedAt time.Time, evaluation Evaluation, candidates []JurisdictionContextCandidate, findings []JurisdictionContextFinding) (JurisdictionContextResult, error) {
	counts := map[JurisdictionContextStatus]int{}
	summary := JurisdictionContextSummary{Candidates: len(candidates), Statuses: []JurisdictionContextStatusCount{}}
	for _, candidate := range candidates {
		counts[candidate.Status]++
		if candidate.Status == JurisdictionContextMatch {
			summary.Matches++
		}
		if candidate.ReviewPriorityAdjustment > 0 {
			summary.AdjustedCandidates++
			summary.MaximumAppliedAdjustment = max(summary.MaximumAppliedAdjustment, candidate.ReviewPriorityAdjustment)
		}
	}
	for _, status := range jurisdictionContextStatusOrder() {
		if count := counts[status]; count > 0 {
			summary.Statuses = append(summary.Statuses, JurisdictionContextStatusCount{Status: status, Candidates: count})
		}
	}
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeJurisdictionContext, GeneratedAt: generatedAt, Evaluation: evaluation}
	canonical, err := json.Marshal(struct {
		Metadata               ResultMetadata                 `json:"metadata"`
		Version                string                         `json:"version"`
		OrganizationID         string                         `json:"organization_id"`
		SourceEnrichmentDigest AnalysisID                     `json:"source_enrichment_digest"`
		PolicyDigest           AnalysisID                     `json:"policy_digest"`
		PolicyFreshness        SourceEnrichmentFreshness      `json:"policy_freshness"`
		Candidates             []JurisdictionContextCandidate `json:"candidates"`
		Findings               []JurisdictionContextFinding   `json:"findings"`
		Summary                JurisdictionContextSummary     `json:"summary"`
	}{metadata, JurisdictionContextVersion, enrichment.OrganizationID(), enrichment.Digest(), policy.Digest(), policyFreshness, candidates, findings, summary})
	if err != nil {
		return JurisdictionContextResult{}, errors.Join(ErrInvalidJurisdictionContextOptions, err)
	}
	return JurisdictionContextResult{
		metadata: metadata, version: JurisdictionContextVersion, organizationID: enrichment.OrganizationID(),
		sourceEnrichmentDigest: enrichment.Digest(), policy: policy, policyFreshness: policyFreshness,
		digest: StableAnalysisID("jurisdiction_context", string(canonical)), candidates: cloneJurisdictionContextCandidates(candidates),
		findings: cloneJurisdictionContextFindings(findings), summary: cloneJurisdictionContextSummary(summary),
	}, nil
}

func jurisdictionContextStatusOrder() []JurisdictionContextStatus {
	return []JurisdictionContextStatus{
		JurisdictionContextMatch, JurisdictionContextNoMatch, JurisdictionContextConflicting, JurisdictionContextStale,
		JurisdictionContextUnknown, JurisdictionContextNotEligible, JurisdictionContextNotEvaluated,
	}
}

func jurisdictionPolicyEntryID(policyID, policyVersion string, entry JurisdictionRiskPolicyEntry) AnalysisID {
	parts := []string{policyID, policyVersion, entry.CountryCode, string(entry.Tier), fmt.Sprint(entry.ReviewPriorityAdjustment)}
	for _, code := range entry.Categories {
		parts = append(parts, string(code))
	}
	for _, code := range entry.Reasons {
		parts = append(parts, string(code))
	}
	return StableAnalysisID("jurisdiction_policy_entry", parts...)
}

func normalizeJurisdictionCategories(values []JurisdictionCategoryCode) []JurisdictionCategoryCode {
	result := append([]JurisdictionCategoryCode{}, values...)
	for index := range result {
		result[index] = JurisdictionCategoryCode(normalizeJurisdictionCode(string(result[index])))
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func normalizeJurisdictionReasons(values []JurisdictionReasonCode) []JurisdictionReasonCode {
	result := append([]JurisdictionReasonCode{}, values...)
	for index := range result {
		result[index] = JurisdictionReasonCode(normalizeJurisdictionCode(string(result[index])))
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func uniqueJurisdictionCategories(values []JurisdictionCategoryCode) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return false
		}
	}
	return true
}

func uniqueJurisdictionReasons(values []JurisdictionReasonCode) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return false
		}
	}
	return true
}

func normalizeJurisdictionCode(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validJurisdictionCode(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validJurisdictionVersion(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validJurisdictionSourceURI(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func validISO3166Alpha2Code(value string) bool {
	if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
		return false
	}
	const codes = "|AD|AE|AF|AG|AI|AL|AM|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW|"
	return strings.Contains(codes, "|"+value+"|")
}

func cloneJurisdictionPolicyEntries(values []JurisdictionRiskPolicyEntry) []JurisdictionRiskPolicyEntry {
	result := append([]JurisdictionRiskPolicyEntry{}, values...)
	for index := range result {
		result[index].Categories = append([]JurisdictionCategoryCode{}, result[index].Categories...)
		result[index].Reasons = append([]JurisdictionReasonCode{}, result[index].Reasons...)
	}
	return result
}

func cloneJurisdictionContextCandidates(values []JurisdictionContextCandidate) []JurisdictionContextCandidate {
	result := append([]JurisdictionContextCandidate{}, values...)
	for index := range result {
		result[index].AssertionReferences = append([]JurisdictionContextAssertionReference{}, result[index].AssertionReferences...)
		result[index].CountryCodes = cloneStrings(result[index].CountryCodes)
		result[index].PolicyEntryIDs = append([]AnalysisID{}, result[index].PolicyEntryIDs...)
		result[index].Categories = append([]JurisdictionCategoryCode{}, result[index].Categories...)
		result[index].Reasons = append([]JurisdictionReasonCode{}, result[index].Reasons...)
		result[index].FindingIDs = append([]FindingID{}, result[index].FindingIDs...)
	}
	return result
}

func cloneJurisdictionContextFindings(values []JurisdictionContextFinding) []JurisdictionContextFinding {
	result := append([]JurisdictionContextFinding{}, values...)
	for index := range result {
		result[index].AssertionIDs = append([]AnalysisID{}, result[index].AssertionIDs...)
		result[index].PolicyEntryIDs = append([]AnalysisID{}, result[index].PolicyEntryIDs...)
		result[index].CountryCodes = cloneStrings(result[index].CountryCodes)
		result[index].Categories = append([]JurisdictionCategoryCode{}, result[index].Categories...)
		result[index].Reasons = append([]JurisdictionReasonCode{}, result[index].Reasons...)
	}
	return result
}

func cloneJurisdictionContextSummary(value JurisdictionContextSummary) JurisdictionContextSummary {
	value.Statuses = append([]JurisdictionContextStatusCount{}, value.Statuses...)
	return value
}
