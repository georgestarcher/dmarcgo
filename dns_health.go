package dmarcgo

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// DNSHealthScoringVersion identifies the current DNS-health scoring algorithm.
const DNSHealthScoringVersion = "1"

// ErrInvalidDNSHealthOptions identifies an unsupported scoring or time option.
var ErrInvalidDNSHealthOptions = errors.New("invalid DNS health options")

// DNSHealthProfileName selects one inspectable scoring profile.
type DNSHealthProfileName string

const (
	DNSHealthProfileConservative DNSHealthProfileName = "conservative"
	DNSHealthProfileBalanced     DNSHealthProfileName = "balanced"
	DNSHealthProfileSensitive    DNSHealthProfileName = "sensitive"
)

// DNSHealthUnknownPolicy controls whether unavailable evidence remains unknown
// or receives the selected profile's explicit unknown-evidence deduction.
type DNSHealthUnknownPolicy string

const (
	DNSHealthUnknownPreserve DNSHealthUnknownPolicy = "preserve_unknown"
	DNSHealthUnknownPenalize DNSHealthUnknownPolicy = "penalize_unknown"
)

// DNSHealthScope identifies the organizational level of a finding or score.
type DNSHealthScope string

const (
	DNSHealthScopeRecord    DNSHealthScope = "record"
	DNSHealthScopeDomain    DNSHealthScope = "domain"
	DNSHealthScopeEntity    DNSHealthScope = "entity"
	DNSHealthScopePortfolio DNSHealthScope = "portfolio"
)

// DNSProviderInventoryState records whether a recognized provider is declared
// by an expected sender in the exact domain scope being evaluated.
type DNSProviderInventoryState string

const (
	DNSProviderInventoryDeclared    DNSProviderInventoryState = "declared"
	DNSProviderInventoryNotDeclared DNSProviderInventoryState = "not_declared"
)

// DNSHealthScoringProfile is the complete, inspectable set of deductions used
// by one named scoring profile. All values are non-negative point deductions.
type DNSHealthScoringProfile struct {
	Name                        DNSHealthProfileName `json:"name"`
	Version                     string               `json:"version"`
	MaximumScore                int                  `json:"maximum_score"`
	SPFWeight                   int                  `json:"spf_weight"`
	DKIMWeight                  int                  `json:"dkim_weight"`
	DMARCWeight                 int                  `json:"dmarc_weight"`
	MissingSPFRecord            int                  `json:"missing_spf_record"`
	MissingDKIMRecord           int                  `json:"missing_dkim_record"`
	MissingDMARCRecord          int                  `json:"missing_dmarc_record"`
	MalformedRecord             int                  `json:"malformed_record"`
	InvalidRecord               int                  `json:"invalid_record"`
	ConflictingRecord           int                  `json:"conflicting_record"`
	UnsupportedRecord           int                  `json:"unsupported_record"`
	WeakRecord                  int                  `json:"weak_record"`
	UnknownEvidence             int                  `json:"unknown_evidence"`
	SPFPermissiveAll            int                  `json:"spf_permissive_all"`
	SPFSoftFailAll              int                  `json:"spf_softfail_all"`
	SPFNeutralAll               int                  `json:"spf_neutral_all"`
	SPFNoAll                    int                  `json:"spf_no_all"`
	DKIMRevoked                 int                  `json:"dkim_revoked"`
	DKIMWeakKey                 int                  `json:"dkim_weak_key"`
	DKIMTesting                 int                  `json:"dkim_testing"`
	DMARCMonitoringOnly         int                  `json:"dmarc_monitoring_only"`
	DMARCQuarantine             int                  `json:"dmarc_quarantine"`
	DMARCTesting                int                  `json:"dmarc_testing"`
	DMARCLegacyTag              int                  `json:"dmarc_legacy_tag"`
	DMARCNoAggregateReporting   int                  `json:"dmarc_no_aggregate_reporting"`
	DMARCRelaxedAlignment       int                  `json:"dmarc_relaxed_alignment"`
	MissingMonitoredMechanism   int                  `json:"missing_monitored_mechanism"`
	UnmonitoredRequiredSelector int                  `json:"unmonitored_required_selector"`
	ChildPolicyWeaker           int                  `json:"child_policy_weaker"`
	StaleSnapshot               int                  `json:"stale_snapshot"`
}

// DNSHealthOptions controls pure evaluation. GeneratedAt defaults to the DNS
// observation time, preserving deterministic output. MaxSnapshotAge of zero
// disables staleness evaluation.
type DNSHealthOptions struct {
	Profile        DNSHealthProfileName
	GeneratedAt    time.Time
	MaxSnapshotAge time.Duration
	UnknownPolicy  DNSHealthUnknownPolicy
}

// DNSHealthScoreContribution explains one score change. Explanation is always
// library-generated and never includes DNS record text.
type DNSHealthScoreContribution struct {
	Code        FindingCode `json:"code"`
	Points      int         `json:"points"`
	FindingIDs  []FindingID `json:"finding_ids"`
	Explanation string      `json:"explanation"`
}

// DNSHealthGrade is a stable presentation band for an available health score.
type DNSHealthGrade string

const (
	DNSHealthGradeAPlus   DNSHealthGrade = "A+"
	DNSHealthGradeA       DNSHealthGrade = "A"
	DNSHealthGradeB       DNSHealthGrade = "B"
	DNSHealthGradeC       DNSHealthGrade = "C"
	DNSHealthGradeD       DNSHealthGrade = "D"
	DNSHealthGradeF       DNSHealthGrade = "F"
	DNSHealthGradeUnknown DNSHealthGrade = "U"
)

// DNSHealthScore is a bounded score plus its complete recomputation evidence.
// Available distinguishes an evaluated zero from an unavailable placeholder;
// unavailable scores also retain an explicit unknown Evaluation.
type DNSHealthScore struct {
	Available     bool                         `json:"available"`
	Value         int                          `json:"value"`
	Maximum       int                          `json:"maximum"`
	Grade         DNSHealthGrade               `json:"grade"`
	Evaluation    Evaluation                   `json:"evaluation"`
	Contributions []DNSHealthScoreContribution `json:"contributions"`
}

// DNSHealthFinding is one stable, evidence-linked posture conclusion. Summary,
// Recommendation, and Standard are library-controlled strings.
type DNSHealthFinding struct {
	ID             FindingID         `json:"id"`
	Code           FindingCode       `json:"code"`
	Severity       FindingSeverity   `json:"severity"`
	Confidence     FindingConfidence `json:"confidence"`
	Scope          DNSHealthScope    `json:"scope"`
	OrganizationID string            `json:"organization_id,omitempty"`
	EntityID       string            `json:"entity_id,omitempty"`
	Domain         string            `json:"domain,omitempty"`
	Name           string            `json:"name,omitempty"`
	RecordType     DNSRecordType     `json:"record_type,omitempty"`
	EvidenceIDs    []EvidenceID      `json:"evidence_ids"`
	Evaluation     Evaluation        `json:"evaluation"`
	ScoreImpact    int               `json:"score_impact"`
	Summary        string            `json:"summary"`
	Recommendation string            `json:"recommendation,omitempty"`
	Standard       string            `json:"standard,omitempty"`
	Sensitivity    Sensitivity       `json:"sensitivity"`
}

// DNSHealthProviderContext links one recognized static SPF dependency to
// catalog and domain-inventory context. It is evidence only and never changes
// health findings, scores, or sender authorization.
type DNSHealthProviderContext struct {
	ID                AnalysisID                `json:"id"`
	EntityID          string                    `json:"entity_id"`
	Domain            string                    `json:"domain"`
	SPFRecordName     string                    `json:"spf_record_name"`
	RelationshipType  string                    `json:"relationship_type"`
	EvidenceID        EvidenceID                `json:"evidence_id"`
	Provider          ProviderMatch             `json:"provider"`
	InventoryState    DNSProviderInventoryState `json:"inventory_state"`
	ExpectedSenderIDs []string                  `json:"expected_sender_ids"`
	Evaluation        Evaluation                `json:"evaluation"`
	Sensitivity       Sensitivity               `json:"sensitivity"`
}

// DNSRecordHealth evaluates one configured record name in one domain scope.
type DNSRecordHealth struct {
	ID          AnalysisID                 `json:"id"`
	EntityID    string                     `json:"entity_id"`
	Domain      string                     `json:"domain"`
	Name        string                     `json:"name"`
	Type        DNSRecordType              `json:"type"`
	Status      AuthenticationRecordStatus `json:"status"`
	ObservedAt  time.Time                  `json:"observed_at"`
	DNSSEC      DNSSECEvidence             `json:"dnssec"`
	EvidenceIDs []EvidenceID               `json:"evidence_ids"`
	FindingIDs  []FindingID                `json:"finding_ids"`
	Score       DNSHealthScore             `json:"score"`
}

// DNSHealthMechanismScores exposes independent SPF, DKIM, and DMARC component
// scores before the domain's weighted 30/35/35 rollup.
type DNSHealthMechanismScores struct {
	SPF   DNSHealthScore `json:"spf"`
	DKIM  DNSHealthScore `json:"dkim"`
	DMARC DNSHealthScore `json:"dmarc"`
}

// DNSDomainHealth rolls configured record health into one normalized domain.
type DNSDomainHealth struct {
	ID         AnalysisID               `json:"id"`
	EntityID   string                   `json:"entity_id"`
	Domain     string                   `json:"domain"`
	Owner      string                   `json:"owner,omitempty"`
	RecordIDs  []AnalysisID             `json:"record_ids"`
	FindingIDs []FindingID              `json:"finding_ids"`
	Mechanisms DNSHealthMechanismScores `json:"mechanisms"`
	Score      DNSHealthScore           `json:"score"`
	Maturity   DNSHealthMaturity        `json:"maturity"`
}

// DNSEntityHealth rolls domain health into one business entity.
type DNSEntityHealth struct {
	ID                  AnalysisID        `json:"id"`
	EntityID            string            `json:"entity_id"`
	Parent              string            `json:"parent,omitempty"`
	PortfolioIncluded   bool              `json:"portfolio_included"`
	PortfolioEvaluation Evaluation        `json:"portfolio_evaluation"`
	DomainIDs           []AnalysisID      `json:"domain_ids"`
	FindingIDs          []FindingID       `json:"finding_ids"`
	Score               DNSHealthScore    `json:"score"`
	Maturity            DNSHealthMaturity `json:"maturity"`
}

// DNSHealthResult is an immutable DNS-only posture result. Accessors return
// defensive copies and never perform parsing, DNS, report, or filesystem I/O.
type DNSHealthResult struct {
	metadata              ResultMetadata
	portfolioDigest       AnalysisID
	snapshotDigest        AnalysisID
	authenticationDigest  AnalysisID
	providerCatalogDigest AnalysisID
	digest                AnalysisID
	profile               DNSHealthScoringProfile
	providerProvenance    ProviderCatalogProvenance
	portfolioScore        DNSHealthScore
	portfolioMaturity     DNSHealthMaturity
	records               []DNSRecordHealth
	domains               []DNSDomainHealth
	entities              []DNSEntityHealth
	findings              []DNSHealthFinding
	providerContexts      []DNSHealthProviderContext
}

func (result DNSHealthResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result DNSHealthResult) PortfolioDigest() AnalysisID    { return result.portfolioDigest }
func (result DNSHealthResult) SnapshotDigest() AnalysisID     { return result.snapshotDigest }

// AuthenticationDigest returns the exact parsed authentication input digest.
func (result DNSHealthResult) AuthenticationDigest() AnalysisID {
	return result.authenticationDigest
}

// ProviderCatalogDigest returns the exact provider-catalog input digest.
func (result DNSHealthResult) ProviderCatalogDigest() AnalysisID { return result.providerCatalogDigest }

func (result DNSHealthResult) Digest() AnalysisID               { return result.digest }
func (result DNSHealthResult) Profile() DNSHealthScoringProfile { return result.profile }

// ProviderCatalogProvenance returns the exact catalog provenance used by the evaluation.
func (result DNSHealthResult) ProviderCatalogProvenance() ProviderCatalogProvenance {
	return cloneProviderCatalogProvenance(result.providerProvenance)
}

func (result DNSHealthResult) PortfolioScore() DNSHealthScore {
	return cloneDNSHealthScore(result.portfolioScore)
}

// PortfolioMaturity returns the conservative domain-maturity rollup.
func (result DNSHealthResult) PortfolioMaturity() DNSHealthMaturity {
	return cloneDNSHealthMaturity(result.portfolioMaturity)
}
func (result DNSHealthResult) Records() []DNSRecordHealth {
	return cloneDNSRecordHealth(result.records)
}
func (result DNSHealthResult) Domains() []DNSDomainHealth {
	return cloneDNSDomainHealth(result.domains)
}
func (result DNSHealthResult) Entities() []DNSEntityHealth {
	return cloneDNSEntityHealth(result.entities)
}
func (result DNSHealthResult) Findings() []DNSHealthFinding {
	return cloneDNSHealthFindings(result.findings)
}

// ProviderContexts returns recognized static SPF dependencies in stable order.
func (result DNSHealthResult) ProviderContexts() []DNSHealthProviderContext {
	return cloneDNSHealthProviderContexts(result.providerContexts)
}

// DNSHealthScoringProfiles returns all built-in profiles in stable
// conservative, balanced, and sensitive order.
func DNSHealthScoringProfiles() []DNSHealthScoringProfile {
	return []DNSHealthScoringProfile{
		dnsHealthConservativeProfile(), dnsHealthBalancedProfile(), dnsHealthSensitiveProfile(),
	}
}

// DNSHealthScoringProfileForName returns one built-in scoring profile.
func DNSHealthScoringProfileForName(name DNSHealthProfileName) (DNSHealthScoringProfile, bool) {
	for _, profile := range DNSHealthScoringProfiles() {
		if profile.Name == name {
			return profile, true
		}
	}
	return DNSHealthScoringProfile{}, false
}

func dnsHealthConservativeProfile() DNSHealthScoringProfile {
	return DNSHealthScoringProfile{
		Name: DNSHealthProfileConservative, Version: DNSHealthScoringVersion, MaximumScore: 100,
		SPFWeight: 30, DKIMWeight: 35, DMARCWeight: 35,
		MissingSPFRecord: 50, MissingDKIMRecord: 50, MissingDMARCRecord: 50,
		MalformedRecord: 60, InvalidRecord: 60, ConflictingRecord: 70,
		UnsupportedRecord: 10, WeakRecord: 10, UnknownEvidence: 5,
		SPFPermissiveAll: 20, SPFSoftFailAll: 5, SPFNeutralAll: 15, SPFNoAll: 5,
		DKIMRevoked: 20, DKIMWeakKey: 10, DKIMTesting: 5,
		DMARCMonitoringOnly: 20, DMARCQuarantine: 8, DMARCTesting: 10, DMARCLegacyTag: 3, DMARCNoAggregateReporting: 5, DMARCRelaxedAlignment: 0,
		MissingMonitoredMechanism: 15, UnmonitoredRequiredSelector: 15, ChildPolicyWeaker: 5, StaleSnapshot: 0,
	}
}

func dnsHealthBalancedProfile() DNSHealthScoringProfile {
	return DNSHealthScoringProfile{
		Name: DNSHealthProfileBalanced, Version: DNSHealthScoringVersion, MaximumScore: 100,
		SPFWeight: 30, DKIMWeight: 35, DMARCWeight: 35,
		MissingSPFRecord: 100, MissingDKIMRecord: 100, MissingDMARCRecord: 70,
		MalformedRecord: 100, InvalidRecord: 100, ConflictingRecord: 100,
		UnsupportedRecord: 20, WeakRecord: 20, UnknownEvidence: 10,
		SPFPermissiveAll: 30, SPFSoftFailAll: 10, SPFNeutralAll: 30, SPFNoAll: 10,
		DKIMRevoked: 30, DKIMWeakKey: 15, DKIMTesting: 10,
		DMARCMonitoringOnly: 30, DMARCQuarantine: 12, DMARCTesting: 25, DMARCLegacyTag: 5, DMARCNoAggregateReporting: 10, DMARCRelaxedAlignment: 0,
		MissingMonitoredMechanism: 25, UnmonitoredRequiredSelector: 25, ChildPolicyWeaker: 10, StaleSnapshot: 10,
	}
}

func dnsHealthSensitiveProfile() DNSHealthScoringProfile {
	return DNSHealthScoringProfile{
		Name: DNSHealthProfileSensitive, Version: DNSHealthScoringVersion, MaximumScore: 100,
		SPFWeight: 30, DKIMWeight: 35, DMARCWeight: 35,
		MissingSPFRecord: 100, MissingDKIMRecord: 100, MissingDMARCRecord: 85,
		MalformedRecord: 100, InvalidRecord: 100, ConflictingRecord: 100,
		UnsupportedRecord: 30, WeakRecord: 30, UnknownEvidence: 20,
		SPFPermissiveAll: 40, SPFSoftFailAll: 15, SPFNeutralAll: 40, SPFNoAll: 15,
		DKIMRevoked: 45, DKIMWeakKey: 25, DKIMTesting: 15,
		DMARCMonitoringOnly: 40, DMARCQuarantine: 18, DMARCTesting: 35, DMARCLegacyTag: 8, DMARCNoAggregateReporting: 15, DMARCRelaxedAlignment: 5,
		MissingMonitoredMechanism: 35, UnmonitoredRequiredSelector: 35, ChildPolicyWeaker: 15, StaleSnapshot: 20,
	}
}

type dnsHealthEvaluator struct {
	portfolio          Portfolio
	authentication     DNSAuthenticationResult
	providerCatalog    ProviderCatalog
	profile            DNSHealthScoringProfile
	options            DNSHealthOptions
	organization       Organization
	sets               map[string]AuthenticationRecordSet
	senders            map[string]ExpectedSender
	providerSenderIDs  map[string][]string
	providerContextIDs map[AnalysisID]struct{}
	findings           []DNSHealthFinding
	records            []DNSRecordHealth
	domains            []DNSDomainHealth
	entities           []DNSEntityHealth
	providerContexts   []DNSHealthProviderContext
}

// EvaluateDNSHealth evaluates a normalized portfolio and already parsed DNS
// authentication evidence using an explicitly supplied provider catalog. It
// performs no DNS, report, filesystem, time, or other I/O and never reparses
// TXT record text. Provider recognition is context only and never affects scores.
func EvaluateDNSHealth(portfolio Portfolio, authentication DNSAuthenticationResult, providerCatalog ProviderCatalog, options DNSHealthOptions) (DNSHealthResult, error) {
	profileName := options.Profile
	if profileName == "" {
		profileName = DNSHealthProfileBalanced
	}
	profile, ok := DNSHealthScoringProfileForName(profileName)
	if !ok {
		return DNSHealthResult{}, errors.Join(ErrInvalidDNSHealthOptions, errors.New("unsupported scoring profile"))
	}
	unknownPolicy := options.UnknownPolicy
	if unknownPolicy == "" {
		unknownPolicy = DNSHealthUnknownPreserve
	}
	if unknownPolicy != DNSHealthUnknownPreserve && unknownPolicy != DNSHealthUnknownPenalize {
		return DNSHealthResult{}, errors.Join(ErrInvalidDNSHealthOptions, errors.New("unsupported unknown-evidence policy"))
	}
	if options.MaxSnapshotAge < 0 {
		return DNSHealthResult{}, errors.Join(ErrInvalidDNSHealthOptions, errors.New("negative maximum snapshot age"))
	}
	metadata := authentication.ResultMetadata()
	if portfolio.Digest() == "" || authentication.Digest() == "" || authentication.SnapshotDigest() == "" || providerCatalog.Digest() == "" ||
		metadata.ContractVersion != AnalysisContractVersion || metadata.Mode != AnalysisModeDNSAuthentication ||
		authentication.PortfolioDigest() != portfolio.Digest() {
		return DNSHealthResult{}, ErrInvalidAnalysisResult
	}
	generatedAt := options.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = metadata.GeneratedAt.UTC()
	}
	if generatedAt.Before(metadata.GeneratedAt) {
		return DNSHealthResult{}, errors.Join(ErrInvalidDNSHealthOptions, errors.New("generation time predates DNS observation"))
	}
	options.Profile = profileName
	options.UnknownPolicy = unknownPolicy
	options.GeneratedAt = generatedAt

	evaluator := dnsHealthEvaluator{
		portfolio: portfolio, authentication: authentication, providerCatalog: providerCatalog, profile: profile, options: options,
		organization: portfolio.Organization(), sets: map[string]AuthenticationRecordSet{}, senders: map[string]ExpectedSender{},
		providerSenderIDs: map[string][]string{}, providerContextIDs: map[AnalysisID]struct{}{},
		findings: []DNSHealthFinding{}, records: []DNSRecordHealth{}, domains: []DNSDomainHealth{}, entities: []DNSEntityHealth{}, providerContexts: []DNSHealthProviderContext{},
	}
	for _, set := range authentication.RecordSets() {
		evaluator.sets[dnsHealthRecordKey(set.Name, set.Type)] = set
	}
	for _, sender := range portfolio.ExpectedSenders() {
		evaluator.senders[sender.ID] = sender
	}
	evaluator.indexProviderSenders()
	evaluator.evaluate()
	portfolioScore := evaluator.portfolioHealthScore()
	portfolioMaturity := evaluator.portfolioHealthMaturity()
	evaluator.addPortfolioRollupFinding(portfolioScore)
	evaluator.addStaleSnapshotFinding(&portfolioScore, metadata.GeneratedAt)
	evaluator.sort()

	canonical, err := json.Marshal(struct {
		PortfolioDigest       AnalysisID                 `json:"portfolio_digest"`
		SnapshotDigest        AnalysisID                 `json:"snapshot_digest"`
		AuthenticationDigest  AnalysisID                 `json:"authentication_digest"`
		ProviderCatalogDigest AnalysisID                 `json:"provider_catalog_digest"`
		ProviderProvenance    ProviderCatalogProvenance  `json:"provider_provenance"`
		GeneratedAt           time.Time                  `json:"generated_at"`
		Profile               DNSHealthScoringProfile    `json:"profile"`
		PortfolioScore        DNSHealthScore             `json:"portfolio_score"`
		PortfolioMaturity     DNSHealthMaturity          `json:"portfolio_maturity"`
		Records               []DNSRecordHealth          `json:"records"`
		Domains               []DNSDomainHealth          `json:"domains"`
		Entities              []DNSEntityHealth          `json:"entities"`
		Findings              []DNSHealthFinding         `json:"findings"`
		ProviderContexts      []DNSHealthProviderContext `json:"provider_contexts"`
	}{portfolio.Digest(), authentication.SnapshotDigest(), authentication.Digest(), providerCatalog.Digest(), providerCatalog.Provenance(), generatedAt, profile, portfolioScore, portfolioMaturity,
		evaluator.records, evaluator.domains, evaluator.entities, evaluator.findings, evaluator.providerContexts})
	if err != nil {
		return DNSHealthResult{}, errors.Join(ErrInvalidAnalysisResult, err)
	}
	return DNSHealthResult{
		metadata:        ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeDNSHealth, GeneratedAt: generatedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}},
		portfolioDigest: portfolio.Digest(), snapshotDigest: authentication.SnapshotDigest(), authenticationDigest: authentication.Digest(),
		providerCatalogDigest: providerCatalog.Digest(), providerProvenance: providerCatalog.Provenance(),
		digest: StableAnalysisID("dns_health", string(canonical)), profile: profile, portfolioScore: cloneDNSHealthScore(portfolioScore), portfolioMaturity: cloneDNSHealthMaturity(portfolioMaturity),
		records: cloneDNSRecordHealth(evaluator.records), domains: cloneDNSDomainHealth(evaluator.domains), entities: cloneDNSEntityHealth(evaluator.entities), findings: cloneDNSHealthFindings(evaluator.findings), providerContexts: cloneDNSHealthProviderContexts(evaluator.providerContexts),
	}, nil
}

func (evaluator *dnsHealthEvaluator) evaluate() {
	for _, entity := range evaluator.portfolio.Entities() {
		entityHealth := DNSEntityHealth{
			ID: StableAnalysisID("dns_health_entity", evaluator.organization.ID, entity.ID), EntityID: entity.ID, Parent: entity.Parent,
			PortfolioIncluded:   entity.Membership != PortfolioMembershipReference,
			PortfolioEvaluation: Evaluation{State: EvaluationStateEvaluated}, DomainIDs: []AnalysisID{}, FindingIDs: []FindingID{},
		}
		if !entityHealth.PortfolioIncluded {
			entityHealth.PortfolioEvaluation = Evaluation{State: EvaluationStateNotApplicable, Reason: "The portfolio marks this entity as a reference, so it is excluded from organization rollups."}
		}
		entityDomainScores := make([]DNSHealthScore, 0, len(entity.Domains))
		for _, domain := range entity.Domains {
			domainHealth := evaluator.evaluateDomain(entity, domain)
			evaluator.domains = append(evaluator.domains, domainHealth)
			entityHealth.DomainIDs = append(entityHealth.DomainIDs, domainHealth.ID)
			entityHealth.FindingIDs = append(entityHealth.FindingIDs, domainHealth.FindingIDs...)
			entityDomainScores = append(entityDomainScores, domainHealth.Score)
		}
		entityHealth.FindingIDs = compactSortedFindingIDs(entityHealth.FindingIDs)
		entityHealth.Score = rollupDNSHealthScores(entityDomainScores, evaluator.profile.MaximumScore, "dns.health.entity_rollup", entityHealth.FindingIDs, "Entity score is the mean of available domain scores.")
		domainMaturities := make([]DNSHealthMaturity, 0, len(entity.Domains))
		for _, domainID := range entityHealth.DomainIDs {
			for _, domainHealth := range evaluator.domains {
				if domainHealth.ID == domainID {
					domainMaturities = append(domainMaturities, domainHealth.Maturity)
					break
				}
			}
		}
		entityHealth.Maturity = rollupDNSHealthMaturity(domainMaturities)
		rollupFinding := evaluator.newRollupFinding(DNSHealthScopeEntity, entity.ID, "", entityHealth.Score)
		if rollupFinding.Code != "" {
			evaluator.findings = append(evaluator.findings, rollupFinding)
			entityHealth.FindingIDs = compactSortedFindingIDs(append(entityHealth.FindingIDs, rollupFinding.ID))
		}
		evaluator.entities = append(evaluator.entities, entityHealth)
	}
}

func (evaluator *dnsHealthEvaluator) evaluateDomain(entity Entity, domain MonitoredDomain) DNSDomainHealth {
	domainHealth := DNSDomainHealth{
		ID: StableAnalysisID("dns_health_domain", evaluator.organization.ID, entity.ID, domain.Name), EntityID: entity.ID, Domain: domain.Name, Owner: domain.Owner,
		RecordIDs: []AnalysisID{}, FindingIDs: []FindingID{},
	}
	recordScores := map[DNSRecordType][]DNSHealthScore{}
	recordFindingIDs := map[DNSRecordType][]FindingID{}
	domainRecords := make([]DNSRecordHealth, 0)
	childFindingIDs := make([]FindingID, 0)
	for _, recordType := range []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC} {
		for _, name := range monitoredRecordNames(domain.Records, recordType) {
			record := evaluator.evaluateRecord(entity.ID, domain.Name, name, recordType)
			evaluator.records = append(evaluator.records, record)
			domainRecords = append(domainRecords, record)
			domainHealth.RecordIDs = append(domainHealth.RecordIDs, record.ID)
			domainHealth.FindingIDs = append(domainHealth.FindingIDs, record.FindingIDs...)
			childFindingIDs = append(childFindingIDs, record.FindingIDs...)
			recordScores[recordType] = append(recordScores[recordType], record.Score)
			recordFindingIDs[recordType] = append(recordFindingIDs[recordType], record.FindingIDs...)
		}
	}
	directFindings := evaluator.evaluateDomainConfiguration(entity, domain)
	for _, finding := range directFindings {
		evaluator.findings = append(evaluator.findings, finding)
		domainHealth.FindingIDs = append(domainHealth.FindingIDs, finding.ID)
	}
	domainHealth.FindingIDs = compactSortedFindingIDs(domainHealth.FindingIDs)
	if applicableDMARC, ok := evaluator.domainDMARCRecordName(domain); ok {
		for _, record := range domainRecords {
			if record.Type == DNSRecordDMARC && record.Name == applicableDMARC {
				recordScores[DNSRecordDMARC] = []DNSHealthScore{record.Score}
				recordFindingIDs[DNSRecordDMARC] = append([]FindingID(nil), record.FindingIDs...)
				break
			}
		}
	} else {
		recordScores[DNSRecordDMARC] = nil
		recordFindingIDs[DNSRecordDMARC] = nil
	}
	domainHealth.Mechanisms = buildDNSHealthMechanismScores(recordScores, recordFindingIDs, evaluator.profile.MaximumScore)
	domainHealth.Score = rollupDNSHealthMechanismScores(domainHealth.Mechanisms, evaluator.profile, compactSortedFindingIDs(childFindingIDs))
	applyDNSHealthFindings(&domainHealth.Score, directFindings)
	domainHealth.Maturity = evaluator.evaluateDomainMaturity(entity, domain, domainRecords)
	rollupFinding := evaluator.newRollupFinding(DNSHealthScopeDomain, entity.ID, domain.Name, domainHealth.Score)
	if rollupFinding.Code != "" {
		evaluator.findings = append(evaluator.findings, rollupFinding)
		domainHealth.FindingIDs = compactSortedFindingIDs(append(domainHealth.FindingIDs, rollupFinding.ID))
	}
	return domainHealth
}

func (evaluator *dnsHealthEvaluator) evaluateRecord(entityID, domain, name string, recordType DNSRecordType) DNSRecordHealth {
	recordHealth := DNSRecordHealth{
		ID:       StableAnalysisID("dns_health_record", evaluator.organization.ID, entityID, domain, string(recordType), name),
		EntityID: entityID, Domain: domain, Name: name, Type: recordType, FindingIDs: []FindingID{}, EvidenceIDs: []EvidenceID{},
	}
	set, ok := evaluator.sets[dnsHealthRecordKey(name, recordType)]
	if !ok {
		recordHealth.Status = AuthenticationRecordIndeterminate
		recordHealth.ObservedAt = evaluator.authentication.ResultMetadata().GeneratedAt
		finding := evaluator.newFinding("dns.health.record_not_evaluated", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, recordType, nil, EvaluationStateUnknown, evaluator.unknownImpact(),
			"The configured record has no corresponding parsed DNS evidence.", "Evaluate a snapshot planned from the same normalized portfolio.", "")
		evaluator.findings = append(evaluator.findings, finding)
		recordHealth.FindingIDs = []FindingID{finding.ID}
		recordHealth.Score = evaluator.unknownScore(finding)
		return recordHealth
	}
	recordHealth.Status = set.Status
	recordHealth.ObservedAt = set.ObservedAt
	recordHealth.DNSSEC = set.DNSSEC
	for _, record := range set.Records {
		recordHealth.EvidenceIDs = append(recordHealth.EvidenceIDs, record.EvidenceID)
	}
	recordHealth.EvidenceIDs = compactSortedEvidenceIDs(recordHealth.EvidenceIDs)
	findings := evaluator.evaluateRecordSet(entityID, domain, set)
	if set.DNSSEC.Available && !set.DNSSEC.AuthenticatedData {
		findings = append(findings, evaluator.newFinding("dns.health.dnssec_not_authenticated", FindingSeverityInfo, FindingConfidenceMedium, DNSHealthScopeRecord,
			entityID, domain, set.Name, set.Type, recordHealth.EvidenceIDs, EvaluationStateUnknown, 0,
			"The resolver exposed DNSSEC metadata without an authenticated-data result.", "Confirm whether the selected resolver validates DNSSEC before drawing a DNSSEC conclusion.", "https://www.rfc-editor.org/rfc/rfc4035.html"))
	}
	for _, finding := range findings {
		evaluator.findings = append(evaluator.findings, finding)
		recordHealth.FindingIDs = append(recordHealth.FindingIDs, finding.ID)
	}
	recordHealth.FindingIDs = compactSortedFindingIDs(recordHealth.FindingIDs)
	if set.Status == AuthenticationRecordIndeterminate {
		if len(findings) > 0 {
			recordHealth.Score = evaluator.unknownScore(findings[0])
		} else {
			recordHealth.Score = DNSHealthScore{Available: false, Maximum: evaluator.profile.MaximumScore, Grade: DNSHealthGradeUnknown, Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: "DNS evidence is unavailable."}, Contributions: []DNSHealthScoreContribution{}}
		}
	} else {
		recordHealth.Score = evaluatedDNSHealthScore(evaluator.profile.MaximumScore)
		applyDNSHealthFindings(&recordHealth.Score, findings)
	}
	return recordHealth
}

func (evaluator *dnsHealthEvaluator) evaluateRecordSet(entityID, domain string, set AuthenticationRecordSet) []DNSHealthFinding {
	findings := make([]DNSHealthFinding, 0)
	evidenceIDs := make([]EvidenceID, 0, len(set.Records))
	for _, record := range set.Records {
		evidenceIDs = append(evidenceIDs, record.EvidenceID)
	}
	evidenceIDs = compactSortedEvidenceIDs(evidenceIDs)
	statusCode, severity, impact, summary, recommendation := evaluator.statusFinding(set.Status, set.Type)
	if statusCode != "" {
		state := EvaluationStateEvaluated
		if set.Status == AuthenticationRecordIndeterminate {
			state = EvaluationStateUnknown
		}
		findings = append(findings, evaluator.newFinding(statusCode, severity, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, set.Name, set.Type, evidenceIDs, state, impact, summary, recommendation, standardForRecordType(set.Type)))
	}
	if len(set.Records) != 1 {
		return findings
	}
	record := set.Records[0]
	switch set.Type {
	case DNSRecordSPF:
		if record.SPF != nil {
			findings = append(findings, evaluator.evaluateSPF(entityID, domain, set.Name, *record.SPF, record.EvidenceID)...)
		}
	case DNSRecordDKIM:
		if record.DKIM != nil {
			findings = append(findings, evaluator.evaluateDKIM(entityID, domain, set.Name, *record.DKIM, record.EvidenceID)...)
		}
	case DNSRecordDMARC:
		if record.DMARC != nil {
			findings = append(findings, evaluator.evaluateDMARC(entityID, domain, set.Name, *record.DMARC, record.EvidenceID)...)
		}
	}
	// A weak parser status is the record-level classification of the more
	// specific semantic findings below. Keep the classification visible, but
	// charge only the specific deductions when they are available.
	if set.Status == AuthenticationRecordWeak && len(findings) > 1 {
		for _, finding := range findings[1:] {
			if finding.ScoreImpact < 0 {
				findings[0].ScoreImpact = 0
				break
			}
		}
	}
	return findings
}

func (evaluator *dnsHealthEvaluator) statusFinding(status AuthenticationRecordStatus, recordType DNSRecordType) (FindingCode, FindingSeverity, int, string, string) {
	switch status {
	case AuthenticationRecordMissing:
		impact := evaluator.profile.MissingDMARCRecord
		switch recordType {
		case DNSRecordSPF:
			impact = evaluator.profile.MissingSPFRecord
		case DNSRecordDKIM:
			impact = evaluator.profile.MissingDKIMRecord
		}
		return "dns.health.record_missing", FindingSeverityHigh, -impact, "A configured authentication record is missing.", "Publish or correct the configured authentication record."
	case AuthenticationRecordMalformed:
		return "dns.health.record_malformed", FindingSeverityHigh, -evaluator.profile.MalformedRecord, "A configured authentication record is malformed.", "Correct the record syntax before relying on it."
	case AuthenticationRecordInvalid:
		return "dns.health.record_invalid", FindingSeverityHigh, -evaluator.profile.InvalidRecord, "A configured authentication record is invalid.", "Correct the invalid record and validate it again."
	case AuthenticationRecordConflicting:
		return "dns.health.record_conflicting", FindingSeverityHigh, -evaluator.profile.ConflictingRecord, "Multiple candidate authentication records conflict at one owner name.", "Publish exactly one usable policy record at the owner name."
	case AuthenticationRecordUnsupported:
		return "dns.health.record_unsupported", FindingSeverityMedium, -evaluator.profile.UnsupportedRecord, "The record uses semantics this evaluator cannot fully assess.", "Review the preserved record evidence with an implementation that supports those semantics."
	case AuthenticationRecordWeak:
		return "dns.health.record_weak", FindingSeverityMedium, -evaluator.profile.WeakRecord, "The record parser identified a weak authentication configuration.", "Review the record-specific findings and strengthen the configuration where appropriate."
	case AuthenticationRecordIndeterminate:
		return "dns.health.evidence_unknown", FindingSeverityLow, evaluator.unknownImpact(), "DNS evidence is unavailable, so record health is unknown.", "Retry explicit DNS collection later or use another trusted resolver."
	default:
		return "", "", 0, "", ""
	}
}

func (evaluator *dnsHealthEvaluator) evaluateSPF(entityID, domain, name string, record SPFRecord, evidenceID EvidenceID) []DNSHealthFinding {
	evaluator.collectProviderContexts(entityID, domain, name, record, evidenceID)
	findings := make([]DNSHealthFinding, 0)
	all, hasAll := firstSPFAllTerm(record)
	if !hasAll && !hasSPFRedirect(record) {
		findings = append(findings, evaluator.newFinding("dns.health.spf_no_all", FindingSeverityLow, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordSPF, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.SPFNoAll,
			"The SPF record has no all mechanism and may not express a complete default result.", "Review whether an explicit terminal all mechanism is appropriate.", spfStandardReference))
	} else {
		switch all.Qualifier {
		case SPFQualifierPass:
			findings = append(findings, evaluator.newFinding("dns.health.spf_permissive_all", FindingSeverityHigh, FindingConfidenceHigh, DNSHealthScopeRecord,
				entityID, domain, name, DNSRecordSPF, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.SPFPermissiveAll,
				"The SPF all mechanism authorizes every source.", "Replace permissive +all with a policy that authorizes only intended senders.", spfStandardReference))
		case SPFQualifierSoftFail:
			findings = append(findings, evaluator.newFinding("dns.health.spf_non_enforcing_all", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
				entityID, domain, name, DNSRecordSPF, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.SPFSoftFailAll,
				"The SPF all mechanism returns a non-enforcing result.", "Confirm that the terminal SPF result matches the intended authorization posture.", spfStandardReference))
		case SPFQualifierNeutral:
			findings = append(findings, evaluator.newFinding("dns.health.spf_neutral_all", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
				entityID, domain, name, DNSRecordSPF, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.SPFNeutralAll,
				"The SPF all mechanism returns neutral for every otherwise unmatched source.", "Replace neutral policy with an explicit authorization result that matches the sender model.", spfStandardReference))
		}
	}
	if len(record.Relationships) > 0 && !record.Lookup.ExpandedAvailable {
		findings = append(findings, evaluator.newFinding("dns.health.spf_dependency_evidence_incomplete", FindingSeverityInfo, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordSPF, []EvidenceID{evidenceID}, EvaluationStateUnknown, 0,
			"The supplied snapshot does not contain a complete SPF dependency graph.", "Collect every declared SPF dependency when complete expanded-lookup evidence is required.", spfStandardReference))
	}
	return findings
}

func firstSPFAllTerm(record SPFRecord) (SPFTerm, bool) {
	for _, term := range record.Terms {
		if term.Mechanism == "all" {
			return term, true
		}
	}
	return SPFTerm{}, false
}

func hasSPFRedirect(record SPFRecord) bool {
	for _, term := range record.Terms {
		if term.Modifier == "redirect" {
			return true
		}
	}
	return false
}

func (evaluator *dnsHealthEvaluator) indexProviderSenders() {
	for _, entity := range evaluator.portfolio.Entities() {
		for _, domain := range entity.Domains {
			for _, senderID := range domain.ExpectedSenders {
				sender, ok := evaluator.senders[senderID]
				if !ok || sender.Provider == "" {
					continue
				}
				provider, ok := evaluator.providerCatalog.LookupProvider(sender.Provider)
				if !ok {
					continue
				}
				key := dnsProviderInventoryKey(entity.ID, domain.Name, provider.ID)
				evaluator.providerSenderIDs[key] = append(evaluator.providerSenderIDs[key], sender.ID)
			}
		}
	}
	for key, senderIDs := range evaluator.providerSenderIDs {
		evaluator.providerSenderIDs[key] = compactSortedStrings(senderIDs)
	}
}

func (evaluator *dnsHealthEvaluator) collectProviderContexts(entityID, domain, name string, record SPFRecord, evidenceID EvidenceID) {
	for _, relationship := range record.Relationships {
		match, ok := evaluator.providerCatalog.MatchSPFRelationship(relationship)
		if !ok {
			continue
		}
		senderIDs := cloneStrings(evaluator.providerSenderIDs[dnsProviderInventoryKey(entityID, domain, match.ProviderID)])
		inventoryState := DNSProviderInventoryNotDeclared
		if len(senderIDs) > 0 {
			inventoryState = DNSProviderInventoryDeclared
		}
		id := StableAnalysisID("dns_health_provider_context", string(evaluator.providerCatalog.Digest()), entityID, domain, name, relationship.Type, match.MatchedInclude, match.ProviderID, string(evidenceID))
		if _, exists := evaluator.providerContextIDs[id]; exists {
			continue
		}
		evaluator.providerContextIDs[id] = struct{}{}
		evaluator.providerContexts = append(evaluator.providerContexts, DNSHealthProviderContext{
			ID: id, EntityID: entityID, Domain: domain, SPFRecordName: name,
			RelationshipType: relationship.Type, EvidenceID: evidenceID, Provider: match,
			InventoryState: inventoryState, ExpectedSenderIDs: senderIDs,
			Evaluation: Evaluation{State: EvaluationStateEvaluated}, Sensitivity: SensitivityOperational,
		})
	}
}

func dnsProviderInventoryKey(entityID, domain, providerID string) string {
	return entityID + "\x00" + domain + "\x00" + providerID
}

func (evaluator *dnsHealthEvaluator) evaluateDKIM(entityID, domain, name string, record DKIMKeyRecord, evidenceID EvidenceID) []DNSHealthFinding {
	findings := make([]DNSHealthFinding, 0)
	if record.Revoked {
		findings = append(findings, evaluator.newFinding("dns.health.dkim_selector_revoked", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDKIM, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DKIMRevoked,
			"The configured DKIM selector is explicitly revoked.", "Remove the selector from active sender configuration or publish a current public key.", dkimStandardReference))
	}
	if record.KeyType == "rsa" && record.KeyBits > 0 && record.KeyBits < 2048 {
		findings = append(findings, evaluator.newFinding("dns.health.dkim_weak_key", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDKIM, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DKIMWeakKey,
			"The DKIM RSA key is shorter than the recommended 2048 bits.", "Rotate the selector to a stronger supported key.", dkimCryptoReference))
	}
	for _, flag := range record.Flags {
		if flag == "y" {
			findings = append(findings, evaluator.newFinding("dns.health.dkim_testing", FindingSeverityLow, FindingConfidenceHigh, DNSHealthScopeRecord,
				entityID, domain, name, DNSRecordDKIM, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DKIMTesting,
				"The DKIM selector is marked for testing.", "Confirm that testing mode remains intentional before treating the selector as production-ready.", dkimStandardReference))
			break
		}
	}
	return findings
}

func (evaluator *dnsHealthEvaluator) evaluateDMARC(entityID, domain, name string, record DMARCPolicyRecord, evidenceID EvidenceID) []DNSHealthFinding {
	findings := make([]DNSHealthFinding, 0)
	effectivePolicy := dmarcPolicyForConfiguredDomain(domain, name, record)
	if effectivePolicy == DMARCPolicyNone {
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_monitoring_only", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDMARC, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DMARCMonitoringOnly,
			"The effective DMARC policy is monitoring only.", "Move toward quarantine or reject after validating every legitimate sending path.", dmarcStandardReference))
	}
	if effectivePolicy == DMARCPolicyQuarantine {
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_quarantine", FindingSeverityLow, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDMARC, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DMARCQuarantine,
			"The effective DMARC policy requests quarantine rather than rejection.", "Confirm whether quarantine is the intended steady state or a staged transition toward rejection.", dmarcStandardReference))
	}
	if record.Testing {
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_testing", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDMARC, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DMARCTesting,
			"DMARC testing mode reduces the effective enforcement level.", "Disable testing mode after confirming the published enforcement policy is safe.", dmarcStandardReference))
	}
	if len(record.AggregateReports) == 0 {
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_no_aggregate_reporting", FindingSeverityLow, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDMARC, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DMARCNoAggregateReporting,
			"The DMARC record has no aggregate-report destination.", "Consider a controlled aggregate-report destination for ongoing visibility.", dmarcStandardReference))
	}
	if len(record.RemovedLegacyTags) > 0 {
		count := len(record.RemovedLegacyTags)
		if count > 2 {
			count = 2
		}
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_legacy_tags", FindingSeverityLow, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDMARC, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -(evaluator.profile.DMARCLegacyTag*count),
			"The DMARC record contains tags removed from the current standard.", "Remove obsolete DMARC tags after confirming the current policy intent.", dmarcStandardReference))
	}
	if record.DKIMAlignment == DMARCAlignmentRelaxed || record.SPFAlignment == DMARCAlignmentRelaxed {
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_relaxed_alignment", FindingSeverityInfo, FindingConfidenceHigh, DNSHealthScopeRecord,
			entityID, domain, name, DNSRecordDMARC, []EvidenceID{evidenceID}, EvaluationStateEvaluated, -evaluator.profile.DMARCRelaxedAlignment,
			"At least one DMARC alignment mode is relaxed.", "Confirm relaxed alignment is appropriate for the organization's sender model.", dmarcStandardReference))
	}
	return findings
}

func (evaluator *dnsHealthEvaluator) evaluateDomainConfiguration(entity Entity, domain MonitoredDomain) []DNSHealthFinding {
	findings := make([]DNSHealthFinding, 0)
	if len(domain.Records.SPF) == 0 {
		findings = append(findings, evaluator.newFinding("dns.health.spf_not_monitored", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeDomain,
			entity.ID, domain.Name, "", DNSRecordSPF, nil, EvaluationStateEvaluated, -evaluator.profile.MissingMonitoredMechanism,
			"The domain has no configured SPF record name to evaluate.", "Declare the complete SPF owner name or document why the domain is outside SPF monitoring.", spfStandardReference))
	}
	if len(orderedDMARCRecordNames(domain.Name, domain.Records.DMARC)) == 0 {
		findings = append(findings, evaluator.newFinding("dns.health.dmarc_not_monitored", FindingSeverityHigh, FindingConfidenceHigh, DNSHealthScopeDomain,
			entity.ID, domain.Name, "", DNSRecordDMARC, nil, EvaluationStateEvaluated, -evaluator.profile.MissingMonitoredMechanism,
			"The domain has no applicable configured DMARC record name to evaluate.", "Declare the complete DMARC policy owner name for the domain or one of its DNS ancestors.", dmarcStandardReference))
	}
	requireDKIM, requireSPF, requireEither, selectors := evaluator.domainSenderRequirements(domain)
	if requireDKIM && len(domain.Records.DKIM) == 0 {
		findings = append(findings, evaluator.newFinding("dns.health.dkim_required_not_monitored", FindingSeverityHigh, FindingConfidenceHigh, DNSHealthScopeDomain,
			entity.ID, domain.Name, "", DNSRecordDKIM, nil, EvaluationStateEvaluated, -evaluator.profile.MissingMonitoredMechanism,
			"An expected sender requires DKIM, but no DKIM selector record is configured for monitoring.", "Add every required complete DKIM selector record name.", dkimStandardReference))
	}
	if requireSPF && len(domain.Records.SPF) == 0 {
		findings = append(findings, evaluator.newFinding("dns.health.spf_required_not_monitored", FindingSeverityHigh, FindingConfidenceHigh, DNSHealthScopeDomain,
			entity.ID, domain.Name, "", DNSRecordSPF, nil, EvaluationStateEvaluated, 0,
			"An expected sender requires SPF, but no SPF record is configured for monitoring.", "Add the required complete SPF record name.", spfStandardReference))
	}
	if requireEither && len(domain.Records.SPF) == 0 && len(domain.Records.DKIM) == 0 {
		findings = append(findings, evaluator.newFinding("dns.health.required_authentication_not_monitored", FindingSeverityHigh, FindingConfidenceHigh, DNSHealthScopeDomain,
			entity.ID, domain.Name, "", "", nil, EvaluationStateEvaluated, 0,
			"An expected sender requires SPF or DKIM, but neither mechanism is configured for monitoring.", "Add at least one required authentication record name.", ""))
	}
	configuredSelectors := map[string]bool{}
	for _, name := range domain.Records.DKIM {
		selector, _, found := strings.Cut(name, "._domainkey.")
		if found {
			configuredSelectors[selector] = true
		}
	}
	for _, selector := range selectors {
		if configuredSelectors[selector] {
			continue
		}
		impact := -evaluator.profile.UnmonitoredRequiredSelector
		if requireDKIM && len(domain.Records.DKIM) == 0 {
			impact = 0
		}
		findings = append(findings, evaluator.newFinding("dns.health.dkim_required_selector_unmonitored", FindingSeverityHigh, FindingConfidenceHigh, DNSHealthScopeDomain,
			entity.ID, domain.Name, selector, DNSRecordDKIM, nil, EvaluationStateEvaluated, impact,
			"A sender policy names a DKIM selector that is not configured for monitoring.", "Add the selector's complete _domainkey record name or correct the sender policy.", dkimStandardReference))
	}
	if domain.Parent != "" {
		parent, ok := findMonitoredDomain(entity.Domains, domain.Parent)
		if ok {
			parentPolicy, parentEvidence, parentOK := evaluator.domainDMARCPolicy(parent)
			childPolicy, childEvidence, childOK := evaluator.domainDMARCPolicy(domain)
			if parentOK && childOK && dmarcPolicyRank(childPolicy) < dmarcPolicyRank(parentPolicy) {
				evidence := compactSortedEvidenceIDs(append(parentEvidence, childEvidence...))
				findings = append(findings, evaluator.newFinding("dns.health.dmarc_child_policy_weaker", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopeDomain,
					entity.ID, domain.Name, "", DNSRecordDMARC, evidence, EvaluationStateEvaluated, -evaluator.profile.ChildPolicyWeaker,
					"The child domain's effective DMARC policy is weaker than its configured parent domain policy.", "Confirm the weaker child policy is intentional and time-bounded.", dmarcStandardReference))
			}
		}
	}
	return findings
}

func (evaluator *dnsHealthEvaluator) domainSenderRequirements(domain MonitoredDomain) (bool, bool, bool, []string) {
	selectors := make([]string, 0)
	var requireDKIM, requireSPF, requireEither bool
	for _, senderID := range domain.ExpectedSenders {
		sender, ok := evaluator.senders[senderID]
		if !ok {
			continue
		}
		requireDKIM = requireDKIM || sender.Policy.RequireDKIM
		requireSPF = requireSPF || sender.Policy.RequireSPF
		requireEither = requireEither || sender.Policy.RequireEither
		selectors = append(selectors, sender.Policy.AllowedSelectors...)
	}
	return requireDKIM, requireSPF, requireEither, compactSortedStrings(selectors)
}

func (evaluator *dnsHealthEvaluator) domainDMARCPolicy(domain MonitoredDomain) (DMARCPolicy, []EvidenceID, bool) {
	name, ok := evaluator.domainDMARCRecordName(domain)
	if !ok {
		return "", nil, false
	}
	set, ok := evaluator.sets[dnsHealthRecordKey(name, DNSRecordDMARC)]
	if !ok || (set.Status != AuthenticationRecordValid && set.Status != AuthenticationRecordWeak) || len(set.Records) != 1 || set.Records[0].DMARC == nil {
		return "", nil, false
	}
	policy := dmarcPolicyForConfiguredDomain(domain.Name, name, *set.Records[0].DMARC)
	if policy == "" {
		return "", nil, false
	}
	return policy, []EvidenceID{set.Records[0].EvidenceID}, true
}

type dmarcPolicyScope int

const (
	dmarcPolicyScopeExact dmarcPolicyScope = iota
	dmarcPolicyScopeSubdomain
	dmarcPolicyScopeNonexistent
)

func dmarcPolicyForConfiguredDomain(domain, recordName string, record DMARCPolicyRecord) DMARCPolicy {
	scope := dmarcPolicyScopeExact
	if recordName != "_dmarc."+domain {
		scope = dmarcPolicyScopeSubdomain
	}
	return effectiveDMARCPolicyForScope(record, scope)
}

func effectiveDMARCPolicyForScope(record DMARCPolicyRecord, scope dmarcPolicyScope) DMARCPolicy {
	policy := record.Policy
	if policy == "" {
		policy = record.EffectivePolicy
	}
	switch scope {
	case dmarcPolicyScopeSubdomain:
		if record.SubdomainPolicy != "" {
			policy = record.SubdomainPolicy
		}
	case dmarcPolicyScopeNonexistent:
		if record.NonexistentPolicy != "" {
			policy = record.NonexistentPolicy
		} else if record.SubdomainPolicy != "" {
			policy = record.SubdomainPolicy
		}
	}
	if record.Testing {
		policy = testingDMARCPolicy(policy)
	}
	return policy
}

func dmarcPolicyIsEnforced(policy DMARCPolicy) bool {
	return policy == DMARCPolicyQuarantine || policy == DMARCPolicyReject
}

func (evaluator *dnsHealthEvaluator) domainDMARCRecordName(domain MonitoredDomain) (string, bool) {
	names := orderedDMARCRecordNames(domain.Name, domain.Records.DMARC)
	for _, name := range names {
		set, ok := evaluator.sets[dnsHealthRecordKey(name, DNSRecordDMARC)]
		if ok && set.Status == AuthenticationRecordMissing {
			continue
		}
		// DMARC discovery may continue only after conclusive absence. An
		// invalid, conflicting, or unavailable record at a closer owner blocks
		// fallback to a more distant inherited policy.
		return name, true
	}
	if len(names) > 0 {
		// Preserve known absence as the closest applicable component rather
		// than allowing unrelated configured owners into the fallback walk.
		return names[0], true
	}
	return "", false
}

func orderedDMARCRecordNames(domain string, names []string) []string {
	ordered := make([]string, 0, len(names))
	for _, name := range names {
		if _, ancestor := dmarcRecordDistance(domain, name); ancestor {
			ordered = append(ordered, name)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		leftDistance, _ := dmarcRecordDistance(domain, ordered[i])
		rightDistance, _ := dmarcRecordDistance(domain, ordered[j])
		if leftDistance != rightDistance {
			return leftDistance < rightDistance
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}

func dmarcRecordDistance(domain, name string) (int, bool) {
	const prefix = "_dmarc."
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	policyDomain := strings.TrimPrefix(name, prefix)
	if domain == policyDomain {
		return 0, true
	}
	if !strings.HasSuffix(domain, "."+policyDomain) {
		return 0, false
	}
	return strings.Count(domain, ".") - strings.Count(policyDomain, "."), true
}

func (evaluator *dnsHealthEvaluator) newFinding(code FindingCode, severity FindingSeverity, confidence FindingConfidence, scope DNSHealthScope,
	entityID, domain, name string, recordType DNSRecordType, evidenceIDs []EvidenceID, state EvaluationState, impact int,
	summary, recommendation, standard string,
) DNSHealthFinding {
	evidenceIDs = compactSortedEvidenceIDs(evidenceIDs)
	idParts := []string{string(code), string(scope), evaluator.organization.ID, entityID, domain, name, string(recordType), string(state)}
	for _, evidenceID := range evidenceIDs {
		idParts = append(idParts, string(evidenceID))
	}
	return DNSHealthFinding{
		ID: FindingID(StableAnalysisID("dns_health_finding", idParts...)), Code: code, Severity: severity, Confidence: confidence, Scope: scope,
		OrganizationID: evaluator.organization.ID, EntityID: entityID, Domain: domain, Name: name, RecordType: recordType,
		EvidenceIDs: evidenceIDs, Evaluation: Evaluation{State: state}, ScoreImpact: impact, Summary: summary,
		Recommendation: recommendation, Standard: standard, Sensitivity: SensitivityOperational,
	}
}

func (evaluator *dnsHealthEvaluator) unknownImpact() int {
	if evaluator.options.UnknownPolicy == DNSHealthUnknownPenalize {
		return -evaluator.profile.UnknownEvidence
	}
	return 0
}

func (evaluator *dnsHealthEvaluator) unknownScore(finding DNSHealthFinding) DNSHealthScore {
	if evaluator.options.UnknownPolicy == DNSHealthUnknownPenalize {
		score := evaluatedDNSHealthScore(evaluator.profile.MaximumScore)
		applyDNSHealthFindings(&score, []DNSHealthFinding{finding})
		return score
	}
	return DNSHealthScore{
		Available: false, Maximum: evaluator.profile.MaximumScore, Grade: DNSHealthGradeUnknown,
		Evaluation:    Evaluation{State: EvaluationStateUnknown, Reason: "DNS evidence is unavailable and the selected policy preserves unknown state."},
		Contributions: []DNSHealthScoreContribution{},
	}
}

func (evaluator *dnsHealthEvaluator) portfolioHealthScore() DNSHealthScore {
	scores := make([]DNSHealthScore, 0, len(evaluator.entities))
	findingIDs := make([]FindingID, 0)
	for _, entity := range evaluator.entities {
		if !entity.PortfolioIncluded {
			continue
		}
		scores = append(scores, entity.Score)
		findingIDs = append(findingIDs, entity.FindingIDs...)
	}
	return rollupDNSHealthScores(scores, evaluator.profile.MaximumScore, "dns.health.portfolio_rollup", compactSortedFindingIDs(findingIDs), "Portfolio score is the mean of available entity scores.")
}

func (evaluator *dnsHealthEvaluator) portfolioHealthMaturity() DNSHealthMaturity {
	maturities := make([]DNSHealthMaturity, 0, len(evaluator.entities))
	for _, entity := range evaluator.entities {
		if !entity.PortfolioIncluded {
			continue
		}
		maturities = append(maturities, entity.Maturity)
	}
	return rollupDNSHealthMaturity(maturities)
}

func (evaluator *dnsHealthEvaluator) newRollupFinding(scope DNSHealthScope, entityID, domain string, score DNSHealthScore) DNSHealthFinding {
	if !score.Available {
		return evaluator.newFinding("dns.health.rollup_unknown", FindingSeverityLow, FindingConfidenceHigh, scope,
			entityID, domain, "", "", nil, EvaluationStateUnknown, 0,
			"No evaluated child scores are available for this scope.", "Restore missing DNS evidence before relying on this rollup.", "")
	}
	if score.Value == score.Maximum {
		return DNSHealthFinding{}
	}
	severity := FindingSeverityLow
	if score.Value < 50 {
		severity = FindingSeverityHigh
	} else if score.Value < 80 {
		severity = FindingSeverityMedium
	}
	return evaluator.newFinding("dns.health.rollup_degraded", severity, FindingConfidenceHigh, scope,
		entityID, domain, "", "", nil, EvaluationStateEvaluated, 0,
		"Child DNS authentication findings reduce this scope's health score.", "Review the linked record and domain findings in score order.", "")
}

func (evaluator *dnsHealthEvaluator) addPortfolioRollupFinding(score DNSHealthScore) {
	finding := evaluator.newRollupFinding(DNSHealthScopePortfolio, "", "", score)
	if finding.Code != "" {
		evaluator.findings = append(evaluator.findings, finding)
	}
}

func (evaluator *dnsHealthEvaluator) addStaleSnapshotFinding(score *DNSHealthScore, observedAt time.Time) {
	if evaluator.options.MaxSnapshotAge == 0 || evaluator.options.GeneratedAt.Sub(observedAt) <= evaluator.options.MaxSnapshotAge {
		return
	}
	impact := -evaluator.profile.StaleSnapshot
	if !score.Available {
		impact = 0
	}
	finding := evaluator.newFinding("dns.health.snapshot_stale", FindingSeverityMedium, FindingConfidenceHigh, DNSHealthScopePortfolio,
		"", "", "", "", nil, EvaluationStateEvaluated, impact,
		"The DNS snapshot is older than the caller's maximum accepted age.", "Collect a new explicit DNS snapshot before making current-posture decisions.", "")
	evaluator.findings = append(evaluator.findings, finding)
	if score.Available {
		applyDNSHealthFindings(score, []DNSHealthFinding{finding})
	}
}

func evaluatedDNSHealthScore(maximum int) DNSHealthScore {
	return DNSHealthScore{
		Available: true, Value: maximum, Maximum: maximum, Grade: dnsHealthGrade(maximum, true), Evaluation: Evaluation{State: EvaluationStateEvaluated},
		Contributions: []DNSHealthScoreContribution{},
	}
}

func applyDNSHealthFindings(score *DNSHealthScore, findings []DNSHealthFinding) {
	for _, finding := range findings {
		if finding.ScoreImpact == 0 {
			continue
		}
		if !score.Available {
			score.Available = true
			score.Value = score.Maximum
			score.Evaluation = Evaluation{State: EvaluationStateEvaluated}
		}
		score.Value += finding.ScoreImpact
		if score.Value < 0 {
			score.Value = 0
		}
		if score.Value > score.Maximum {
			score.Value = score.Maximum
		}
		score.Contributions = append(score.Contributions, DNSHealthScoreContribution{
			Code: finding.Code, Points: finding.ScoreImpact, FindingIDs: []FindingID{finding.ID}, Explanation: finding.Summary,
		})
	}
	sortDNSHealthContributions(score.Contributions)
	score.Grade = dnsHealthGrade(score.Value, score.Available)
}

func rollupDNSHealthScores(scores []DNSHealthScore, maximum int, code FindingCode, findingIDs []FindingID, explanation string) DNSHealthScore {
	total, count := 0, 0
	for _, score := range scores {
		if !score.Available {
			continue
		}
		total += score.Value
		count++
	}
	if count == 0 {
		return DNSHealthScore{
			Available: false, Maximum: maximum, Grade: DNSHealthGradeUnknown, Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: "No evaluated child scores are available."},
			Contributions: []DNSHealthScoreContribution{},
		}
	}
	value := (total + count/2) / count
	result := evaluatedDNSHealthScore(maximum)
	result.Value = value
	result.Grade = dnsHealthGrade(value, true)
	if value != maximum {
		result.Contributions = append(result.Contributions, DNSHealthScoreContribution{
			Code: code, Points: value - maximum, FindingIDs: compactSortedFindingIDs(findingIDs), Explanation: explanation,
		})
	}
	return result
}

func buildDNSHealthMechanismScores(scores map[DNSRecordType][]DNSHealthScore, findingIDs map[DNSRecordType][]FindingID, maximum int) DNSHealthMechanismScores {
	return DNSHealthMechanismScores{
		SPF:   rollupDNSHealthScores(scores[DNSRecordSPF], maximum, "dns.health.spf_component_rollup", findingIDs[DNSRecordSPF], "SPF component score is the mean of available configured SPF record scores."),
		DKIM:  rollupDNSHealthScores(scores[DNSRecordDKIM], maximum, "dns.health.dkim_component_rollup", findingIDs[DNSRecordDKIM], "DKIM component score is the mean of available configured selector scores."),
		DMARC: rollupDNSHealthScores(scores[DNSRecordDMARC], maximum, "dns.health.dmarc_component_rollup", findingIDs[DNSRecordDMARC], "DMARC component score is the mean of available configured policy-record scores."),
	}
}

func rollupDNSHealthMechanismScores(scores DNSHealthMechanismScores, profile DNSHealthScoringProfile, findingIDs []FindingID) DNSHealthScore {
	weights := map[DNSRecordType]int{
		DNSRecordSPF: profile.SPFWeight, DNSRecordDKIM: profile.DKIMWeight, DNSRecordDMARC: profile.DMARCWeight,
	}
	mechanisms := map[DNSRecordType]DNSHealthScore{
		DNSRecordSPF: scores.SPF, DNSRecordDKIM: scores.DKIM, DNSRecordDMARC: scores.DMARC,
	}
	weightedTotal, availableWeight := 0, 0
	for _, recordType := range []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC} {
		mechanism := mechanisms[recordType]
		if !mechanism.Available || weights[recordType] <= 0 {
			continue
		}
		weightedTotal += mechanism.Value * weights[recordType]
		availableWeight += weights[recordType]
	}
	if availableWeight == 0 {
		return DNSHealthScore{
			Available: false, Maximum: profile.MaximumScore, Grade: DNSHealthGradeUnknown,
			Evaluation:    Evaluation{State: EvaluationStateUnknown, Reason: "No evaluated authentication-mechanism scores are available."},
			Contributions: []DNSHealthScoreContribution{},
		}
	}
	value := (weightedTotal + availableWeight/2) / availableWeight
	result := evaluatedDNSHealthScore(profile.MaximumScore)
	result.Value = value
	result.Grade = dnsHealthGrade(value, true)
	if value != profile.MaximumScore {
		result.Contributions = append(result.Contributions, DNSHealthScoreContribution{
			Code: "dns.health.domain_weighted_rollup", Points: value - profile.MaximumScore,
			FindingIDs:  compactSortedFindingIDs(findingIDs),
			Explanation: "Domain score combines available SPF, DKIM, and DMARC component scores using the profile's 30/35/35 weights.",
		})
	}
	return result
}

func dnsHealthGrade(value int, available bool) DNSHealthGrade {
	if !available {
		return DNSHealthGradeUnknown
	}
	switch {
	case value >= 95:
		return DNSHealthGradeAPlus
	case value >= 90:
		return DNSHealthGradeA
	case value >= 80:
		return DNSHealthGradeB
	case value >= 70:
		return DNSHealthGradeC
	case value >= 60:
		return DNSHealthGradeD
	default:
		return DNSHealthGradeF
	}
}

func monitoredRecordNames(records MonitoredRecords, recordType DNSRecordType) []string {
	switch recordType {
	case DNSRecordSPF:
		return records.SPF
	case DNSRecordDKIM:
		return records.DKIM
	case DNSRecordDMARC:
		return records.DMARC
	default:
		return nil
	}
}

func dnsHealthRecordKey(name string, recordType DNSRecordType) string {
	return string(recordType) + "\x00" + name
}

func findMonitoredDomain(domains []MonitoredDomain, name string) (MonitoredDomain, bool) {
	for _, domain := range domains {
		if domain.Name == name {
			return domain, true
		}
	}
	return MonitoredDomain{}, false
}

func dmarcPolicyRank(policy DMARCPolicy) int {
	switch policy {
	case DMARCPolicyReject:
		return 3
	case DMARCPolicyQuarantine:
		return 2
	case DMARCPolicyNone:
		return 1
	default:
		return 0
	}
}

func compactSortedFindingIDs(values []FindingID) []FindingID {
	if len(values) == 0 {
		return []FindingID{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return append([]FindingID(nil), result...)
}

func compactSortedEvidenceIDs(values []EvidenceID) []EvidenceID {
	if len(values) == 0 {
		return []EvidenceID{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return append([]EvidenceID(nil), result...)
}

func sortDNSHealthContributions(values []DNSHealthScoreContribution) {
	for index := range values {
		values[index].FindingIDs = compactSortedFindingIDs(values[index].FindingIDs)
	}
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Code != values[j].Code {
			return values[i].Code < values[j].Code
		}
		if values[i].Points != values[j].Points {
			return values[i].Points < values[j].Points
		}
		return strings.Join(findingIDsToStrings(values[i].FindingIDs), "\x00") < strings.Join(findingIDsToStrings(values[j].FindingIDs), "\x00")
	})
}

func findingIDsToStrings(values []FindingID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func (evaluator *dnsHealthEvaluator) sort() {
	sort.Slice(evaluator.records, func(i, j int) bool {
		if evaluator.records[i].EntityID != evaluator.records[j].EntityID {
			return evaluator.records[i].EntityID < evaluator.records[j].EntityID
		}
		if evaluator.records[i].Domain != evaluator.records[j].Domain {
			return evaluator.records[i].Domain < evaluator.records[j].Domain
		}
		if evaluator.records[i].Type != evaluator.records[j].Type {
			return evaluator.records[i].Type < evaluator.records[j].Type
		}
		return evaluator.records[i].Name < evaluator.records[j].Name
	})
	sort.Slice(evaluator.domains, func(i, j int) bool {
		if evaluator.domains[i].EntityID != evaluator.domains[j].EntityID {
			return evaluator.domains[i].EntityID < evaluator.domains[j].EntityID
		}
		return evaluator.domains[i].Domain < evaluator.domains[j].Domain
	})
	sort.Slice(evaluator.entities, func(i, j int) bool { return evaluator.entities[i].EntityID < evaluator.entities[j].EntityID })
	sort.Slice(evaluator.providerContexts, func(i, j int) bool {
		left, right := evaluator.providerContexts[i], evaluator.providerContexts[j]
		if left.EntityID != right.EntityID {
			return left.EntityID < right.EntityID
		}
		if left.Domain != right.Domain {
			return left.Domain < right.Domain
		}
		if left.SPFRecordName != right.SPFRecordName {
			return left.SPFRecordName < right.SPFRecordName
		}
		if left.Provider.ProviderID != right.Provider.ProviderID {
			return left.Provider.ProviderID < right.Provider.ProviderID
		}
		if left.Provider.MatchedInclude != right.Provider.MatchedInclude {
			return left.Provider.MatchedInclude < right.Provider.MatchedInclude
		}
		return left.ID < right.ID
	})
	sort.Slice(evaluator.findings, func(i, j int) bool {
		if evaluator.findings[i].Severity != evaluator.findings[j].Severity {
			return dnsHealthSeverityRank(evaluator.findings[i].Severity) > dnsHealthSeverityRank(evaluator.findings[j].Severity)
		}
		if evaluator.findings[i].Code != evaluator.findings[j].Code {
			return evaluator.findings[i].Code < evaluator.findings[j].Code
		}
		return evaluator.findings[i].ID < evaluator.findings[j].ID
	})
}

func dnsHealthSeverityRank(value FindingSeverity) int {
	switch value {
	case FindingSeverityCritical:
		return 5
	case FindingSeverityHigh:
		return 4
	case FindingSeverityMedium:
		return 3
	case FindingSeverityLow:
		return 2
	case FindingSeverityInfo:
		return 1
	default:
		return 0
	}
}

func cloneDNSHealthScore(value DNSHealthScore) DNSHealthScore {
	value.Contributions = append([]DNSHealthScoreContribution(nil), value.Contributions...)
	for index := range value.Contributions {
		value.Contributions[index].FindingIDs = append([]FindingID(nil), value.Contributions[index].FindingIDs...)
	}
	return value
}

func cloneDNSRecordHealth(values []DNSRecordHealth) []DNSRecordHealth {
	result := append([]DNSRecordHealth(nil), values...)
	for index := range result {
		result[index].EvidenceIDs = append([]EvidenceID(nil), result[index].EvidenceIDs...)
		result[index].FindingIDs = append([]FindingID(nil), result[index].FindingIDs...)
		result[index].Score = cloneDNSHealthScore(result[index].Score)
	}
	return result
}

func cloneDNSDomainHealth(values []DNSDomainHealth) []DNSDomainHealth {
	result := append([]DNSDomainHealth(nil), values...)
	for index := range result {
		result[index].RecordIDs = append([]AnalysisID(nil), result[index].RecordIDs...)
		result[index].FindingIDs = append([]FindingID(nil), result[index].FindingIDs...)
		result[index].Mechanisms.SPF = cloneDNSHealthScore(result[index].Mechanisms.SPF)
		result[index].Mechanisms.DKIM = cloneDNSHealthScore(result[index].Mechanisms.DKIM)
		result[index].Mechanisms.DMARC = cloneDNSHealthScore(result[index].Mechanisms.DMARC)
		result[index].Score = cloneDNSHealthScore(result[index].Score)
		result[index].Maturity = cloneDNSHealthMaturity(result[index].Maturity)
	}
	return result
}

func cloneDNSEntityHealth(values []DNSEntityHealth) []DNSEntityHealth {
	result := append([]DNSEntityHealth(nil), values...)
	for index := range result {
		result[index].DomainIDs = append([]AnalysisID(nil), result[index].DomainIDs...)
		result[index].FindingIDs = append([]FindingID(nil), result[index].FindingIDs...)
		result[index].Score = cloneDNSHealthScore(result[index].Score)
		result[index].Maturity = cloneDNSHealthMaturity(result[index].Maturity)
	}
	return result
}

func cloneDNSHealthFindings(values []DNSHealthFinding) []DNSHealthFinding {
	result := append([]DNSHealthFinding(nil), values...)
	for index := range result {
		result[index].EvidenceIDs = append([]EvidenceID(nil), result[index].EvidenceIDs...)
	}
	return result
}

func cloneDNSHealthProviderContexts(values []DNSHealthProviderContext) []DNSHealthProviderContext {
	result := append([]DNSHealthProviderContext(nil), values...)
	for index := range result {
		result[index].ExpectedSenderIDs = cloneStrings(result[index].ExpectedSenderIDs)
	}
	return result
}

func cloneProviderCatalogProvenance(value ProviderCatalogProvenance) ProviderCatalogProvenance {
	value.AddedProviderIDs = cloneStrings(value.AddedProviderIDs)
	value.ReplacedProviderIDs = cloneStrings(value.ReplacedProviderIDs)
	return value
}
