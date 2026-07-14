package dmarcgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// CampaignClassificationVersion identifies the pure reported-message matching
// contract.
const CampaignClassificationVersion = "1"

const defaultCampaignMaximumEvaluated = 1024
const defaultCampaignMaximumRelevant = 64

var (
	// ErrInvalidCampaignClassificationOptions identifies inconsistent inputs,
	// generation times, or work limits.
	ErrInvalidCampaignClassificationOptions = errors.New("invalid campaign classification options")
	// ErrCampaignClassificationWorkLimit identifies a bounded evaluation that
	// could not safely consider every in-scope campaign. It never returns a
	// potentially incomplete authorization decision.
	ErrCampaignClassificationWorkLimit = errors.New("campaign classification work limit exceeded")
)

// CampaignClassification is a stable workflow category, not a blanket trust,
// maliciousness, or safe-to-delete verdict.
type CampaignClassification string

const (
	CampaignAuthorizedHighConfidence CampaignClassification = "authorized_simulation_high_confidence"
	CampaignPossibleAuthorized       CampaignClassification = "possible_authorized_simulation"
	CampaignConfigurationMismatch    CampaignClassification = "simulation_configuration_mismatch"
	CampaignOutsideWindow            CampaignClassification = "simulation_outside_campaign_window"
	CampaignAuthorizationExpired     CampaignClassification = "simulation_authorization_expired"
	CampaignAuthorizationUnavailable CampaignClassification = "simulation_authorization_unavailable"
	CampaignUnknownSuspiciousMessage CampaignClassification = "unknown_suspicious_message"
)

// CampaignFactorState is the result of evaluating one factor independently.
type CampaignFactorState string

const (
	CampaignFactorMatched      CampaignFactorState = "matched"
	CampaignFactorMismatched   CampaignFactorState = "mismatched"
	CampaignFactorMissing      CampaignFactorState = "missing"
	CampaignFactorUnverifiable CampaignFactorState = "unverifiable"
)

// CampaignFactorEvaluation preserves positive, contradictory, missing, and
// unverifiable evidence without copying raw evidence values.
type CampaignFactorEvaluation struct {
	Factor      CampaignMatchFactor `json:"factor"`
	State       CampaignFactorState `json:"state"`
	Required    bool                `json:"required"`
	EvidenceIDs []EvidenceID        `json:"evidence_ids"`
	Sensitivity Sensitivity         `json:"sensitivity"`
}

// CampaignClassificationRecord is one campaign-specific evaluation. Campaign
// and source identifiers are restricted data and are omitted from disclosure-
// safe output.
type CampaignClassificationRecord struct {
	ID                           AnalysisID                 `json:"id"`
	EvidenceID                   EvidenceID                 `json:"evidence_id"`
	CampaignID                   string                     `json:"campaign_id"`
	CampaignDigest               AnalysisID                 `json:"campaign_digest"`
	SourceID                     string                     `json:"authorization_source"`
	Classification               CampaignClassification     `json:"classification"`
	Confidence                   FindingConfidence          `json:"confidence"`
	Factors                      []CampaignFactorEvaluation `json:"factors"`
	Matched                      []CampaignMatchFactor      `json:"matched"`
	Mismatched                   []CampaignMatchFactor      `json:"mismatched"`
	Missing                      []CampaignMatchFactor      `json:"missing"`
	Unverifiable                 []CampaignMatchFactor      `json:"unverifiable"`
	EmployeeDisclosure           CampaignEmployeeDisclosure `json:"employee_disclosure"`
	PrivilegedWorkflowID         string                     `json:"privileged_workflow_id,omitempty"`
	PrivilegedEmployeeTemplateID string                     `json:"privileged_employee_template_id,omitempty"`
	AutomaticDispositionEligible bool                       `json:"automatic_disposition_eligible"`
	AggregateEvidenceOnly        bool                       `json:"aggregate_evidence_only"`
	AuthenticationRetained       bool                       `json:"authentication_findings_retained"`
	Sensitivity                  Sensitivity                `json:"sensitivity"`
}

// CampaignClassificationFinding is library-controlled prose linked to
// normalized records and evidence. No untrusted string is interpolated.
type CampaignClassificationFinding struct {
	ID              FindingID              `json:"id"`
	Code            FindingCode            `json:"code"`
	Severity        FindingSeverity        `json:"severity"`
	Confidence      FindingConfidence      `json:"confidence"`
	Classification  CampaignClassification `json:"classification"`
	RecordIDs       []AnalysisID           `json:"record_ids"`
	EvidenceIDs     []EvidenceID           `json:"evidence_ids"`
	Summary         string                 `json:"summary"`
	Recommendation  string                 `json:"recommendation"`
	AutomaticAction bool                   `json:"automatic_action"`
	Sensitivity     Sensitivity            `json:"sensitivity"`
}

// CampaignClassificationCount is a deterministic summary count.
type CampaignClassificationCount struct {
	Classification CampaignClassification `json:"classification"`
	Records        int                    `json:"records"`
}

// CampaignClassificationSummary describes the bounded evaluation.
type CampaignClassificationSummary struct {
	OverallClassification     CampaignClassification        `json:"overall_classification"`
	CampaignsAvailable        int                           `json:"campaigns_available"`
	CampaignsEvaluated        int                           `json:"campaigns_evaluated"`
	RelevantRecords           int                           `json:"relevant_records"`
	HighConfidenceRecords     int                           `json:"high_confidence_records"`
	PossibleRecords           int                           `json:"possible_records"`
	AutomaticDispositionReady int                           `json:"automatic_disposition_ready"`
	AggregateEvidenceOnly     bool                          `json:"aggregate_evidence_only"`
	Classifications           []CampaignClassificationCount `json:"classifications"`
}

// CampaignClassificationOptions controls pure matching. GeneratedAt defaults
// to the snapshot timestamp; no system clock is consulted. Automatic
// disposition requires explicit opt-in here and in exactly one high-confidence
// campaign definition.
type CampaignClassificationOptions struct {
	GeneratedAt               time.Time
	MaximumCampaignsEvaluated int
	MaximumRelevantRecords    int
	AllowAutomaticDisposition bool
}

// CampaignClassificationResult is an immutable pure result. It performs no
// source loading, DNS, report parsing, enrichment, storage, or network access.
type CampaignClassificationResult struct {
	metadata       ResultMetadata
	version        string
	snapshotDigest AnalysisID
	evidenceDigest AnalysisID
	digest         AnalysisID
	records        []CampaignClassificationRecord
	findings       []CampaignClassificationFinding
	summary        CampaignClassificationSummary
}

func (result CampaignClassificationResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result CampaignClassificationResult) Version() string                { return result.version }
func (result CampaignClassificationResult) SnapshotDigest() AnalysisID     { return result.snapshotDigest }
func (result CampaignClassificationResult) EvidenceDigest() AnalysisID     { return result.evidenceDigest }
func (result CampaignClassificationResult) Digest() AnalysisID             { return result.digest }
func (result CampaignClassificationResult) Records() []CampaignClassificationRecord {
	return cloneCampaignClassificationRecords(result.records)
}
func (result CampaignClassificationResult) Findings() []CampaignClassificationFinding {
	return cloneCampaignClassificationFindings(result.findings)
}
func (result CampaignClassificationResult) Summary() CampaignClassificationSummary {
	value := result.summary
	value.Classifications = append([]CampaignClassificationCount(nil), value.Classifications...)
	return value
}

// ClassifyReportedMessage compares one normalized message evidence object with
// one immutable campaign snapshot. Domain, provider, display-name, URL, or
// source-address matches alone can never produce authorization.
func ClassifyReportedMessage(snapshot CampaignConfigurationSnapshot, evidence ReportedMessageEvidence, options CampaignClassificationOptions) (CampaignClassificationResult, error) {
	if snapshot.digest == "" || snapshot.metadata.ContractVersion != AnalysisContractVersion || snapshot.metadata.Mode != AnalysisModeCampaignValidation ||
		evidence.digest == "" || evidence.value.ID == "" {
		return CampaignClassificationResult{}, ErrInvalidCampaignClassificationOptions
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = snapshot.metadata.GeneratedAt
	}
	options.GeneratedAt = options.GeneratedAt.UTC()
	if options.GeneratedAt.Before(snapshot.metadata.GeneratedAt) {
		return CampaignClassificationResult{}, ErrInvalidCampaignClassificationOptions
	}
	evaluationSnapshot := snapshot
	evaluationSnapshot.authorizationAvailable = campaignSnapshotAuthorizationAvailable(snapshot, options.GeneratedAt)
	if options.MaximumCampaignsEvaluated == 0 {
		options.MaximumCampaignsEvaluated = defaultCampaignMaximumEvaluated
	}
	if options.MaximumCampaignsEvaluated < 1 || options.MaximumCampaignsEvaluated > maxCampaignDefinitions {
		return CampaignClassificationResult{}, ErrInvalidCampaignClassificationOptions
	}
	if options.MaximumRelevantRecords == 0 {
		options.MaximumRelevantRecords = defaultCampaignMaximumRelevant
	}
	if options.MaximumRelevantRecords < 1 || options.MaximumRelevantRecords > options.MaximumCampaignsEvaluated {
		return CampaignClassificationResult{}, ErrInvalidCampaignClassificationOptions
	}
	value := evidence.value
	inScope := make([]SecuritySimulationCampaign, 0)
	for _, campaign := range snapshot.campaigns {
		if campaign.Organization == value.Organization {
			inScope = append(inScope, campaign)
		}
	}
	if len(inScope) > options.MaximumCampaignsEvaluated {
		return CampaignClassificationResult{}, ErrCampaignClassificationWorkLimit
	}
	records := make([]CampaignClassificationRecord, 0)
	for _, campaign := range inScope {
		record := evaluateCampaign(evaluationSnapshot, evidence, campaign, options)
		if campaignRecordRelevant(record) {
			records = append(records, record)
			if len(records) > options.MaximumRelevantRecords {
				return CampaignClassificationResult{}, ErrCampaignClassificationWorkLimit
			}
		}
	}
	sort.Slice(records, func(i, j int) bool {
		left, right := campaignClassificationRank(records[i].Classification), campaignClassificationRank(records[j].Classification)
		if left != right {
			return left < right
		}
		return records[i].CampaignID < records[j].CampaignID
	})
	high := 0
	for _, record := range records {
		if record.Classification == CampaignAuthorizedHighConfidence {
			high++
		}
	}
	if high > 1 {
		for index := range records {
			if records[index].Classification == CampaignAuthorizedHighConfidence {
				records[index].Classification = CampaignPossibleAuthorized
				records[index].Confidence = FindingConfidenceMedium
				records[index].AutomaticDispositionEligible = false
				records[index].ID = campaignClassificationRecordID(records[index])
			}
		}
	}
	if high == 1 {
		for index := range records {
			if records[index].Classification == CampaignAuthorizedHighConfidence {
				records[index].AutomaticDispositionEligible = records[index].AutomaticDispositionEligible && options.AllowAutomaticDisposition
			}
		}
	}
	findings := campaignFindings(evaluationSnapshot, evidence, records, high > 1, options.GeneratedAt)
	summary := summarizeCampaignClassification(len(snapshot.campaigns), len(inScope), value.AggregateOnly, records)
	if !evaluationSnapshot.authorizationAvailable {
		summary.OverallClassification = campaignUnavailableClassification(snapshot, options.GeneratedAt)
	}
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeCampaignClassification, GeneratedAt: options.GeneratedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
	result := CampaignClassificationResult{
		metadata: metadata, version: CampaignClassificationVersion, snapshotDigest: snapshot.digest, evidenceDigest: evidence.digest,
		records: cloneCampaignClassificationRecords(records), findings: cloneCampaignClassificationFindings(findings), summary: summary,
	}
	canonical, _ := json.Marshal(struct {
		Metadata       ResultMetadata                  `json:"metadata"`
		Version        string                          `json:"version"`
		SnapshotDigest AnalysisID                      `json:"snapshot_digest"`
		EvidenceDigest AnalysisID                      `json:"evidence_digest"`
		Records        []CampaignClassificationRecord  `json:"records"`
		Findings       []CampaignClassificationFinding `json:"findings"`
		Summary        CampaignClassificationSummary   `json:"summary"`
	}{result.metadata, result.version, result.snapshotDigest, result.evidenceDigest, result.records, result.findings, result.summary})
	result.digest = StableAnalysisID("campaign_classification", string(canonical))
	return result, nil
}

func evaluateCampaign(snapshot CampaignConfigurationSnapshot, evidence ReportedMessageEvidence, campaign SecuritySimulationCampaign, options CampaignClassificationOptions) CampaignClassificationRecord {
	value := evidence.value
	required := make(map[CampaignMatchFactor]struct{}, len(campaign.RequiredFactors))
	for _, factor := range campaign.RequiredFactors {
		required[factor] = struct{}{}
	}
	evaluations := []CampaignFactorEvaluation{
		campaignFactor(evidence, CampaignFactorWindow, campaignWindowState(campaign, value), required),
		campaignFactor(evidence, CampaignFactorOrganizationScope, campaignOrganizationState(campaign, value), required),
		campaignFactor(evidence, CampaignFactorRecipientScope, campaignListFactor(campaign.RecipientDomains, value.RecipientDomains, campaign.RecipientScopeIDs, value.RecipientScopeIDs), required),
		campaignFactor(evidence, CampaignFactorHeaderFrom, campaignSingleDomainFactor(campaign.ExpectedIdentity.HeaderFromDomains, value.HeaderFromDomain), required),
		campaignFactor(evidence, CampaignFactorEnvelopeFrom, campaignSingleDomainFactor(campaign.ExpectedIdentity.EnvelopeFromDomains, value.EnvelopeFromDomain), required),
		campaignFactor(evidence, CampaignFactorDKIM, campaignDKIMFactor(campaign.ExpectedIdentity.DKIM, value.DKIM), required),
		campaignFactor(evidence, CampaignFactorSourceAddress, campaignSourceAddressFactor(campaign.ExpectedSources.CIDRs, value.SourceAddresses), required),
		campaignFactor(evidence, CampaignFactorSourceHostname, campaignListFactor(campaign.ExpectedSources.Hostnames, value.SourceHostnames, nil, nil), required),
		campaignFactor(evidence, CampaignFactorMessageID, campaignSingleDomainFactor(campaign.ExpectedIdentity.MessageIDDomains, value.MessageIDDomain), required),
		campaignFactor(evidence, CampaignFactorInfrastructure, campaignListFactor(campaign.ExpectedSources.InfrastructureIDs, value.InfrastructureIDs, nil, nil), required),
		campaignFactor(evidence, CampaignFactorTokenDigest, campaignListFactor(campaign.TokenDigests, value.TokenDigests, nil, nil), required),
		campaignFactor(evidence, CampaignFactorURLDomain, campaignListFactor(campaign.URLDomains, value.URLDomains, nil, nil), required),
		campaignFactor(evidence, CampaignFactorContentFingerprint, campaignListFactor(campaign.ContentFingerprints, value.ContentFingerprints, nil, nil), required),
		campaignFactor(evidence, CampaignFactorAuthentication, campaignAuthenticationState(campaign, value), required),
		campaignFactor(evidence, CampaignFactorDeliveryException, campaignListFactor(campaign.DeliveryExceptions, value.DeliveryExceptionIDs, nil, nil), required),
	}
	confidenceFactor := campaignFactor(evidence, CampaignFactorEvidenceConfidence, campaignEvidenceConfidenceState(evidence, evaluations), required)
	confidenceFactor.Required = true
	evaluations = append(evaluations, confidenceFactor)
	record := CampaignClassificationRecord{
		EvidenceID: value.ID, CampaignID: campaign.ID, CampaignDigest: campaign.Digest, SourceID: campaign.SourceID,
		Factors: evaluations, EmployeeDisclosure: campaign.ResponsePolicy.EmployeeDisclosure,
		PrivilegedWorkflowID: campaign.Handling.WorkflowID, PrivilegedEmployeeTemplateID: campaign.ResponsePolicy.EmployeeTemplateID,
		AggregateEvidenceOnly: value.AggregateOnly, AuthenticationRetained: true, Sensitivity: SensitivityRestricted,
		Matched: []CampaignMatchFactor{}, Mismatched: []CampaignMatchFactor{}, Missing: []CampaignMatchFactor{}, Unverifiable: []CampaignMatchFactor{},
	}
	for _, factor := range evaluations {
		switch factor.State {
		case CampaignFactorMatched:
			record.Matched = append(record.Matched, factor.Factor)
		case CampaignFactorMismatched:
			record.Mismatched = append(record.Mismatched, factor.Factor)
		case CampaignFactorMissing:
			record.Missing = append(record.Missing, factor.Factor)
		case CampaignFactorUnverifiable:
			record.Unverifiable = append(record.Unverifiable, factor.Factor)
		}
	}
	requiredMatched := true
	for _, factor := range evaluations {
		if factor.Required && factor.State != CampaignFactorMatched {
			requiredMatched = false
		}
	}
	identityMatched := campaignAnyMatched(evaluations, CampaignFactorHeaderFrom, CampaignFactorEnvelopeFrom, CampaignFactorDKIM, CampaignFactorMessageID)
	specificMatched := campaignAnyMatched(evaluations, CampaignFactorDKIM, CampaignFactorInfrastructure, CampaignFactorTokenDigest, CampaignFactorContentFingerprint)
	windowState := campaignEvaluationState(evaluations, CampaignFactorWindow)
	authState := campaignEvaluationState(evaluations, CampaignFactorAuthentication)
	authRequired := campaignAuthenticationIsRequired(campaign.Authentication)
	matchedFactorCount := campaignMatchedFactorCount(evaluations)
	baseHigh := snapshot.authorizationAvailable && campaign.Status != CampaignStatusCanceled && !value.AggregateOnly && requiredMatched &&
		identityMatched && specificMatched && windowState == CampaignFactorMatched && campaignEvaluationState(evaluations, CampaignFactorOrganizationScope) == CampaignFactorMatched &&
		campaignEvaluationState(evaluations, CampaignFactorEvidenceConfidence) == CampaignFactorMatched && (!authRequired || authState == CampaignFactorMatched)
	switch {
	case baseHigh:
		record.Classification = CampaignAuthorizedHighConfidence
		record.Confidence = FindingConfidenceHigh
		record.AutomaticDispositionEligible = campaign.Handling.AutomaticDispositionEligible
	case !snapshot.authorizationAvailable && (identityMatched || specificMatched):
		record.Classification = campaignUnavailableClassification(snapshot, options.GeneratedAt)
		record.Confidence = FindingConfidenceLow
	case windowState == CampaignFactorMismatched && (identityMatched || specificMatched):
		record.Classification = CampaignOutsideWindow
		record.Confidence = FindingConfidenceMedium
	case (identityMatched || specificMatched) && campaignRequiredContradiction(evaluations):
		record.Classification = CampaignConfigurationMismatch
		record.Confidence = FindingConfidenceMedium
	case matchedFactorCount >= campaign.MinimumMatchedFactors && (identityMatched && specificMatched || specificMatched && campaignEvaluationState(evaluations, CampaignFactorOrganizationScope) == CampaignFactorMatched):
		record.Classification = CampaignPossibleAuthorized
		record.Confidence = FindingConfidenceMedium
	default:
		record.Classification = CampaignUnknownSuspiciousMessage
		record.Confidence = FindingConfidenceLow
	}
	record.ID = campaignClassificationRecordID(record)
	return record
}

func campaignEvidenceConfidenceState(evidence ReportedMessageEvidence, evaluations []CampaignFactorEvaluation) CampaignFactorState {
	highHeaders := false
	highGateway := false
	highToken := false
	highContent := false
	for _, provenance := range evidence.value.Provenance {
		if provenance.Confidence != FindingConfidenceHigh {
			continue
		}
		switch provenance.Type {
		case CampaignEvidenceMessageHeaders:
			highHeaders = true
		case CampaignEvidenceMailGateway:
			highHeaders = true
			highGateway = true
		case CampaignEvidenceVerifiedToken:
			highToken = true
		case CampaignEvidenceContentScanner:
			highContent = true
		}
	}
	identitySupported := highHeaders && campaignAnyMatched(evaluations, CampaignFactorHeaderFrom, CampaignFactorEnvelopeFrom, CampaignFactorDKIM, CampaignFactorMessageID)
	specificSupported := highHeaders && campaignAnyMatched(evaluations, CampaignFactorDKIM) ||
		highGateway && campaignAnyMatched(evaluations, CampaignFactorInfrastructure) ||
		highToken && campaignAnyMatched(evaluations, CampaignFactorTokenDigest) ||
		highContent && campaignAnyMatched(evaluations, CampaignFactorContentFingerprint)
	if identitySupported && specificSupported {
		return CampaignFactorMatched
	}
	return CampaignFactorMissing
}

func campaignSnapshotAuthorizationAvailable(snapshot CampaignConfigurationSnapshot, generatedAt time.Time) bool {
	return snapshot.authorizationAvailable && !snapshot.expiresAt.IsZero() &&
		(snapshot.effectiveAt.IsZero() || !generatedAt.Before(snapshot.effectiveAt)) && generatedAt.Before(snapshot.expiresAt)
}

func campaignUnavailableClassification(snapshot CampaignConfigurationSnapshot, generatedAt time.Time) CampaignClassification {
	if !snapshot.expiresAt.IsZero() && !generatedAt.Before(snapshot.expiresAt) {
		return CampaignAuthorizationExpired
	}
	for _, source := range snapshot.sources {
		if source.Required && source.State == CampaignSourceExpired {
			return CampaignAuthorizationExpired
		}
	}
	return CampaignAuthorizationUnavailable
}

func campaignClassificationRecordID(record CampaignClassificationRecord) AnalysisID {
	return StableAnalysisID("campaign_classification_record", string(record.EvidenceID), record.CampaignID, record.SourceID, string(record.Classification), string(record.CampaignDigest))
}

func campaignFactor(evidence ReportedMessageEvidence, factor CampaignMatchFactor, state CampaignFactorState, required map[CampaignMatchFactor]struct{}) CampaignFactorEvaluation {
	_, isRequired := required[factor]
	ids := []EvidenceID{}
	if state != CampaignFactorUnverifiable {
		ids = []EvidenceID{evidence.value.ID}
	}
	return CampaignFactorEvaluation{Factor: factor, State: state, Required: isRequired, EvidenceIDs: ids, Sensitivity: SensitivityRestricted}
}

func campaignWindowState(campaign SecuritySimulationCampaign, evidence ReportedMessageEvidenceValue) CampaignFactorState {
	if evidence.AggregateOnly {
		if evidence.PeriodEnd.Before(campaign.ValidFrom) || evidence.PeriodStart.After(campaign.ValidUntil) {
			return CampaignFactorMismatched
		}
		return CampaignFactorUnverifiable
	}
	if evidence.MessageTime.IsZero() {
		return CampaignFactorMissing
	}
	if evidence.MessageTime.Before(campaign.ValidFrom) || evidence.MessageTime.After(campaign.ValidUntil) {
		return CampaignFactorMismatched
	}
	return CampaignFactorMatched
}

func campaignOrganizationState(campaign SecuritySimulationCampaign, evidence ReportedMessageEvidenceValue) CampaignFactorState {
	if campaign.Organization != evidence.Organization {
		return CampaignFactorMismatched
	}
	if campaign.Entity != "" {
		if evidence.Entity == "" {
			return CampaignFactorMissing
		}
		if campaign.Entity != evidence.Entity {
			return CampaignFactorMismatched
		}
	}
	if campaign.BusinessUnit != "" {
		if evidence.BusinessUnit == "" {
			return CampaignFactorMissing
		}
		if campaign.BusinessUnit != evidence.BusinessUnit {
			return CampaignFactorMismatched
		}
	}
	return CampaignFactorMatched
}

func campaignSingleDomainFactor(expected []string, observed string) CampaignFactorState {
	if len(expected) == 0 {
		return CampaignFactorUnverifiable
	}
	if observed == "" {
		return CampaignFactorMissing
	}
	if campaignContainsString(expected, observed) {
		return CampaignFactorMatched
	}
	return CampaignFactorMismatched
}

func campaignListFactor(expected, observed, alternateExpected, alternateObserved []string) CampaignFactorState {
	if len(expected) == 0 && len(alternateExpected) == 0 {
		return CampaignFactorUnverifiable
	}
	if len(observed) == 0 && len(alternateObserved) == 0 {
		return CampaignFactorMissing
	}
	if stringSetsIntersect(expected, observed) || stringSetsIntersect(alternateExpected, alternateObserved) {
		return CampaignFactorMatched
	}
	return CampaignFactorMismatched
}

func campaignDKIMFactor(expected []CampaignDKIMIdentity, observed []CampaignDKIMEvidence) CampaignFactorState {
	if len(expected) == 0 {
		return CampaignFactorUnverifiable
	}
	if len(observed) == 0 {
		return CampaignFactorMissing
	}
	for expectedIndex, observedIndex := 0, 0; expectedIndex < len(expected) && observedIndex < len(observed); {
		want := expected[expectedIndex]
		got := observed[observedIndex]
		switch {
		case want.Domain < got.Domain:
			expectedIndex++
		case want.Domain > got.Domain:
			observedIndex++
		default:
			domain := got.Domain
			for observedIndex < len(observed) && observed[observedIndex].Domain == domain {
				if campaignContainsString(want.Selectors, observed[observedIndex].Selector) {
					return CampaignFactorMatched
				}
				observedIndex++
			}
			expectedIndex++
		}
	}
	return CampaignFactorMismatched
}

func campaignSourceAddressFactor(prefixes, addresses []string) CampaignFactorState {
	if len(prefixes) == 0 {
		return CampaignFactorUnverifiable
	}
	if len(addresses) == 0 {
		return CampaignFactorMissing
	}
	for _, rawPrefix := range prefixes {
		prefix, _ := netip.ParsePrefix(rawPrefix)
		for _, rawAddress := range addresses {
			address, _ := netip.ParseAddr(rawAddress)
			if prefix.Contains(address) {
				return CampaignFactorMatched
			}
		}
	}
	return CampaignFactorMismatched
}

func campaignAuthenticationState(campaign SecuritySimulationCampaign, evidence ReportedMessageEvidenceValue) CampaignFactorState {
	states := []CampaignFactorState{
		campaignAuthenticationOutcomeState(campaign.Authentication.DMARC, evidence.DMARCOutcome),
		campaignSPFAuthenticationState(campaign, evidence),
		campaignDKIMAuthenticationState(campaign, evidence),
	}
	configured := false
	missing := false
	for _, state := range states {
		switch state {
		case CampaignFactorMismatched:
			return CampaignFactorMismatched
		case CampaignFactorMissing:
			configured = true
			missing = true
		case CampaignFactorMatched:
			configured = true
		}
	}
	if !configured {
		return CampaignFactorUnverifiable
	}
	if missing {
		return CampaignFactorMissing
	}
	return CampaignFactorMatched
}

func campaignAuthenticationOutcomeState(expected CampaignAuthenticationExpectation, observed ReportAuthenticationOutcome) CampaignFactorState {
	if expected == CampaignAuthenticationOptional {
		return CampaignFactorUnverifiable
	}
	if observed == ReportAuthenticationUnknown {
		return CampaignFactorMissing
	}
	if expected == CampaignAuthenticationRequired && observed != ReportAuthenticationPass ||
		expected == CampaignAuthenticationNotExpected && observed == ReportAuthenticationPass {
		return CampaignFactorMismatched
	}
	return CampaignFactorMatched
}

func campaignSPFAuthenticationState(campaign SecuritySimulationCampaign, evidence ReportedMessageEvidenceValue) CampaignFactorState {
	expected := campaign.Authentication.SPF
	if expected != CampaignAuthenticationRequired || len(campaign.ExpectedIdentity.EnvelopeFromDomains) == 0 {
		return campaignAuthenticationOutcomeState(expected, evidence.SPFOutcome)
	}
	if evidence.SPFDomain == "" {
		return CampaignFactorMissing
	}
	if !campaignContainsString(campaign.ExpectedIdentity.EnvelopeFromDomains, evidence.SPFDomain) {
		return CampaignFactorMismatched
	}
	return campaignAuthenticationOutcomeState(expected, evidence.SPFOutcome)
}

func campaignDKIMAuthenticationState(campaign SecuritySimulationCampaign, evidence ReportedMessageEvidenceValue) CampaignFactorState {
	expected := campaign.Authentication.DKIM
	if expected != CampaignAuthenticationRequired || len(campaign.ExpectedIdentity.DKIM) == 0 {
		return campaignAuthenticationOutcomeState(expected, evidence.DKIMOutcome)
	}
	foundIdentity := false
	foundUnknown := false
	for _, want := range campaign.ExpectedIdentity.DKIM {
		for _, got := range evidence.DKIM {
			if want.Domain != got.Domain || !campaignContainsString(want.Selectors, got.Selector) {
				continue
			}
			foundIdentity = true
			switch got.Outcome {
			case ReportAuthenticationPass:
				return campaignAuthenticationOutcomeState(expected, evidence.DKIMOutcome)
			case ReportAuthenticationUnknown:
				foundUnknown = true
			}
		}
	}
	if foundIdentity && !foundUnknown {
		return CampaignFactorMismatched
	}
	if foundUnknown || len(evidence.DKIM) == 0 {
		return CampaignFactorMissing
	}
	return CampaignFactorMismatched
}

func campaignAuthenticationIsRequired(value CampaignAuthentication) bool {
	return value.DMARC != CampaignAuthenticationOptional || value.SPF != CampaignAuthenticationOptional || value.DKIM != CampaignAuthenticationOptional
}

func campaignRecordRelevant(record CampaignClassificationRecord) bool {
	if record.Classification != CampaignUnknownSuspiciousMessage {
		return true
	}
	return campaignAnyFactor(record.Matched, CampaignFactorHeaderFrom, CampaignFactorEnvelopeFrom, CampaignFactorDKIM, CampaignFactorMessageID,
		CampaignFactorSourceAddress, CampaignFactorSourceHostname, CampaignFactorInfrastructure, CampaignFactorTokenDigest,
		CampaignFactorURLDomain, CampaignFactorContentFingerprint)
}

func campaignRequiredContradiction(values []CampaignFactorEvaluation) bool {
	for _, value := range values {
		if value.Required && value.State == CampaignFactorMismatched {
			return true
		}
	}
	return false
}

func campaignAnyMatched(values []CampaignFactorEvaluation, factors ...CampaignMatchFactor) bool {
	for _, value := range values {
		if value.State == CampaignFactorMatched && campaignAnyFactor(factors, value.Factor) {
			return true
		}
	}
	return false
}

func campaignMatchedFactorCount(values []CampaignFactorEvaluation) int {
	count := 0
	for _, value := range values {
		if value.State == CampaignFactorMatched {
			count++
		}
	}
	return count
}

func campaignEvaluationState(values []CampaignFactorEvaluation, factor CampaignMatchFactor) CampaignFactorState {
	for _, value := range values {
		if value.Factor == factor {
			return value.State
		}
	}
	return CampaignFactorUnverifiable
}

func campaignAnyFactor(values []CampaignMatchFactor, factors ...CampaignMatchFactor) bool {
	for _, value := range values {
		for _, factor := range factors {
			if value == factor {
				return true
			}
		}
	}
	return false
}

func campaignContainsString(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

func stringSetsIntersect(left, right []string) bool {
	i, j := 0, 0
	for i < len(left) && j < len(right) {
		switch {
		case left[i] == right[j]:
			return true
		case left[i] < right[j]:
			i++
		default:
			j++
		}
	}
	return false
}

func campaignFindings(snapshot CampaignConfigurationSnapshot, evidence ReportedMessageEvidence, records []CampaignClassificationRecord, ambiguous bool, generatedAt time.Time) []CampaignClassificationFinding {
	findings := make([]CampaignClassificationFinding, 0)
	if !snapshot.authorizationAvailable {
		classification := campaignUnavailableClassification(snapshot, generatedAt)
		code := FindingCode("campaign.configuration.unavailable")
		if classification == CampaignAuthorizationExpired {
			code = "campaign.authorization_expired"
		}
		findings = append(findings, newCampaignFinding(code, FindingSeverityHigh, FindingConfidenceHigh,
			classification, nil, []EvidenceID{evidence.value.ID},
			"Required campaign authorization evidence was unavailable or unusable.",
			"Continue ordinary suspicious-message analysis and obtain a current authorized campaign snapshot."))
	}
	if snapshot.authorizationAvailable && len(records) == 0 && (len(evidence.value.TokenDigests) != 0 || len(evidence.value.InfrastructureIDs) != 0 || len(evidence.value.ContentFingerprints) != 0) {
		findings = append(findings, newCampaignFinding("campaign.undeclared_simulation_like_service", FindingSeverityMedium, FindingConfidenceLow,
			CampaignUnknownSuspiciousMessage, nil, []EvidenceID{evidence.value.ID},
			"Supplied evidence included simulation-like signals but matched no declared campaign.",
			"Continue ordinary security review and verify whether an undeclared testing service was introduced."))
	}
	if ambiguous {
		ids := make([]AnalysisID, 0)
		for _, record := range records {
			if record.Classification == CampaignPossibleAuthorized {
				ids = append(ids, record.ID)
			}
		}
		findings = append(findings, newCampaignFinding("campaign.classification.ambiguous", FindingSeverityHigh, FindingConfidenceHigh,
			CampaignPossibleAuthorized, ids, []EvidenceID{evidence.value.ID},
			"More than one campaign satisfied the high-confidence factor set.",
			"Require analyst review and correct overlapping campaign definitions before any automated disposition."))
	}
	for _, record := range records {
		var code FindingCode
		var severity FindingSeverity
		var summary, recommendation string
		switch record.Classification {
		case CampaignAuthorizedHighConfidence:
			code, severity = "campaign.authorized_simulation_observed", FindingSeverityInfo
			summary = "Supplied message evidence matched one authorized campaign with high confidence."
			recommendation = "Route through the restricted simulation-review workflow while retaining authentication and threat evidence."
		case CampaignPossibleAuthorized:
			code, severity = "campaign.possible_simulation_review", FindingSeverityMedium
			summary = "Supplied evidence partially matched an authorized campaign."
			recommendation = "Require analyst review and do not disclose campaign status to the reporting user."
		case CampaignConfigurationMismatch:
			code, severity = "campaign.configuration_mismatch", FindingSeverityHigh
			summary = "Campaign-like evidence contradicted one or more required authorization factors."
			recommendation = "Investigate configuration drift or possible imitation without suppressing the original threat evidence."
		case CampaignOutsideWindow:
			code, severity = "campaign.outside_window", FindingSeverityHigh
			summary = "Campaign-like evidence was observed outside the authorized campaign window."
			recommendation = "Treat the message as analyst-reviewable and verify campaign timing with the authorized owner."
		case CampaignAuthorizationExpired:
			code, severity = "campaign.authorization_expired", FindingSeverityHigh
			summary = "Campaign-like evidence could not rely on current authorization data."
			recommendation = "Continue ordinary suspicious-message handling until current authorization is available."
		case CampaignAuthorizationUnavailable:
			code, severity = "campaign.authorization_unavailable", FindingSeverityHigh
			summary = "Campaign-like evidence could not rely on complete current authorization data."
			recommendation = "Continue ordinary suspicious-message handling until complete current authorization is available."
		default:
			continue
		}
		findings = append(findings, newCampaignFinding(code, severity, record.Confidence, record.Classification,
			[]AnalysisID{record.ID}, []EvidenceID{record.EvidenceID}, summary, recommendation))
		if campaignAnyFactor(record.Mismatched, CampaignFactorAuthentication) {
			findings = append(findings, newCampaignFinding("campaign.authentication_variance", FindingSeverityHigh, FindingConfidenceHigh,
				record.Classification, []AnalysisID{record.ID}, []EvidenceID{record.EvidenceID},
				"Observed authentication contradicted the campaign definition.",
				"Retain the SPF, DKIM, and DMARC evidence and verify the campaign's sending configuration."))
		}
		if record.Classification == CampaignConfigurationMismatch && campaignAnyFactor(record.Matched, CampaignFactorSourceAddress, CampaignFactorSourceHostname, CampaignFactorHeaderFrom, CampaignFactorEnvelopeFrom) &&
			campaignAnyFactor(record.Mismatched, CampaignFactorDKIM, CampaignFactorTokenDigest, CampaignFactorContentFingerprint, CampaignFactorAuthentication) {
			findings = append(findings, newCampaignFinding("campaign.possible_infrastructure_imitation", FindingSeverityHigh, FindingConfidenceMedium,
				record.Classification, []AnalysisID{record.ID}, []EvidenceID{record.EvidenceID},
				"Some campaign-like infrastructure or identity evidence matched while stronger evidence contradicted the authorization.",
				"Investigate as possible imitation and do not treat the infrastructure match as trust."))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

func newCampaignFinding(code FindingCode, severity FindingSeverity, confidence FindingConfidence, classification CampaignClassification, records []AnalysisID, evidence []EvidenceID, summary, recommendation string) CampaignClassificationFinding {
	sort.Slice(records, func(i, j int) bool { return records[i] < records[j] })
	sort.Slice(evidence, func(i, j int) bool { return evidence[i] < evidence[j] })
	id := FindingID(StableAnalysisID("campaign_classification_finding", string(code), string(classification), fmt.Sprint(records), fmt.Sprint(evidence)))
	return CampaignClassificationFinding{
		ID: id, Code: code, Severity: severity, Confidence: confidence, Classification: classification,
		RecordIDs: append([]AnalysisID(nil), records...), EvidenceIDs: append([]EvidenceID(nil), evidence...),
		Summary: summary, Recommendation: recommendation, AutomaticAction: false, Sensitivity: SensitivityRestricted,
	}
}

func summarizeCampaignClassification(available, evaluated int, aggregate bool, records []CampaignClassificationRecord) CampaignClassificationSummary {
	counts := map[CampaignClassification]int{}
	summary := CampaignClassificationSummary{OverallClassification: CampaignUnknownSuspiciousMessage, CampaignsAvailable: available, CampaignsEvaluated: evaluated, RelevantRecords: len(records), AggregateEvidenceOnly: aggregate, Classifications: []CampaignClassificationCount{}}
	for _, record := range records {
		counts[record.Classification]++
		if summary.OverallClassification == CampaignUnknownSuspiciousMessage || campaignClassificationRank(record.Classification) < campaignClassificationRank(summary.OverallClassification) {
			summary.OverallClassification = record.Classification
		}
		if record.Classification == CampaignAuthorizedHighConfidence {
			summary.HighConfidenceRecords++
		}
		if record.Classification == CampaignPossibleAuthorized {
			summary.PossibleRecords++
		}
		if record.AutomaticDispositionEligible {
			summary.AutomaticDispositionReady++
		}
	}
	for classification, count := range counts {
		summary.Classifications = append(summary.Classifications, CampaignClassificationCount{Classification: classification, Records: count})
	}
	sort.Slice(summary.Classifications, func(i, j int) bool {
		return summary.Classifications[i].Classification < summary.Classifications[j].Classification
	})
	return summary
}

func campaignClassificationRank(value CampaignClassification) int {
	switch value {
	case CampaignAuthorizedHighConfidence:
		return 0
	case CampaignAuthorizationExpired:
		return 1
	case CampaignAuthorizationUnavailable:
		return 2
	case CampaignOutsideWindow:
		return 3
	case CampaignConfigurationMismatch:
		return 4
	case CampaignPossibleAuthorized:
		return 5
	default:
		return 6
	}
}

func cloneCampaignClassificationRecords(values []CampaignClassificationRecord) []CampaignClassificationRecord {
	result := make([]CampaignClassificationRecord, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Factors = make([]CampaignFactorEvaluation, len(value.Factors))
		for factorIndex, factor := range value.Factors {
			result[index].Factors[factorIndex] = factor
			result[index].Factors[factorIndex].EvidenceIDs = append([]EvidenceID(nil), factor.EvidenceIDs...)
		}
		result[index].Matched = append([]CampaignMatchFactor{}, value.Matched...)
		result[index].Mismatched = append([]CampaignMatchFactor{}, value.Mismatched...)
		result[index].Missing = append([]CampaignMatchFactor{}, value.Missing...)
		result[index].Unverifiable = append([]CampaignMatchFactor{}, value.Unverifiable...)
	}
	return result
}

func cloneCampaignClassificationFindings(values []CampaignClassificationFinding) []CampaignClassificationFinding {
	result := make([]CampaignClassificationFinding, len(values))
	for index, value := range values {
		result[index] = value
		result[index].RecordIDs = append([]AnalysisID(nil), value.RecordIDs...)
		result[index].EvidenceIDs = append([]EvidenceID(nil), value.EvidenceIDs...)
	}
	return result
}
