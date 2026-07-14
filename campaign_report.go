package dmarcgo

import (
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const defaultCampaignMaximumReportObservations = 10000

// CampaignReportCorrelationOptions provides organization scope that aggregate
// DMARC evidence does not contain. Aggregate evidence can never produce a
// high-confidence individual-message authorization.
type CampaignReportCorrelationOptions struct {
	Organization              string
	Entity                    string
	BusinessUnit              string
	GeneratedAt               time.Time
	MaximumObservations       int
	MaximumCampaignsEvaluated int
	MaximumRelevantRecords    int
	// CoverageSufficient is an explicit caller assertion that the supplied
	// aggregate corpus is complete enough to note declared campaigns that were
	// not observed. The library never infers corpus completeness.
	CoverageSufficient bool
}

// CampaignReportObservationClassification preserves one aggregate observation
// reference and its lower-confidence campaign classification records.
type CampaignReportObservationClassification struct {
	ObservationID        EvidenceID                     `json:"observation_id"`
	ReportEvidenceID     EvidenceID                     `json:"report_evidence_id"`
	Messages             int64                          `json:"messages"`
	ClassificationDigest AnalysisID                     `json:"classification_digest"`
	Records              []CampaignClassificationRecord `json:"records"`
	FindingIDs           []FindingID                    `json:"finding_ids"`
	Sensitivity          Sensitivity                    `json:"sensitivity"`
}

// CampaignReportCorrelationDiagnostic is library-controlled and never copies
// invalid report values.
type CampaignReportCorrelationDiagnostic struct {
	ID            AnalysisID      `json:"id"`
	Code          DiagnosticCode  `json:"code"`
	ObservationID EvidenceID      `json:"observation_id,omitempty"`
	CampaignID    string          `json:"campaign_id,omitempty"`
	Severity      FindingSeverity `json:"severity"`
	Message       string          `json:"message"`
	Sensitivity   Sensitivity     `json:"sensitivity"`
}

// CampaignReportCorrelationSummary describes aggregate coverage. It does not
// imply that any individual reported message belonged to a campaign.
type CampaignReportCorrelationSummary struct {
	Observations              int   `json:"observations"`
	Messages                  int64 `json:"messages"`
	RelevantObservations      int   `json:"relevant_observations"`
	PossibleObservations      int   `json:"possible_observations"`
	MismatchObservations      int   `json:"mismatch_observations"`
	OutsideWindowObservations int   `json:"outside_window_observations"`
}

// CampaignReportCorrelationResult is immutable, pure aggregate correlation.
// It never treats DMARC aggregate evidence as individual-message proof.
type CampaignReportCorrelationResult struct {
	metadata             ResultMetadata
	version              string
	snapshotDigest       AnalysisID
	reportEvidenceDigest AnalysisID
	digest               AnalysisID
	observations         []CampaignReportObservationClassification
	diagnostics          []CampaignReportCorrelationDiagnostic
	summary              CampaignReportCorrelationSummary
}

func (result CampaignReportCorrelationResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result CampaignReportCorrelationResult) Version() string                { return result.version }
func (result CampaignReportCorrelationResult) SnapshotDigest() AnalysisID {
	return result.snapshotDigest
}
func (result CampaignReportCorrelationResult) ReportEvidenceDigest() AnalysisID {
	return result.reportEvidenceDigest
}
func (result CampaignReportCorrelationResult) Digest() AnalysisID { return result.digest }
func (result CampaignReportCorrelationResult) Observations() []CampaignReportObservationClassification {
	return cloneCampaignReportObservationClassifications(result.observations)
}
func (result CampaignReportCorrelationResult) Diagnostics() []CampaignReportCorrelationDiagnostic {
	return append([]CampaignReportCorrelationDiagnostic(nil), result.diagnostics...)
}
func (result CampaignReportCorrelationResult) Summary() CampaignReportCorrelationSummary {
	return result.summary
}

// CorrelateCampaignReportEvidence evaluates aggregate identity, source, and
// report-period evidence separately. Overlapping report periods remain
// unverifiable message-time evidence, so this API can never return
// authorized_simulation_high_confidence or automatic disposition eligibility.
// Invalid evaluation times and classifier work limits fail before observations
// are processed.
func CorrelateCampaignReportEvidence(snapshot CampaignConfigurationSnapshot, evidence ReportEvidenceResult, options CampaignReportCorrelationOptions) (CampaignReportCorrelationResult, error) {
	if snapshot.digest == "" || snapshot.metadata.ContractVersion != AnalysisContractVersion || snapshot.metadata.Mode != AnalysisModeCampaignValidation ||
		evidence.digest == "" || evidence.metadata.ContractVersion != AnalysisContractVersion || evidence.metadata.Mode != AnalysisModeReportEvidence {
		return CampaignReportCorrelationResult{}, ErrInvalidCampaignClassificationOptions
	}
	organization, err := normalizeCampaignEvidenceID(options.Organization, true)
	if err != nil {
		return CampaignReportCorrelationResult{}, err
	}
	entity, err := normalizeCampaignEvidenceID(options.Entity, false)
	if err != nil {
		return CampaignReportCorrelationResult{}, err
	}
	businessUnit, err := normalizeCampaignEvidenceID(options.BusinessUnit, false)
	if err != nil {
		return CampaignReportCorrelationResult{}, err
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = snapshot.metadata.GeneratedAt
	}
	classificationOptions, err := normalizeCampaignClassificationOptions(snapshot, CampaignClassificationOptions{
		GeneratedAt:               options.GeneratedAt,
		MaximumCampaignsEvaluated: options.MaximumCampaignsEvaluated,
		MaximumRelevantRecords:    options.MaximumRelevantRecords,
	})
	if err != nil {
		return CampaignReportCorrelationResult{}, err
	}
	options.GeneratedAt = classificationOptions.GeneratedAt
	if options.MaximumObservations == 0 {
		options.MaximumObservations = defaultCampaignMaximumReportObservations
	}
	if options.MaximumObservations < 1 || options.MaximumObservations > 1_000_000 || len(evidence.observations) > options.MaximumObservations {
		return CampaignReportCorrelationResult{}, ErrCampaignClassificationWorkLimit
	}
	result := CampaignReportCorrelationResult{
		metadata: ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeCampaignClassification, GeneratedAt: options.GeneratedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}},
		version:  CampaignClassificationVersion, snapshotDigest: snapshot.digest, reportEvidenceDigest: evidence.digest,
		observations: []CampaignReportObservationClassification{}, diagnostics: []CampaignReportCorrelationDiagnostic{},
	}
	for _, observation := range evidence.observations {
		if !observation.Period.Begin.Available || !observation.Period.End.Available {
			result.diagnostics = append(result.diagnostics, campaignReportDiagnostic(observation.ID, "campaign.report.period_unavailable", "A report observation lacked usable period bounds."))
			continue
		}
		input := ReportedMessageEvidenceInput{
			ExternalReference: string(observation.ID), Organization: organization, Entity: entity, BusinessUnit: businessUnit,
			SPFOutcome: observation.PolicyOutcome.SPF, DKIMOutcome: observation.PolicyOutcome.DKIM, DMARCOutcome: observation.PolicyOutcome.Combined,
			AggregateOnly: true, PeriodStart: observation.Period.Begin.Value, PeriodEnd: observation.Period.End.Value,
			Provenance: []CampaignEvidenceProvenanceInput{{SourceID: string(observation.ReportEvidenceID), Type: CampaignEvidenceAggregateReport, ObservedAt: observation.Period.End.Value, Confidence: FindingConfidenceMedium}},
		}
		if observation.AuthorDomain.Evaluation.State == EvaluationStateEvaluated {
			input.HeaderFromDomain = observation.AuthorDomain.Value
		}
		if observation.SourceIP.Evaluation.State == EvaluationStateEvaluated {
			input.SourceAddresses = []string{observation.SourceIP.Value}
		}
		if mailFromDomain := campaignReportMailFromDomain(observation.SPF); mailFromDomain != "" {
			// RFC 9990 reports only the MAIL FROM SPF identity; its optional
			// scope can only be mfrom. Preserve that identity for both the
			// envelope-from factor and identity-aware SPF authentication.
			input.EnvelopeFromDomain = mailFromDomain
			input.SPFDomain = mailFromDomain
		}
		for _, dkim := range observation.DKIM {
			if dkim.Domain.Evaluation.State == EvaluationStateEvaluated && dkim.Selector.Evaluation.State == EvaluationStateEvaluated {
				input.DKIM = append(input.DKIM, CampaignDKIMEvidenceInput{Domain: dkim.Domain.Value, Selector: dkim.Selector.Value, Outcome: normalizedPolicyOutcome(dkim.Result)})
			}
		}
		normalized, normalizeErr := NormalizeReportedMessageEvidence(input)
		if normalizeErr != nil {
			result.diagnostics = append(result.diagnostics, campaignReportDiagnostic(observation.ID, "campaign.report.evidence_unavailable", "A report observation could not be normalized for campaign correlation."))
			continue
		}
		classification, classifyErr := ClassifyReportedMessage(snapshot, normalized, classificationOptions)
		if classifyErr != nil {
			if errors.Is(classifyErr, ErrCampaignClassificationWorkLimit) || errors.Is(classifyErr, ErrInvalidCampaignClassificationOptions) {
				return CampaignReportCorrelationResult{}, classifyErr
			}
			result.diagnostics = append(result.diagnostics, campaignReportDiagnostic(observation.ID, "campaign.report.classification_unavailable", "A report observation could not be classified."))
			continue
		}
		records := classification.Records()
		for index := range records {
			if records[index].Classification == CampaignAuthorizedHighConfidence || records[index].AutomaticDispositionEligible {
				return CampaignReportCorrelationResult{}, ErrInvalidAnalysisResult
			}
		}
		findingIDs := make([]FindingID, 0, len(classification.findings))
		for _, finding := range classification.findings {
			findingIDs = append(findingIDs, finding.ID)
		}
		messages := int64(0)
		if observation.Count.Available {
			messages = observation.Count.Value
		}
		result.observations = append(result.observations, CampaignReportObservationClassification{
			ObservationID: observation.ID, ReportEvidenceID: observation.ReportEvidenceID, Messages: messages,
			ClassificationDigest: classification.digest, Records: records, FindingIDs: findingIDs, Sensitivity: SensitivityRestricted,
		})
	}
	if options.CoverageSufficient {
		observedCampaigns := map[string]struct{}{}
		for _, observation := range result.observations {
			for _, record := range observation.Records {
				observedCampaigns[record.CampaignID] = struct{}{}
			}
		}
		for _, campaign := range snapshot.campaigns {
			if campaign.Status == CampaignStatusCanceled || !campaignMatchesReportScope(campaign, organization, entity, businessUnit) || !campaignOverlapsReportEvidence(campaign, evidence.observations) {
				continue
			}
			if _, observed := observedCampaigns[campaign.ID]; !observed {
				result.diagnostics = append(result.diagnostics, CampaignReportCorrelationDiagnostic{
					ID:   StableAnalysisID("campaign_report_correlation_diagnostic", campaign.ID, "campaign.report.declared_not_observed"),
					Code: "campaign.report.declared_not_observed", CampaignID: campaign.ID, Severity: FindingSeverityInfo,
					Message: "A declared campaign was not observed in a caller-confirmed complete aggregate evidence window.", Sensitivity: SensitivityRestricted,
				})
			}
		}
	}
	sort.Slice(result.observations, func(i, j int) bool {
		return result.observations[i].ObservationID < result.observations[j].ObservationID
	})
	sort.Slice(result.diagnostics, func(i, j int) bool { return result.diagnostics[i].ID < result.diagnostics[j].ID })
	result.summary = summarizeCampaignReportCorrelation(result.observations)
	canonical, _ := json.Marshal(struct {
		Metadata       ResultMetadata                            `json:"metadata"`
		Version        string                                    `json:"version"`
		SnapshotDigest AnalysisID                                `json:"snapshot_digest"`
		EvidenceDigest AnalysisID                                `json:"report_evidence_digest"`
		Observations   []CampaignReportObservationClassification `json:"observations"`
		Diagnostics    []CampaignReportCorrelationDiagnostic     `json:"diagnostics"`
		Summary        CampaignReportCorrelationSummary          `json:"summary"`
	}{result.metadata, result.version, result.snapshotDigest, result.reportEvidenceDigest, result.observations, result.diagnostics, result.summary})
	result.digest = StableAnalysisID("campaign_report_correlation", string(canonical))
	return result, nil
}

func campaignReportMailFromDomain(spf ReportEvidenceSPF) string {
	if spf.Evaluation.State != EvaluationStateEvaluated || spf.Domain.Evaluation.State != EvaluationStateEvaluated {
		return ""
	}
	// RFC 9990 makes scope optional because only mfrom is valid. Historical
	// reports can explicitly carry helo, which must not become MAIL FROM.
	if spf.Scope.Evaluation.State == EvaluationStateEvaluated && spf.Scope.Value != "mfrom" {
		return ""
	}
	return spf.Domain.Value
}

func campaignMatchesReportScope(campaign SecuritySimulationCampaign, organization, entity, businessUnit string) bool {
	if campaign.Organization != organization {
		return false
	}
	if campaign.Entity != "" && campaign.Entity != entity {
		return false
	}
	return campaign.BusinessUnit == "" || campaign.BusinessUnit == businessUnit
}

func campaignReportDiagnostic(observationID EvidenceID, code DiagnosticCode, message string) CampaignReportCorrelationDiagnostic {
	return CampaignReportCorrelationDiagnostic{
		ID:   StableAnalysisID("campaign_report_correlation_diagnostic", string(observationID), string(code)),
		Code: code, ObservationID: observationID, Severity: FindingSeverityMedium, Message: message, Sensitivity: SensitivityOperational,
	}
}

func campaignOverlapsReportEvidence(campaign SecuritySimulationCampaign, observations []ReportEvidenceObservation) bool {
	for _, observation := range observations {
		if !observation.Period.Begin.Available || !observation.Period.End.Available {
			continue
		}
		if !observation.Period.End.Value.Before(campaign.ValidFrom) && !observation.Period.Begin.Value.After(campaign.ValidUntil) {
			return true
		}
	}
	return false
}

func summarizeCampaignReportCorrelation(values []CampaignReportObservationClassification) CampaignReportCorrelationSummary {
	summary := CampaignReportCorrelationSummary{Observations: len(values)}
	for _, value := range values {
		summary.Messages += value.Messages
		if len(value.Records) != 0 {
			summary.RelevantObservations++
		}
		seen := map[CampaignClassification]struct{}{}
		for _, record := range value.Records {
			seen[record.Classification] = struct{}{}
		}
		if _, ok := seen[CampaignPossibleAuthorized]; ok {
			summary.PossibleObservations++
		}
		if _, ok := seen[CampaignConfigurationMismatch]; ok {
			summary.MismatchObservations++
		}
		if _, ok := seen[CampaignOutsideWindow]; ok {
			summary.OutsideWindowObservations++
		}
	}
	return summary
}

func cloneCampaignReportObservationClassifications(values []CampaignReportObservationClassification) []CampaignReportObservationClassification {
	result := make([]CampaignReportObservationClassification, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Records = cloneCampaignClassificationRecords(value.Records)
		result[index].FindingIDs = append([]FindingID(nil), value.FindingIDs...)
	}
	return result
}
