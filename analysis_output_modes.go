package dmarcgo

import "time"

type analysisOutputHeader struct {
	Schema        string            `json:"schema"`
	SchemaVersion string            `json:"schema_version"`
	Mode          AnalysisMode      `json:"mode"`
	Profile       string            `json:"profile"`
	Metadata      ResultMetadata    `json:"metadata"`
	ResultDigest  AnalysisID        `json:"result_digest"`
	Redaction     RedactionMetadata `json:"redaction"`
}

type dnsHealthOutputDocument struct {
	analysisOutputHeader
	ObservedAt            time.Time                  `json:"observed_at"`
	PortfolioDigest       AnalysisID                 `json:"portfolio_digest"`
	SnapshotDigest        AnalysisID                 `json:"snapshot_digest"`
	AuthenticationDigest  AnalysisID                 `json:"authentication_digest"`
	ProviderCatalogDigest AnalysisID                 `json:"provider_catalog_digest"`
	ProviderProvenance    ProviderCatalogProvenance  `json:"provider_catalog_provenance"`
	ScoringProfile        DNSHealthScoringProfile    `json:"scoring_profile"`
	PortfolioScore        DNSHealthScore             `json:"portfolio_score"`
	PortfolioMaturity     DNSHealthMaturity          `json:"portfolio_maturity"`
	Records               []DNSRecordHealth          `json:"records"`
	Domains               []DNSDomainHealth          `json:"domains"`
	Entities              []DNSEntityHealth          `json:"entities"`
	Findings              []DNSHealthFinding         `json:"findings"`
	ProviderContexts      []DNSHealthProviderContext `json:"provider_contexts"`
}

type reportEvidenceOutputDocument struct {
	analysisOutputHeader
	EvidenceSchemaVersion string                      `json:"evidence_schema_version"`
	Reports               []ReportEvidenceReport      `json:"reports"`
	Observations          []ReportEvidenceObservation `json:"observations"`
	Summary               ReportEvidenceAggregate     `json:"summary"`
	Diagnostics           []ReportEvidenceDiagnostic  `json:"diagnostics"`
}

type correlationOutputDocument struct {
	analysisOutputHeader
	Version               string                          `json:"version"`
	OrganizationID        string                          `json:"organization_id"`
	PortfolioDigest       AnalysisID                      `json:"portfolio_digest"`
	DNSHealthDigest       AnalysisID                      `json:"dns_health_digest"`
	DNSSnapshotDigest     AnalysisID                      `json:"dns_snapshot_digest"`
	AuthenticationDigest  AnalysisID                      `json:"authentication_digest"`
	ProviderCatalogDigest AnalysisID                      `json:"provider_catalog_digest"`
	ProviderProvenance    ProviderCatalogProvenance       `json:"provider_catalog_provenance"`
	ReportEvidenceDigest  AnalysisID                      `json:"report_evidence_digest"`
	PreviousDigest        AnalysisID                      `json:"previous_digest,omitempty"`
	DNSObservedAt         time.Time                       `json:"dns_observed_at"`
	Thresholds            DNSReportCorrelationThresholds  `json:"thresholds"`
	Inventory             []DNSReportCorrelationInventory `json:"inventory"`
	Streams               []DNSReportCorrelationStream    `json:"streams"`
	Findings              []DNSReportCorrelationFinding   `json:"findings"`
	Summary               DNSReportCorrelationSummary     `json:"summary"`
}

type threatCandidateOutputDocument struct {
	analysisOutputHeader
	Version              string                        `json:"version"`
	OrganizationID       string                        `json:"organization_id"`
	PortfolioDigest      AnalysisID                    `json:"portfolio_digest"`
	ReportEvidenceDigest AnalysisID                    `json:"report_evidence_digest"`
	CorrelationDigest    AnalysisID                    `json:"correlation_digest"`
	ScoringProfile       ThreatCandidateScoringProfile `json:"scoring_profile"`
	Candidates           []ThreatCandidate             `json:"candidates"`
	Summary              ThreatCandidateSummary        `json:"summary"`
}

type sourceEnrichmentOutputDocument struct {
	analysisOutputHeader
	Version               string                       `json:"version"`
	OrganizationID        string                       `json:"organization_id"`
	ThreatCandidateDigest AnalysisID                   `json:"threat_candidate_digest"`
	Complete              bool                         `json:"complete"`
	Candidates            []EnrichedThreatCandidate    `json:"candidates"`
	ASNs                  []ASNEnrichment              `json:"asns"`
	Diagnostics           []SourceEnrichmentDiagnostic `json:"diagnostics"`
	Summary               SourceEnrichmentSummary      `json:"summary"`
}

type jurisdictionContextOutputDocument struct {
	analysisOutputHeader
	Version                string                         `json:"version"`
	OrganizationID         string                         `json:"organization_id"`
	SourceEnrichmentDigest AnalysisID                     `json:"source_enrichment_digest"`
	PolicyDigest           AnalysisID                     `json:"policy_digest"`
	PolicyFreshness        SourceEnrichmentFreshness      `json:"policy_freshness"`
	Candidates             []JurisdictionContextCandidate `json:"candidates"`
	Findings               []JurisdictionContextFinding   `json:"findings"`
	Summary                JurisdictionContextSummary     `json:"summary"`
}

type dnsHealthOutputMetadata struct {
	Metadata              ResultMetadata            `json:"metadata"`
	ObservedAt            time.Time                 `json:"observed_at"`
	PortfolioDigest       AnalysisID                `json:"portfolio_digest"`
	SnapshotDigest        AnalysisID                `json:"snapshot_digest"`
	AuthenticationDigest  AnalysisID                `json:"authentication_digest"`
	ProviderCatalogDigest AnalysisID                `json:"provider_catalog_digest"`
	ProviderProvenance    ProviderCatalogProvenance `json:"provider_catalog_provenance"`
	ScoringProfile        DNSHealthScoringProfile   `json:"scoring_profile"`
	PortfolioScore        DNSHealthScore            `json:"portfolio_score"`
	PortfolioMaturity     DNSHealthMaturity         `json:"portfolio_maturity"`
}

type reportEvidenceOutputMetadata struct {
	Metadata              ResultMetadata          `json:"metadata"`
	EvidenceSchemaVersion string                  `json:"evidence_schema_version"`
	Summary               ReportEvidenceAggregate `json:"summary"`
}

type correlationOutputMetadata struct {
	Metadata              ResultMetadata                 `json:"metadata"`
	Version               string                         `json:"version"`
	OrganizationID        string                         `json:"organization_id"`
	PortfolioDigest       AnalysisID                     `json:"portfolio_digest"`
	DNSHealthDigest       AnalysisID                     `json:"dns_health_digest"`
	DNSSnapshotDigest     AnalysisID                     `json:"dns_snapshot_digest"`
	AuthenticationDigest  AnalysisID                     `json:"authentication_digest"`
	ProviderCatalogDigest AnalysisID                     `json:"provider_catalog_digest"`
	ReportEvidenceDigest  AnalysisID                     `json:"report_evidence_digest"`
	PreviousDigest        AnalysisID                     `json:"previous_digest,omitempty"`
	ProviderProvenance    ProviderCatalogProvenance      `json:"provider_catalog_provenance"`
	DNSObservedAt         time.Time                      `json:"dns_observed_at"`
	Thresholds            DNSReportCorrelationThresholds `json:"thresholds"`
	Summary               DNSReportCorrelationSummary    `json:"summary"`
}

type threatCandidateOutputMetadata struct {
	Metadata             ResultMetadata                `json:"metadata"`
	Version              string                        `json:"version"`
	OrganizationID       string                        `json:"organization_id"`
	PortfolioDigest      AnalysisID                    `json:"portfolio_digest"`
	ReportEvidenceDigest AnalysisID                    `json:"report_evidence_digest"`
	CorrelationDigest    AnalysisID                    `json:"correlation_digest"`
	ScoringProfile       ThreatCandidateScoringProfile `json:"scoring_profile"`
	Summary              ThreatCandidateSummary        `json:"summary"`
}

type sourceEnrichmentOutputMetadata struct {
	Metadata              ResultMetadata          `json:"metadata"`
	Version               string                  `json:"version"`
	OrganizationID        string                  `json:"organization_id"`
	ThreatCandidateDigest AnalysisID              `json:"threat_candidate_digest"`
	Complete              bool                    `json:"complete"`
	Summary               SourceEnrichmentSummary `json:"summary"`
}

type jurisdictionContextOutputMetadata struct {
	Metadata               ResultMetadata             `json:"metadata"`
	Version                string                     `json:"version"`
	OrganizationID         string                     `json:"organization_id"`
	SourceEnrichmentDigest AnalysisID                 `json:"source_enrichment_digest"`
	PolicyDigest           AnalysisID                 `json:"policy_digest"`
	PolicyFreshness        SourceEnrichmentFreshness  `json:"policy_freshness"`
	Summary                JurisdictionContextSummary `json:"summary"`
}

func newAnalysisOutputHeader(mode AnalysisMode, metadata ResultMetadata, digest AnalysisID) analysisOutputHeader {
	schema, _ := AnalysisOutputSchemaID(mode, AnalysisOutputSchemaVersion)
	return analysisOutputHeader{
		Schema: schema, SchemaVersion: AnalysisOutputSchemaVersion, Mode: mode, Profile: AnalysisOutputProfileNative,
		Metadata: metadata, ResultDigest: digest,
		Redaction: RedactionMetadata{Profile: OutputRedactionOperational},
	}
}

func dnsHealthOutputSpec(result DNSHealthResult) analysisOutputSpec {
	metadata := result.metadata
	header := newAnalysisOutputHeader(AnalysisModeDNSHealth, metadata, result.digest)
	meta := dnsHealthOutputMetadata{metadata, result.observedAt, result.portfolioDigest, result.snapshotDigest, result.authenticationDigest, result.providerCatalogDigest, result.providerProvenance, result.profile, result.portfolioScore, result.portfolioMaturity}
	document := dnsHealthOutputDocument{
		analysisOutputHeader: header, ObservedAt: result.observedAt, PortfolioDigest: result.portfolioDigest,
		SnapshotDigest: result.snapshotDigest, AuthenticationDigest: result.authenticationDigest,
		ProviderCatalogDigest: result.providerCatalogDigest, ProviderProvenance: result.providerProvenance,
		ScoringProfile: result.profile, PortfolioScore: result.portfolioScore, PortfolioMaturity: result.portfolioMaturity,
		Records: analysisOutputSlice(result.records), Domains: analysisOutputSlice(result.domains), Entities: analysisOutputSlice(result.entities),
		Findings: analysisOutputSlice(result.findings), ProviderContexts: analysisOutputSlice(result.providerContexts),
	}
	return analysisOutputSpec{mode: AnalysisModeDNSHealth, metadata: metadata, digest: result.digest, document: document, csvColumns: analysisModeCSVColumns[AnalysisModeDNSHealth], walk: func(visit func(string, string, any) error) error {
		if err := visit("metadata", "metadata", meta); err != nil {
			return err
		}
		if err := walkSlice("record", result.records, visit); err != nil {
			return err
		}
		if err := walkSlice("domain", result.domains, visit); err != nil {
			return err
		}
		if err := walkSlice("entity", result.entities, visit); err != nil {
			return err
		}
		if err := walkSlice("finding", result.findings, visit); err != nil {
			return err
		}
		return walkSlice("provider_context", result.providerContexts, visit)
	}}
}

func reportEvidenceOutputSpec(result ReportEvidenceResult) analysisOutputSpec {
	metadata := result.metadata
	header := newAnalysisOutputHeader(AnalysisModeReportEvidence, metadata, result.digest)
	meta := reportEvidenceOutputMetadata{metadata, ReportEvidenceSchemaVersion, result.summary}
	document := reportEvidenceOutputDocument{
		analysisOutputHeader: header, EvidenceSchemaVersion: ReportEvidenceSchemaVersion,
		Reports: analysisOutputSlice(result.reports), Observations: analysisOutputSlice(result.observations),
		Summary: result.summary, Diagnostics: analysisOutputSlice(result.diagnostics),
	}
	return analysisOutputSpec{mode: AnalysisModeReportEvidence, metadata: metadata, digest: result.digest, document: document, csvColumns: analysisModeCSVColumns[AnalysisModeReportEvidence], walk: func(visit func(string, string, any) error) error {
		if err := visit("metadata", "metadata", meta); err != nil {
			return err
		}
		if err := walkSlice("report", result.reports, visit); err != nil {
			return err
		}
		if err := walkSlice("observation", result.observations, visit); err != nil {
			return err
		}
		return walkSlice("diagnostic", result.diagnostics, visit)
	}}
}

func correlationOutputSpec(result DNSReportCorrelationResult) analysisOutputSpec {
	metadata := result.metadata
	header := newAnalysisOutputHeader(AnalysisModeDNSReportCorrelation, metadata, result.digest)
	meta := correlationOutputMetadata{metadata, result.version, result.organizationID, result.portfolioDigest, result.dnsHealthDigest, result.dnsSnapshotDigest, result.authenticationDigest, result.providerCatalogDigest, result.reportEvidenceDigest, result.previousDigest, result.providerProvenance, result.dnsObservedAt, result.thresholds, result.summary}
	document := correlationOutputDocument{
		analysisOutputHeader: header, Version: result.version, OrganizationID: result.organizationID,
		PortfolioDigest: result.portfolioDigest, DNSHealthDigest: result.dnsHealthDigest, DNSSnapshotDigest: result.dnsSnapshotDigest,
		AuthenticationDigest: result.authenticationDigest, ProviderCatalogDigest: result.providerCatalogDigest,
		ProviderProvenance: result.providerProvenance, ReportEvidenceDigest: result.reportEvidenceDigest, PreviousDigest: result.previousDigest,
		DNSObservedAt: result.dnsObservedAt, Thresholds: result.thresholds, Inventory: analysisOutputSlice(result.inventory),
		Streams: analysisOutputSlice(result.streams), Findings: analysisOutputSlice(result.findings), Summary: result.summary,
	}
	return analysisOutputSpec{mode: AnalysisModeDNSReportCorrelation, metadata: metadata, digest: result.digest, document: document, csvColumns: analysisModeCSVColumns[AnalysisModeDNSReportCorrelation], walk: func(visit func(string, string, any) error) error {
		if err := visit("metadata", "metadata", meta); err != nil {
			return err
		}
		if err := walkSlice("inventory", result.inventory, visit); err != nil {
			return err
		}
		if err := walkSlice("stream", result.streams, visit); err != nil {
			return err
		}
		return walkSlice("finding", result.findings, visit)
	}}
}

func threatCandidateOutputSpec(result ThreatCandidateResult) analysisOutputSpec {
	metadata := result.metadata
	header := newAnalysisOutputHeader(AnalysisModeThreatCandidates, metadata, result.digest)
	meta := threatCandidateOutputMetadata{metadata, result.version, result.organizationID, result.portfolioDigest, result.reportEvidenceDigest, result.correlationDigest, result.profile, result.summary}
	document := threatCandidateOutputDocument{
		analysisOutputHeader: header, Version: result.version, OrganizationID: result.organizationID,
		PortfolioDigest: result.portfolioDigest, ReportEvidenceDigest: result.reportEvidenceDigest, CorrelationDigest: result.correlationDigest,
		ScoringProfile: result.profile, Candidates: analysisOutputSlice(result.candidates), Summary: result.summary,
	}
	return analysisOutputSpec{mode: AnalysisModeThreatCandidates, metadata: metadata, digest: result.digest, document: document, csvColumns: analysisModeCSVColumns[AnalysisModeThreatCandidates], walk: func(visit func(string, string, any) error) error {
		if err := visit("metadata", "metadata", meta); err != nil {
			return err
		}
		return walkSlice("candidate", result.candidates, visit)
	}}
}

func sourceEnrichmentOutputSpec(result SourceEnrichmentResult) analysisOutputSpec {
	metadata := result.metadata
	header := newAnalysisOutputHeader(AnalysisModeSourceEnrichment, metadata, result.digest)
	meta := sourceEnrichmentOutputMetadata{metadata, result.version, result.organizationID, result.threatCandidateDigest, result.complete, result.summary}
	document := sourceEnrichmentOutputDocument{
		analysisOutputHeader: header, Version: result.version, OrganizationID: result.organizationID,
		ThreatCandidateDigest: result.threatCandidateDigest, Complete: result.complete,
		Candidates: analysisOutputSlice(result.candidates), ASNs: analysisOutputSlice(result.asns),
		Diagnostics: analysisOutputSlice(result.diagnostics), Summary: result.summary,
	}
	return analysisOutputSpec{mode: AnalysisModeSourceEnrichment, metadata: metadata, digest: result.digest, document: document, csvColumns: analysisModeCSVColumns[AnalysisModeSourceEnrichment], walk: func(visit func(string, string, any) error) error {
		if err := visit("metadata", "metadata", meta); err != nil {
			return err
		}
		if err := walkSlice("candidate", result.candidates, visit); err != nil {
			return err
		}
		if err := walkSlice("asn", result.asns, visit); err != nil {
			return err
		}
		return walkSlice("diagnostic", result.diagnostics, visit)
	}}
}

func jurisdictionContextOutputSpec(result JurisdictionContextResult) analysisOutputSpec {
	metadata := result.metadata
	header := newAnalysisOutputHeader(AnalysisModeJurisdictionContext, metadata, result.digest)
	meta := jurisdictionContextOutputMetadata{metadata, result.version, result.organizationID, result.sourceEnrichmentDigest, result.policy.Digest(), result.policyFreshness, result.summary}
	document := jurisdictionContextOutputDocument{
		analysisOutputHeader: header, Version: result.version, OrganizationID: result.organizationID,
		SourceEnrichmentDigest: result.sourceEnrichmentDigest, PolicyDigest: result.policy.Digest(), PolicyFreshness: result.policyFreshness,
		Candidates: analysisOutputSlice(result.candidates), Findings: analysisOutputSlice(result.findings), Summary: result.summary,
	}
	return analysisOutputSpec{mode: AnalysisModeJurisdictionContext, metadata: metadata, digest: result.digest, document: document, csvColumns: analysisModeCSVColumns[AnalysisModeJurisdictionContext], walk: func(visit func(string, string, any) error) error {
		if err := visit("metadata", "metadata", meta); err != nil {
			return err
		}
		if err := walkSlice("candidate", result.candidates, visit); err != nil {
			return err
		}
		return walkSlice("finding", result.findings, visit)
	}}
}

func analysisOutputSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
