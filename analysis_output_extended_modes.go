package dmarcgo

type configurationValidationOutputDocument struct {
	analysisOutputHeader
	Diagnostics []ConfigurationDiagnostic `json:"diagnostics"`
}

type dnsSnapshotOutputDocument struct {
	analysisOutputHeader
	PortfolioDigest AnalysisID                `json:"portfolio_digest"`
	Complete        bool                      `json:"complete"`
	Observations    []DNSObservation          `json:"observations"`
	Diagnostics     []DNSCollectionDiagnostic `json:"diagnostics"`
}

type dnsAuthenticationOutputDocument struct {
	analysisOutputHeader
	PortfolioDigest AnalysisID                 `json:"portfolio_digest"`
	SnapshotDigest  AnalysisID                 `json:"snapshot_digest"`
	RecordSets      []AuthenticationRecordSet  `json:"record_sets"`
	Diagnostics     []AuthenticationDiagnostic `json:"diagnostics"`
}

type dnsPerspectivesOutputDocument struct {
	analysisOutputHeader
	Version         string                      `json:"version"`
	PortfolioDigest AnalysisID                  `json:"portfolio_digest"`
	SnapshotDigest  AnalysisID                  `json:"snapshot_digest"`
	Complete        bool                        `json:"complete"`
	Queries         []DNSPerspectiveQueryResult `json:"queries"`
	Findings        []DNSPerspectiveFinding     `json:"findings"`
	Diagnostics     []DNSPerspectiveDiagnostic  `json:"diagnostics"`
	Summary         DNSPerspectiveSummary       `json:"summary"`
}

type sourceActivityOutputDocument struct {
	analysisOutputHeader
	Version                string                     `json:"version"`
	OrganizationID         string                     `json:"organization_id"`
	ThreatCandidateDigest  AnalysisID                 `json:"threat_candidate_digest"`
	SourceEnrichmentDigest AnalysisID                 `json:"source_enrichment_digest,omitempty"`
	Complete               bool                       `json:"complete"`
	Records                []SourceActivityRecord     `json:"records"`
	Findings               []SourceActivityFinding    `json:"findings"`
	Diagnostics            []SourceActivityDiagnostic `json:"diagnostics"`
	Summary                SourceActivitySummary      `json:"summary"`
}

type phishingIntelligenceOutputDocument struct {
	analysisOutputHeader
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
}

type configurationValidationOutputMetadata struct {
	Metadata     ResultMetadata `json:"metadata"`
	ResultDigest AnalysisID     `json:"result_digest"`
}

type dnsSnapshotOutputMetadata struct {
	Metadata        ResultMetadata `json:"metadata"`
	PortfolioDigest AnalysisID     `json:"portfolio_digest"`
	Complete        bool           `json:"complete"`
}

type dnsAuthenticationOutputMetadata struct {
	Metadata        ResultMetadata `json:"metadata"`
	PortfolioDigest AnalysisID     `json:"portfolio_digest"`
	SnapshotDigest  AnalysisID     `json:"snapshot_digest"`
}

type dnsPerspectivesOutputMetadata struct {
	Metadata        ResultMetadata        `json:"metadata"`
	Version         string                `json:"version"`
	PortfolioDigest AnalysisID            `json:"portfolio_digest"`
	SnapshotDigest  AnalysisID            `json:"snapshot_digest"`
	Complete        bool                  `json:"complete"`
	Summary         DNSPerspectiveSummary `json:"summary"`
}

type sourceActivityOutputMetadata struct {
	Metadata               ResultMetadata        `json:"metadata"`
	Version                string                `json:"version"`
	OrganizationID         string                `json:"organization_id"`
	ThreatCandidateDigest  AnalysisID            `json:"threat_candidate_digest"`
	SourceEnrichmentDigest AnalysisID            `json:"source_enrichment_digest,omitempty"`
	Complete               bool                  `json:"complete"`
	Summary                SourceActivitySummary `json:"summary"`
}

type phishingIntelligenceOutputMetadata struct {
	Metadata              ResultMetadata              `json:"metadata"`
	Version               string                      `json:"version"`
	OrganizationID        string                      `json:"organization_id"`
	ThreatCandidateDigest AnalysisID                  `json:"threat_candidate_digest"`
	ReportEvidenceDigest  AnalysisID                  `json:"report_evidence_digest"`
	SnapshotDigests       []AnalysisID                `json:"snapshot_digests"`
	Summary               PhishingIntelligenceSummary `json:"summary"`
}

func configurationValidationOutputSpec(result ConfigurationValidationResult) analysisOutputSpec {
	digest := StableAnalysisID("configuration_validation", canonicalSortKey(result))
	metadata := configurationValidationOutputMetadata{Metadata: result.Metadata, ResultDigest: digest}
	document := configurationValidationOutputDocument{
		analysisOutputHeader: newAnalysisOutputHeader(AnalysisModeConfigurationValidation, result.Metadata, digest),
		Diagnostics:          analysisOutputSlice(result.Diagnostics),
	}
	return analysisOutputSpec{
		mode: AnalysisModeConfigurationValidation, metadata: result.Metadata, digest: digest, document: document,
		csvColumns: analysisModeCSVColumns[AnalysisModeConfigurationValidation],
		walk: func(visit func(string, string, any) error) error {
			if err := visit("metadata", "metadata", metadata); err != nil {
				return err
			}
			return walkSlice("diagnostic", result.Diagnostics, visit)
		},
	}
}

func dnsSnapshotOutputSpec(result DNSSnapshot) analysisOutputSpec {
	metadata := result.ResultMetadata()
	observations, diagnostics := result.Observations(), result.Diagnostics()
	meta := dnsSnapshotOutputMetadata{Metadata: metadata, PortfolioDigest: result.PortfolioDigest(), Complete: result.Complete()}
	document := dnsSnapshotOutputDocument{
		analysisOutputHeader: newAnalysisOutputHeader(AnalysisModeDNSSnapshot, metadata, result.Digest()),
		PortfolioDigest:      result.PortfolioDigest(), Complete: result.Complete(),
		Observations: analysisOutputSlice(observations), Diagnostics: analysisOutputSlice(diagnostics),
	}
	return analysisOutputSpec{
		mode: AnalysisModeDNSSnapshot, metadata: metadata, digest: result.Digest(), document: document,
		csvColumns: analysisModeCSVColumns[AnalysisModeDNSSnapshot],
		walk: func(visit func(string, string, any) error) error {
			if err := visit("metadata", "metadata", meta); err != nil {
				return err
			}
			if err := walkSlice("observation", observations, visit); err != nil {
				return err
			}
			return walkSlice("diagnostic", diagnostics, visit)
		},
	}
}

func dnsAuthenticationOutputSpec(result DNSAuthenticationResult) analysisOutputSpec {
	metadata := result.ResultMetadata()
	recordSets, diagnostics := result.RecordSets(), result.Diagnostics()
	meta := dnsAuthenticationOutputMetadata{Metadata: metadata, PortfolioDigest: result.PortfolioDigest(), SnapshotDigest: result.SnapshotDigest()}
	document := dnsAuthenticationOutputDocument{
		analysisOutputHeader: newAnalysisOutputHeader(AnalysisModeDNSAuthentication, metadata, result.Digest()),
		PortfolioDigest:      result.PortfolioDigest(), SnapshotDigest: result.SnapshotDigest(),
		RecordSets: analysisOutputSlice(recordSets), Diagnostics: analysisOutputSlice(diagnostics),
	}
	return analysisOutputSpec{
		mode: AnalysisModeDNSAuthentication, metadata: metadata, digest: result.Digest(), document: document,
		csvColumns: analysisModeCSVColumns[AnalysisModeDNSAuthentication],
		walk: func(visit func(string, string, any) error) error {
			if err := visit("metadata", "metadata", meta); err != nil {
				return err
			}
			if err := walkSlice("record_set", recordSets, visit); err != nil {
				return err
			}
			return walkSlice("diagnostic", diagnostics, visit)
		},
	}
}

func dnsPerspectivesOutputSpec(result DNSPerspectiveResult) analysisOutputSpec {
	metadata := result.ResultMetadata()
	queries, findings, diagnostics := result.Queries(), result.Findings(), result.Diagnostics()
	meta := dnsPerspectivesOutputMetadata{
		Metadata: metadata, Version: result.Version(), PortfolioDigest: result.PortfolioDigest(), SnapshotDigest: result.SnapshotDigest(),
		Complete: result.Complete(), Summary: result.Summary(),
	}
	document := dnsPerspectivesOutputDocument{
		analysisOutputHeader: newAnalysisOutputHeader(AnalysisModeDNSPerspectives, metadata, result.Digest()),
		Version:              result.Version(), PortfolioDigest: result.PortfolioDigest(), SnapshotDigest: result.SnapshotDigest(), Complete: result.Complete(),
		Queries: analysisOutputSlice(queries), Findings: analysisOutputSlice(findings), Diagnostics: analysisOutputSlice(diagnostics), Summary: result.Summary(),
	}
	return analysisOutputSpec{
		mode: AnalysisModeDNSPerspectives, metadata: metadata, digest: result.Digest(), document: document,
		csvColumns: analysisModeCSVColumns[AnalysisModeDNSPerspectives],
		walk: func(visit func(string, string, any) error) error {
			if err := visit("metadata", "metadata", meta); err != nil {
				return err
			}
			if err := walkSlice("query", queries, visit); err != nil {
				return err
			}
			if err := walkSlice("finding", findings, visit); err != nil {
				return err
			}
			return walkSlice("diagnostic", diagnostics, visit)
		},
	}
}

func sourceActivityOutputSpec(result SourceActivityResult) analysisOutputSpec {
	metadata := result.ResultMetadata()
	records, findings, diagnostics := result.Records(), result.Findings(), result.Diagnostics()
	meta := sourceActivityOutputMetadata{
		Metadata: metadata, Version: result.Version(), OrganizationID: result.OrganizationID(), ThreatCandidateDigest: result.ThreatCandidateDigest(),
		SourceEnrichmentDigest: result.SourceEnrichmentDigest(), Complete: result.Complete(), Summary: result.Summary(),
	}
	document := sourceActivityOutputDocument{
		analysisOutputHeader: newAnalysisOutputHeader(AnalysisModeSourceActivity, metadata, result.Digest()),
		Version:              result.Version(), OrganizationID: result.OrganizationID(), ThreatCandidateDigest: result.ThreatCandidateDigest(),
		SourceEnrichmentDigest: result.SourceEnrichmentDigest(), Complete: result.Complete(), Records: analysisOutputSlice(records),
		Findings: analysisOutputSlice(findings), Diagnostics: analysisOutputSlice(diagnostics), Summary: result.Summary(),
	}
	return analysisOutputSpec{
		mode: AnalysisModeSourceActivity, metadata: metadata, digest: result.Digest(), document: document,
		csvColumns: analysisModeCSVColumns[AnalysisModeSourceActivity],
		walk: func(visit func(string, string, any) error) error {
			if err := visit("metadata", "metadata", meta); err != nil {
				return err
			}
			if err := walkSlice("record", records, visit); err != nil {
				return err
			}
			if err := walkSlice("finding", findings, visit); err != nil {
				return err
			}
			return walkSlice("diagnostic", diagnostics, visit)
		},
	}
}

func phishingIntelligenceOutputSpec(result PhishingIntelligenceResult) analysisOutputSpec {
	metadata := result.ResultMetadata()
	sources, candidates, matches, findings := result.Sources(), result.Candidates(), result.Matches(), result.Findings()
	meta := phishingIntelligenceOutputMetadata{
		Metadata: metadata, Version: result.Version(), OrganizationID: result.OrganizationID(), ThreatCandidateDigest: result.ThreatCandidateDigest(),
		ReportEvidenceDigest: result.ReportEvidenceDigest(), SnapshotDigests: result.SnapshotDigests(), Summary: result.Summary(),
	}
	document := phishingIntelligenceOutputDocument{
		analysisOutputHeader: newAnalysisOutputHeader(AnalysisModePhishingIntelligence, metadata, result.Digest()),
		Version:              result.Version(), OrganizationID: result.OrganizationID(), ThreatCandidateDigest: result.ThreatCandidateDigest(),
		ReportEvidenceDigest: result.ReportEvidenceDigest(), SnapshotDigests: result.SnapshotDigests(), Sources: analysisOutputSlice(sources),
		Candidates: analysisOutputSlice(candidates), Matches: analysisOutputSlice(matches), Findings: analysisOutputSlice(findings), Summary: result.Summary(),
	}
	return analysisOutputSpec{
		mode: AnalysisModePhishingIntelligence, metadata: metadata, digest: result.Digest(), document: document,
		csvColumns: analysisModeCSVColumns[AnalysisModePhishingIntelligence],
		walk: func(visit func(string, string, any) error) error {
			if err := visit("metadata", "metadata", meta); err != nil {
				return err
			}
			if err := walkSlice("source", sources, visit); err != nil {
				return err
			}
			if err := walkSlice("candidate", candidates, visit); err != nil {
				return err
			}
			if err := walkSlice("match", matches, visit); err != nil {
				return err
			}
			return walkSlice("finding", findings, visit)
		},
	}
}
