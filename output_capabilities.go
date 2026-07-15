package dmarcgo

import "fmt"

// OutputAccess describes whether producing a completed mode result may use a
// caller-selected side effect. Output serialization always uses OutputAccessNone.
type OutputAccess string

const (
	OutputAccessNone             OutputAccess = "none"
	OutputAccessExplicitRequired OutputAccess = "explicit_required"
	OutputAccessExplicitOptional OutputAccess = "explicit_optional"
)

// OutputModeEffects describes side effects of producing or serializing one
// mode. SubjectIPContact must remain false for every dmarcgo mode.
type OutputModeEffects struct {
	NetworkAccess        OutputAccess `json:"network_access"`
	ReportFileAccess     OutputAccess `json:"report_file_access"`
	DNSAccess            OutputAccess `json:"dns_access"`
	ProviderCatalogUse   OutputAccess `json:"provider_catalog_use"`
	EnrichmentUse        OutputAccess `json:"enrichment_use"`
	CampaignSourceAccess OutputAccess `json:"campaign_source_access"`
	SubjectIPContact     bool         `json:"subject_ip_contact"`
}

// OutputModeDescriptor is the stable, inspectable mode-isolation contract.
// Required and optional inputs describe result production. Prohibited inputs
// identify adjacent workflows that must not be invoked implicitly.
type OutputModeDescriptor struct {
	Mode              OutputMode        `json:"mode"`
	RequiredInputs    []string          `json:"required_inputs"`
	OptionalInputs    []string          `json:"optional_inputs"`
	ProhibitedInputs  []string          `json:"prohibited_inputs"`
	Analysis          OutputModeEffects `json:"analysis"`
	Serialization     OutputModeEffects `json:"serialization"`
	ComputationalWork string            `json:"computational_work"`
	SensitiveOutputs  []string          `json:"sensitive_outputs"`
}

var outputModeOrder = []OutputMode{
	OutputModeConfigurationValidation,
	OutputModeDNSSnapshot,
	OutputModeDNSAuthentication,
	OutputModeDNSHealth,
	OutputModeDNSPerspectives,
	OutputModeReportValidation,
	OutputModeReportSummary,
	OutputModeAggregateSummary,
	OutputModeReportRows,
	OutputModeSourceReview,
	OutputModeReportEvidence,
	OutputModeDNSReportCorrelation,
	OutputModeThreatCandidates,
	OutputModeSourceEnrichment,
	OutputModeSourceActivity,
	OutputModePhishingIntelligence,
	OutputModeJurisdictionContext,
	OutputModeCampaignValidation,
	OutputModeCampaignClassification,
}

var noOutputEffects = OutputModeEffects{
	NetworkAccess: OutputAccessNone, ReportFileAccess: OutputAccessNone, DNSAccess: OutputAccessNone,
	ProviderCatalogUse: OutputAccessNone, EnrichmentUse: OutputAccessNone, CampaignSourceAccess: OutputAccessNone,
	SubjectIPContact: false,
}

var outputModeDescriptors = map[OutputMode]OutputModeDescriptor{
	OutputModeConfigurationValidation: outputDescriptor(OutputModeConfigurationValidation,
		[]string{"portfolio configuration"}, nil, []string{"DNS snapshot", "aggregate reports", "campaign sources"}, noOutputEffects,
		"bounded configuration normalization and validation", []string{"organization identifiers", "configuration paths"}),
	OutputModeDNSSnapshot: outputDescriptor(OutputModeDNSSnapshot,
		[]string{"normalized portfolio", "caller-supplied TXT resolver"}, nil, []string{"aggregate reports", "enrichment", "campaign sources"},
		OutputModeEffects{NetworkAccess: OutputAccessExplicitRequired, ReportFileAccess: OutputAccessNone, DNSAccess: OutputAccessExplicitRequired, ProviderCatalogUse: OutputAccessNone, EnrichmentUse: OutputAccessNone, CampaignSourceAccess: OutputAccessNone},
		"bounded explicit DNS collection", []string{"record owner names", "TXT answers", "resolver identity"}),
	OutputModeDNSAuthentication: outputDescriptor(OutputModeDNSAuthentication,
		[]string{"completed DNS snapshot"}, nil, []string{"network access", "aggregate reports", "campaign sources"}, noOutputEffects,
		"bounded parsing of supplied DNS evidence", []string{"record owner names", "authentication record values"}),
	OutputModeDNSHealth: outputDescriptor(OutputModeDNSHealth,
		[]string{"normalized portfolio", "parsed authentication records"}, []string{"provider catalog"}, []string{"network access", "aggregate reports", "campaign sources"},
		withProviderCatalog(noOutputEffects), "bounded DNS health and maturity evaluation", []string{"organization inventory", "record names", "provider context"}),
	OutputModeDNSPerspectives: outputDescriptor(OutputModeDNSPerspectives,
		[]string{"normalized portfolio", "completed DNS snapshot", "explicit record selection"}, []string{"caller-supplied DNS perspective provider"}, []string{"aggregate reports", "source-IP lookup", "health-score mutation"},
		OutputModeEffects{NetworkAccess: OutputAccessExplicitOptional, ReportFileAccess: OutputAccessNone, DNSAccess: OutputAccessExplicitOptional, ProviderCatalogUse: OutputAccessNone, EnrichmentUse: OutputAccessNone, CampaignSourceAccess: OutputAccessNone},
		"bounded explicit remote-perspective collection", []string{"selected DNS names", "remote answers", "provider provenance"}),
	OutputModeReportValidation: outputDescriptor(OutputModeReportValidation,
		[]string{"parsed aggregate report"}, nil, []string{"DNS", "portfolio", "enrichment", "campaign sources"}, noOutputEffects,
		"bounded report validation", []string{"report validation paths"}),
	OutputModeReportSummary: outputDescriptor(OutputModeReportSummary,
		[]string{"computed report summary"}, nil, []string{"DNS", "portfolio", "enrichment", "campaign sources"}, noOutputEffects,
		"bounded summary representation", []string{"reporter", "domains", "source IPs"}),
	OutputModeAggregateSummary: outputDescriptor(OutputModeAggregateSummary,
		[]string{"computed aggregate summary"}, nil, []string{"DNS", "portfolio", "enrichment", "campaign sources"}, noOutputEffects,
		"bounded summary representation", []string{"reporters", "domains", "source IPs"}),
	OutputModeReportRows: outputDescriptor(OutputModeReportRows,
		[]string{"computed report rows"}, nil, []string{"DNS", "portfolio", "enrichment", "campaign sources"}, noOutputEffects,
		"bounded row representation", []string{"report metadata", "domains", "selectors", "source IPs", "untrusted report text"}),
	OutputModeSourceReview: outputDescriptor(OutputModeSourceReview,
		[]string{"computed source-review summaries"}, nil, []string{"DNS", "portfolio", "enrichment", "campaign sources"}, noOutputEffects,
		"bounded source-summary representation", []string{"domains", "source IPs"}),
	OutputModeReportEvidence: outputDescriptor(OutputModeReportEvidence,
		[]string{"parsed aggregate reports"}, nil, []string{"DNS", "portfolio", "enrichment", "campaign sources"}, noOutputEffects,
		"bounded report-only normalization", []string{"reporters", "domains", "selectors", "source IPs", "report identities"}),
	OutputModeDNSReportCorrelation: outputDescriptor(OutputModeDNSReportCorrelation,
		[]string{"normalized portfolio", "completed DNS health", "completed report evidence"}, []string{"caller-selected prior correlation result"}, []string{"DNS collection", "report parsing", "enrichment", "campaign sources"},
		noOutputEffects, "bounded pure correlation", []string{"organization inventory", "domains", "selectors", "source IPs"}),
	OutputModeThreatCandidates: outputDescriptor(OutputModeThreatCandidates,
		[]string{"normalized portfolio", "completed report evidence", "completed DNS/report correlation"}, nil, []string{"DNS", "network access", "enrichment", "subject-IP contact"}, noOutputEffects,
		"bounded pure candidate scoring", []string{"organization inventory", "source IPs", "exclusions"}),
	OutputModeSourceEnrichment: outputDescriptor(OutputModeSourceEnrichment,
		[]string{"completed threat candidates"}, []string{"caller-supplied IP enricher"}, []string{"DNS", "report parsing", "subject-IP contact"},
		OutputModeEffects{NetworkAccess: OutputAccessExplicitOptional, ReportFileAccess: OutputAccessNone, DNSAccess: OutputAccessNone, ProviderCatalogUse: OutputAccessNone, EnrichmentUse: OutputAccessExplicitOptional, CampaignSourceAccess: OutputAccessNone},
		"bounded explicit third-party enrichment", []string{"source IPs", "provider metadata", "ASN and country assertions"}),
	OutputModeSourceActivity: outputDescriptor(OutputModeSourceActivity,
		[]string{"completed threat candidates", "explicit candidate or source-IP selection"}, []string{"matching source enrichment", "caller-supplied source-activity provider"}, []string{"DNS", "report parsing", "subject-IP contact"},
		OutputModeEffects{NetworkAccess: OutputAccessExplicitOptional, ReportFileAccess: OutputAccessNone, DNSAccess: OutputAccessNone, ProviderCatalogUse: OutputAccessNone, EnrichmentUse: OutputAccessExplicitOptional, CampaignSourceAccess: OutputAccessNone},
		"bounded explicit third-party activity lookup", []string{"source IPs", "provider activity", "feed memberships"}),
	OutputModePhishingIntelligence: outputDescriptor(OutputModePhishingIntelligence,
		[]string{"completed threat candidates", "completed report evidence", "normalized offline intelligence snapshots"}, nil, []string{"network access", "DNS", "subject-IP contact"}, noOutputEffects,
		"bounded pure exact-match correlation", []string{"source IPs", "domains", "provider intelligence"}),
	OutputModeJurisdictionContext: outputDescriptor(OutputModeJurisdictionContext,
		[]string{"completed source enrichment", "explicit immutable jurisdiction policy"}, nil, []string{"network access", "DNS", "policy discovery", "subject-IP contact"}, noOutputEffects,
		"bounded pure jurisdiction evaluation", []string{"source IPs", "country assertions", "policy context"}),
	OutputModeCampaignValidation: outputDescriptor(OutputModeCampaignValidation,
		[]string{"explicit campaign configuration sources"}, []string{"caller-supplied source adapters", "caller-supplied prior snapshot"}, []string{"DMARC reports", "DNS", "source enrichment"},
		OutputModeEffects{NetworkAccess: OutputAccessExplicitOptional, ReportFileAccess: OutputAccessExplicitOptional, DNSAccess: OutputAccessNone, ProviderCatalogUse: OutputAccessNone, EnrichmentUse: OutputAccessNone, CampaignSourceAccess: OutputAccessExplicitRequired},
		"bounded explicit campaign-source resolution", []string{"restricted campaign inventory", "source provenance"}),
	OutputModeCampaignClassification: outputDescriptor(OutputModeCampaignClassification,
		[]string{"completed campaign snapshot", "normalized body-free message or aggregate evidence"}, nil, []string{"campaign retrieval", "DNS", "enrichment", "message body"}, noOutputEffects,
		"bounded pure campaign classification", []string{"restricted campaign identity", "message evidence", "workflow routing"}),
}

func outputDescriptor(mode OutputMode, required, optional, prohibited []string, analysis OutputModeEffects, work string, sensitive []string) OutputModeDescriptor {
	return OutputModeDescriptor{
		Mode: mode, RequiredInputs: required, OptionalInputs: emptyStrings(optional), ProhibitedInputs: prohibited,
		Analysis: analysis, Serialization: noOutputEffects, ComputationalWork: work, SensitiveOutputs: sensitive,
	}
}

func withProviderCatalog(effects OutputModeEffects) OutputModeEffects {
	effects.ProviderCatalogUse = OutputAccessExplicitOptional
	return effects
}

func emptyStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// OutputModeDescriptors returns the supported modes in dependency order.
func OutputModeDescriptors() []OutputModeDescriptor {
	result := make([]OutputModeDescriptor, 0, len(outputModeOrder))
	for _, mode := range outputModeOrder {
		descriptor, _ := OutputModeDescriptorFor(mode)
		result = append(result, descriptor)
	}
	return result
}

// OutputModeDescriptorFor returns a defensive copy of one isolation contract.
func OutputModeDescriptorFor(mode OutputMode) (OutputModeDescriptor, error) {
	descriptor, ok := outputModeDescriptors[mode]
	if !ok {
		return OutputModeDescriptor{}, fmt.Errorf("%w: unsupported mode %q", ErrInvalidOutputOptions, mode)
	}
	descriptor.RequiredInputs = append([]string(nil), descriptor.RequiredInputs...)
	descriptor.OptionalInputs = append([]string(nil), descriptor.OptionalInputs...)
	descriptor.ProhibitedInputs = append([]string(nil), descriptor.ProhibitedInputs...)
	descriptor.SensitiveOutputs = append([]string(nil), descriptor.SensitiveOutputs...)
	return descriptor, nil
}
