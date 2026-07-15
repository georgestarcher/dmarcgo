package dmarcgo

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

type exampleTXTResolver map[string]string

func (resolver exampleTXTResolver) LookupTXT(_ context.Context, name string) (TXTLookupResult, error) {
	value := resolver[name]
	ttl := DNSDurationEvidence{Available: true, Seconds: 300}
	return TXTLookupResult{
		Name: name, Status: DNSObservationSuccess,
		Records: []TXTRecord{{Fragments: []string{value}, FragmentsAvailable: true, Joined: value, TTL: ttl}},
		TTL:     ttl, AnswerSource: DNSAnswerSourceRecursive, RCode: DNSRCodeEvidence{Available: true}, CNAMEPath: []string{},
	}, nil
}

type exampleDNSPerspectiveProvider map[string]string

func (provider exampleDNSPerspectiveProvider) LookupDNSPerspective(ctx context.Context, query DNSPerspectiveQuery) (DNSPerspectiveResponse, error) {
	select {
	case <-ctx.Done():
		return DNSPerspectiveResponse{}, ctx.Err()
	default:
	}
	answer := DNSPerspectiveAnswer{Fragments: []string{provider[query.Name]}, FragmentsAvailable: true}
	return DNSPerspectiveResponse{
		Provider: "offline-example", Dataset: "embedded-fixture-v1",
		Observations: []DNSPerspectiveProviderObservation{
			{PerspectiveID: "resolver-a", Perspective: "fixture-a", Outcome: DNSPerspectiveSuccess, Answers: []DNSPerspectiveAnswer{answer}},
			{PerspectiveID: "resolver-b", Perspective: "fixture-b", Outcome: DNSPerspectiveSuccess, Answers: []DNSPerspectiveAnswer{answer}},
		},
	}, nil
}

type exampleIPEnricher map[netip.Addr]IPMetadata

func (enricher exampleIPEnricher) EnrichIP(ctx context.Context, ip netip.Addr) (IPMetadata, error) {
	select {
	case <-ctx.Done():
		return IPMetadata{}, ctx.Err()
	default:
	}
	metadata, ok := enricher[ip]
	if !ok {
		return IPMetadata{}, ErrIPMetadataUnavailable
	}
	return metadata, nil
}

type exampleSourceActivityProvider map[netip.Addr]SourceActivityResponse

func (provider exampleSourceActivityProvider) LookupSourceActivity(ctx context.Context, ip netip.Addr) (SourceActivityResponse, error) {
	select {
	case <-ctx.Done():
		return SourceActivityResponse{}, ctx.Err()
	default:
	}
	response, ok := provider[ip]
	if !ok {
		return SourceActivityResponse{}, ErrSourceActivityUnavailable
	}
	return response, nil
}

type exampleRoundTripper func(*http.Request) (*http.Response, error)

func (roundTripper exampleRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

func exampleCampaignConfiguration() CampaignConfigurationConfig {
	return CampaignConfigurationConfig{
		SchemaVersion: CampaignConfigurationSchemaVersion,
		GeneratedAt:   time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		SecuritySimulations: []SecuritySimulationCampaignConfig{{
			ID: "quarterly-awareness", Provider: CampaignProviderConfig{Type: CampaignProviderSelfHosted, ID: "awareness-platform", Name: "Example Awareness Platform"},
			Organization: "example-org", Owner: "security-awareness", ApprovalReference: "TEST-1001", Status: CampaignStatusActive,
			CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), ValidFrom: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2026, 7, 20, 23, 59, 59, 0, time.UTC),
			RecipientDomains: []string{"example.test"},
			ExpectedIdentity: CampaignExpectedIdentityConfig{
				HeaderFromDomains: []string{"training.example.test"},
				DKIM:              []CampaignDKIMIdentityConfig{{Domain: "training.example.test", Selectors: []string{"simulation-2026"}}},
			},
			TokenDigests:   []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Authentication: CampaignAuthenticationConfig{DMARC: CampaignAuthenticationRequired, DKIM: CampaignAuthenticationRequired},
			ResponsePolicy: CampaignResponsePolicyConfig{EmployeeDisclosure: CampaignDisclosureProhibited},
			Handling:       CampaignHandlingConfig{WorkflowID: "restricted-simulation-review"},
			MatchPolicy: CampaignMatchPolicyConfig{RequiredFactors: []CampaignMatchFactor{
				CampaignFactorWindow, CampaignFactorOrganizationScope, CampaignFactorHeaderFrom, CampaignFactorDKIM, CampaignFactorTokenDigest, CampaignFactorAuthentication,
			}},
		}},
	}
}

// ExampleLoadCampaignConfiguration demonstrates strict, offline parsing and
// normalization of a versioned campaign inventory.
func ExampleLoadCampaignConfiguration() {
	data, err := json.Marshal(exampleCampaignConfiguration())
	if err != nil {
		log.Fatal(err)
	}
	document, err := LoadCampaignConfiguration(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("schema=%d campaigns=%d\n", document.SchemaVersion(), len(document.Campaigns()))
	// Output: schema=1 campaigns=1
}

// ExampleResolveCampaignConfiguration demonstrates explicit source loading and
// an immutable freshness-checked snapshot.
func ExampleResolveCampaignConfiguration() {
	data, err := json.Marshal(exampleCampaignConfiguration())
	if err != nil {
		log.Fatal(err)
	}
	snapshot, err := ResolveCampaignConfiguration(context.Background(), []CampaignConfigurationSourceSpec{{
		ID: "testing-team-feed", Source: NewCampaignBytesSource(data, CampaignConfigurationMetadata{}), Required: true,
	}}, CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time {
		return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	})})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("complete=%t authorization=%t sources=%d\n", snapshot.Complete(), snapshot.AuthorizationAvailable(), len(snapshot.Sources()))
	// Output: complete=true authorization=true sources=1
}

// ExampleNewCampaignHTTPSSource demonstrates caller-controlled HTTPS retrieval
// with an offline transport fixture. Production callers own endpoint and
// redirect allowlists, credentials, response limits, caching, and scheduling.
func ExampleNewCampaignHTTPSSource() {
	data, err := json.Marshal(exampleCampaignConfiguration())
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: exampleRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(data)),
			Request:    request,
		}, nil
	})}
	source, err := NewCampaignHTTPSSource("https://config.example.test/security-simulations.json", client)
	if err != nil {
		log.Fatal(err)
	}
	snapshot, err := ResolveCampaignConfiguration(context.Background(), []CampaignConfigurationSourceSpec{{
		ID: "testing-team-https", Source: source, Required: true,
	}}, CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time {
		return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	})})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("complete=%t authorization=%t sources=%d\n", snapshot.Complete(), snapshot.AuthorizationAvailable(), len(snapshot.Sources()))
	// Output: complete=true authorization=true sources=1
}

// ExampleClassifyReportedMessage demonstrates pure classification followed by
// a disclosure-safe view suitable for neutral response routing.
func ExampleClassifyReportedMessage() {
	data, err := json.Marshal(exampleCampaignConfiguration())
	if err != nil {
		log.Fatal(err)
	}
	snapshot, err := ResolveCampaignConfiguration(context.Background(), []CampaignConfigurationSourceSpec{{
		ID: "testing-team-feed", Source: NewCampaignBytesSource(data, CampaignConfigurationMetadata{}), Required: true,
	}}, CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time {
		return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	})})
	if err != nil {
		log.Fatal(err)
	}
	evidence, err := NormalizeReportedMessageEvidence(ReportedMessageEvidenceInput{
		Organization: "example-org", HeaderFromDomain: "training.example.test",
		DKIM:        []CampaignDKIMEvidenceInput{{Domain: "training.example.test", Selector: "simulation-2026", Outcome: ReportAuthenticationPass}},
		DKIMOutcome: ReportAuthenticationPass, DMARCOutcome: ReportAuthenticationPass,
		RecipientDomains: []string{"example.test"}, TokenDigests: []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		MessageTime: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
		Provenance:  []CampaignEvidenceProvenanceInput{{SourceID: "message-parser", Type: CampaignEvidenceMessageHeaders, ObservedAt: time.Date(2026, 7, 15, 12, 1, 0, 0, time.UTC), Confidence: FindingConfidenceHigh}},
	})
	if err != nil {
		log.Fatal(err)
	}
	result, err := ClassifyReportedMessage(snapshot, evidence, CampaignClassificationOptions{})
	if err != nil {
		log.Fatal(err)
	}
	safe, err := result.DisclosureSafe()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("privileged=%s safe_route=%s employee_template=%s automatic=%t\n",
		result.Summary().OverallClassification, safe.Records[0].Routing, safe.Records[0].NeutralEmployeeTemplateID, safe.Records[0].AutomaticDispositionEligible)
	// Output: privileged=authorized_simulation_high_confidence safe_route=restricted_policy_review employee_template=suspicious-message-received automatic=false
}

// ExampleEvaluateDNSHealth demonstrates explicit collection followed by pure
// authentication parsing and DNS-only posture evaluation.
func ExampleEvaluateDNSHealth() {
	portfolio, err := NormalizePortfolio(PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-org"},
		Entities: []EntityConfig{{ID: "primary", Domains: []DomainConfig{{
			Name: "example.test", Records: MonitoredRecordsConfig{
				SPF: []string{"example.test"}, DMARC: []string{"_dmarc.example.test"},
			},
		}}}},
	})
	if err != nil {
		log.Fatal(err)
	}
	observedAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, exampleTXTResolver{
		"example.test":        "v=spf1 -all",
		"_dmarc.example.test": "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:reports@example.test",
	}, DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return observedAt }), MaxAttempts: 1})
	if err != nil {
		log.Fatal(err)
	}
	authentication, err := ParseAuthenticationRecords(snapshot)
	if err != nil {
		log.Fatal(err)
	}
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		log.Fatal(err)
	}
	health, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{Profile: DNSHealthProfileBalanced})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("score=%d grade=%s maturity=%s findings=%d\n", health.PortfolioScore().Value, health.PortfolioScore().Grade, health.PortfolioMaturity().Name, len(health.Findings()))
	// Output: score=100 grade=A+ maturity=basic findings=0
}

// ExampleCollectDNSPerspectives demonstrates explicit, offline-fixture
// resolver-consistency collection for selected portfolio record roles.
func ExampleCollectDNSPerspectives() {
	portfolio, err := NormalizePortfolio(PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-org"},
		Entities: []EntityConfig{{ID: "primary", Domains: []DomainConfig{{
			Name: "example.test", Records: MonitoredRecordsConfig{
				SPF:   []string{"example.test"},
				DKIM:  []string{"primary._domainkey.example.test"},
				DMARC: []string{"_dmarc.example.test"},
			},
		}}}},
	})
	if err != nil {
		log.Fatal(err)
	}
	values := map[string]string{
		"example.test":                    "v=spf1 -all",
		"primary._domainkey.example.test": "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"_dmarc.example.test":             "v=DMARC1; p=reject",
	}
	observedAt := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, exampleTXTResolver(values), DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return observedAt }), MaxAttempts: 1,
	})
	if err != nil {
		log.Fatal(err)
	}
	result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, exampleDNSPerspectiveProvider(values), DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC}},
		Clock:     ClockFunc(func() time.Time { return observedAt.Add(time.Minute) }),
	})
	if err != nil {
		log.Fatal(err)
	}
	summary := result.Summary()
	fmt.Printf("queries=%d successful_perspectives=%d findings=%d complete=%t\n", summary.Queries, summary.SuccessfulPerspectives, summary.Findings, result.Complete())
	// Output: queries=3 successful_perspectives=6 findings=0 complete=true
}

// ExampleAnalyzeReportEvidence demonstrates reusable report-only evidence and
// deterministic source grouping.
func ExampleAnalyzeReportEvidence() {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		log.Fatal(err)
	}
	evidence, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{
		GeneratedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		log.Fatal(err)
	}
	sources, err := evidence.Aggregate(ReportEvidenceFilter{}, ReportEvidenceBySourceIP)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("reports=%d messages=%d sources=%d failed=%d\n",
		evidence.Summary().Reports, evidence.Summary().Messages, len(sources), evidence.Summary().Combined.Fail)
	// Output: reports=1 messages=5 sources=2 failed=3
}

// ExampleCorrelateReportEvidence demonstrates the pure comparison of declared
// sender intent, current DNS health, and normalized historical report evidence.
func ExampleCorrelateReportEvidence() {
	portfolio, err := NormalizePortfolio(PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-org"},
		ExpectedSenders: []ExpectedSenderConfig{{
			ID: "workspace", RequireDKIM: true, AllowedSelectors: []string{"s1"},
		}},
		Entities: []EntityConfig{{ID: "primary", Domains: []DomainConfig{{
			Name: "example.com", Records: MonitoredRecordsConfig{
				SPF: []string{"example.com"}, DKIM: []string{"s1._domainkey.example.com"}, DMARC: []string{"_dmarc.example.com"},
			}, ExpectedSenders: []string{"workspace"},
		}}}},
	})
	if err != nil {
		log.Fatal(err)
	}
	observedAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, exampleTXTResolver{
		"example.com":               "v=spf1 -all",
		"s1._domainkey.example.com": "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"_dmarc.example.com":        "v=DMARC1; p=reject; rua=mailto:reports@example.com",
	}, DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return observedAt }), MaxAttempts: 1})
	if err != nil {
		log.Fatal(err)
	}
	authentication, err := ParseAuthenticationRecords(snapshot)
	if err != nil {
		log.Fatal(err)
	}
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		log.Fatal(err)
	}
	health, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{})
	if err != nil {
		log.Fatal(err)
	}
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		log.Fatal(err)
	}
	evidence, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{GeneratedAt: observedAt})
	if err != nil {
		log.Fatal(err)
	}
	correlation, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		log.Fatal(err)
	}
	unknownFailures := 0
	for _, finding := range correlation.Findings() {
		if finding.Classification == CorrelationUnknownSourceFailure {
			unknownFailures++
		}
	}
	fmt.Printf("streams=%d unknown_failures=%d\n", correlation.Summary().Streams, unknownFailures)
	// Output: streams=2 unknown_failures=1
}

// ExampleScoreThreatCandidates demonstrates pure, review-only scoring from
// completed report evidence and correlation.
func ExampleScoreThreatCandidates() {
	result, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	candidate := result.Candidates()[0]
	fmt.Printf("candidates=%d score=%d confidence=%d usage=%s promotion=%t\n",
		result.Summary().Candidates, candidate.Score, candidate.Confidence, candidate.RecommendedUsage, candidate.PromotionEligible)
	// Output: candidates=1 score=35 confidence=45 usage=review_only promotion=false
}

// ExampleCorrelatePhishingIntelligence demonstrates exact, offline correlation
// with a caller-owned synthetic snapshot. A match does not change scoring or
// authorize action.
func ExampleCorrelatePhishingIntelligence() {
	candidates, evidence, err := exampleThreatCandidatesAndEvidence()
	if err != nil {
		log.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	firstSeen := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC)
	snapshot, err := NormalizePhishingIntelligenceSnapshot(PhishingIntelligenceSnapshotConfig{
		Provider: "offline-example", Dataset: "synthetic-fixture-v1", SchemaVersion: "1",
		CollectedAt: lastSeen, AsOf: lastSeen,
		License: PhishingIntelligenceLicense{
			Name: "synthetic fixture terms", CommercialUse: PhishingIntelligenceUsagePermitted,
			Redistribution: PhishingIntelligenceUsagePermitted,
		},
		Indicators: []PhishingIntelligenceIndicatorConfig{{
			Type: PhishingIntelligenceSourceIP, Value: candidate.SourceIP,
			State: PhishingIntelligenceIndicatorActive, FirstSeen: &firstSeen, LastSeen: &lastSeen,
		}},
	})
	if err != nil {
		log.Fatal(err)
	}
	result, err := CorrelatePhishingIntelligence(candidates, evidence, []PhishingIntelligenceSnapshot{snapshot}, PhishingIntelligenceOptions{GeneratedAt: lastSeen})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("status=%s matches=%d score=%d promotion=%t\n",
		result.Candidates()[0].Status, len(result.Matches()), candidate.Score, candidate.PromotionEligible)
	// Output: status=match matches=1 score=35 promotion=false
}

// ExampleBuildSTIXBundle demonstrates the default observation-only STIX 2.1
// export. Creating an Indicator requires an explicit promotion option.
func ExampleBuildSTIXBundle() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	bundle, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{
		Producer: STIXProducer{
			Name:      "Example SOC",
			CreatedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		TLP: STIXTLPAmber,
	})
	if err != nil {
		log.Fatal(err)
	}
	observed, indicators := 0, 0
	for _, object := range bundle.Objects() {
		switch object.Type() {
		case "observed-data":
			observed++
		case "indicator":
			indicators++
		}
	}
	fmt.Printf("observed=%d indicators=%d valid=%t\n", observed, indicators, ValidateSTIXBundle(bundle) == nil)
	// Output: observed=1 indicators=0 valid=true
}

// ExampleBuildThreatConnectIndicatorPayloads demonstrates review-oriented
// native request encoding without credentials, HTTP, or submission.
func ExampleBuildThreatConnectIndicatorPayloads() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	payloads, err := BuildThreatConnectIndicatorPayloads(candidates, nil, ThreatConnectExportOptions{
		Owner:               ThreatConnectOwner{Name: "Example Community"},
		CandidateSelections: []ThreatConnectCandidateSelection{{CandidateID: candidate.ID}},
	})
	if err != nil {
		log.Fatal(err)
	}
	request := struct {
		Active      bool   `json:"active"`
		PrivateFlag bool   `json:"privateFlag"`
		OwnerName   string `json:"ownerName"`
	}{}
	encoded, err := json.Marshal(payloads[0])
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &request); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("type=%s active=%t private=%t owner=%s valid=%t\n",
		payloads[0].Type(), request.Active, request.PrivateFlag, request.OwnerName,
		ValidateThreatConnectIndicatorPayload(payloads[0]) == nil)
	// Output: type=Address active=false private=true owner=Example Community valid=true
}

// ExampleBuildMISPAttributePayloads demonstrates a review-only native
// Attribute request for an explicitly identified existing Event.
func ExampleBuildMISPAttributePayloads() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	mapping := MISPAttributeMapping{Type: MISPAttributeTypeIPSource, Category: "Network activity"}
	payloads, err := BuildMISPAttributePayloads(candidates, MISPAttributeExportOptions{
		Event: MISPEventReference{Identifier: "42"},
		Capabilities: MISPInstanceCapabilities{
			ContractVersion:   "2.5",
			AttributeMappings: []MISPAttributeMapping{mapping},
		},
		Selections: []MISPAttributeSelection{{CandidateID: candidate.ID, Mapping: mapping}},
	})
	if err != nil {
		log.Fatal(err)
	}
	request := struct {
		ToIDS              bool `json:"to_ids"`
		DisableCorrelation bool `json:"disable_correlation"`
	}{}
	encoded, err := json.Marshal(payloads[0])
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &request); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("endpoint=%s to_ids=%t correlation_disabled=%t valid=%t\n",
		payloads[0].Endpoint(), request.ToIDS, request.DisableCorrelation,
		ValidateMISPAttributePayload(payloads[0]) == nil)
	// Output: endpoint=/attributes/add/42 to_ids=false correlation_disabled=true valid=true
}

// ExampleBuildMISPEventPayload demonstrates a complete offline Event body.
// The caller still owns review, credentials, HTTP, and submission.
func ExampleBuildMISPEventPayload() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	mapping := MISPAttributeMapping{Type: MISPAttributeTypeIPSource, Category: "Network activity"}
	published, disableCorrelation := false, true
	payload, err := BuildMISPEventPayload(candidates, MISPEventExportOptions{
		Capabilities: MISPInstanceCapabilities{
			ContractVersion:   "2.5",
			AttributeMappings: []MISPAttributeMapping{mapping},
		},
		Event: MISPEventDefinition{
			UUID: "11111111-2222-4333-8444-555555555555", Info: "DMARC source review",
			Date: candidates.ResultMetadata().GeneratedAt, Distribution: MISPDistributionOrganizationOnly,
			ThreatLevel: MISPThreatLevelUndefined, Analysis: MISPAnalysisInitial,
			Published: &published, DisableCorrelation: &disableCorrelation,
		},
		Selections: []MISPAttributeSelection{{CandidateID: candidate.ID, Mapping: mapping}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("endpoint=%s uuid=%s attributes=%d valid=%t\n",
		payload.Endpoint(), payload.UUID(), len(payload.Source().Attributes), ValidateMISPEventPayload(payload) == nil)
	// Output: endpoint=/events/add uuid=11111111-2222-4333-8444-555555555555 attributes=1 valid=true
}

// ExampleBuildThreatStreamPayloads demonstrates a reviewed, private native
// request using an exact tenant-confirmed fixture contract. The application
// obtains the real fields, allowed values, endpoint, and response assumptions
// from its own ThreatStream tenant; the library never discovers or calls them.
func ExampleBuildThreatStreamPayloads() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	root := func(name string) ThreatStreamJSONField {
		return ThreatStreamJSONField{Name: name, Scope: ThreatStreamFieldRoot}
	}
	payloads, err := BuildThreatStreamPayloads(candidates, ThreatStreamExportOptions{
		Capabilities: ThreatStreamTenantCapabilities{
			ContractVersion: "example-tenant-import-v1", Variant: ThreatStreamReviewedImport,
			Endpoint: "/tenant/api/imports", ItemsField: "observables",
			Fields: ThreatStreamFieldMappings{
				Observable: ThreatStreamJSONField{Name: "value", Scope: ThreatStreamFieldItem},
				IType:      ThreatStreamJSONField{Name: "itype", Scope: ThreatStreamFieldItem},
				Confidence: root("source_confidence"), Severity: root("severity"), Classification: root("classification"),
				TLP: root("tlp"), Tags: root("tags"), Expiration: root("expiration_ts"), ReviewState: root("review_state"),
			},
			ITypes:     []ThreatStreamITypeCapability{{Value: "review_ip", IPTypes: []ThreatCandidateIPType{ThreatCandidateIPv4}}},
			Confidence: ThreatStreamValueRange{Minimum: 0, Maximum: 100},
			Severities: []string{"low"}, Classifications: []string{"private"}, TLPs: []string{"amber"}, ReviewStates: []string{"pending"},
			TagEncoding: ThreatStreamTagsStringArray, TimestampEncoding: ThreatStreamTimestampRFC3339,
			MaximumStringBytes: 256, MaximumTags: 8, MaximumPayloadBytes: 4096,
			ReviewDefaults: ThreatStreamReviewDefaults{
				Confidence: 20, Severity: "low", PrivateClassification: "private", TLP: "amber",
				PendingReviewState: "pending", Tags: []string{"human-review-required"}, ExpirationAfter: 24 * time.Hour,
			},
			Response: ThreatStreamResponseAssumptions{
				ContractVersion: "example-response-v1", Mode: ThreatStreamResponseAsynchronous,
				IdentifierField: "job_id", StatusField: "status", AcceptedStatuses: []string{"queued"},
			},
		},
		Selections: []ThreatStreamCandidateSelection{{CandidateID: candidate.ID, IType: "review_ip"}},
	})
	if err != nil {
		log.Fatal(err)
	}
	request := struct {
		Classification string `json:"classification"`
		ReviewState    string `json:"review_state"`
		Observables    []any  `json:"observables"`
	}{}
	encoded, err := json.Marshal(payloads[0])
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &request); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("variant=%s private=%s review=%s observables=%d valid=%t\n",
		payloads[0].Variant(), request.Classification, request.ReviewState, len(request.Observables),
		ValidateThreatStreamPayload(payloads[0]) == nil)
	// Output: variant=reviewed_import private=private review=pending observables=1 valid=true
}

// ExampleEnrichThreatCandidates demonstrates explicit, offline source
// enrichment after candidate scoring. Applications may instead supply their
// own context-aware third-party service adapter.
func ExampleEnrichThreatCandidates() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	lookupAt := time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)
	expiresAt := lookupAt.Add(24 * time.Hour)
	enriched, err := EnrichThreatCandidates(context.Background(), candidates, exampleIPEnricher{
		netip.MustParseAddr("198.51.100.25"): {Assertions: []IPMetadataAssertion{{
			ASN: 64500, ASNName: "Example Network", NetworkPrefix: "198.51.100.0/24", Organization: "Example Org", CountryCode: "US",
			Provenance: IPMetadataProvenance{Provider: "offline-example", Source: "embedded-fixture", LookupAt: lookupAt, ExpiresAt: &expiresAt},
		}}},
	}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return lookupAt })})
	if err != nil {
		log.Fatal(err)
	}
	value := enriched.Candidates()[0]
	fmt.Printf("status=%s asns=%d confidence=%d promotion=%t\n", value.Status, len(enriched.ASNs()), value.Candidate.Confidence, value.Candidate.PromotionEligible)
	// Output: status=success asns=1 confidence=45 promotion=false
}

// ExampleCollectSourceActivity demonstrates one explicitly selected source
// lookup through an offline provider fixture. A real adapter may contact only
// its configured third-party service, never the selected source address.
func ExampleCollectSourceActivity() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	collectedAt := time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC)
	firstSeen := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)
	result, err := CollectSourceActivity(context.Background(), candidates, nil, exampleSourceActivityProvider{
		netip.MustParseAddr(candidate.SourceIP): {
			Provider: "offline-example", Dataset: "embedded-fixture-v1", EndpointIdentity: "offline-fixture",
			ActivityObserved: true, FirstSeen: &firstSeen, LastSeen: &lastSeen,
			Metrics: []SourceActivityMetric{{Name: "observations", Value: 3, Unit: "count"}},
		},
	}, SourceActivityOptions{
		Selection:  SourceActivitySelection{CandidateIDs: []AnalysisID{candidate.ID}},
		MaxQueries: 1, MaxConcurrency: 1, Clock: ClockFunc(func() time.Time { return collectedAt }),
	})
	if err != nil {
		log.Fatal(err)
	}
	record := result.Records()[0]
	fmt.Printf("status=%s observed=%t score=%d promotion=%t\n", record.Status, record.Evidence.ActivityObserved, candidate.Score, candidate.PromotionEligible)
	// Output: status=success observed=true score=35 promotion=false
}

// ExampleEvaluateJurisdictionContext demonstrates explicit, offline review
// context after source enrichment. A match is not malicious attribution or an
// automatic-action authorization.
func ExampleEvaluateJurisdictionContext() {
	candidates, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	lookupAt := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := lookupAt.Add(24 * time.Hour)
	enriched, err := EnrichThreatCandidates(context.Background(), candidates, exampleIPEnricher{
		netip.MustParseAddr("198.51.100.25"): {Assertions: []IPMetadataAssertion{{
			ASN: 64500, NetworkPrefix: "198.51.100.0/24", CountryCode: "IR",
			Provenance: IPMetadataProvenance{Provider: "offline-example", Source: "embedded-fixture", LookupAt: lookupAt, ExpiresAt: &expiresAt},
		}}},
	}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return lookupAt })})
	if err != nil {
		log.Fatal(err)
	}
	contextResult, err := EvaluateJurisdictionContext(enriched, BuiltinJurisdictionRiskPolicy(), JurisdictionContextOptions{
		EnableReviewPriorityAdjustment: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	value := contextResult.Candidates()[0]
	fmt.Printf("status=%s adjustment=%d score=%d promotion=%t\n",
		value.Status, value.ReviewPriorityAdjustment, enriched.Candidates()[0].Candidate.Score, enriched.Candidates()[0].Candidate.PromotionEligible)
	// Output: status=match adjustment=10 score=35 promotion=false
}

func exampleThreatCandidates() (ThreatCandidateResult, error) {
	result, _, err := exampleThreatCandidatesAndEvidence()
	return result, err
}

func exampleThreatCandidatesAndEvidence() (ThreatCandidateResult, ReportEvidenceResult, error) {
	portfolio, err := NormalizePortfolio(PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-org"},
		Entities: []EntityConfig{{ID: "primary", Domains: []DomainConfig{{
			Name: "example.com", Records: MonitoredRecordsConfig{
				SPF: []string{"example.com"}, DMARC: []string{"_dmarc.example.com"},
			},
		}}}},
	})
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	observedAt := time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, exampleTXTResolver{
		"example.com":        "v=spf1 -all",
		"_dmarc.example.com": "v=DMARC1; p=reject; rua=mailto:reports@example.com",
	}, DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return observedAt }), MaxAttempts: 1})
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	authentication, err := ParseAuthenticationRecords(snapshot)
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	health, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{})
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	evidence, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{GeneratedAt: observedAt})
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	correlation, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	result, err := ScoreThreatCandidates(portfolio, evidence, correlation, ThreatCandidateOptions{})
	if err != nil {
		return ThreatCandidateResult{}, ReportEvidenceResult{}, err
	}
	return result, evidence, nil
}

// ExampleBuildReportSummaryOutput demonstrates agent-friendly structured output.
func ExampleBuildReportSummaryOutput() {
	report, err := ParseBytes([]byte(exampleReportXML))
	if err != nil {
		log.Fatal(err)
	}

	output, err := BuildReportSummaryOutput(report.Summary(), OutputOptions{
		Profile:     OutputProfileAgent,
		Redaction:   OutputRedactionPublic,
		GeneratedAt: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("mode=%s status=%s findings=%d\n", output.Mode, output.Status, len(output.Findings))
	// Output: mode=report_summary status=completed findings=0
}

func ExampleBuildValidationOutput() {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		log.Fatal(err)
	}

	generatedAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	result := report.ValidationResult(ValidationModeCompatibility, generatedAt)
	output, err := BuildValidationOutput(result, OutputOptions{
		Profile: OutputProfileAutomation,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("mode=%s findings=%d\n", output.Mode, len(output.Findings))
	// Output:
	// mode=report_validation findings=0
}

func ExampleBuildAnalysisOutput() {
	generatedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	completed := ValidatePortfolio(PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-org"},
	}, generatedAt)
	output, err := BuildAnalysisOutput(completed, OutputOptions{
		Profile: OutputProfileAgent, Detail: OutputDetailStandard, Redaction: OutputRedactionPublic,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("mode=%s generated=%s schema=%t\n", output.Mode, output.GeneratedAt.Format(time.RFC3339), output.DataSchema != "")
	// Output: mode=configuration_validation generated=2026-07-15T12:00:00Z schema=true
}

func ExampleOutputModeDescriptors() {
	descriptor, err := OutputModeDescriptorFor(OutputModeSourceEnrichment)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("serialization_network=%s subject_ip_contact=%t\n", descriptor.Serialization.NetworkAccess, descriptor.Serialization.SubjectIPContact)
	// Output: serialization_network=none subject_ip_contact=false
}

func ExampleStableAnalysisID() {
	first := StableAnalysisID("finding", "report.authentication_failures", "example.test")
	second := StableAnalysisID("finding", "report.authentication_failures", "example.test")
	fmt.Println(first == second)
	// Output: true
}

func ExampleNormalizePortfolio() {
	config := PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-org"},
		ExpectedSenders: []ExpectedSenderConfig{{
			ID:            "workspace",
			RequireEither: true,
		}},
		Entities: []EntityConfig{{
			ID: "corporate",
			Domains: []DomainConfig{{
				Name: "example.test",
				Records: MonitoredRecordsConfig{
					SPF:   []string{"example.test"},
					DKIM:  []string{"primary._domainkey.example.test"},
					DMARC: []string{"_dmarc.example.test"},
				},
				ExpectedSenders: []string{"workspace"},
			}},
		}},
	}
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("organization=%s entities=%d\n", portfolio.Organization().ID, len(portfolio.Entities()))
	// Output: organization=example-org entities=1
}

func ExampleLoadPortfolioYAML() {
	data := []byte(`schema_version: 1
organization:
  id: example-org
expected_senders:
  - id: workspace
    require_either: true
entities:
  - id: corporate
    domains:
      - name: example.test
        records:
          spf: [example.test]
          dkim: [primary._domainkey.example.test]
          dmarc: [_dmarc.example.test]
        expected_senders: [workspace]
`)
	portfolio, err := LoadPortfolioYAML(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(portfolio.Entities()[0].Domains[0].Name)
	// Output: example.test
}

func ExampleParseSPFRecord() {
	record, diagnostics := ParseSPFRecord("v=spf1 include:sender.example.test -all")
	fmt.Printf("status=%s terms=%d lookups=%d diagnostics=%d\n", record.Status, len(record.Terms), record.Lookup.DirectTerms, len(diagnostics))
	// Output: status=valid terms=2 lookups=1 diagnostics=0
}

func ExampleDefaultProviderCatalog() {
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		log.Fatal(err)
	}
	record, diagnostics := ParseSPFRecord("v=spf1 include:_spf.google.com -all")
	if len(diagnostics) != 0 {
		log.Fatal(diagnostics)
	}
	match, ok := catalog.MatchSPFRelationship(record.Relationships[0])
	fmt.Printf("provider=%s context_only=%t matched=%t\n", match.ProviderID, match.ContextOnly, ok)
	// Output: provider=google-workspace context_only=true matched=true
}

func ExampleParseDMARCPolicyRecord() {
	record, diagnostics := ParseDMARCPolicyRecord("v=DMARC1; p=reject; rua=mailto:reports@example.test")
	fmt.Printf("status=%s policy=%s reports=%d diagnostics=%d\n", record.Status, record.Policy, len(record.AggregateReports), len(diagnostics))
	// Output: status=valid policy=reject reports=1 diagnostics=0
}

func ExampleDMARCPolicyDiscoveryNames() {
	names, err := DMARCPolicyDiscoveryNames("mail.example.test")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(names)
	// Output: [_dmarc.mail.example.test _dmarc.example.test _dmarc.test]
}

// ExampleBuildFailureOutput demonstrates a stable error envelope for work that
// could not be evaluated.
func ExampleBuildFailureOutput() {
	output, err := BuildFailureOutput(
		OutputModeReportValidation,
		OutputScope{},
		OutputInput{ReportCount: 1},
		[]OutputMessage{{
			Code:     "report.malformed_xml",
			Category: "malformed_xml",
			Message:  "the synthetic report could not be parsed",
		}},
		OutputOptions{GeneratedAt: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)},
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("status=%s evaluation=%s errors=%d\n", output.Status, output.Evaluation.State, len(output.Errors))
	// Output: status=failed evaluation=not_evaluated errors=1
}

const exampleReportXML = `<feedback>
  <report_metadata>
    <org_name>Example Org</org_name>
    <email>alerts@example.com</email>
    <report_id>example-report-id</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <aspf>r</aspf>
    <adkim>r</adkim>
    <p>none</p>
    <pct>100</pct>
    <fo>0</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>27</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>s1</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

// ExampleReport_LoadFile demonstrates successful loading and feature extraction.
func ExampleReport_LoadFile() {
	tmpFile, err := os.CreateTemp("", "dmarc-report-*.xml.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		// Removal is cleanup-only and cannot change the demonstrated result.
		_ = os.Remove(tmpFile.Name())
	}()

	gzw := gzip.NewWriter(tmpFile)
	if _, err := gzw.Write([]byte(exampleReportXML)); err != nil {
		log.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		log.Fatal(err)
	}

	var report Report
	if err := report.LoadFile(tmpFile.Name()); err != nil {
		log.Fatal(err)
	}

	features := report.Content.Rows()
	fmt.Printf("records=%d first_count=%d\n", len(features), features[0].MailCount)
	// Output: records=1 first_count=27
}

// ExampleAggregateReport demonstrates structured access to parsed report data.
func ExampleAggregateReport() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	record := report.Record[0]
	fmt.Printf("source=%s dkim_selector=%s\n", record.Row.SourceIP, record.AuthResults.DKIM[0].Selector)
	// Output: source=203.0.113.7 dkim_selector=s1
}

// ExampleReport_LoadFile_error demonstrates malformed XML detection.
func ExampleReport_LoadFile_error() {
	tmpFile, err := os.CreateTemp("", "dmarc-report-malformed-*.xml.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		// Removal is cleanup-only and cannot change the demonstrated result.
		_ = os.Remove(tmpFile.Name())
	}()

	gzw := gzip.NewWriter(tmpFile)
	if _, err := gzw.Write([]byte("<feedback><report_metadata></feedback")); err != nil {
		log.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		log.Fatal(err)
	}

	var report Report
	err = report.LoadFile(tmpFile.Name())
	fmt.Println(err != nil)
	// Output: true
}

// ExampleFeatureRow_invalidCount shows that malformed counts are surfaced.
func ExampleFeatureRow_invalidCount() {
	var report AggregateReport
	xmlPayload := []byte(`
<feedback>
  <report_metadata>
    <org_name>example org</org_name>
    <email>alerts@example.com</email>
    <report_id>example-report-id</report_id>
    <date_range>
      <begin>1</begin>
      <end>2</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <aspf>r</aspf>
    <adkim>r</adkim>
    <p>none</p>
    <pct>100</pct>
    <fo>0</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.12</source_ip>
      <count>not-a-number</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
  </record>
</feedback>
`)
	if err := xml.Unmarshal(xmlPayload, &report); err != nil {
		log.Fatal(err)
	}

	features := report.Rows()
	fmt.Println(features[0].MailCount)
	// Output: -1
}

// ExampleLoadBytes demonstrates parsing a compressed attachment already in memory.
func ExampleLoadBytes() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(exampleReportXML)); err != nil {
		log.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		log.Fatal(err)
	}

	report, err := LoadBytes(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(report.ReportMetadata.ReportID)
	// Output: example-report-id
}

// ExampleLoadReaderContext demonstrates request cancellation before parsing.
func ExampleLoadReaderContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := LoadReaderContext(ctx, strings.NewReader("<feedback/>"))
	fmt.Println(errors.Is(err, context.Canceled))
	// Output: true
}

// ExampleAggregateReport_Summary demonstrates aggregate message counts.
func ExampleAggregateReport_Summary() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	summary := report.Summary()
	fmt.Printf("messages=%d passed=%d\n", summary.TotalMessages, summary.PassedMessages)
	// Output: messages=27 passed=27
}

// ExampleAggregateReport_Validate demonstrates non-fatal report validation findings.
func ExampleAggregateReport_Validate() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(report.Validate()))
	// Output: 0
}

// ExampleAggregateReport_UnauthenticatedSources demonstrates finding unauthenticated sources.
func ExampleAggregateReport_UnauthenticatedSources() {
	report, err := ParseBytes([]byte(`<feedback>
  <report_metadata><org_name>Example Org</org_name><email>alerts@example.com</email><report_id>id</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p></policy_published>
  <record><row><source_ip>198.51.100.25</source_ip><count>3</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record>
</feedback>`))
	if err != nil {
		log.Fatal(err)
	}

	sources := report.UnauthenticatedSources("example.com")
	fmt.Printf("source=%s messages=%d\n", sources[0].SourceIP, sources[0].Messages)
	// Output: source=198.51.100.25 messages=3
}

// ExampleExcludeUnauthenticatedSources demonstrates caller-owned source exclusions.
func ExampleExcludeUnauthenticatedSources() {
	sources := []SuspiciousSource{
		{SourceIP: "198.51.100.25", Messages: 3},
		{SourceIP: "203.0.113.10", Messages: 2},
	}
	filtered, err := ExcludeUnauthenticatedSources(sources, []SourceExclusion{
		{Pattern: "198.51.100.0/24", Reason: "known sender"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(filtered[0].SourceIP)
	// Output: 203.0.113.10
}

// ExampleParseReportFilename demonstrates parsing common RUA attachment names.
func ExampleParseReportFilename() {
	info, err := ParseReportFilename("google.com!example.com!1700000000!1700086399.zip")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s %s %s\n", info.Reporter, info.PolicyDomain, info.Compression)
	// Output: google.com example.com zip
}

// ExampleDeduplicateReports demonstrates keeping the first report per identity.
func ExampleDeduplicateReports() {
	report, err := ParseBytes([]byte(exampleReportXML))
	if err != nil {
		log.Fatal(err)
	}

	reports := DeduplicateReports([]*AggregateReport{report, report})
	fmt.Println(len(reports))
	// Output: 1
}

// ExampleAnonymizeReport demonstrates creating a safe synthetic report copy.
func ExampleAnonymizeReport() {
	report, err := ParseBytes([]byte(exampleReportXML))
	if err != nil {
		log.Fatal(err)
	}

	anonymized := AnonymizeReport(*report, AnonymizeOptions{})
	fmt.Printf("%s %s\n", anonymized.ReportMetadata.OrgName, anonymized.Record[0].Row.SourceIP)
	// Output: Example Reporter 192.0.2.1
}

// ExampleTopSources demonstrates selecting the highest-volume sources.
func ExampleTopSources() {
	report, err := ParseBytes([]byte(exampleReportXML))
	if err != nil {
		log.Fatal(err)
	}

	top := TopSources(report.Summary().BySourceIP, 1)
	fmt.Println(top[0].SourceIP)
	// Output: 203.0.113.7
}

// ExampleWriteFeaturesJSONL demonstrates writing flattened feature rows as JSON Lines.
func ExampleWriteFeaturesJSONL() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	if err := WriteFeaturesJSONL(os.Stdout, report.Rows()); err != nil {
		log.Fatal(err)
	}
	// Output: {"reporting_org":"Example Org","reporting_addr":"alerts@example.com","report_id":"example-report-id","begin_date":"1609459200","end_date":"1609545600","target_domain":"example.com","spf_policy_published":"r","dkim_policy_published":"r","requested_handling_policy":"none","sampling_percentage":"100","failure_reporting_options":"0","source_ip":"203.0.113.7","mail_count":27,"vendor_action":"none","dkim_policy_evaluated":"pass","spf_policy_evaluated":"pass","header_from":"example.com","dkim_domain":"example.com","dkim_selector":"s1","dkim_result":"pass","spf_domain":"example.com","spf_result":"pass","dkim_auth_results":[{"domain":"example.com","selector":"s1","result":"pass","human_result":{}}],"spf_auth_result":{"domain":"example.com","result":"pass","human_result":{}}}
}

// ExampleWriteFeaturesCSV demonstrates writing flattened feature rows as CSV.
func ExampleWriteFeaturesCSV() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	if err := WriteFeaturesCSV(os.Stdout, report.Rows()); err != nil {
		log.Fatal(err)
	}
	// Output: reporting_org,reporting_addr,report_id,begin_date,end_date,target_domain,requested_handling_policy,subdomain_policy_published,nonexistent_subdomain_policy,source_ip,mail_count,vendor_action,dkim_policy_evaluated,spf_policy_evaluated,header_from,envelope_from,envelope_to,dkim_domain,dkim_selector,dkim_result,spf_domain,spf_scope,spf_result
	// Example Org,alerts@example.com,example-report-id,1609459200,1609545600,example.com,none,,,203.0.113.7,27,none,pass,pass,example.com,,,example.com,s1,pass,example.com,,pass
}

// ExampleWriteThreatCandidatesOutput demonstrates a native, mode-specific JSONL export.
func ExampleWriteThreatCandidatesOutput() {
	result, err := exampleThreatCandidates()
	if err != nil {
		log.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteThreatCandidatesOutput(&output, result, AnalysisOutputJSONL, AnalysisOutputOptions{
		Redaction: OutputRedactionPublic,
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Println(bytes.Contains(output.Bytes(), []byte(`"mode":"threat_candidates"`)))
	// Output: true
}

// ExampleAggregateReport_ValidateStrict demonstrates strict RFC 9990 validation.
func ExampleAggregateReport_ValidateStrict() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	for _, finding := range report.ValidateStrict() {
		fmt.Println(finding.Path)
		break
	}
	// Output: feedback.xmlns
}

// ExampleSummarizeReports demonstrates combining multiple parsed reports.
func ExampleSummarizeReports() {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	summary := SummarizeReports([]*AggregateReport{&report, &report})
	fmt.Printf("reports=%d messages=%d\n", summary.Reports, summary.TotalMessages)
	// Output: reports=2 messages=54
}

// ExampleAggregateReport_RejectedUnauthenticatedSources demonstrates policy-rejected unauthenticated source detection.
func ExampleAggregateReport_RejectedUnauthenticatedSources() {
	report, err := ParseBytes([]byte(`<feedback>
  <report_metadata><org_name>Example Org</org_name><email>alerts@example.com</email><report_id>id</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p></policy_published>
  <record><row><source_ip>198.51.100.25</source_ip><count>3</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record>
</feedback>`))
	if err != nil {
		log.Fatal(err)
	}

	sources := report.RejectedUnauthenticatedSources("example.com")
	fmt.Printf("source=%s rejected=%d\n", sources[0].SourceIP, sources[0].RejectedMessages)
	// Output: source=198.51.100.25 rejected=3
}
