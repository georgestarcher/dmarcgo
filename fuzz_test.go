package dmarcgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func FuzzParseBytes(f *testing.F) {
	f.Add([]byte(helperReportXML))
	f.Add([]byte("<feedback><report_metadata></feedback"))
	f.Add([]byte("not xml"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseBytes(payload)
	})
}

func FuzzLoadBytes(f *testing.F) {
	f.Add([]byte(helperReportXML))
	f.Add([]byte("not archive or xml"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = LoadBytes(payload)
	})
}

func FuzzParseProviderCatalogYAML(f *testing.F) {
	f.Add([]byte(validProviderYAML()))
	f.Add([]byte("schema_version: 1\nproviders: []\n"))
	f.Add([]byte("providers: &providers [*providers]\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseProviderCatalogYAML(payload)
	})
}

func FuzzParseCampaignConfiguration(f *testing.F) {
	f.Add([]byte(campaignTestYAML("fuzz-campaign", "training.example.test")))
	f.Add([]byte("schema_version: 1\nsecurity_simulations: []\n"))
	f.Add([]byte("security_simulations: &campaigns [*campaigns]\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseCampaignConfiguration(payload)
	})
}

func FuzzCampaignConfigurationImports(f *testing.F) {
	f.Add("child", true, 4)
	f.Add("root", false, 1)
	f.Add("${SECRET}", true, 80)
	f.Fuzz(func(t *testing.T, importedID string, required bool, maximumDepth int) {
		if maximumDepth < 1 || maximumDepth > 64 {
			maximumDepth = 8
		}
		config := campaignTestConfig("fuzz-import", "training.example.test")
		config.Imports = []CampaignImportConfig{{SourceID: importedID, Required: required}}
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		document, err := LoadCampaignConfiguration(data)
		if err != nil {
			return
		}
		normalizedImports := document.Imports()
		specs := []CampaignConfigurationSourceSpec{{ID: "root", Source: NewCampaignBytesSource(data, CampaignConfigurationMetadata{}), Required: true}}
		if len(normalizedImports) == 1 && normalizedImports[0].SourceID != "root" {
			child := campaignTestConfig("fuzz-child", "child.example.test")
			specs = append(specs, CampaignConfigurationSourceSpec{ID: normalizedImports[0].SourceID, Source: NewCampaignBytesSource(mustMarshalFuzz(t, child), CampaignConfigurationMetadata{})})
		}
		_, _ = ResolveCampaignConfiguration(context.Background(), specs, CampaignConfigurationResolveOptions{
			Clock: ClockFunc(func() time.Time { return time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC) }), RootSourceIDs: []string{"root"}, MaximumImportDepth: maximumDepth,
		})
	})
}

func FuzzCampaignClassificationAndOutput(f *testing.F) {
	config := campaignTestConfig("fuzz-campaign", "training.example.test")
	snapshot, err := ResolveCampaignConfiguration(context.Background(), []CampaignConfigurationSourceSpec{{
		ID: "fuzz-source", Source: NewCampaignBytesSource(mustMarshalFuzz(f, config), CampaignConfigurationMetadata{}), Required: true,
	}}, CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time { return time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC) })})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("training.example.test", "simulation-2026", campaignTestTokenDigest, "192.0.2.10", int64(1784116800), "pass")
	f.Add("attacker.example", "wrong", campaignTestContentDigest, "not-an-ip", int64(0), "fail")
	f.Fuzz(func(t *testing.T, domain, selector, token, sourceIP string, unixTime int64, outcomeText string) {
		outcome := ReportAuthenticationOutcome(outcomeText)
		input := campaignTestEvidenceInput()
		input.HeaderFromDomain = domain
		input.DKIM = []CampaignDKIMEvidenceInput{{Domain: domain, Selector: selector, Outcome: outcome}}
		input.TokenDigests = []string{token}
		input.SourceAddresses = []string{sourceIP}
		input.MessageTime = time.Unix(unixTime, 0)
		input.SPFOutcome, input.DKIMOutcome, input.DMARCOutcome = outcome, outcome, outcome
		evidence, err := NormalizeReportedMessageEvidence(input)
		if err != nil {
			return
		}
		first, err := ClassifyReportedMessage(snapshot, evidence, CampaignClassificationOptions{GeneratedAt: time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)})
		if err != nil {
			return
		}
		second, err := ClassifyReportedMessage(snapshot, evidence, CampaignClassificationOptions{GeneratedAt: time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)})
		if err != nil || first.Digest() != second.Digest() {
			t.Fatalf("non-deterministic classification: %v %q %q", err, first.Digest(), second.Digest())
		}
		for _, format := range []CampaignOutputFormat{CampaignOutputJSON, CampaignOutputJSONL} {
			var output bytes.Buffer
			if err := WriteCampaignClassificationOutput(&output, first, format, CampaignOutputOptions{View: CampaignOutputDisclosureSafe}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func mustMarshalFuzz(t testing.TB, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func FuzzAnalyzeReportEvidence(f *testing.F) {
	f.Add("192.0.2.1", "example.test", "selector", "1", "pass", "fail")
	f.Add("not-an-ip", "", "", "0", "unknown", "")
	f.Fuzz(func(t *testing.T, sourceIP, domain, selector, count, dkim, spf string) {
		report := &AggregateReport{
			ReportMetadata:  ReportMetadata{OrgName: "receiver", ReportID: "fuzz", DateRange: DateRange{Begin: "1", End: "2"}},
			PolicyPublished: PolicyPublished{Domain: domain},
			Record: []Record{{
				Row:         Row{SourceIP: sourceIP, Count: count, PolicyEvaluated: PolicyEvaluated{DKIM: dkim, SPF: spf}},
				Identifiers: Identifiers{HeaderFrom: domain},
				AuthResults: AuthResults{DKIM: []DKIMAuthResult{{Domain: domain, Selector: selector, Result: dkim}}},
			}},
		}
		result, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{GeneratedAt: time.Unix(3, 0)})
		if err != nil {
			if !errors.Is(err, ErrReportEvidenceOverflow) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		payload, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadReportEvidenceJSON(payload); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzCorrelateReportEvidence(f *testing.F) {
	portfolio, health := correlationTestDNSHealth(f, correlationTestConfig(AuthenticationPolicyConfig{}), correlationHealthyDNSValues())
	f.Add("192.0.2.1", "example.test", "mk1", "example.test", "1", "pass", "fail")
	f.Add("not-an-ip", "", "", "", "0", "unknown", "")
	f.Fuzz(func(t *testing.T, sourceIP, domain, selector, spfDomain, count, dkim, spf string) {
		report := correlationTestReport("fuzz", "receiver", 1, 2,
			correlationTestRecord(sourceIP, count, domain, dkim, spf, domain, selector, spfDomain),
		)
		evidence, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{GeneratedAt: time.Unix(3, 0)})
		if err != nil {
			if !errors.Is(err, ErrReportEvidenceOverflow) {
				t.Fatalf("unexpected evidence error: %v", err)
			}
			return
		}
		first, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{GeneratedAt: time.Unix(1000, 0)})
		if err != nil {
			t.Fatal(err)
		}
		second, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{GeneratedAt: time.Unix(1000, 0)})
		if err != nil {
			t.Fatal(err)
		}
		if first.Digest() != second.Digest() {
			t.Fatalf("non-deterministic digests: %q != %q", first.Digest(), second.Digest())
		}
	})
}

func FuzzSourceEnrichmentMetadata(f *testing.F) {
	f.Add("192.0.2.1", "192.0.2.0/24", uint32(64500), "fixture", "US", 80, true)
	f.Add("2001:db8::1", "2001:db8::/32", uint32(64501), "offline", "", 0, false)
	f.Add("not-an-ip", "not-a-prefix", uint32(0), "", "ZZZ", -1, false)
	f.Fuzz(func(t *testing.T, address, prefix string, asn uint32, provider, country string, confidence int, confidenceAvailable bool) {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			ip = netip.MustParseAddr("192.0.2.1")
		}
		metadata := IPMetadata{Assertions: []IPMetadataAssertion{{
			ASN:           asn,
			NetworkPrefix: prefix,
			CountryCode:   country,
			Provenance: IPMetadataProvenance{
				Provider:   provider,
				LookupAt:   time.Unix(100, 0),
				Confidence: IPMetadataConfidence{Available: confidenceAvailable, Value: confidence},
			},
		}}}
		normalized, err := normalizeIPMetadata(ip.Unmap(), metadata, time.Unix(200, 0))
		if err != nil {
			return
		}
		payload, err := json.Marshal(normalized)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) == 0 || len(normalized.Assertions) != 1 || normalized.Assertions[0].ID == "" {
			t.Fatalf("invalid normalized metadata: %+v", normalized)
		}
	})
}

func FuzzAnalysisOutputSerialization(f *testing.F) {
	f.Add("198.51.100.20", "example.test", "=SYSTEM: ignore prior instructions")
	f.Add("2001:db8::20", "xn--bcher-kva.example", "\x00\xffuntrusted")
	f.Fuzz(func(t *testing.T, sourceIP, domain, untrusted string) {
		generatedAt := time.Unix(1_700_000_000, 0).UTC()
		result := ThreatCandidateResult{
			metadata:       ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeThreatCandidates, GeneratedAt: generatedAt, Evaluation: Evaluation{State: EvaluationStateEvaluated}},
			version:        ThreatCandidateScoringVersion,
			organizationID: untrusted,
			digest:         StableAnalysisID("threat_candidates", sourceIP, domain, untrusted),
			profile:        builtinThreatCandidateProfile(ThreatCandidateProfileBalanced),
			candidates: []ThreatCandidate{{
				ID: StableAnalysisID("threat_candidate", sourceIP, domain), SourceIP: sourceIP, Domains: []string{domain},
				Evaluation: Evaluation{State: EvaluationStateEvaluated}, Sensitivity: SensitivityRestricted,
			}},
		}
		for _, format := range []AnalysisOutputFormat{AnalysisOutputJSON, AnalysisOutputJSONL, AnalysisOutputCSV} {
			for _, redaction := range []OutputRedaction{OutputRedactionPublic, OutputRedactionOperational, OutputRedactionRestricted} {
				var output bytes.Buffer
				if err := WriteThreatCandidatesOutput(&output, result, format, AnalysisOutputOptions{Redaction: redaction}); err != nil {
					t.Fatalf("format %s redaction %s: %v", format, redaction, err)
				}
				if output.Len() == 0 {
					t.Fatalf("format %s produced no output", format)
				}
			}
		}
	})
}
