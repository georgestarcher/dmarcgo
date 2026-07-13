package dmarcgo

import (
	"encoding/json"
	"errors"
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
