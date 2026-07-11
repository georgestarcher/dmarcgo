package dmarcgo

import (
	"encoding/xml"
	"testing"
)

func TestAnonymizeReport(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	anonymized := AnonymizeReport(*report, AnonymizeOptions{})
	if anonymized.ReportMetadata.OrgName != "Example Reporter" {
		t.Fatalf("unexpected reporter: %q", anonymized.ReportMetadata.OrgName)
	}
	if anonymized.PolicyPublished.Domain != "example.com" {
		t.Fatalf("unexpected policy domain: %q", anonymized.PolicyPublished.Domain)
	}
	if anonymized.ReportMetadata.ReportID != "example-report-id" {
		t.Fatalf("unexpected report id: %q", anonymized.ReportMetadata.ReportID)
	}
	if anonymized.Record[0].Row.SourceIP != "192.0.2.1" || anonymized.Record[1].Row.SourceIP != "192.0.2.2" {
		t.Fatalf("unexpected anonymized IPs: %+v", anonymized.Record)
	}
	if anonymized.Record[1].AuthResults.SPF.Domain == "spoof.example" {
		t.Fatal("SPF domain was not anonymized")
	}
	if report.Record[0].Row.SourceIP == anonymized.Record[0].Row.SourceIP {
		t.Fatal("original report was modified")
	}
}

func TestAnonymizeReportCustomOptionsAndCopies(t *testing.T) {
	report := AggregateReport{
		ReportMetadata: ReportMetadata{
			OrgName:          "Original Reporter",
			Email:            "real@example.test",
			ReportID:         "secret-report-id",
			ExtraContactInfo: LangString{Value: "https://reporter.example.test/contact"},
			Error:            LangString{Value: "real error"},
		},
		PolicyPublished: PolicyPublished{Domain: "real.example"},
		Extension:       Extension{Elements: []RawElement{{XMLName: xmlName("urn:test", "file-ext"), InnerXML: "secret"}}},
		Record: []Record{{
			Row: Row{SourceIP: "2001:db8:abcd::1", Count: "1", PolicyEvaluated: PolicyEvaluated{
				Disposition: "none",
				DKIM:        "pass",
				SPF:         "fail",
				Reasons:     []PolicyOverrideReason{{Type: "other", Comment: LangString{Value: "kept"}}},
			}},
			Identifiers: Identifiers{HeaderFrom: "real.example", EnvelopeFrom: "bounce.real.example", EnvelopeTo: "receiver.example"},
			AuthResults: AuthResults{
				DKIM: []DKIMAuthResult{{Domain: "signer.example", Selector: "s1", Result: "pass"}},
				SPF:  &SPFAuthResult{Domain: "bounce.real.example", Result: "fail"},
			},
			Extensions: []RawElement{{XMLName: xmlName("urn:test", "record-ext"), InnerXML: "secret"}},
		}},
	}

	anonymized := AnonymizeReport(report, AnonymizeOptions{
		PolicyDomain: "safe.example",
		ReportingOrg: "Safe Reporter",
		ReportEmail:  "safe@example.net",
		ReportID:     "safe-report-id",
	})
	if anonymized.ReportMetadata.OrgName != "Safe Reporter" || anonymized.ReportMetadata.Email != "safe@example.net" {
		t.Fatalf("unexpected reporter metadata: %+v", anonymized.ReportMetadata)
	}
	if anonymized.ReportMetadata.ReportID != "safe-report-id" {
		t.Fatalf("unexpected report id: %q", anonymized.ReportMetadata.ReportID)
	}
	if anonymized.ReportMetadata.ExtraContactInfo.Value != "" || anonymized.ReportMetadata.Error.Value != "" {
		t.Fatalf("sensitive metadata was not cleared: %+v", anonymized.ReportMetadata)
	}
	if anonymized.Record[0].Row.SourceIP != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 anonymization: %s", anonymized.Record[0].Row.SourceIP)
	}
	if anonymized.Record[0].Identifiers.HeaderFrom != "safe.example" {
		t.Fatalf("policy domain was not mapped to safe domain: %+v", anonymized.Record[0].Identifiers)
	}
	if anonymized.Record[0].AuthResults.DKIM[0].Domain == "signer.example" {
		t.Fatal("DKIM domain was not anonymized")
	}
	anonymized.Record[0].Row.PolicyEvaluated.Reasons[0].Type = "mutated"
	if report.Record[0].Row.PolicyEvaluated.Reasons[0].Type == "mutated" {
		t.Fatal("policy override reasons were not deep-copied")
	}
	if len(anonymized.Extension.Elements) != 0 || len(anonymized.Record[0].Extensions) != 0 {
		t.Fatalf("extensions were not cleared by default: %+v %+v", anonymized.Extension.Elements, anonymized.Record[0].Extensions)
	}
}

func TestAnonymizeReportCanPreserveExtensions(t *testing.T) {
	report := AggregateReport{
		Extension: Extension{Elements: []RawElement{{XMLName: xmlName("urn:test", "file-ext"), InnerXML: "reviewed"}}},
		Record: []Record{{
			Extensions: []RawElement{{XMLName: xmlName("urn:test", "record-ext"), InnerXML: "reviewed"}},
		}},
	}

	anonymized := AnonymizeReport(report, AnonymizeOptions{PreserveExtensions: true})
	if len(anonymized.Extension.Elements) != 1 || len(anonymized.Record[0].Extensions) != 1 {
		t.Fatalf("extensions were not preserved: %+v %+v", anonymized.Extension.Elements, anonymized.Record[0].Extensions)
	}
	anonymized.Extension.Elements[0].InnerXML = "changed"
	if report.Extension.Elements[0].InnerXML == "changed" {
		t.Fatal("file extensions were not copied")
	}
	anonymized.Record[0].Extensions[0].InnerXML = "changed"
	if report.Record[0].Extensions[0].InnerXML == "changed" {
		t.Fatal("record extensions were not copied")
	}
}

func xmlName(space, local string) xml.Name {
	return xml.Name{Space: space, Local: local}
}
