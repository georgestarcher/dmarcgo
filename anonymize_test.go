package dmarcgo

import "testing"

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
