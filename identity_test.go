package dmarcgo

import "testing"

func TestReportIdentityHelpers(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	key := ReportKey(report)
	if key.ReportID != "helper-report" || key.PolicyDomain != "example.com" || key.String() == "" {
		t.Fatalf("unexpected report key: %+v", key)
	}
	if !SameReport(report, report) {
		t.Fatal("same report was not recognized")
	}
	if SameReport(nil, report) {
		t.Fatal("nil report should not match")
	}
}

func TestFilenameReportKey(t *testing.T) {
	key, err := FilenameReportKey("google.com!example.com!1700000000!1700086399!abc123.xml.gz")
	if err != nil {
		t.Fatal(err)
	}
	if key.ReportingOrg != "google.com" || key.PolicyDomain != "example.com" || key.ReportID != "abc123" {
		t.Fatalf("unexpected filename key: %+v", key)
	}
}

func TestFilenameReportKeyRejectsInvalidName(t *testing.T) {
	if _, err := FilenameReportKey("invalid.xml.gz"); err == nil {
		t.Fatal("expected invalid filename error")
	}
}

func TestDeduplicateReports(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	unique := DeduplicateReports([]*AggregateReport{report, nil, report})
	if len(unique) != 1 {
		t.Fatalf("got %d unique reports, wanted 1", len(unique))
	}
}

func TestDeduplicateReportsKeepsZeroIdentityReports(t *testing.T) {
	left := &AggregateReport{}
	right := &AggregateReport{}
	unique := DeduplicateReports([]*AggregateReport{left, right})
	if len(unique) != 2 {
		t.Fatalf("got %d unique reports, wanted zero-identity reports kept", len(unique))
	}
}
