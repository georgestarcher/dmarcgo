package dmarcgo

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"testing"
)

func TestValidateValidReport(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if findings := report.Validate(); len(findings) != 0 {
		t.Fatalf("got findings for valid report: %+v", findings)
	}
}

func TestValidateFindings(t *testing.T) {
	report := AggregateReport{
		ReportMetadata:  ReportMetadata{DateRange: DateRange{Begin: "bad", End: "1"}},
		PolicyPublished: PolicyPublished{P: "explode", Pct: "101"},
		Record: []Record{{
			Row:         Row{SourceIP: "not-ip", Count: "-1", PolicyEvaluated: PolicyEvaluated{Disposition: "wat", DKIM: "maybe", SPF: ""}},
			Identifiers: Identifiers{},
		}},
	}
	findings := report.Validate()
	if len(findings) < 8 {
		t.Fatalf("got %d findings, wanted several: %+v", len(findings), findings)
	}
	if !hasFinding(findings, "report_metadata.org_name") || !hasFinding(findings, "record[0].row.count") {
		t.Fatalf("missing expected findings: %+v", findings)
	}
}

func TestMergeSummariesAndSummarizeReports(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	reports := []*AggregateReport{report, nil, report}
	agg := SummarizeReports(reports)
	if agg.Reports != 2 || agg.TotalMessages != 10 || agg.PassedMessages != 4 || agg.FailedMessages != 6 || agg.RejectedMessages != 6 {
		t.Fatalf("unexpected aggregate summary: %+v", agg)
	}
	if agg.PassRate != 0.4 || agg.FailureRate != 0.6 {
		t.Fatalf("unexpected aggregate rates: %+v", agg)
	}
	if len(agg.BySourceIP) != 2 || agg.BySourceIP[0].SourceIP != "198.51.100.25" {
		t.Fatalf("unexpected aggregate source ordering: %+v", agg.BySourceIP)
	}

	merged := MergeSummaries([]ReportSummary{report.Summary(), report.Summary()})
	if merged.TotalRecords != 4 || merged.ByReporter["Example Receiver"] != 10 {
		t.Fatalf("unexpected merged summary: %+v", merged)
	}
}

func TestWriteFeaturesCSV(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteFeaturesCSV(&buf, report.Rows()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d CSV rows, wanted header plus 2 records", len(rows))
	}
	if rows[0][0] != "reporting_org" || rows[1][9] != "203.0.113.10" {
		t.Fatalf("unexpected CSV rows: %+v", rows)
	}
}

func hasFinding(findings []ValidationFinding, path string) bool {
	for _, finding := range findings {
		if finding.Path == path {
			return true
		}
	}
	return false
}

func BenchmarkLoadBytes(b *testing.B) {
	payload := []byte(helperReportXML)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadBytes(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSummary(b *testing.B) {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(helperReportXML), &report); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.Summary()
	}
}

func TestValidationModes(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(report.Validate()); got != 0 {
		t.Fatalf("compatibility findings got %d", got)
	}
	strict := report.ValidateStrict()
	if !hasFinding(strict, "feedback.xmlns") {
		t.Fatalf("strict findings missing namespace issue: %+v", strict)
	}
}

func TestFeatureCSVHeaders(t *testing.T) {
	headers := FeatureCSVHeaders()
	if len(headers) == 0 || headers[0] != "reporting_org" {
		t.Fatalf("unexpected headers: %+v", headers)
	}
	headers[0] = "mutated"
	if FeatureCSVHeaders()[0] != "reporting_org" {
		t.Fatal("FeatureCSVHeaders must return a copy")
	}
}

func TestSourceHelperVariants(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if got := report.UnauthenticatedSources("example.com"); len(got) != 1 || got[0].Messages != 3 {
		t.Fatalf("unexpected unauthenticated sources: %+v", got)
	}
	if got := report.RejectedUnauthenticatedSources("example.com"); len(got) != 1 || got[0].RejectedMessages != 3 {
		t.Fatalf("unexpected rejected unauthenticated sources: %+v", got)
	}
	if got := report.PassingSources("example.com"); len(got) != 1 || got[0].Messages != 2 {
		t.Fatalf("unexpected passing sources: %+v", got)
	}
}

func BenchmarkUnauthenticatedSources(b *testing.B) {
	var report AggregateReport
	if err := xml.Unmarshal([]byte(helperReportXML), &report); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.UnauthenticatedSources("example.com")
	}
}
