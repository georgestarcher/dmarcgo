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
	report := DmarcReport{
		ReportMetadata:  ReportMetadata{DateRange: DateRange{Begin: "bad", End: "1"}},
		PolicyPublished: PolicyPublished{P: "explode", Pct: "101"},
		Record: []Record{{
			Row:         Row{SourceIp: "not-ip", Count: "-1", PolicyEvaluated: PolicyEvaluated{Disposition: "wat", Dkim: "maybe", Spf: ""}},
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
	reports := []*Report{{Content: *report}, nil, {Content: *report}}
	agg := SummarizeReports(reports)
	if agg.Reports != 2 || agg.TotalMessages != 10 || agg.RejectedMessages != 6 {
		t.Fatalf("unexpected aggregate summary: %+v", agg)
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
	if err := WriteFeaturesCSV(&buf, report.Features()[1:]); err != nil {
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

func BenchmarkLoadReportBytes(b *testing.B) {
	payload := []byte(helperReportXML)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadReportBytes(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSummary(b *testing.B) {
	var report DmarcReport
	if err := xml.Unmarshal([]byte(helperReportXML), &report); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.Summary()
	}
}

func BenchmarkSuspiciousSources(b *testing.B) {
	var report DmarcReport
	if err := xml.Unmarshal([]byte(helperReportXML), &report); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.SuspiciousSources("example.com")
	}
}
