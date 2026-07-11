package dmarcgo

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const helperReportXML = `<feedback>
  <report_metadata>
    <org_name>Example Receiver</org_name>
    <email>dmarc@example.net</email>
    <report_id>helper-report</report_id>
    <date_range><begin>1609459200</begin><end>1609545600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.10</source_ip>
      <count>2</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.25</source_ip>
      <count>3</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>spoof.example</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`

func TestParseBytesAndReader(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if report.ReportMetadata.ReportID != "helper-report" {
		t.Fatalf("got report id %q", report.ReportMetadata.ReportID)
	}

	fromReader, err := ParseReader(strings.NewReader(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(fromReader.Record); got != 2 {
		t.Fatalf("got %d records, wanted 2", got)
	}
}

func TestLoadReportBytesSupportsRawAndGzip(t *testing.T) {
	raw, err := LoadReportBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if raw.ReportMetadata.OrgName != "Example Receiver" {
		t.Fatalf("got org %q", raw.ReportMetadata.OrgName)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(helperReportXML)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	compressed, err := LoadReportBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if compressed.ReportMetadata.ReportID != "helper-report" {
		t.Fatalf("got report id %q", compressed.ReportMetadata.ReportID)
	}
}

func TestLoadReportsFromDirCapturesPerFileErrors(t *testing.T) {
	dir := t.TempDir()
	writeGzipFile(t, filepath.Join(dir, "good.xml.gz"), []byte(helperReportXML))
	if err := os.WriteFile(filepath.Join(dir, "bad.txt"), []byte("not xml"), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := LoadReportsFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, wanted 2", len(results))
	}

	good := 0
	bad := 0
	for _, result := range results {
		if result.Err != nil {
			bad++
		} else if result.Report != nil {
			good++
		}
	}
	if good != 1 || bad != 1 {
		t.Fatalf("got good=%d bad=%d, wanted 1 each", good, bad)
	}
}

func TestSummaryAndSuspiciousSources(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}

	summary := report.Summary()
	if summary.TotalMessages != 5 || summary.PassedMessages != 2 || summary.RejectedMessages != 3 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(summary.BySourceIP) != 2 || summary.BySourceIP[0].SourceIP != "198.51.100.25" {
		t.Fatalf("unexpected source ordering: %+v", summary.BySourceIP)
	}
	if !summary.BeginTime.Equal(time.Unix(1609459200, 0).UTC()) {
		t.Fatalf("unexpected begin time %s", summary.BeginTime)
	}

	suspicious := report.SuspiciousSources("example.com")
	if len(suspicious) != 1 {
		t.Fatalf("got %d suspicious sources, wanted 1", len(suspicious))
	}
	if suspicious[0].SourceIP != "198.51.100.25" || suspicious[0].RejectedMessages != 3 {
		t.Fatalf("unexpected suspicious source: %+v", suspicious[0])
	}
}

func TestWriteFeaturesJSONL(t *testing.T) {
	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := WriteFeaturesJSONL(&buf, report.Features()[1:]); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d JSONL lines, wanted 2", len(lines))
	}
	var row DmarcReportFeatures
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatal(err)
	}
	if row.SrcIp == "" {
		t.Fatal("expected source IP in JSONL row")
	}
}

func TestDateRangeTimes(t *testing.T) {
	rangeValue := DateRange{Begin: "1609459200", End: "1609545600"}
	begin, err := rangeValue.BeginTime()
	if err != nil {
		t.Fatal(err)
	}
	end, err := rangeValue.EndTime()
	if err != nil {
		t.Fatal(err)
	}
	if !begin.Equal(time.Unix(1609459200, 0).UTC()) || !end.Equal(time.Unix(1609545600, 0).UTC()) {
		t.Fatalf("unexpected times begin=%s end=%s", begin, end)
	}
}

func writeGzipFile(t *testing.T, path string, payload []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	if _, err := gz.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReportBytesSupportsZipAndZlib(t *testing.T) {
	var zipBuf bytes.Buffer
	zipWriter := zip.NewWriter(&zipBuf)
	entry, err := zipWriter.Create("report.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(helperReportXML)); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	zipReport, err := LoadReportBytes(zipBuf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if zipReport.ReportMetadata.ReportID != "helper-report" {
		t.Fatalf("got report id %q", zipReport.ReportMetadata.ReportID)
	}

	var zlibBuf bytes.Buffer
	zlibWriter := zlib.NewWriter(&zlibBuf)
	if _, err := zlibWriter.Write([]byte(helperReportXML)); err != nil {
		t.Fatal(err)
	}
	if err := zlibWriter.Close(); err != nil {
		t.Fatal(err)
	}
	zlibReport, err := LoadReportBytes(zlibBuf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if zlibReport.ReportMetadata.ReportID != "helper-report" {
		t.Fatalf("got report id %q", zlibReport.ReportMetadata.ReportID)
	}
}

func TestLoadReportReaderAndOptions(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(helperReportXML)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadReportReader(bytes.NewReader(buf.Bytes()), WithMaxDecompressedBytes(20)); err == nil {
		t.Fatal("expected size limit error")
	}

	report, err := LoadReportReader(bytes.NewReader(buf.Bytes()), WithMaxDecompressedBytes(-1))
	if err != nil {
		t.Fatal(err)
	}
	if report.ReportMetadata.ReportID != "helper-report" {
		t.Fatalf("got report id %q", report.ReportMetadata.ReportID)
	}
}

func TestLoadReportFileConvenience(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.xml.gz")
	writeGzipFile(t, path, []byte(helperReportXML))

	report, err := LoadReportFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Content.ReportMetadata.ReportID != "helper-report" {
		t.Fatalf("got report id %q", report.Content.ReportMetadata.ReportID)
	}
}

func TestLoadReportReaderContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := LoadReportReaderContext(ctx, strings.NewReader(helperReportXML))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, wanted context canceled", err)
	}
}

func TestReportLoadError(t *testing.T) {
	_, err := LoadReportFile("")
	var loadErr *ReportLoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("got %T, wanted ReportLoadError", err)
	}
	if !errors.Is(err, ErrNoFilePath) {
		t.Fatalf("got %v, wanted wrapped ErrNoFilePath", err)
	}
}
