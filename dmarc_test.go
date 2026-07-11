package dmarcgo

import (
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReport(t *testing.T) {
	dmarcReport := new(FileReport)
	dmarcReport.FilePath = "testdata/fixtures/amazonses.com!georgestarcher.com!1518134400!1518220800.xml.gz"

	err := dmarcReport.Load()
	if err != nil {
		t.Fatal(err)
	}

	reportID := dmarcReport.Content.ReportMetadata.ReportID
	want := "072b67ad-a2bd-4ee2-bbb3-533ca391825f"
	if reportID != want {
		t.Errorf("got %v, wanted %v", reportID, want)
	}
}

func TestLoadFileMalformedXML(t *testing.T) {
	reportFile := filepath.Join(t.TempDir(), "broken.xml.gz")
	fileHandle, err := os.Create(reportFile)
	if err != nil {
		t.Fatal(err)
	}

	gzw := gzip.NewWriter(fileHandle)
	if _, err := gzw.Write([]byte("<feedback><report_metadata></feedback")); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fileHandle.Close(); err != nil {
		t.Fatal(err)
	}

	report := new(FileReport)
	report.FilePath = reportFile
	if err := report.Load(); err == nil {
		t.Fatal("expected XML parse error, got nil")
	} else if !strings.Contains(err.Error(), "failed to parse DMARC XML") {
		t.Fatalf("got error %q, wanted parse-specific failure", err.Error())
	}
}

func TestFeaturesMailCountParsing(t *testing.T) {
	report := AggregateReport{}
	payload := []byte(`
	<feedback>
	  <report_metadata>
	    <org_name>unit</org_name>
	    <email>alerts@example.com</email>
	    <report_id>test-report</report_id>
	    <date_range>
	      <begin>1</begin>
	      <end>2</end>
	    </date_range>
	  </report_metadata>
	  <policy_published>
	    <domain>example.com</domain>
	    <adkim>r</adkim>
	    <aspf>r</aspf>
	    <p>none</p>
	    <pct>100</pct>
	    <fo>0</fo>
	  </policy_published>
	  <record>
	    <row>
	      <source_ip>192.0.2.1</source_ip>
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
	if err := xml.Unmarshal(payload, &report); err != nil {
		t.Fatal(err)
	}

	features := report.Rows()
	if len(features) != 1 {
		t.Fatalf("got %d features, wanted 1", len(features))
	}
	if features[0].MailCount != InvalidMailCount {
		t.Fatalf("got MailCount %d, wanted %d", features[0].MailCount, InvalidMailCount)
	}
}

func TestLoadFileEmpty(t *testing.T) {
	report := new(FileReport)
	if err := report.LoadFile(""); err == nil {
		t.Fatal("expected error for empty report path")
	}
}

func TestFixtureReportsParse(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "fixtures")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}

	parsed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			var report Report
			if err := report.LoadFile(filepath.Join(fixtureDir, entry.Name())); err != nil {
				t.Fatal(err)
			}
			if features := report.Content.Rows(); len(features) == 0 {
				t.Fatal("expected at least one feature row")
			}
		})
		parsed++
	}

	if parsed == 0 {
		t.Fatal("expected at least one fixture report")
	}
}

func TestFeaturesJSONContract(t *testing.T) {
	reportXML := []byte(`<feedback>
	<report_metadata>
		<org_name>example org</org_name>
		<email>alerts@example.com</email>
		<report_id>report-1</report_id>
		<date_range>
			<begin>1</begin>
			<end>2</end>
		</date_range>
	</report_metadata>
	<policy_published>
		<domain>example.com</domain>
		<adkim>r</adkim>
		<aspf>r</aspf>
		<p>none</p>
		<sp>none</sp>
		<pct>100</pct>
		<fo>0</fo>
	</policy_published>
	<record>
		<row>
			<source_ip>198.51.100.12</source_ip>
			<count>42</count>
			<policy_evaluated>
				<disposition>none</disposition>
				<dkim>pass</dkim>
				<spf>pass</spf>
				<reason>
					<type>trusted_forwarder</type>
					<comment>ok</comment>
				</reason>
			</policy_evaluated>
		</row>
		<identifiers>
			<header_from>example.com</header_from>
		</identifiers>
		<auth_results>
			<spf>
				<domain>example.com</domain>
				<result>pass</result>
			</spf>
			<dkim>
				<domain>example.com</domain>
				<selector>s1</selector>
				<result>pass</result>
				<human_result>OK</human_result>
			</dkim>
		</auth_results>
	</record>
	</feedback>`)

	var report AggregateReport
	if err := xml.Unmarshal(reportXML, &report); err != nil {
		t.Fatal(err)
	}

	features := report.Rows()
	if len(features) != 1 {
		t.Fatalf("got %d features, wanted %d", len(features), 1)
	}

	got, err := json.Marshal(features[0])
	if err != nil {
		t.Fatal(err)
	}
	var gotMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"reporting_org":             "example org",
		"reporting_addr":            "alerts@example.com",
		"report_id":                 "report-1",
		"begin_date":                "1",
		"end_date":                  "2",
		"target_domain":             "example.com",
		"spf_policy_published":      "r",
		"dkim_policy_published":     "r",
		"requested_handling_policy": "none",
		"sampling_percentage":       "100",
		"failure_reporting_options": "0",
		"source_ip":                 "198.51.100.12",
		"mail_count":                float64(42),
		"vendor_action":             "none",
		"dkim_policy_evaluated":     "pass",
		"spf_policy_evaluated":      "pass",
		"type":                      "trusted_forwarder",
		"comment":                   "ok",
		"header_from":               "example.com",
		"dkim_domain":               "example.com",
		"dkim_selector":             "s1",
		"dkim_result":               "pass",
		"dkim_human_result":         "OK",
		"spf_domain":                "example.com",
		"spf_result":                "pass",
	}

	for key, wantValue := range want {
		gotValue, ok := gotMap[key]
		if !ok {
			t.Fatalf("missing JSON key %q", key)
		}
		if gotValue != wantValue {
			t.Fatalf("key %q got %v (%T), wanted %v (%T)", key, gotValue, gotValue, wantValue, wantValue)
		}
	}
}

func TestRFC9990SyntheticFixture(t *testing.T) {
	var report Report
	if err := report.LoadFile(filepath.Join("testdata", "fixtures", "rfc9990-modern-synthetic.xml.gz")); err != nil {
		t.Fatal(err)
	}

	features := report.Content.Rows()
	if len(features) != 2 {
		t.Fatalf("got %d features, wanted 2", len(features))
	}
	if report.Content.XMLName.Space != RFC9990Namespace {
		t.Fatalf("got namespace %q, wanted %q", report.Content.XMLName.Space, RFC9990Namespace)
	}
	if got := len(report.Content.Record[0].AuthResults.DKIM); got != 2 {
		t.Fatalf("got %d DKIM results, wanted 2", got)
	}
	if features[0].DKIMSelector != "selector1" || len(features[0].DKIMAuthResults) != 2 {
		t.Fatalf("modern DKIM feature fields were not preserved")
	}
	if features[1].VendorAction != "reject" || features[1].SPFResult != "fail" {
		t.Fatalf("rejected synthetic row was not flattened correctly")
	}
}

func TestRFC9990ReportFeaturesPreserveModernFields(t *testing.T) {
	payload := []byte(`<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
	<version>1.0</version>
	<report_metadata>
		<org_name>Example Reporter</org_name>
		<email>reports@example.net</email>
		<extra_contact_info lang="en">https://example.net/dmarc</extra_contact_info>
		<report_id>rfc9990-report</report_id>
		<date_range><begin>1777075200</begin><end>1777161599</end></date_range>
		<error lang="en">policy lookup warning</error>
		<generator>Example Generator 2.0</generator>
	</report_metadata>
	<policy_published>
		<domain>example.com</domain>
		<p>reject</p>
		<sp>quarantine</sp>
		<np>none</np>
		<adkim>s</adkim>
		<aspf>r</aspf>
		<discovery_method>treewalk</discovery_method>
		<fo>1</fo>
		<testing>n</testing>
	</policy_published>
	<extension><ext:sample xmlns:ext="https://example.net/ext">kept</ext:sample></extension>
	<record>
		<row>
			<source_ip>2001:db8::1</source_ip>
			<count>3</count>
			<policy_evaluated>
				<disposition>reject</disposition>
				<dkim>fail</dkim>
				<spf>fail</spf>
				<reason><type>local_policy</type><comment lang="en">first</comment></reason>
				<reason><type>other</type><comment>second</comment></reason>
			</policy_evaluated>
		</row>
		<identifiers>
			<header_from>example.com</header_from>
			<envelope_from></envelope_from>
			<envelope_to>example.net</envelope_to>
		</identifiers>
		<auth_results>
			<dkim><domain>example.com</domain><selector>s1</selector><result>fail</result><human_result>bad signature</human_result></dkim>
			<dkim><domain>thirdparty.example</domain><selector>s2</selector><result>pass</result></dkim>
			<spf><domain>bounce.example.com</domain><scope>mfrom</scope><result>fail</result><human_result>not authorized</human_result></spf>
		</auth_results>
		<ext:record-note xmlns:ext="https://example.net/ext">kept</ext:record-note>
	</record>
</feedback>`)

	var report AggregateReport
	if err := decodeDMARCXML(payload, &report); err != nil {
		t.Fatal(err)
	}

	features := report.Rows()
	if len(features) != 1 {
		t.Fatalf("got %d features, wanted 1", len(features))
	}
	record := features[0]
	if record.ReportGenerator != "Example Generator 2.0" {
		t.Fatalf("got generator %q", record.ReportGenerator)
	}
	if record.NonexistentSubdomainPolicy != "none" {
		t.Fatalf("got np %q", record.NonexistentSubdomainPolicy)
	}
	if record.PolicyDiscoveryMethod != "treewalk" {
		t.Fatalf("got discovery method %q", record.PolicyDiscoveryMethod)
	}
	if record.EnvelopeTo != "example.net" {
		t.Fatalf("got envelope_to %q", record.EnvelopeTo)
	}
	if record.DKIMSelector != "s1" {
		t.Fatalf("got first DKIM selector %q", record.DKIMSelector)
	}
	if len(record.DKIMAuthResults) != 2 {
		t.Fatalf("got %d flattened DKIM auth results, wanted 2", len(record.DKIMAuthResults))
	}
	if record.SPFScope != "mfrom" {
		t.Fatalf("got SPF scope %q", record.SPFScope)
	}
	if len(record.PolicyOverrideReasons) != 2 {
		t.Fatalf("got %d flattened override reasons, wanted 2", len(record.PolicyOverrideReasons))
	}
	if record.Type != "local_policy" || record.Comment != "first" {
		t.Fatalf("legacy reason fields got type=%q comment=%q", record.Type, record.Comment)
	}
	if record.ExtensionCount != 2 {
		t.Fatalf("got extension count %d, wanted 2", record.ExtensionCount)
	}
}

func BenchmarkReportFeatures(b *testing.B) {
	const baseReport = `<feedback>
		<report_metadata><org_name>bench</org_name><email>bench@example.com</email><report_id>bench</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
		<policy_published><domain>example.com</domain><p>none</p></policy_published>
		<record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record>
	</feedback>`
	var report AggregateReport
	if err := xml.Unmarshal([]byte(baseReport), &report); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.Rows()
	}
}
