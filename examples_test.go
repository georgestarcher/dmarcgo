package dmarcgo

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"time"
)

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
