package dmarcgo

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"os"
)

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

// ExampleReport_LoadReportFile demonstrates successful loading and feature extraction.
func ExampleReport_LoadReportFile() {
	tmpFile, err := os.CreateTemp("", "dmarc-report-*.xml.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	gzw := gzip.NewWriter(tmpFile)
	if _, err := gzw.Write([]byte(exampleReportXML)); err != nil {
		log.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		log.Fatal(err)
	}

	var report Report
	if err := report.LoadReportFileFromPath(tmpFile.Name()); err != nil {
		log.Fatal(err)
	}

	features := report.Content.Features()
	fmt.Printf("records=%d first_count=%d\n", len(features), features[1].MailCount)
	// Output: records=2 first_count=27
}

// ExampleDmarcReport demonstrates structured access to parsed report data.
func ExampleDmarcReport() {
	var report DmarcReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	record := report.Record[0]
	fmt.Printf("source=%s dkim_selector=%s\n", record.Row.SourceIp, record.AuthResults.Dkim[0].Selector)
	// Output: source=203.0.113.7 dkim_selector=s1
}

// ExampleReport_LoadReportFile_error demonstrates malformed XML detection.
func ExampleReport_LoadReportFile_error() {
	tmpFile, err := os.CreateTemp("", "dmarc-report-malformed-*.xml.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	gzw := gzip.NewWriter(tmpFile)
	if _, err := gzw.Write([]byte("<feedback><report_metadata></feedback")); err != nil {
		log.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		log.Fatal(err)
	}

	var report Report
	err = report.LoadReportFileFromPath(tmpFile.Name())
	fmt.Println(err != nil)
	// Output: true
}

// ExampleDmarcReportFeatures_invalidCount shows that malformed counts are surfaced.
func ExampleDmarcReportFeatures_invalidCount() {
	var report DmarcReport
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

	features := report.Features()
	fmt.Println(features[1].MailCount)
	// Output: -1
}

// ExampleLoadReportBytes demonstrates parsing a compressed attachment already in memory.
func ExampleLoadReportBytes() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(exampleReportXML)); err != nil {
		log.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		log.Fatal(err)
	}

	report, err := LoadReportBytes(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(report.ReportMetadata.ReportID)
	// Output: example-report-id
}

// ExampleDmarcReport_Summary demonstrates aggregate message counts.
func ExampleDmarcReport_Summary() {
	var report DmarcReport
	if err := xml.Unmarshal([]byte(exampleReportXML), &report); err != nil {
		log.Fatal(err)
	}

	summary := report.Summary()
	fmt.Printf("messages=%d passed=%d\n", summary.TotalMessages, summary.PassedMessages)
	// Output: messages=27 passed=27
}
