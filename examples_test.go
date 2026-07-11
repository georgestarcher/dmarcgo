package dmarcgo

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"os"
)

// ExampleReport_LoadReportFile demonstrates successful loading and feature extraction.
func ExampleReport_LoadReportFile() {
	reportXML, err := xml.Marshal(struct {
		XMLName        struct{} `xml:"feedback"`
		ReportMetadata struct {
			OrgName   string `xml:"org_name"`
			Email     string `xml:"email"`
			ReportID  string `xml:"report_id"`
			DateRange struct {
				Begin string `xml:"begin"`
				End   string `xml:"end"`
			} `xml:"date_range"`
		} `xml:"report_metadata"`
		PolicyPublished struct {
			Domain string `xml:"domain"`
			Aspf   string `xml:"aspf"`
			Adkim  string `xml:"adkim"`
			P      string `xml:"p"`
			Pct    string `xml:"pct"`
			Fo     string `xml:"fo"`
		} `xml:"policy_published"`
		Record []struct {
			Row struct {
				SourceIp        string `xml:"source_ip"`
				Count           string `xml:"count"`
				PolicyEvaluated struct {
					Disposition string `xml:"disposition"`
					Dkim        string `xml:"dkim"`
					Spf         string `xml:"spf"`
				} `xml:"policy_evaluated"`
			} `xml:"row"`
			Identifiers struct {
				HeaderFrom string `xml:"header_from"`
			} `xml:"identifiers"`
		} `xml:"record"`
	}{
		ReportMetadata: struct {
			OrgName   string `xml:"org_name"`
			Email     string `xml:"email"`
			ReportID  string `xml:"report_id"`
			DateRange struct {
				Begin string `xml:"begin"`
				End   string `xml:"end"`
			} `xml:"date_range"`
		}{
			OrgName:  "Example Org",
			Email:    "alerts@example.com",
			ReportID: "example-report-id",
			DateRange: struct {
				Begin string `xml:"begin"`
				End   string `xml:"end"`
			}{Begin: "1609459200", End: "1609545600"},
		},
		PolicyPublished: struct {
			Domain string `xml:"domain"`
			Aspf   string `xml:"aspf"`
			Adkim  string `xml:"adkim"`
			P      string `xml:"p"`
			Pct    string `xml:"pct"`
			Fo     string `xml:"fo"`
		}{
			Domain: "example.com",
			Aspf:   "r",
			Adkim:  "r",
			P:      "none",
			Pct:    "100",
			Fo:     "0",
		},
		Record: []struct {
			Row struct {
				SourceIp        string `xml:"source_ip"`
				Count           string `xml:"count"`
				PolicyEvaluated struct {
					Disposition string `xml:"disposition"`
					Dkim        string `xml:"dkim"`
					Spf         string `xml:"spf"`
				} `xml:"policy_evaluated"`
			} `xml:"row"`
			Identifiers struct {
				HeaderFrom string `xml:"header_from"`
			} `xml:"identifiers"`
		}{
			{
				Row: struct {
					SourceIp        string `xml:"source_ip"`
					Count           string `xml:"count"`
					PolicyEvaluated struct {
						Disposition string `xml:"disposition"`
						Dkim        string `xml:"dkim"`
						Spf         string `xml:"spf"`
					} `xml:"policy_evaluated"`
				}{
					SourceIp: "203.0.113.7",
					Count:    "27",
					PolicyEvaluated: struct {
						Disposition string `xml:"disposition"`
						Dkim        string `xml:"dkim"`
						Spf         string `xml:"spf"`
					}{Disposition: "none", Dkim: "pass", Spf: "pass"},
				},
				Identifiers: struct {
					HeaderFrom string `xml:"header_from"`
				}{HeaderFrom: "example.com"},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "dmarc-report-*.xml.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	gzw := gzip.NewWriter(tmpFile)
	if _, err := gzw.Write(reportXML); err != nil {
		log.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		log.Fatal(err)
	}

	var report Report
	report.FilePath = tmpFile.Name()
	if err := report.LoadReportFile(); err != nil {
		log.Fatal(err)
	}

	features := report.Content.Features()
	fmt.Printf("records=%d first_count=%d\n", len(features), features[1].MailCount)
	// Output: records=2 first_count=27
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
	report.FilePath = tmpFile.Name()
	err = report.LoadReportFile()
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
