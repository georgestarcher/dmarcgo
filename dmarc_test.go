package dmarcgo

import (
	"log"
	"testing"
)

// Test Setup and Load Report from File
func TestLoadReport(t *testing.T) {

	dmarcReport := new(Report)
	dmarcReport.FilePath = "test_files/amazonses.com!georgestarcher.com!1518134400!1518220800.xml.gz"

	err := dmarcReport.LoadReportFile()
	if err != nil {
		t.Fatal(err)
	}

	report_id := dmarcReport.Content.Features()[0].ReportID

	want := "072b67ad-a2bd-4ee2-bbb3-533ca391825f"
	got := report_id

	if got != want {
		t.Errorf("got %v, wanted %v", got, want)
	}
	log.Println(got)
}
