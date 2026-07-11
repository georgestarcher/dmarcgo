package dmarcgo

import (
	"strings"
	"testing"
	"time"
)

func TestParseReportFilename(t *testing.T) {
	info, err := ParseReportFilename("/tmp/google.com!example.com!1700000000!1700086399.zip")
	if err != nil {
		t.Fatal(err)
	}
	if info.Reporter != "google.com" || info.PolicyDomain != "example.com" || info.End != "1700086399" {
		t.Fatalf("unexpected filename metadata: %+v", info)
	}
	if info.Compression != "zip" || info.Extension != ".zip" {
		t.Fatalf("unexpected extension metadata: %+v", info)
	}
	if !info.BeginTime.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("unexpected begin time: %s", info.BeginTime)
	}
}

func TestParseReportFilenameWithUniqueID(t *testing.T) {
	info, err := ParseReportFilename("mimecast.org!example.com!1781308800!1781395199!abc123.xml.gz")
	if err != nil {
		t.Fatal(err)
	}
	if info.UniqueID != "abc123" || info.Compression != "gzip" || info.Extension != ".xml.gz" {
		t.Fatalf("unexpected unique filename metadata: %+v", info)
	}
}

func TestParseReportFilenameWithTarGZ(t *testing.T) {
	info, err := ParseReportFilename("reporter.example!example.com!1700000000!1700086399.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if info.Compression != "tar" || info.Extension != ".tar.gz" {
		t.Fatalf("unexpected tar filename metadata: %+v", info)
	}
}

func TestParseReportFilenameRejectsInvalidShape(t *testing.T) {
	if _, err := ParseReportFilename("not-a-dmarc-report.xml.gz"); err == nil {
		t.Fatal("expected invalid filename error")
	}
	if _, err := ParseReportFilename("reporter!example.com!2!1.xml.gz"); err == nil || !strings.Contains(err.Error(), "precedes") {
		t.Fatalf("got %v, wanted end-before-begin error", err)
	}
}
