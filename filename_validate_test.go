package dmarcgo

import "testing"

func TestValidateReportFilename(t *testing.T) {
	info, err := ParseReportFilename("google.com!example.com!1700000000!1700086399.xml.gz")
	if err != nil {
		t.Fatal(err)
	}
	if findings := ValidateReportFilename(info, ValidationModeCompatibility); len(findings) != 0 {
		t.Fatalf("unexpected compatibility findings: %+v", findings)
	}
	if findings := ValidateReportFilename(info, ValidationModeStrictRFC9990); len(findings) != 0 {
		t.Fatalf("unexpected strict findings: %+v", findings)
	}
}

func TestValidateReportFilenameStrictRejectsZip(t *testing.T) {
	info, err := ParseReportFilename("google.com!example.com!1700000000!1700086399.zip")
	if err != nil {
		t.Fatal(err)
	}
	findings := ValidateReportFilename(info, ValidationModeStrictRFC9990)
	if !hasFinding(findings, "filename.extension") {
		t.Fatalf("strict filename findings missing extension issue: %+v", findings)
	}
}
