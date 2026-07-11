package dmarcgo

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ReportFilename describes the common bang-separated DMARC aggregate report
// attachment filename format.
type ReportFilename struct {
	Raw          string    `json:"raw"`
	Reporter     string    `json:"reporter"`
	PolicyDomain string    `json:"policy_domain"`
	Begin        string    `json:"begin"`
	End          string    `json:"end"`
	BeginTime    time.Time `json:"begin_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
	UniqueID     string    `json:"unique_id,omitempty"`
	Extension    string    `json:"extension,omitempty"`
	Compression  string    `json:"compression,omitempty"`
}

// ParseReportFilename parses common DMARC aggregate report attachment names
// such as reporter.example!example.com!1700000000!1700086399.xml.gz or
// reporter.example!example.com!1700000000!1700086399!unique.zip.
func ParseReportFilename(path string) (ReportFilename, error) {
	name := filepath.Base(path)
	info := ReportFilename{Raw: name}
	parts := strings.Split(name, "!")
	if len(parts) < 4 {
		return info, fmt.Errorf("dmarc report filename %q: expected at least 4 bang-separated fields", name)
	}

	info.Reporter = parts[0]
	info.PolicyDomain = parts[1]
	info.Begin = parts[2]
	last := parts[3]
	if len(parts) > 4 {
		info.UniqueID = stripReportExtension(strings.Join(parts[4:], "!"), &info)
	} else {
		last = stripReportExtension(last, &info)
	}
	info.End = last

	begin, err := epochStringToTime(info.Begin)
	if err != nil {
		return info, fmt.Errorf("dmarc report filename %q: invalid begin epoch: %w", name, err)
	}
	end, err := epochStringToTime(info.End)
	if err != nil {
		return info, fmt.Errorf("dmarc report filename %q: invalid end epoch: %w", name, err)
	}
	info.BeginTime = begin
	info.EndTime = end
	if end.Before(begin) {
		return info, fmt.Errorf("dmarc report filename %q: end epoch precedes begin epoch", name)
	}
	return info, nil
}

func stripReportExtension(value string, info *ReportFilename) string {
	lower := strings.ToLower(value)
	for _, suffix := range []string{".xml.gz", ".xml.zip", ".xml.zlib", ".xml.zz", ".gzip", ".gz", ".zip", ".zlib", ".zz", ".xml"} {
		if strings.HasSuffix(lower, suffix) {
			info.Extension = suffix
			switch suffix {
			case ".xml.gz", ".gzip", ".gz":
				info.Compression = "gzip"
			case ".xml.zip", ".zip":
				info.Compression = "zip"
			case ".xml.zlib", ".xml.zz", ".zlib", ".zz":
				info.Compression = "zlib"
			}
			return value[:len(value)-len(suffix)]
		}
	}
	return value
}
