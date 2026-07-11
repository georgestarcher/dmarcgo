package dmarcgo

import "testing"

func FuzzParseBytes(f *testing.F) {
	f.Add([]byte(helperReportXML))
	f.Add([]byte("<feedback><report_metadata></feedback"))
	f.Add([]byte("not xml"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseBytes(payload)
	})
}

func FuzzLoadBytes(f *testing.F) {
	f.Add([]byte(helperReportXML))
	f.Add([]byte("not archive or xml"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = LoadBytes(payload)
	})
}
