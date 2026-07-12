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

func FuzzParseProviderCatalogYAML(f *testing.F) {
	f.Add([]byte(validProviderYAML()))
	f.Add([]byte("schema_version: 1\nproviders: []\n"))
	f.Add([]byte("providers: &providers [*providers]\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseProviderCatalogYAML(payload)
	})
}
