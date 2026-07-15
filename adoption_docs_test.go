package dmarcgo

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAdoptionDocumentationFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path              string
		organization      string
		minimumEntities   int
		minimumSenders    int
		referenceEntities int
	}{
		{
			path:            "testdata/portfolio/minimal-synthetic.yaml",
			organization:    "example-organization",
			minimumEntities: 1,
			minimumSenders:  1,
		},
		{
			path:              "testdata/portfolio/adoption-synthetic.yaml",
			organization:      "example-holdings",
			minimumEntities:   4,
			minimumSenders:    3,
			referenceEntities: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			portfolio, err := LoadPortfolioYAML(data)
			if err != nil {
				t.Fatal(err)
			}
			if portfolio.Organization().ID != test.organization {
				t.Fatalf("organization = %q, want %q", portfolio.Organization().ID, test.organization)
			}
			if len(portfolio.Entities()) < test.minimumEntities || len(portfolio.ExpectedSenders()) < test.minimumSenders {
				t.Fatalf("fixture coverage: entities=%d senders=%d", len(portfolio.Entities()), len(portfolio.ExpectedSenders()))
			}
			references := 0
			for _, entity := range portfolio.Entities() {
				if entity.Membership == PortfolioMembershipReference {
					references++
				}
			}
			if references != test.referenceEntities {
				t.Fatalf("reference entities = %d, want %d", references, test.referenceEntities)
			}
		})
	}
}

func TestOptionalContextConfigurationReference(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("docs/optional-context-configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	types := []any{
		SourceEnrichmentOptions{},
		IPMetadata{},
		IPMetadataAssertion{},
		IPMetadataProvenance{},
		IPMetadataConfidence{},
		SourceActivitySelection{},
		SourceActivityOptions{},
		SourceActivityResponse{},
		SourceActivityMetric{},
		SourceActivityThreatFeed{},
		SourceActivityNetworkAssertion{},
		PhishingIntelligenceSnapshotConfig{},
		PhishingIntelligenceLicense{},
		PhishingIntelligenceIndicatorConfig{},
		PhishingIntelligenceConfidence{},
		PhishingIntelligenceContext{},
		PhishingIntelligenceOptions{},
		JurisdictionRiskPolicyConfig{},
		JurisdictionRiskPolicySource{},
		JurisdictionRiskPolicyEntry{},
		JurisdictionContextOptions{},
		DNSPerspectiveSelection{},
		DNSPerspectiveOptions{},
		DNSPerspectiveResponse{},
		DNSPerspectiveProviderObservation{},
		DNSPerspectiveAnswer{},
	}
	for _, value := range types {
		typeOf := reflect.TypeOf(value)
		for index := range typeOf.NumField() {
			field := typeOf.Field(index)
			if field.PkgPath != "" {
				continue
			}
			plain := "`" + field.Name + "`"
			qualified := "`" + typeOf.Name() + "." + field.Name + "`"
			if !strings.Contains(text, plain) && !strings.Contains(text, qualified) {
				t.Errorf("%s.%s is not documented", typeOf.Name(), field.Name)
			}
		}
	}
}

func TestConsumerAgentGuideIncludesGuidedOnboarding(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("docs/consumer-agent-guide.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	required := []string{
		"## Guided onboarding interaction",
		"### 2. Build the domain inventory",
		"complete SPF TXT owner names",
		"complete DMARC TXT owner names",
		"every known DKIM selector",
		"confirmed/proposed/unknown fact table",
		"exact preview of the TXT owner names",
		"### 3. Add optional context only when it answers a question",
		"application-owned secret reference",
		"Never ask the user to paste a credential",
		"explicit selection preview",
		"### 4. Confirm the run and handoff",
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Errorf("guided onboarding is missing %q", value)
		}
	}
}
