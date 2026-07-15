package dmarcgo

import (
	"os"
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
