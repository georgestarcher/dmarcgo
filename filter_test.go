package dmarcgo

import "testing"

func TestExcludeUnauthenticatedSources(t *testing.T) {
	sources := []SuspiciousSource{
		{SourceIP: "198.51.100.25", Messages: 3},
		{SourceIP: "203.0.113.10", Messages: 2},
		{SourceIP: "2001:db8::10", Messages: 1},
	}
	filtered, err := ExcludeUnauthenticatedSources(sources, []SourceExclusion{
		{Pattern: "198.51.100.0/24", Reason: "known test net"},
		{Pattern: "2001:db8::10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].SourceIP != "203.0.113.10" {
		t.Fatalf("unexpected filtered sources: %+v", filtered)
	}
}

func TestExcludeUnauthenticatedSourcesRejectsInvalidPattern(t *testing.T) {
	_, err := ExcludeUnauthenticatedSources(nil, []SourceExclusion{{Pattern: "not-an-ip"}})
	if err == nil {
		t.Fatal("expected invalid exclusion error")
	}
}
