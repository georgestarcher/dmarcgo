package dmarcgo

import "testing"

func TestTopHelpers(t *testing.T) {
	sources := []SourceSummary{
		{SourceIP: "203.0.113.10", Messages: 2},
		{SourceIP: "198.51.100.25", Messages: 3},
	}
	if got := TopSources(sources, 1); len(got) != 1 || got[0].SourceIP != "198.51.100.25" {
		t.Fatalf("unexpected top sources: %+v", got)
	}
	unauth := []SuspiciousSource{
		{SourceIP: "203.0.113.10", Messages: 2},
		{SourceIP: "198.51.100.25", Messages: 3},
	}
	if got := TopUnauthenticatedSources(unauth, 1); len(got) != 1 || got[0].SourceIP != "198.51.100.25" {
		t.Fatalf("unexpected top unauthenticated sources: %+v", got)
	}
	counts := map[string]int{"b.example": 1, "a.example": 3}
	if got := TopCounts(counts, 1); len(got) != 1 || got[0].Value != "a.example" {
		t.Fatalf("unexpected top counts: %+v", got)
	}
}

func TestTopHelpersHandleEmptyAndTieCases(t *testing.T) {
	if got := TopSources([]SourceSummary{{SourceIP: "203.0.113.10", Messages: 1}}, 0); got != nil {
		t.Fatalf("expected nil top sources for zero limit, got %+v", got)
	}
	tied := []SourceSummary{{SourceIP: "203.0.113.20", Messages: 1}, {SourceIP: "203.0.113.10", Messages: 1}}
	if got := TopSources(tied, 5); len(got) != 2 || got[0].SourceIP != "203.0.113.10" {
		t.Fatalf("unexpected tied source order: %+v", got)
	}
	if got := TopUnauthenticatedSources(nil, 1); got != nil {
		t.Fatalf("expected nil top unauthenticated sources, got %+v", got)
	}
	if got := TopCounts(map[string]int{"b": 1, "a": 1}, 5); len(got) != 2 || got[0].Value != "a" {
		t.Fatalf("unexpected tied count order: %+v", got)
	}
}
