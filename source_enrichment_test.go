package dmarcgo

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnrichThreatCandidatesSuccessAndASN(t *testing.T) {
	generatedAt := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20", "2001:db8::20")
	original := candidates.Candidates()
	expiresAt := generatedAt.Add(time.Hour)
	ipv4Metadata := sourceTestMetadata(64500, "Example Network", "198.51.100.0/24", "Example Org", "US", "fixture-a", generatedAt.Add(-time.Minute), &expiresAt)
	ipv4Metadata.Assertions[0].Provenance.Confidence.Value = 90
	ipv6Metadata := sourceTestMetadata(64500, "Example Network", "2001:db8::/32", "Example Org", "US", "fixture-b", generatedAt.Add(-time.Minute), &expiresAt)
	ipv6Metadata.Assertions[0].Provenance.Confidence.Value = 20
	enricher := &sourceFixtureEnricher{metadata: map[string]IPMetadata{
		"198.51.100.20": ipv4Metadata,
		"2001:db8::20":  ipv6Metadata,
	}}
	result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return generatedAt })})
	if err != nil {
		t.Fatal(err)
	}
	if metadata := result.ResultMetadata(); metadata.Mode != AnalysisModeSourceEnrichment || metadata.Evaluation.State != EvaluationStateEvaluated || !metadata.GeneratedAt.Equal(generatedAt) {
		t.Fatalf("metadata=%+v", metadata)
	}
	if result.Version() != SourceEnrichmentVersion || result.OrganizationID() != "example-group" || result.ThreatCandidateDigest() != candidates.Digest() || result.Digest() == "" || !result.Complete() {
		t.Fatalf("result provenance version=%q org=%q upstream=%q digest=%q complete=%v", result.Version(), result.OrganizationID(), result.ThreatCandidateDigest(), result.Digest(), result.Complete())
	}
	values := result.Candidates()
	if len(values) != 2 {
		t.Fatalf("candidates=%+v", values)
	}
	wantConfidence := map[string]int{"198.51.100.20": 90, "2001:db8::20": 20}
	for index, value := range values {
		if value.Status != SourceEnrichmentSuccess || value.Candidate.Enrichment.State != EvaluationStateEvaluated || value.Candidate.Score != original[index].Score ||
			value.Candidate.Confidence != wantConfidence[value.Candidate.SourceIP] || value.Candidate.PromotionEligible ||
			hasThreatCandidateConfidenceAdjustment(value.Candidate, "threat_candidate.unenriched") ||
			!hasThreatCandidateConfidenceAdjustment(value.Candidate, "threat_candidate.enrichment_provider_confidence") {
			t.Fatalf("enriched candidate=%+v", value)
		}
		if len(value.Metadata.Assertions) != 1 || value.Metadata.Assertions[0].ID == "" || value.Metadata.Assertions[0].Freshness != SourceEnrichmentFreshnessFresh ||
			value.Metadata.Assertions[0].Sensitivity != SensitivityRestricted {
			t.Fatalf("metadata=%+v", value.Metadata)
		}
		if confidence, recomputeErr := RecomputeThreatCandidateConfidence(value.Candidate); recomputeErr != nil || confidence != value.Candidate.Confidence {
			t.Fatalf("recomputed confidence=%d error=%v", confidence, recomputeErr)
		}
	}
	if candidates.Candidates()[0].Confidence != original[0].Confidence || candidates.Candidates()[0].Enrichment.State != EvaluationStateNotEvaluated {
		t.Fatal("source enrichment mutated the caller-owned candidate result")
	}
	asns := result.ASNs()
	if len(asns) != 1 || asns[0].ASN != 64500 || !slices.Equal(asns[0].SourceIPs, []string{"198.51.100.20", "2001:db8::20"}) ||
		len(asns[0].CandidateIDs) != 2 || len(asns[0].AssertionIDs) != 2 || asns[0].Sensitivity != SensitivityRestricted {
		t.Fatalf("asns=%+v", asns)
	}
	if summary := result.Summary(); summary.Candidates != 2 || summary.Eligible != 2 || summary.ASNs != 1 || !slices.Equal(summary.Statuses, []SourceEnrichmentStatusCount{{Status: SourceEnrichmentSuccess, Candidates: 2}}) {
		t.Fatalf("summary=%+v", summary)
	}
	if enricher.callCount("198.51.100.20") != 1 || enricher.callCount("2001:db8::20") != 1 {
		t.Fatalf("calls=%+v", enricher.callsSnapshot())
	}

	values[0].Metadata.Assertions[0].Provenance.Provider = "mutated"
	values[0].Candidate.Domains[0] = "mutated"
	asns[0].SourceIPs[0] = "mutated"
	if result.Candidates()[0].Metadata.Assertions[0].Provenance.Provider == "mutated" || result.Candidates()[0].Candidate.Domains[0] == "mutated" || result.ASNs()[0].SourceIPs[0] == "mutated" {
		t.Fatal("source enrichment accessors did not return defensive copies")
	}
}

func TestEnrichThreatCandidatesNilEnricherIsNoOp(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	var typedNil *sourceFixtureEnricher
	result, err := EnrichThreatCandidates(context.Background(), candidates, typedNil, SourceEnrichmentOptions{Clock: sourcePanicClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResultMetadata().Evaluation.State != EvaluationStateNotEvaluated || !result.ResultMetadata().GeneratedAt.Equal(candidates.ResultMetadata().GeneratedAt) || result.Complete() {
		t.Fatalf("metadata=%+v complete=%v", result.ResultMetadata(), result.Complete())
	}
	values := result.Candidates()
	if len(values) != 1 || values[0].Status != SourceEnrichmentNotEvaluated || values[0].Candidate.Enrichment.State != EvaluationStateNotEvaluated || len(values[0].Metadata.Assertions) != 0 {
		t.Fatalf("candidates=%+v", values)
	}
	if summary := result.Summary(); summary.Candidates != 1 || summary.Eligible != 1 || !slices.Equal(summary.Statuses, []SourceEnrichmentStatusCount{{Status: SourceEnrichmentNotEvaluated, Candidates: 1}}) {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestEnrichThreatCandidatesOnlyEligibleAndDeduplicates(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	duplicate := candidates.candidates[0]
	duplicate.ID = StableAnalysisID("duplicate_candidate", duplicate.SourceIP)
	candidates.candidates = append(candidates.candidates, duplicate)
	ineligible := duplicate
	ineligible.ID = StableAnalysisID("ineligible_candidate", "192.0.2.99")
	ineligible.SourceIP = "192.0.2.99"
	ineligible.IPType = ThreatCandidateIPv4
	ineligible.ReviewEligible = false
	candidates.candidates = append(candidates.candidates, ineligible)
	now := time.Unix(200_000, 0)
	enricher := &sourceFixtureEnricher{metadata: map[string]IPMetadata{
		"198.51.100.20": sourceTestMetadata(64500, "", "198.51.100.0/24", "", "", "fixture", now, nil),
		"192.0.2.99":    sourceTestMetadata(64501, "", "192.0.2.0/24", "", "", "fixture", now, nil),
	}}
	result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	if enricher.callCount("198.51.100.20") != 1 || enricher.callCount("192.0.2.99") != 0 {
		t.Fatalf("calls=%+v", enricher.callsSnapshot())
	}
	values := result.Candidates()
	if len(values) != 3 || values[0].Status != SourceEnrichmentSuccess || values[1].Status != SourceEnrichmentSuccess || values[2].Status != SourceEnrichmentNotEligible ||
		values[2].Candidate.Enrichment.State != EvaluationStateNotApplicable {
		t.Fatalf("candidates=%+v", values)
	}
}

func TestEnrichThreatCandidatesPartialFailuresAreValueSafe(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	enricher := &sourceFixtureEnricher{
		metadata: map[string]IPMetadata{"192.0.2.1": sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "fixture", now, nil)},
		errors: map[string]error{
			"192.0.2.2": ErrIPMetadataUnavailable,
			"192.0.2.3": errors.New("SENSITIVE PROVIDER FAILURE TEXT"),
		},
	}
	result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	statuses := sourceEnrichmentStatusesByIP(result.Candidates())
	if statuses["192.0.2.1"] != SourceEnrichmentSuccess || statuses["192.0.2.2"] != SourceEnrichmentUnavailable || statuses["192.0.2.3"] != SourceEnrichmentFailed {
		t.Fatalf("statuses=%+v", statuses)
	}
	if len(result.Diagnostics()) != 2 || !result.Complete() {
		t.Fatalf("diagnostics=%+v complete=%v", result.Diagnostics(), result.Complete())
	}
	payload, marshalErr := json.Marshal(struct {
		Candidates  []EnrichedThreatCandidate    `json:"candidates"`
		Diagnostics []SourceEnrichmentDiagnostic `json:"diagnostics"`
	}{result.Candidates(), result.Diagnostics()})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(payload), "SENSITIVE PROVIDER FAILURE TEXT") {
		t.Fatalf("provider error leaked: %s", payload)
	}
}

func TestEnrichThreatCandidatesFailFastReturnsPartialResult(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1", "192.0.2.2")
	enricher := &sourceFixtureEnricher{errors: map[string]error{"192.0.2.1": errors.New("failure")}}
	result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{
		Clock: ClockFunc(func() time.Time { return now }), MaxConcurrency: 1, FailurePolicy: SourceEnrichmentFailFast,
	})
	if !errors.Is(err, ErrSourceEnrichmentFailed) {
		t.Fatalf("error=%v", err)
	}
	if result.Digest() == "" || result.Complete() || enricher.callCount("192.0.2.1") != 1 || enricher.callCount("192.0.2.2") != 0 {
		t.Fatalf("result digest=%q complete=%v calls=%+v", result.Digest(), result.Complete(), enricher.callsSnapshot())
	}
	statuses := sourceEnrichmentStatusesByIP(result.Candidates())
	if statuses["192.0.2.1"] != SourceEnrichmentFailed || statuses["192.0.2.2"] != SourceEnrichmentCanceled {
		t.Fatalf("statuses=%+v", statuses)
	}
}

func TestEnrichThreatCandidatesCancellationAndTimeout(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		now := time.Unix(200_000, 0)
		candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1", "192.0.2.2")
		enricher := &sourceFixtureEnricher{delays: map[string]time.Duration{"192.0.2.1": time.Second, "192.0.2.2": time.Second}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := EnrichThreatCandidates(ctx, candidates, enricher, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
		if !errors.Is(err, context.Canceled) || result.Digest() == "" {
			t.Fatalf("error=%v digest=%q", err, result.Digest())
		}
		for ip, status := range sourceEnrichmentStatusesByIP(result.Candidates()) {
			if status != SourceEnrichmentCanceled {
				t.Fatalf("status[%s]=%s", ip, status)
			}
		}
	})

	t.Run("per lookup timeout", func(t *testing.T) {
		now := time.Unix(200_000, 0)
		candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1")
		enricher := &sourceFixtureEnricher{delays: map[string]time.Duration{"192.0.2.1": time.Second}}
		result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{
			Clock: ClockFunc(func() time.Time { return now }), LookupTimeout: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Candidates()[0].Status != SourceEnrichmentTimeout || !result.Complete() {
			t.Fatalf("candidate=%+v complete=%v", result.Candidates()[0], result.Complete())
		}
	})

	t.Run("provider returns metadata after timeout", func(t *testing.T) {
		now := time.Unix(200_000, 0)
		candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1")
		original := candidates.Candidates()[0]
		result, err := EnrichThreatCandidates(context.Background(), candidates, sourceLateMetadataEnricher{
			metadata: sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "late-fixture", now, nil),
		}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now }), LookupTimeout: time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		candidate := result.Candidates()[0]
		if candidate.Status != SourceEnrichmentTimeout || !result.Complete() || len(candidate.Metadata.Assertions) != 0 ||
			candidate.Candidate.Confidence != original.Confidence || !hasThreatCandidateConfidenceAdjustment(candidate.Candidate, "threat_candidate.unenriched") ||
			len(result.Diagnostics()) != 1 || result.Diagnostics()[0].Code != "source_enrichment.timeout" {
			t.Fatalf("candidate=%+v complete=%v diagnostics=%+v", candidate, result.Complete(), result.Diagnostics())
		}
	})
}

func TestEnrichThreatCandidatesBoundsConcurrency(t *testing.T) {
	now := time.Unix(200_000, 0)
	sources := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8"}
	candidates := sourceEnrichmentTestCandidates(t, sources...)
	enricher := &sourceFixtureEnricher{metadata: map[string]IPMetadata{}, delays: map[string]time.Duration{}}
	for _, source := range sources {
		enricher.metadata[source] = sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "fixture", now, nil)
		enricher.delays[source] = 10 * time.Millisecond
	}
	_, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{
		Clock: ClockFunc(func() time.Time { return now }), MaxConcurrency: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if enricher.maxActiveCount() < 2 || enricher.maxActiveCount() > 3 {
		t.Fatalf("max active=%d", enricher.maxActiveCount())
	}
	for _, source := range sources {
		if enricher.callCount(source) != 1 {
			t.Fatalf("calls[%s]=%d", source, enricher.callCount(source))
		}
	}
}

func TestEnrichThreatCandidatesStaleAndConflicting(t *testing.T) {
	now := time.Unix(200_000, 0)
	expired := now.Add(-time.Minute)
	lookupAt := now.Add(-time.Hour)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1", "192.0.2.2")
	conflicting := IPMetadata{Assertions: []IPMetadataAssertion{
		sourceTestMetadata(64501, "First", "192.0.2.0/24", "First Org", "US", "fixture-a", lookupAt, nil).Assertions[0],
		sourceTestMetadata(64502, "Second", "192.0.2.0/24", "Second Org", "CA", "fixture-b", lookupAt, nil).Assertions[0],
	}}
	enricher := &sourceFixtureEnricher{metadata: map[string]IPMetadata{
		"192.0.2.1": sourceTestMetadata(64500, "Stale", "192.0.2.0/24", "Stale Org", "US", "fixture", lookupAt, &expired),
		"192.0.2.2": conflicting,
	}}
	result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]EnrichedThreatCandidate{}
	for _, value := range result.Candidates() {
		byIP[value.Candidate.SourceIP] = value
	}
	if byIP["192.0.2.1"].Status != SourceEnrichmentStale || byIP["192.0.2.1"].Candidate.Enrichment.State != EvaluationStateUnknown ||
		byIP["192.0.2.1"].Candidate.Confidence != 70 || !hasThreatCandidateConfidenceAdjustment(byIP["192.0.2.1"].Candidate, "threat_candidate.unenriched") {
		t.Fatalf("stale=%+v", byIP["192.0.2.1"])
	}
	if byIP["192.0.2.2"].Status != SourceEnrichmentConflicting || !slices.Equal(byIP["192.0.2.2"].Metadata.ConflictFields, []string{"asn", "country_code"}) {
		t.Fatalf("conflicting=%+v", byIP["192.0.2.2"])
	}
	asns := result.ASNs()
	if len(asns) != 3 {
		t.Fatalf("asns=%+v", asns)
	}
	for _, asn := range asns {
		switch asn.ASN {
		case 64500:
			if !slices.Equal(asn.StaleSourceIPs, []string{"192.0.2.1"}) {
				t.Fatalf("stale ASN=%+v", asn)
			}
		case 64501, 64502:
			if !slices.Equal(asn.ConflictingSourceIPs, []string{"192.0.2.2"}) {
				t.Fatalf("conflicting ASN=%+v", asn)
			}
		}
	}
}

func TestEnrichThreatCandidatesUnknownProviderConfidenceKeepsConservativeCap(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1")
	metadata := sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "fixture", now, nil)
	metadata.Assertions[0].Provenance.Confidence = IPMetadataConfidence{}
	result, err := EnrichThreatCandidates(context.Background(), candidates, &sourceFixtureEnricher{metadata: map[string]IPMetadata{
		"192.0.2.1": metadata,
	}}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	candidate := result.Candidates()[0]
	if candidate.Status != SourceEnrichmentSuccess || candidate.Candidate.Confidence != candidates.Profile().UnenrichedConfidenceCap ||
		hasThreatCandidateConfidenceAdjustment(candidate.Candidate, "threat_candidate.unenriched") ||
		!hasThreatCandidateConfidenceAdjustment(candidate.Candidate, "threat_candidate.enrichment_confidence_unknown") {
		t.Fatalf("candidate=%+v", candidate)
	}
}

func TestEnrichThreatCandidatesUsesBatchAndHandlesMissingItems(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.2", "192.0.2.1", "2001:db8::1")
	batch := &sourceBatchFixtureEnricher{items: []IPEnrichmentBatchItem{
		{IP: netip.MustParseAddr("192.0.2.1"), Metadata: sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "fixture", now, nil)},
		{IP: netip.MustParseAddr("192.0.2.2"), Err: ErrIPMetadataUnavailable},
	}}
	result, err := EnrichThreatCandidates(context.Background(), candidates, batch, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	if batch.batchCalls != 1 || batch.singleCalls != 0 || !slices.Equal(batch.received, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1")}) {
		t.Fatalf("batch calls=%d single=%d received=%+v", batch.batchCalls, batch.singleCalls, batch.received)
	}
	statuses := sourceEnrichmentStatusesByIP(result.Candidates())
	if statuses["192.0.2.1"] != SourceEnrichmentSuccess || statuses["192.0.2.2"] != SourceEnrichmentUnavailable || statuses["2001:db8::1"] != SourceEnrichmentFailed || result.Complete() {
		t.Fatalf("statuses=%+v complete=%v", statuses, result.Complete())
	}
}

func TestEnrichThreatCandidatesBatchRejectsMetadataAfterTimeout(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1", "192.0.2.2")
	originals := candidates.Candidates()
	result, err := EnrichThreatCandidates(context.Background(), candidates, sourceLateBatchEnricher{
		metadata: sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "late-fixture", now, nil),
	}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now }), LookupTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	values := result.Candidates()
	if !result.Complete() || len(values) != len(originals) || len(result.ASNs()) != 0 || len(result.Diagnostics()) != len(originals) {
		t.Fatalf("complete=%v candidates=%+v ASNs=%+v diagnostics=%+v", result.Complete(), values, result.ASNs(), result.Diagnostics())
	}
	for index, candidate := range values {
		if candidate.Status != SourceEnrichmentTimeout || len(candidate.Metadata.Assertions) != 0 ||
			candidate.Candidate.Confidence != originals[index].Confidence || !hasThreatCandidateConfidenceAdjustment(candidate.Candidate, "threat_candidate.unenriched") ||
			result.Diagnostics()[index].Code != "source_enrichment.timeout" {
			t.Fatalf("candidate[%d]=%+v diagnostic=%+v", index, candidate, result.Diagnostics()[index])
		}
	}
}

func TestEnrichThreatCandidatesDoesNotBatchAfterContextDone(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1", "192.0.2.2")
	tests := []struct {
		name       string
		context    func() (context.Context, context.CancelFunc)
		wantError  error
		wantStatus SourceEnrichmentStatus
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			wantError:  context.Canceled,
			wantStatus: SourceEnrichmentCanceled,
		},
		{
			name: "deadline exceeded",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Unix(1, 0))
			},
			wantError:  context.DeadlineExceeded,
			wantStatus: SourceEnrichmentTimeout,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.context()
			defer cancel()
			batch := &sourceBatchFixtureEnricher{}
			result, err := EnrichThreatCandidates(ctx, candidates, batch, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
			if !errors.Is(err, test.wantError) || result.Digest() == "" || result.Complete() {
				t.Fatalf("error=%v digest=%q complete=%v", err, result.Digest(), result.Complete())
			}
			if batch.batchCalls != 0 || batch.singleCalls != 0 || len(batch.received) != 0 {
				t.Fatalf("batch calls=%d single=%d received=%+v", batch.batchCalls, batch.singleCalls, batch.received)
			}
			for ip, status := range sourceEnrichmentStatusesByIP(result.Candidates()) {
				if status != test.wantStatus {
					t.Fatalf("status[%s]=%s want=%s", ip, status, test.wantStatus)
				}
			}
		})
	}
}

func TestEnrichThreatCandidatesDeterministicAcrossAssertionOrder(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1")
	first := sourceTestMetadata(64500, "One", "192.0.2.0/24", "Example", "US", "fixture-a", now, nil).Assertions[0]
	second := sourceTestMetadata(64500, "Two", "192.0.2.0/24", "Example", "US", "fixture-b", now, nil).Assertions[0]
	build := func(assertions []IPMetadataAssertion) SourceEnrichmentResult {
		t.Helper()
		result, err := EnrichThreatCandidates(context.Background(), candidates, &sourceFixtureEnricher{metadata: map[string]IPMetadata{
			"192.0.2.1": {Assertions: assertions},
		}}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	left := build([]IPMetadataAssertion{first, second})
	right := build([]IPMetadataAssertion{second, first})
	if left.Digest() != right.Digest() {
		t.Fatalf("digests left=%q right=%q", left.Digest(), right.Digest())
	}
}

func TestEnrichThreatCandidatesRejectsInvalidOptionsAndMetadata(t *testing.T) {
	now := time.Unix(200_000, 0)
	candidates := sourceEnrichmentTestCandidates(t, "192.0.2.1")
	valid := &sourceFixtureEnricher{metadata: map[string]IPMetadata{"192.0.2.1": sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "fixture", now, nil)}}
	for _, options := range []SourceEnrichmentOptions{
		{MaxConcurrency: -1},
		{LookupTimeout: -1},
		{FailurePolicy: "unknown"},
		{Clock: ClockFunc(func() time.Time { return time.Unix(100, 0) })},
	} {
		if _, err := EnrichThreatCandidates(context.Background(), candidates, valid, options); !errors.Is(err, ErrInvalidSourceEnrichmentOptions) {
			t.Fatalf("options=%+v error=%v", options, err)
		}
	}
	invalid := &sourceFixtureEnricher{metadata: map[string]IPMetadata{"192.0.2.1": sourceTestMetadata(64500, "", "198.51.100.0/24", "", "", "fixture", now, nil)}}
	result, err := EnrichThreatCandidates(context.Background(), candidates, invalid, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidates()[0].Status != SourceEnrichmentFailed || result.Diagnostics()[0].Code != "source_enrichment.invalid_metadata" {
		t.Fatalf("candidate=%+v diagnostics=%+v", result.Candidates()[0], result.Diagnostics())
	}
	tooMany := make([]IPMetadataAssertion, maxSourceEnrichmentAssertions+1)
	for index := range tooMany {
		tooMany[index] = sourceTestMetadata(64500, "", "192.0.2.0/24", "", "", "fixture", now, nil).Assertions[0]
	}
	outOfRangeTime := time.Date(10_000, time.January, 1, 0, 0, 0, 0, time.UTC)
	for name, metadata := range map[string]IPMetadata{
		"too many assertions": {Assertions: tooMany},
		"control text":        sourceTestMetadata(64500, "", "192.0.2.0/24", "bad\norganization", "", "fixture", now, nil),
		"invalid UTF-8":       sourceTestMetadata(64500, "", "192.0.2.0/24", string([]byte{0xff}), "", "fixture", now, nil),
		"lookup time outside JSON range": sourceTestMetadata(
			64500, "", "192.0.2.0/24", "", "", "fixture", outOfRangeTime, nil,
		),
		"expiration time outside JSON range": sourceTestMetadata(
			64500, "", "192.0.2.0/24", "", "", "fixture", now, &outOfRangeTime,
		),
	} {
		t.Run(name, func(t *testing.T) {
			result, enrichErr := EnrichThreatCandidates(context.Background(), candidates, &sourceFixtureEnricher{metadata: map[string]IPMetadata{
				"192.0.2.1": metadata,
			}}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
			if enrichErr != nil || result.Digest() == "" || result.Candidates()[0].Status != SourceEnrichmentFailed ||
				len(result.Candidates()[0].Metadata.Assertions) != 0 || result.Diagnostics()[0].Code != "source_enrichment.invalid_metadata" {
				t.Fatalf("error=%v candidate=%+v diagnostics=%+v", enrichErr, result.Candidates()[0], result.Diagnostics())
			}
		})
	}
	if _, err := EnrichThreatCandidates(context.Background(), ThreatCandidateResult{}, valid, SourceEnrichmentOptions{}); !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("invalid input error=%v", err)
	}
}

func TestSourceEnrichmentDependencyIsNeverImplicit(t *testing.T) {
	spy := &sourceFixtureEnricher{}
	_ = sourceEnrichmentTestCandidates(t, "198.51.100.20")
	if calls := spy.totalCalls(); calls != 0 {
		t.Fatalf("candidate scoring invoked source enrichment %d times", calls)
	}

	portfolio, health := correlationTestDNSHealth(t, correlationTestConfig(AuthenticationPolicyConfig{}), correlationHealthyDNSValues())
	if portfolio.Digest() == "" || health.Digest() == "" {
		t.Fatal("test setup did not produce completed DNS health")
	}
	if calls := spy.totalCalls(); calls != 0 {
		t.Fatalf("DNS health invoked source enrichment %d times", calls)
	}
}

func BenchmarkEnrichThreatCandidatesLargeCandidateSet(b *testing.B) {
	sources := make([]string, 1_000)
	for index := range sources {
		sources[index] = netip.AddrFrom4([4]byte{198, 18, byte(index / 256), byte(index % 256)}).String()
	}
	candidates := sourceEnrichmentTestCandidates(b, sources...)
	now := time.Unix(200_000, 0)
	enricher := sourceBenchmarkEnricher{lookupAt: now}
	options := SourceEnrichmentOptions{
		Clock:          ClockFunc(func() time.Time { return now }),
		MaxConcurrency: 8,
	}
	b.ResetTimer()
	for range b.N {
		result, err := EnrichThreatCandidates(context.Background(), candidates, enricher, options)
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Candidates()) != len(sources) {
			b.Fatalf("candidates=%d", len(result.Candidates()))
		}
	}
}

type sourcePanicClock struct{}

func (sourcePanicClock) Now() time.Time { panic("clock must not be called") }

type sourceLateMetadataEnricher struct {
	metadata IPMetadata
}

func (enricher sourceLateMetadataEnricher) EnrichIP(ctx context.Context, _ netip.Addr) (IPMetadata, error) {
	<-ctx.Done()
	return enricher.metadata, nil
}

type sourceLateBatchEnricher struct {
	metadata IPMetadata
}

func (sourceLateBatchEnricher) EnrichIP(context.Context, netip.Addr) (IPMetadata, error) {
	panic("batch enricher must not receive single-address calls")
}

func (enricher sourceLateBatchEnricher) EnrichIPs(ctx context.Context, ips []netip.Addr) ([]IPEnrichmentBatchItem, error) {
	<-ctx.Done()
	items := make([]IPEnrichmentBatchItem, len(ips))
	for index, ip := range ips {
		items[index] = IPEnrichmentBatchItem{IP: ip, Metadata: enricher.metadata}
	}
	return items, nil
}

type sourceFixtureEnricher struct {
	mu        sync.Mutex
	metadata  map[string]IPMetadata
	errors    map[string]error
	delays    map[string]time.Duration
	calls     map[string]int
	active    int
	maxActive int
}

func (enricher *sourceFixtureEnricher) EnrichIP(ctx context.Context, ip netip.Addr) (IPMetadata, error) {
	enricher.mu.Lock()
	if enricher.calls == nil {
		enricher.calls = map[string]int{}
	}
	enricher.calls[ip.String()]++
	enricher.active++
	if enricher.active > enricher.maxActive {
		enricher.maxActive = enricher.active
	}
	delay := enricher.delays[ip.String()]
	enricher.mu.Unlock()
	defer func() {
		enricher.mu.Lock()
		enricher.active--
		enricher.mu.Unlock()
	}()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return IPMetadata{}, ctx.Err()
		case <-timer.C:
		}
	}
	enricher.mu.Lock()
	metadata := enricher.metadata[ip.String()]
	err := enricher.errors[ip.String()]
	enricher.mu.Unlock()
	return metadata, err
}

func (enricher *sourceFixtureEnricher) callCount(ip string) int {
	enricher.mu.Lock()
	defer enricher.mu.Unlock()
	return enricher.calls[ip]
}

func (enricher *sourceFixtureEnricher) totalCalls() int {
	enricher.mu.Lock()
	defer enricher.mu.Unlock()
	total := 0
	for _, count := range enricher.calls {
		total += count
	}
	return total
}

func (enricher *sourceFixtureEnricher) callsSnapshot() map[string]int {
	enricher.mu.Lock()
	defer enricher.mu.Unlock()
	result := map[string]int{}
	for ip, count := range enricher.calls {
		result[ip] = count
	}
	return result
}

func (enricher *sourceFixtureEnricher) maxActiveCount() int {
	enricher.mu.Lock()
	defer enricher.mu.Unlock()
	return enricher.maxActive
}

type sourceBatchFixtureEnricher struct {
	items       []IPEnrichmentBatchItem
	err         error
	received    []netip.Addr
	batchCalls  int
	singleCalls int
}

type sourceBenchmarkEnricher struct {
	lookupAt time.Time
}

func (enricher sourceBenchmarkEnricher) EnrichIP(ctx context.Context, ip netip.Addr) (IPMetadata, error) {
	if err := ctx.Err(); err != nil {
		return IPMetadata{}, err
	}
	prefix := netip.PrefixFrom(ip, 24).Masked().String()
	return sourceTestMetadata(64500, "", prefix, "", "", "offline-benchmark", enricher.lookupAt, nil), nil
}

func (enricher *sourceBatchFixtureEnricher) EnrichIP(context.Context, netip.Addr) (IPMetadata, error) {
	enricher.singleCalls++
	return IPMetadata{}, errors.New("single lookup must not be called")
}

func (enricher *sourceBatchFixtureEnricher) EnrichIPs(_ context.Context, ips []netip.Addr) ([]IPEnrichmentBatchItem, error) {
	enricher.batchCalls++
	enricher.received = append([]netip.Addr{}, ips...)
	return append([]IPEnrichmentBatchItem{}, enricher.items...), enricher.err
}

func sourceEnrichmentTestCandidates(t testing.TB, sources ...string) ThreatCandidateResult {
	t.Helper()
	recordsA := make([]Record, 0, len(sources))
	recordsB := make([]Record, 0, len(sources))
	for _, source := range sources {
		recordsA = append(recordsA, threatTestRecord(source, "70", "example.test", "reject"))
		recordsB = append(recordsB, threatTestRecord(source, "70", "example.test", "quarantine"))
	}
	return threatTestScore(t, correlationTestConfig(AuthenticationPolicyConfig{}), correlationHealthyDNSValues(), []*AggregateReport{
		correlationTestReport("r1", "receiver-a.example", 100, 1_000, recordsA...),
		correlationTestReport("r2", "receiver-b.example", 90_000, 100_000, recordsB...),
	}, ThreatCandidateOptions{})
}

func sourceTestMetadata(asn uint32, asnName, prefix, organization, country, provider string, lookupAt time.Time, expiresAt *time.Time) IPMetadata {
	return IPMetadata{Assertions: []IPMetadataAssertion{{
		ASN: asn, ASNName: asnName, NetworkPrefix: prefix, Organization: organization, CountryCode: country,
		Provenance: IPMetadataProvenance{Provider: provider, Source: "offline-fixture", LookupAt: lookupAt, ExpiresAt: expiresAt, Confidence: IPMetadataConfidence{Available: true, Value: 80}, ReferenceID: "fixture-reference"},
	}}}
}

func sourceEnrichmentStatusesByIP(values []EnrichedThreatCandidate) map[string]SourceEnrichmentStatus {
	result := map[string]SourceEnrichmentStatus{}
	for _, value := range values {
		result[value.Candidate.SourceIP] = value.Status
	}
	return result
}
