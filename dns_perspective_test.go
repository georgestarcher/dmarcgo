package dmarcgo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var dnsPerspectiveTestTime = dnsTestTime.Add(time.Hour)

type fixtureDNSPerspectiveProvider struct {
	mu        sync.Mutex
	responses map[string]DNSPerspectiveResponse
	errors    map[string]error
	delays    map[string]time.Duration
	calls     []DNSPerspectiveQuery
	active    int
	maxActive int
}

func newFixtureDNSPerspectiveProvider() *fixtureDNSPerspectiveProvider {
	return &fixtureDNSPerspectiveProvider{
		responses: map[string]DNSPerspectiveResponse{},
		errors:    map[string]error{},
		delays:    map[string]time.Duration{},
	}
}

func (provider *fixtureDNSPerspectiveProvider) LookupDNSPerspective(ctx context.Context, query DNSPerspectiveQuery) (DNSPerspectiveResponse, error) {
	provider.mu.Lock()
	provider.calls = append(provider.calls, query)
	provider.active++
	if provider.active > provider.maxActive {
		provider.maxActive = provider.active
	}
	delay := provider.delays[query.Name]
	response, ok := provider.responses[query.Name]
	err := provider.errors[query.Name]
	provider.mu.Unlock()

	defer func() {
		provider.mu.Lock()
		provider.active--
		provider.mu.Unlock()
	}()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return response, ctx.Err()
		}
	}
	if !ok {
		response = DNSPerspectiveResponse{Provider: "offline-fixture", Dataset: "fixture-v1", Observations: []DNSPerspectiveProviderObservation{}}
	}
	return response, err
}

func (provider *fixtureDNSPerspectiveProvider) callsSnapshot() []DNSPerspectiveQuery {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]DNSPerspectiveQuery(nil), provider.calls...)
}

func (provider *fixtureDNSPerspectiveProvider) maximumActive() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.maxActive
}

func TestCollectDNSPerspectivesNilProviderIsNoOp(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	var provider *fixtureDNSPerspectiveProvider
	result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC}},
		Clock:     sourcePanicClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := result.ResultMetadata()
	if metadata.Mode != AnalysisModeDNSPerspectives || metadata.Evaluation.State != EvaluationStateNotEvaluated ||
		!metadata.GeneratedAt.Equal(snapshot.ObservedAt()) || result.Complete() || result.Digest() == "" ||
		result.PortfolioDigest() != portfolio.Digest() || result.SnapshotDigest() != snapshot.Digest() {
		t.Fatalf("result metadata=%+v complete=%v digest=%q", metadata, result.Complete(), result.Digest())
	}
	if len(result.Queries()) != len(snapshot.Observations()) {
		t.Fatalf("queries=%d observations=%d", len(result.Queries()), len(snapshot.Observations()))
	}
	for _, query := range result.Queries() {
		if query.Outcome != DNSPerspectiveNotEvaluated || query.PerspectiveAgreement != DNSPerspectiveAgreementNotEvaluated ||
			query.SnapshotAgreement != DNSPerspectiveAgreementNotEvaluated || len(query.Observations) != 0 {
			t.Fatalf("query=%+v", query)
		}
	}
}

func TestCollectDNSPerspectivesSelectsOnlyDeclaredTXTNames(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	provider := dnsPerspectiveSuccessProvider(snapshot)
	selection := DNSPerspectiveSelection{
		Names: []string{" SHARED._DOMAINKEY.SHARED.TEST. ", "one.test"},
		Roles: []DNSRecordType{DNSRecordDMARC},
	}
	result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
		Selection: selection, Clock: fixedDNSPerspectiveClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []DNSPerspectiveQuery{
		{Name: "_dmarc.one.test", Type: DNSPerspectiveTXT},
		{Name: "_dmarc.two.test", Type: DNSPerspectiveTXT},
		{Name: "one.test", Type: DNSPerspectiveTXT},
		{Name: "shared._domainkey.shared.test", Type: DNSPerspectiveTXT},
	}
	if calls := provider.callsSnapshot(); !slices.Equal(calls, want) {
		t.Fatalf("calls=%+v want=%+v", calls, want)
	}
	if !result.Complete() || result.Summary().Queries != len(want) || result.Summary().SuccessfulPerspectives != len(want)*2 {
		t.Fatalf("summary=%+v complete=%v", result.Summary(), result.Complete())
	}
	for _, query := range result.Queries() {
		if query.Outcome != DNSPerspectiveSuccess || query.PerspectiveAgreement != DNSPerspectiveAnswersAgree || query.SnapshotAgreement != DNSPerspectiveAnswersAgree ||
			query.SuccessfulPerspectives != 2 || query.NoAnswerPerspectives != 0 || query.FailedPerspectives != 0 || !query.Snapshot.ObservedAt.Equal(snapshot.ObservedAt()) {
			t.Fatalf("query=%+v", query)
		}
	}
	if snapshot.Digest() != result.SnapshotDigest() {
		t.Fatal("perspective collection mutated or replaced the trusted snapshot")
	}
}

func TestCollectDNSPerspectivesDisagreementIsSupplementalAndValueSafe(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	provider := newFixtureDNSPerspectiveProvider()
	provider.responses["one.test"] = DNSPerspectiveResponse{
		Provider: "HOSTILE PROVIDER", Dataset: "HOSTILE DATASET", ReferenceID: "HOSTILE REFERENCE",
		Observations: []DNSPerspectiveProviderObservation{
			{PerspectiveID: "b", Perspective: "HOSTILE COUNTRY", Status: "HOSTILE STATUS", Outcome: DNSPerspectiveSuccess,
				Answers: []DNSPerspectiveAnswer{{Joined: "different-value"}}},
			{PerspectiveID: "a", Perspective: "OTHER HOSTILE COUNTRY", Outcome: DNSPerspectiveSuccess,
				Answers: []DNSPerspectiveAnswer{{Fragments: []string{"synthetic-", "value"}, FragmentsAvailable: true}}},
		},
	}
	result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Names: []string{"one.test"}}, Clock: fixedDNSPerspectiveClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	query := result.Queries()[0]
	if query.PerspectiveAgreement != DNSPerspectiveAnswersDisagree || query.SnapshotAgreement != DNSPerspectiveAnswersDisagree || len(result.Findings()) != 2 {
		t.Fatalf("query=%+v findings=%+v", query, result.Findings())
	}
	if query.Observations[0].PerspectiveID != "a" || query.Observations[1].PerspectiveID != "b" {
		t.Fatalf("observations are not deterministic: %+v", query.Observations)
	}
	payload, err := json.Marshal(struct {
		Findings    []DNSPerspectiveFinding    `json:"findings"`
		Diagnostics []DNSPerspectiveDiagnostic `json:"diagnostics"`
	}{result.Findings(), result.Diagnostics()})
	if err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{"HOSTILE PROVIDER", "HOSTILE DATASET", "HOSTILE REFERENCE", "HOSTILE COUNTRY", "HOSTILE STATUS", "different-value"} {
		if strings.Contains(string(payload), hostile) {
			t.Fatalf("provider-controlled text leaked into generated prose: %s", payload)
		}
	}

	queries := result.Queries()
	queries[0].Snapshot.References[0].Domain = "mutated.test"
	queries[0].Observations[0].Answers[0].Fragments[0] = "mutated"
	findings := result.Findings()
	findings[0].EvidenceIDs[0] = "mutated"
	if fresh := result.Queries(); fresh[0].Snapshot.References[0].Domain == "mutated.test" || fresh[0].Observations[0].Answers[0].Fragments[0] == "mutated" {
		t.Fatal("query accessor did not return defensive copies")
	}
	if result.Findings()[0].EvidenceIDs[0] == "mutated" {
		t.Fatal("finding accessor did not return defensive copies")
	}
}

func TestCollectDNSPerspectivesPreservesPartialFailuresWithoutRetry(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	provider := dnsPerspectiveSuccessProvider(snapshot)
	provider.errors["one.test"] = errors.New("SENSITIVE PROVIDER ERROR")
	provider.errors["two.test"] = ErrDNSPerspectiveRateLimited
	response := provider.responses["two.test"]
	response.RetryAfter = 2 * time.Hour
	provider.responses["two.test"] = response
	result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF}}, Clock: fixedDNSPerspectiveClock(), MaxRetryAfter: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete() || len(provider.callsSnapshot()) != 2 || len(result.Diagnostics()) != 2 {
		t.Fatalf("complete=%v calls=%+v diagnostics=%+v", result.Complete(), provider.callsSnapshot(), result.Diagnostics())
	}
	byName := dnsPerspectiveQueriesByName(result.Queries())
	if byName["one.test"].Outcome != DNSPerspectiveFailed || byName["two.test"].Outcome != DNSPerspectiveRateLimited ||
		!byName["two.test"].RetryAfter.Available || byName["two.test"].RetryAfter.Seconds != 1800 || !byName["two.test"].RetryAfter.Capped {
		t.Fatalf("queries=%+v", result.Queries())
	}
	payload, marshalErr := json.Marshal(result.Diagnostics())
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(payload), "SENSITIVE PROVIDER ERROR") {
		t.Fatalf("provider error leaked: %s", payload)
	}
}

func TestCollectDNSPerspectivesCoverageStates(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	tests := []struct {
		name              string
		observations      []DNSPerspectiveProviderObservation
		wantOutcome       DNSPerspectiveOutcome
		wantAgreement     DNSPerspectiveAgreement
		wantSnapshot      DNSPerspectiveAgreement
		wantSuccess       int
		wantNoAnswer      int
		wantFailed        int
		wantDiagnostics   int
		wantNormalizedAns int
	}{
		{
			name: "one successful perspective is not agreement",
			observations: []DNSPerspectiveProviderObservation{{
				PerspectiveID: "one", Outcome: DNSPerspectiveSuccess,
				Answers: []DNSPerspectiveAnswer{{Joined: "synthetic-value"}, {Joined: "synthetic-value"}},
			}},
			wantOutcome: DNSPerspectiveSuccess, wantAgreement: DNSPerspectiveAgreementUnknown,
			wantSnapshot: DNSPerspectiveAnswersAgree, wantSuccess: 1, wantNormalizedAns: 1,
		},
		{
			name: "no answer perspectives",
			observations: []DNSPerspectiveProviderObservation{
				{PerspectiveID: "one", Outcome: DNSPerspectiveNoAnswer},
				{PerspectiveID: "two", Outcome: DNSPerspectiveNoAnswer},
			},
			wantOutcome: DNSPerspectiveNoAnswer, wantAgreement: DNSPerspectiveAgreementUnknown,
			wantSnapshot: DNSPerspectiveAgreementUnknown, wantNoAnswer: 2, wantDiagnostics: 1,
		},
		{
			name: "successful and failed perspectives preserve partial coverage",
			observations: []DNSPerspectiveProviderObservation{
				{PerspectiveID: "one", Outcome: DNSPerspectiveSuccess, Answers: []DNSPerspectiveAnswer{{Joined: "synthetic-value"}}},
				{PerspectiveID: "two", Outcome: DNSPerspectiveFailed},
			},
			wantOutcome: DNSPerspectiveSuccess, wantAgreement: DNSPerspectiveAgreementUnknown,
			wantSnapshot: DNSPerspectiveAnswersAgree, wantSuccess: 1, wantFailed: 1, wantDiagnostics: 1, wantNormalizedAns: 1,
		},
		{
			name:        "empty provider coverage is unavailable",
			wantOutcome: DNSPerspectiveUnavailable, wantAgreement: DNSPerspectiveAgreementUnknown,
			wantSnapshot: DNSPerspectiveAgreementUnknown, wantDiagnostics: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newFixtureDNSPerspectiveProvider()
			provider.responses["one.test"] = DNSPerspectiveResponse{
				Provider: "offline-fixture", Dataset: "fixture-v1", Observations: test.observations,
			}
			result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
				Selection: DNSPerspectiveSelection{Names: []string{"one.test"}}, Clock: fixedDNSPerspectiveClock(),
			})
			if err != nil {
				t.Fatal(err)
			}
			query := result.Queries()[0]
			if !result.Complete() || query.Outcome != test.wantOutcome || query.PerspectiveAgreement != test.wantAgreement ||
				query.SnapshotAgreement != test.wantSnapshot || query.SuccessfulPerspectives != test.wantSuccess ||
				query.NoAnswerPerspectives != test.wantNoAnswer || query.FailedPerspectives != test.wantFailed ||
				len(result.Diagnostics()) != test.wantDiagnostics {
				t.Fatalf("query=%+v diagnostics=%+v", query, result.Diagnostics())
			}
			if test.wantNormalizedAns > 0 && len(query.Observations[0].Answers) != test.wantNormalizedAns {
				t.Fatalf("normalized answers=%+v", query.Observations[0].Answers)
			}
		})
	}
}

func TestCollectDNSPerspectivesCancellationAndTimeout(t *testing.T) {
	t.Run("pre-canceled invokes no provider", func(t *testing.T) {
		portfolio, snapshot := dnsPerspectiveTestInputs(t)
		provider := dnsPerspectiveSuccessProvider(snapshot)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := CollectDNSPerspectives(ctx, portfolio, snapshot, provider, DNSPerspectiveOptions{
			Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF}}, Clock: fixedDNSPerspectiveClock(),
		})
		if !errors.Is(err, context.Canceled) || len(provider.callsSnapshot()) != 0 || result.Digest() == "" || result.Complete() {
			t.Fatalf("error=%v calls=%+v digest=%q complete=%v", err, provider.callsSnapshot(), result.Digest(), result.Complete())
		}
	})

	t.Run("per-query timeout is terminal", func(t *testing.T) {
		portfolio, snapshot := dnsPerspectiveTestInputs(t)
		provider := dnsPerspectiveSuccessProvider(snapshot)
		provider.delays["one.test"] = time.Second
		result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
			Selection: DNSPerspectiveSelection{Names: []string{"one.test"}}, Clock: fixedDNSPerspectiveClock(), LookupTimeout: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.Complete() || result.Queries()[0].Outcome != DNSPerspectiveFailed || result.Diagnostics()[0].Code != "dns_perspective.timeout" {
			t.Fatalf("result=%+v diagnostics=%+v", result.Queries(), result.Diagnostics())
		}
	})

	t.Run("parent deadline preserves partial result", func(t *testing.T) {
		portfolio, snapshot := dnsPerspectiveTestInputs(t)
		provider := dnsPerspectiveSuccessProvider(snapshot)
		provider.delays["one.test"] = time.Second
		provider.delays["two.test"] = time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		result, err := CollectDNSPerspectives(ctx, portfolio, snapshot, provider, DNSPerspectiveOptions{
			Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF}}, Clock: fixedDNSPerspectiveClock(), MaxConcurrency: 1,
		})
		if !errors.Is(err, context.DeadlineExceeded) || result.Digest() == "" || result.Complete() {
			t.Fatalf("error=%v digest=%q complete=%v", err, result.Digest(), result.Complete())
		}
	})
}

func TestCollectDNSPerspectivesRejectsMalformedProviderEvidence(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	tests := []struct {
		name     string
		response DNSPerspectiveResponse
		options  DNSPerspectiveOptions
	}{
		{name: "missing provider", response: DNSPerspectiveResponse{Dataset: "fixture"}},
		{name: "duplicate perspective", response: DNSPerspectiveResponse{Provider: "fixture", Dataset: "fixture", Observations: []DNSPerspectiveProviderObservation{
			{PerspectiveID: "same", Outcome: DNSPerspectiveNoAnswer}, {PerspectiveID: "same", Outcome: DNSPerspectiveNoAnswer},
		}}},
		{name: "answers on failure", response: DNSPerspectiveResponse{Provider: "fixture", Dataset: "fixture", Observations: []DNSPerspectiveProviderObservation{
			{PerspectiveID: "one", Outcome: DNSPerspectiveFailed, Answers: []DNSPerspectiveAnswer{{Joined: "value"}}},
		}}},
		{name: "control text", response: DNSPerspectiveResponse{Provider: "fixture\nattack", Dataset: "fixture"}},
		{name: "total text budget", response: DNSPerspectiveResponse{Provider: "fixture", Dataset: "fixture", Observations: []DNSPerspectiveProviderObservation{
			{PerspectiveID: "one", Perspective: strings.Repeat("x", 32), Outcome: DNSPerspectiveNoAnswer},
		}}, options: DNSPerspectiveOptions{MaxTextBytes: 64, MaxTotalTextBytes: 16}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newFixtureDNSPerspectiveProvider()
			provider.responses["one.test"] = test.response
			test.options.Selection = DNSPerspectiveSelection{Names: []string{"one.test"}}
			test.options.Clock = fixedDNSPerspectiveClock()
			result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Complete() || result.Queries()[0].Outcome != DNSPerspectiveMalformed || len(result.Diagnostics()) != 1 ||
				result.Diagnostics()[0].Code != "dns_perspective.malformed" {
				t.Fatalf("queries=%+v diagnostics=%+v", result.Queries(), result.Diagnostics())
			}
		})
	}
}

func TestCollectDNSPerspectivesValidatesInputsAndSelection(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	provider := dnsPerspectiveSuccessProvider(snapshot)
	base := DNSPerspectiveOptions{Selection: DNSPerspectiveSelection{Names: []string{"one.test"}}, Clock: fixedDNSPerspectiveClock()}
	tests := []struct {
		name      string
		portfolio Portfolio
		snapshot  DNSSnapshot
		options   DNSPerspectiveOptions
		want      error
	}{
		{name: "empty selection", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Clock: fixedDNSPerspectiveClock()}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "unknown name", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Selection: DNSPerspectiveSelection{Names: []string{"unknown.test"}}, Clock: fixedDNSPerspectiveClock()}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "invalid role", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{"mx"}}, Clock: fixedDNSPerspectiveClock()}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "query limit", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF}}, MaxQueries: 1, Clock: fixedDNSPerspectiveClock()}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "excessive concurrency", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Selection: base.Selection, MaxConcurrency: maxDNSPerspectiveConcurrency + 1, Clock: fixedDNSPerspectiveClock()}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "excessive timeout", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Selection: base.Selection, LookupTimeout: maxDNSPerspectiveLookupTimeout + time.Second, Clock: fixedDNSPerspectiveClock()}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "clock before snapshot", portfolio: portfolio, snapshot: snapshot, options: DNSPerspectiveOptions{Selection: base.Selection, Clock: ClockFunc(func() time.Time { return dnsTestTime.Add(-time.Second) })}, want: ErrInvalidDNSPerspectiveOptions},
		{name: "empty snapshot", portfolio: portfolio, options: base, want: ErrInvalidAnalysisResult},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CollectDNSPerspectives(context.Background(), test.portfolio, test.snapshot, provider, test.options)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestCollectDNSPerspectivesIsDeterministicAndBounded(t *testing.T) {
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	firstProvider := dnsPerspectiveSuccessProvider(snapshot)
	secondProvider := dnsPerspectiveSuccessProvider(snapshot)
	for _, observation := range snapshot.Observations() {
		firstProvider.delays[observation.Name] = 2 * time.Millisecond
		secondProvider.delays[observation.Name] = 2 * time.Millisecond
	}
	for name, response := range secondProvider.responses {
		slices.Reverse(response.Observations)
		for index := range response.Observations {
			slices.Reverse(response.Observations[index].Answers)
		}
		secondProvider.responses[name] = response
	}
	options := DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC}},
		Clock:     fixedDNSPerspectiveClock(), MaxConcurrency: 2,
	}
	first, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, firstProvider, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, secondProvider, options)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() || !slices.EqualFunc(first.Queries(), second.Queries(), func(a, b DNSPerspectiveQueryResult) bool {
		return a.ID == b.ID && a.Outcome == b.Outcome && slices.EqualFunc(a.Observations, b.Observations, func(a, b DNSPerspectiveObservation) bool {
			return a.ID == b.ID && a.AnswerFingerprint == b.AnswerFingerprint
		})
	}) {
		t.Fatalf("reordered evidence changed result: %q != %q", first.Digest(), second.Digest())
	}
	if maximum := firstProvider.maximumActive(); maximum > 2 || maximum < 2 {
		t.Fatalf("maximum active lookups=%d", maximum)
	}
}

func TestPrivatePortfolioDNSPerspectiveCompatibility(t *testing.T) {
	paths, err := filepath.Glob("test_dmarc_reports/*-records.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("private DNS record notes are not present")
	}
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var config PortfolioConfig
		if unmarshalErr := yaml.Unmarshal(data, &config); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		portfolio, normalizeErr := NormalizePortfolio(config)
		if normalizeErr != nil {
			t.Fatal(normalizeErr)
		}
		resolver := successfulFixtureResolver(portfolio)
		snapshot, collectErr := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1,
		})
		if collectErr != nil {
			t.Fatal(collectErr)
		}
		provider := dnsPerspectiveSuccessProvider(snapshot)
		result, perspectiveErr := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
			Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC}},
			Clock:     fixedDNSPerspectiveClock(), MaxQueries: maxDNSPerspectiveQueries,
		})
		if perspectiveErr != nil || !result.Complete() || result.Summary().Queries != len(snapshot.Observations()) || len(provider.callsSnapshot()) != len(snapshot.Observations()) {
			t.Fatalf("private portfolio perspective queries=%d observations=%d complete=%v error=%v", result.Summary().Queries, len(snapshot.Observations()), result.Complete(), perspectiveErr)
		}
	}
}

func BenchmarkCollectDNSPerspectives(b *testing.B) {
	portfolio, snapshot := dnsPerspectiveTestInputs(b)
	options := DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC}},
		Clock:     fixedDNSPerspectiveClock(),
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, dnsPerspectiveSuccessProvider(snapshot), options); err != nil {
			b.Fatal(err)
		}
	}
}

func dnsPerspectiveTestInputs(t testing.TB) (Portfolio, DNSSnapshot) {
	t.Helper()
	portfolio := dnsTestPortfolio(t)
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, successfulFixtureResolver(portfolio), DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return portfolio, snapshot
}

func dnsPerspectiveSuccessProvider(snapshot DNSSnapshot) *fixtureDNSPerspectiveProvider {
	provider := newFixtureDNSPerspectiveProvider()
	for _, observation := range snapshot.Observations() {
		answers := make([]DNSPerspectiveAnswer, len(observation.Records))
		for index, record := range observation.Records {
			answers[index] = DNSPerspectiveAnswer{
				Fragments: append([]string(nil), record.Fragments...), FragmentsAvailable: record.FragmentsAvailable, Joined: record.Joined,
			}
		}
		provider.responses[observation.Name] = DNSPerspectiveResponse{
			Provider: "offline-fixture", Dataset: "fixture-v1", ReferenceID: "fixture-reference",
			Observations: []DNSPerspectiveProviderObservation{
				{PerspectiveID: "resolver-b", Perspective: "fixture-b", Outcome: DNSPerspectiveSuccess, Answers: answers},
				{PerspectiveID: "resolver-a", Perspective: "fixture-a", Outcome: DNSPerspectiveSuccess, Answers: answers},
			},
		}
	}
	return provider
}

func fixedDNSPerspectiveClock() Clock {
	return ClockFunc(func() time.Time { return dnsPerspectiveTestTime })
}

func dnsPerspectiveQueriesByName(values []DNSPerspectiveQueryResult) map[string]DNSPerspectiveQueryResult {
	result := make(map[string]DNSPerspectiveQueryResult, len(values))
	for _, value := range values {
		result[value.Query.Name] = value
	}
	return result
}
