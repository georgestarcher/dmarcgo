package dmarcgo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var dnsTestTime = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

type fixtureTXTResolver struct {
	mu        sync.Mutex
	results   map[string]TXTLookupResult
	errors    map[string][]error
	delays    map[string]time.Duration
	calls     map[string]int
	active    int
	maxActive int
}

func newFixtureTXTResolver() *fixtureTXTResolver {
	return &fixtureTXTResolver{
		results: map[string]TXTLookupResult{}, errors: map[string][]error{},
		delays: map[string]time.Duration{}, calls: map[string]int{},
	}
}

func (resolver *fixtureTXTResolver) LookupTXT(ctx context.Context, name string) (TXTLookupResult, error) {
	resolver.mu.Lock()
	call := resolver.calls[name]
	resolver.calls[name] = call + 1
	resolver.active++
	if resolver.active > resolver.maxActive {
		resolver.maxActive = resolver.active
	}
	delay := resolver.delays[name]
	result := resolver.results[name]
	errorsForName := resolver.errors[name]
	resolver.mu.Unlock()

	defer func() {
		resolver.mu.Lock()
		resolver.active--
		resolver.mu.Unlock()
	}()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return result, ctx.Err()
		}
	}
	if call < len(errorsForName) && errorsForName[call] != nil {
		return result, errorsForName[call]
	}
	return result, nil
}

func (resolver *fixtureTXTResolver) callCount(name string) int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls[name]
}

func TestCollectDNSSnapshotDeduplicatesAndPreservesEvidence(t *testing.T) {
	portfolio := dnsTestPortfolio(t)
	resolver := successfulFixtureResolver(portfolio)
	shared := "shared._domainkey.shared.test"
	resolver.results[shared] = TXTLookupResult{
		Name:    shared,
		Records: []TXTRecord{{Fragments: []string{"v=DKIM1; p=", "example-key"}}},
		TTL:     DNSDurationEvidence{Available: true, Seconds: 300}, Resolver: "authoritative-fixture",
		AnswerSource: DNSAnswerSourceAuthoritative, RCode: DNSRCodeEvidence{Available: true},
	}

	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxConcurrency: 2, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Complete() || snapshot.ResultMetadata().Mode != AnalysisModeDNSSnapshot || !snapshot.ObservedAt().Equal(dnsTestTime) {
		t.Fatalf("snapshot metadata = %+v complete=%v", snapshot.ResultMetadata(), snapshot.Complete())
	}
	observations := snapshot.Observations()
	if !slices.IsSortedFunc(observations, func(a, b DNSObservation) int { return compareStrings(a.Name, b.Name) }) {
		t.Fatalf("observations are not sorted: %+v", observations)
	}
	sharedObservation := findDNSObservation(t, observations, shared)
	if resolver.callCount(shared) != 1 || len(sharedObservation.References) != 2 {
		t.Fatalf("shared lookup calls=%d references=%+v", resolver.callCount(shared), sharedObservation.References)
	}
	if sharedObservation.Records[0].Joined != "v=DKIM1; p=example-key" || !slices.Equal(sharedObservation.Records[0].Fragments, []string{"v=DKIM1; p=", "example-key"}) {
		t.Fatalf("TXT evidence = %+v", sharedObservation.Records)
	}
	if !sharedObservation.TTL.Available || sharedObservation.TTL.Seconds != 300 || sharedObservation.AnswerSource != DNSAnswerSourceAuthoritative {
		t.Fatalf("TTL/source evidence = %+v source=%q", sharedObservation.TTL, sharedObservation.AnswerSource)
	}

	observations[0].Records = append(observations[0].Records, TXTRecord{Fragments: []string{"changed"}})
	observations[0].References[0].Domain = "changed.test"
	if fresh := snapshot.Observations(); len(fresh[0].Records) != 1 || fresh[0].References[0].Domain == "changed.test" {
		t.Fatal("snapshot accessor exposed internal slices")
	}
}

func TestCollectDNSSnapshotIsDeterministicForInputOrder(t *testing.T) {
	config := dnsTestPortfolioConfig()
	firstPortfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(config.Entities)
	secondPortfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	options := DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1}
	first, err := CollectDNSSnapshot(context.Background(), firstPortfolio, successfulFixtureResolver(firstPortfolio), options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CollectDNSSnapshot(context.Background(), secondPortfolio, successfulFixtureResolver(secondPortfolio), options)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() || !slices.EqualFunc(first.Observations(), second.Observations(), dnsObservationsEqual) {
		t.Fatalf("reordered snapshot changed: %q != %q", first.Digest(), second.Digest())
	}
}

func TestCollectDNSSnapshotPreservesNegativeEvidence(t *testing.T) {
	portfolio := dnsTestPortfolio(t)
	resolver := successfulFixtureResolver(portfolio)
	nxdomain := "_dmarc.one.test"
	nodata := "two.test"
	soa := &DNSSOAEvidence{Name: "test", MName: "ns.test", RName: "hostmaster.test", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 600, TTL: 900}
	resolver.results[nxdomain] = TXTLookupResult{
		Name: nxdomain, Status: DNSObservationNXDOMAIN, NegativeTTL: DNSDurationEvidence{Available: true, Seconds: 600},
		SOA: soa, Resolver: "recursive-fixture", AnswerSource: DNSAnswerSourceRecursive, RCode: DNSRCodeEvidence{Available: true, Value: 3},
	}
	resolver.results[nodata] = TXTLookupResult{
		Name: nodata, Status: DNSObservationNoData, NegativeTTL: DNSDurationEvidence{Available: true, Seconds: 120},
		SOA: soa, Resolver: "authoritative-fixture", AnswerSource: DNSAnswerSourceAuthoritative,
	}
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotNX := findDNSObservation(t, snapshot.Observations(), nxdomain)
	gotNoData := findDNSObservation(t, snapshot.Observations(), nodata)
	if gotNX.Status != DNSObservationNXDOMAIN || !gotNX.RCode.Available || gotNX.RCode.Value != 3 || !gotNX.NegativeTTL.Available || gotNX.SOA == nil {
		t.Fatalf("NXDOMAIN evidence = %+v", gotNX)
	}
	if gotNoData.Status != DNSObservationNoData || gotNoData.RCode.Available || gotNoData.NegativeTTL.Seconds != 120 {
		t.Fatalf("NODATA evidence = %+v", gotNoData)
	}
	if len(snapshot.Diagnostics()) != 2 {
		t.Fatalf("diagnostics = %+v", snapshot.Diagnostics())
	}
}

func TestCollectDNSSnapshotRetriesTransientFailure(t *testing.T) {
	portfolio := singleDNSNamePortfolio(t)
	resolver := newFixtureTXTResolver()
	resolver.errors["one.test"] = []error{ErrDNSTemporary, nil}
	resolver.results["one.test"] = successTXTResult("one.test")
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 2, RetryDelay: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	observation := snapshot.Observations()[0]
	if observation.Status != DNSObservationSuccess || observation.Attempts != 2 || resolver.callCount("one.test") != 2 {
		t.Fatalf("retry observation = %+v calls=%d", observation, resolver.callCount("one.test"))
	}
}

func TestCollectDNSSnapshotDoesNotAcceptSuccessWithError(t *testing.T) {
	portfolio := singleDNSNamePortfolio(t)
	resolver := newFixtureTXTResolver()
	resolver.results["one.test"] = TXTLookupResult{
		Name: "one.test", Status: DNSObservationSuccess,
		Records: []TXTRecord{{Fragments: []string{"value"}}},
		TTL:     DNSDurationEvidence{Available: true, Seconds: 300},
	}
	resolver.errors["one.test"] = []error{ErrDNSTemporary}
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	observation := snapshot.Observations()[0]
	if observation.Status != DNSObservationTemporaryFailure || observation.TTL.Available || len(observation.Records) != 0 {
		t.Fatalf("errored success result = %+v", observation)
	}
}

func TestCollectDNSSnapshotCanonicalizesRRSetOrder(t *testing.T) {
	portfolio := singleDNSNamePortfolio(t)
	resolver := newFixtureTXTResolver()
	resolver.results["one.test"] = TXTLookupResult{
		Name: "one.test", Status: DNSObservationSuccess,
		Records: []TXTRecord{{Fragments: []string{"z-value"}}, {Fragments: []string{"a-", "value"}}},
	}
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if records := snapshot.Observations()[0].Records; records[0].Joined != "a-value" || records[1].Joined != "z-value" {
		t.Fatalf("records = %+v", records)
	}
}

func TestCollectDNSSnapshotTimeoutAndCancellation(t *testing.T) {
	portfolio := singleDNSNamePortfolio(t)
	t.Run("timeout", func(t *testing.T) {
		resolver := newFixtureTXTResolver()
		resolver.delays["one.test"] = time.Second
		snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1, QueryTimeout: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := snapshot.Observations()[0]; got.Status != DNSObservationTimeout || got.TTL.Available || got.NegativeTTL.Available {
			t.Fatalf("timeout observation = %+v", got)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		resolver := newFixtureTXTResolver()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		snapshot, err := CollectDNSSnapshot(ctx, portfolio, resolver, DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return dnsTestTime })})
		if !errors.Is(err, context.Canceled) || snapshot.Complete() || resolver.callCount("one.test") != 0 {
			t.Fatalf("canceled snapshot complete=%v error=%v calls=%d", snapshot.Complete(), err, resolver.callCount("one.test"))
		}
	})
}

func TestCollectDNSSnapshotFailurePolicies(t *testing.T) {
	portfolio := dnsTestPortfolio(t)
	t.Run("collect all", func(t *testing.T) {
		resolver := successfulFixtureResolver(portfolio)
		resolver.errors["_dmarc.one.test"] = []error{ErrDNSTemporary}
		snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1, FailurePolicy: DNSFailureCollectAll,
		})
		if err != nil || !snapshot.Complete() || len(snapshot.Diagnostics()) != 1 {
			t.Fatalf("collect-all snapshot complete=%v diagnostics=%+v error=%v", snapshot.Complete(), snapshot.Diagnostics(), err)
		}
	})
	t.Run("fail fast", func(t *testing.T) {
		resolver := successfulFixtureResolver(portfolio)
		resolver.results["_dmarc.one.test"] = TXTLookupResult{Name: "_dmarc.one.test", Status: DNSObservationNXDOMAIN}
		snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxConcurrency: 1, MaxAttempts: 1, FailurePolicy: DNSFailureFailFast,
		})
		if !errors.Is(err, ErrDNSCollectionFailed) || snapshot.Complete() || resolver.callCount("_dmarc.one.test") != 1 {
			t.Fatalf("fail-fast snapshot complete=%v error=%v calls=%d", snapshot.Complete(), err, resolver.callCount("_dmarc.one.test"))
		}
		calls := 0
		for _, observation := range snapshot.Observations() {
			calls += resolver.callCount(observation.Name)
		}
		if calls != 1 {
			t.Fatalf("fail-fast performed %d resolver calls", calls)
		}
	})
}

func TestCollectDNSSnapshotBoundsConcurrency(t *testing.T) {
	portfolio := dnsTestPortfolio(t)
	resolver := successfulFixtureResolver(portfolio)
	for _, observation := range buildDNSQueryPlan(portfolio) {
		resolver.delays[observation.name] = 2 * time.Millisecond
	}
	_, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
		Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxConcurrency: 2, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.maxActive > 2 || resolver.maxActive < 2 {
		t.Fatalf("maximum active lookups = %d", resolver.maxActive)
	}
}

func TestCollectDNSSnapshotEmptyPortfolio(t *testing.T) {
	config := minimalPortfolioConfig()
	config.Entities[0].Domains = nil
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, newFixtureTXTResolver(), DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return dnsTestTime })})
	if err != nil || !snapshot.Complete() || len(snapshot.Observations()) != 0 {
		t.Fatalf("empty snapshot = %+v error=%v", snapshot, err)
	}
}

func TestPrivatePortfolioCanPlanOfflineDNSSnapshot(t *testing.T) {
	paths, err := filepath.Glob("test_dmarc_reports/*-records.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("private DNS record notes are not present")
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var config PortfolioConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		portfolio, err := NormalizePortfolio(config)
		if err != nil {
			t.Fatal(err)
		}
		resolver := successfulFixtureResolver(portfolio)
		snapshot, err := CollectDNSSnapshot(context.Background(), portfolio, resolver, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxAttempts: 1,
		})
		if err != nil || !snapshot.Complete() || len(snapshot.Observations()) < 3 {
			t.Fatalf("private portfolio snapshot observations=%d complete=%v error=%v", len(snapshot.Observations()), snapshot.Complete(), err)
		}
	}
}

func BenchmarkCollectDNSSnapshotSharedPortfolio(b *testing.B) {
	portfolio := dnsTestPortfolio(b)
	options := DNSCollectionOptions{Clock: ClockFunc(func() time.Time { return dnsTestTime }), MaxConcurrency: 8, MaxAttempts: 1}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := CollectDNSSnapshot(context.Background(), portfolio, successfulFixtureResolver(portfolio), options); err != nil {
			b.Fatal(err)
		}
	}
}

func dnsTestPortfolio(t testing.TB) Portfolio {
	t.Helper()
	portfolio, err := NormalizePortfolio(dnsTestPortfolioConfig())
	if err != nil {
		t.Fatal(err)
	}
	return portfolio
}

func dnsTestPortfolioConfig() PortfolioConfig {
	return PortfolioConfig{
		SchemaVersion:   PortfolioSchemaVersion,
		Organization:    OrganizationConfig{ID: "dns-test"},
		ExpectedSenders: []ExpectedSenderConfig{{ID: "sender", RequireEither: true}},
		Entities: []EntityConfig{
			{ID: "one", Domains: []DomainConfig{{Name: "one.test", Records: MonitoredRecordsConfig{
				SPF: []string{"one.test"}, DKIM: []string{"shared._domainkey.shared.test"}, DMARC: []string{"_dmarc.one.test"},
			}, ExpectedSenders: []string{"sender"}}}},
			{ID: "two", Domains: []DomainConfig{{Name: "two.test", Records: MonitoredRecordsConfig{
				SPF: []string{"two.test"}, DKIM: []string{"shared._domainkey.shared.test"}, DMARC: []string{"_dmarc.two.test"},
			}, ExpectedSenders: []string{"sender"}}}},
		},
	}
}

func singleDNSNamePortfolio(t testing.TB) Portfolio {
	t.Helper()
	config := minimalPortfolioConfig()
	config.Entities[0].Domains[0].Records = MonitoredRecordsConfig{SPF: []string{"one.test"}}
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	return portfolio
}

func successfulFixtureResolver(portfolio Portfolio) *fixtureTXTResolver {
	resolver := newFixtureTXTResolver()
	for _, query := range buildDNSQueryPlan(portfolio) {
		resolver.results[query.name] = successTXTResult(query.name)
	}
	return resolver
}

func successTXTResult(name string) TXTLookupResult {
	return TXTLookupResult{
		Name: name, Status: DNSObservationSuccess,
		Records:  []TXTRecord{{Fragments: []string{"synthetic-value"}, Joined: "synthetic-value"}},
		Resolver: "offline-fixture", AnswerSource: DNSAnswerSourceUnknown, CNAMEPath: []string{},
	}
}

func findDNSObservation(t testing.TB, observations []DNSObservation, name string) DNSObservation {
	t.Helper()
	for _, observation := range observations {
		if observation.Name == name {
			return observation
		}
	}
	t.Fatalf("observation %q not found", name)
	return DNSObservation{}
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func dnsObservationsEqual(a, b DNSObservation) bool {
	return a.Name == b.Name && a.Status == b.Status && a.Attempts == b.Attempts &&
		slices.Equal(a.References, b.References) && slices.EqualFunc(a.Records, b.Records, func(a, b TXTRecord) bool {
		return a.Joined == b.Joined && slices.Equal(a.Fragments, b.Fragments)
	})
}
