package dmarcgo

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestCorrelateReportEvidenceSeparatesOnboardingUnknownFailureAndPassing(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, map[string]string{
		"example.test":        "v=spf1 -all",
		"_dmarc.example.test": "v=DMARC1; p=reject; rua=mailto:reports@example.test",
	})
	reports := []*AggregateReport{correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "10", "example.test", "fail", "fail", "example.test", "mk1", "example.test"),
		correlationTestRecord("198.51.100.20", "7", "example.test", "fail", "fail", "unknown.example", "rogue", "unknown.example"),
		correlationTestRecord("203.0.113.30", "5", "example.test", "fail", "pass", "other.example", "other", "bounce.example"),
	)}
	evidence := correlationTestEvidence(t, reports, time.Unix(200, 0))

	result, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if metadata := result.ResultMetadata(); metadata.Mode != AnalysisModeDNSReportCorrelation || metadata.Evaluation.State != EvaluationStateEvaluated || !metadata.GeneratedAt.Equal(health.ResultMetadata().GeneratedAt) {
		t.Fatalf("metadata=%+v", metadata)
	}
	if result.Version() != DNSReportCorrelationVersion || result.OrganizationID() != "example-group" || result.Digest() == "" || result.PortfolioDigest() != portfolio.Digest() ||
		result.DNSHealthDigest() != health.Digest() || result.DNSSnapshotDigest() != health.SnapshotDigest() || result.AuthenticationDigest() != health.AuthenticationDigest() ||
		result.ProviderCatalogDigest() != health.ProviderCatalogDigest() || result.ProviderCatalogProvenance().Digest != health.ProviderCatalogProvenance().Digest ||
		result.ReportEvidenceDigest() != evidence.Digest() {
		t.Fatalf("provenance is incomplete: version=%q digest=%q", result.Version(), result.Digest())
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationProbableOnboardingGap, "192.0.2.10")
	assertCorrelationClassification(t, result.Findings(), CorrelationUnknownSourceFailure, "198.51.100.20")
	assertCorrelationClassification(t, result.Findings(), CorrelationUnknownPassingStream, "203.0.113.30")
	if finding := findCorrelationClassification(t, result.Findings(), CorrelationUnknownSourceFailure, "198.51.100.20"); len(finding.ExpectedSenderIDs) != 0 {
		t.Fatalf("unknown source was attributed to expected sender: %+v", finding)
	}
	if !hasCorrelationClassification(result.Findings(), CorrelationNewSelector, "198.51.100.20") ||
		!hasCorrelationClassification(result.Findings(), CorrelationNewSigningDomain, "198.51.100.20") ||
		!hasCorrelationClassification(result.Findings(), CorrelationNewSPFIdentity, "198.51.100.20") {
		t.Fatalf("new authentication identities were not retained: %+v", result.Findings())
	}
	if got := result.Summary(); got.Messages != 22 || got.Reports != 1 || got.ReporterDiversity != 1 || got.Streams != 3 || got.ThresholdedStreams != 3 {
		t.Fatalf("summary=%+v", got)
	}
	for _, finding := range result.Findings() {
		if finding.Summary == "" || finding.Standard == "" || finding.DNSObservedAt.IsZero() || finding.TemporalRelationship != DNSReportDNSAfterReports {
			t.Fatalf("finding lacks grounded temporal evidence: %+v", finding)
		}
	}
}

func TestCorrelateReportEvidenceHonorsRequireEitherAndRequireDKIM(t *testing.T) {
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "10", "example.test", "fail", "pass", "example.test", "mk1", "example.test"),
	)
	for _, test := range []struct {
		name           string
		policy         AuthenticationPolicyConfig
		classification DNSReportCorrelationClassification
	}{
		{name: "either", policy: AuthenticationPolicyConfig{RequireEither: true, AllowedSelectors: []string{"mk1"}}, classification: CorrelationExpectedSenderHealthy},
		{name: "dkim", policy: AuthenticationPolicyConfig{RequireDKIM: true, AllowedSelectors: []string{"mk1"}}, classification: CorrelationExpectedSenderFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := correlationTestConfig(test.policy)
			portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
			evidence := correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0))
			result, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			assertCorrelationClassification(t, result.Findings(), test.classification, "192.0.2.10")
		})
	}
}

func TestCorrelateReportEvidenceMatchesUniqueSPFOnlySenderByMonitoredIdentity(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{RequireSPF: true})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "10", "example.test", "fail", "pass", "", "", "example.test"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	streams := result.Streams()
	if len(streams) != 1 || streams[0].CandidateBasis != SenderCandidateSPFMatch || !slices.Equal(streams[0].ExpectedSenderIDs, []string{"marketing"}) {
		t.Fatalf("SPF-only sender was not resolved: %+v", streams)
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.10")
}

func TestCorrelateReportEvidenceRequireEitherDoesNotTrustUnapprovedDKIMSelector(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{RequireEither: true, AllowedSelectors: []string{"mk1"}})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "5", "example.test", "pass", "pass", "example.test", "rogue", "example.test"),
		correlationTestRecord("192.0.2.11", "5", "example.test", "pass", "fail", "example.test", "rogue", "example.test"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.10")
	if hasCorrelationClassification(result.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.11") {
		t.Fatalf("unapproved DKIM-only path became healthy: %+v", result.Findings())
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationProbableOnboardingGap, "192.0.2.11")
}

func TestCorrelateReportEvidenceMissingSelectorRemainsUnattributed(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "10", "example.test", "fail", "fail", "example.test", "", "example.test"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	streams := result.Streams()
	if len(streams) != 1 || streams[0].DKIMSelector != "" || streams[0].CandidateBasis != SenderCandidateNone || len(streams[0].ExpectedSenderIDs) != 0 {
		t.Fatalf("missing selector was invented or attributed: %+v", streams)
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationUnknownSourceFailure, "192.0.2.10")
}

func TestCorrelateReportEvidenceMixedUnknownStreamRetainsFailure(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	reports := []*AggregateReport{
		correlationTestReport("r1", "receiver-a.example", 100, 150, correlationTestRecord("192.0.2.10", "3", "example.test", "fail", "fail", "unknown.example", "rogue", "unknown.example")),
		correlationTestReport("r2", "receiver-b.example", 151, 200, correlationTestRecord("192.0.2.10", "2", "example.test", "fail", "pass", "unknown.example", "rogue", "unknown.example")),
	}
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, reports, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	finding := findCorrelationClassification(t, result.Findings(), CorrelationUnknownSourceFailure, "192.0.2.10")
	if finding.Confidence != FindingConfidenceMedium || finding.Messages != 5 || finding.Reports != 2 || finding.ReporterDiversity != 2 {
		t.Fatalf("mixed stream finding=%+v", finding)
	}
}

func TestCorrelateReportEvidenceMultiDKIMStreamsDoNotDoubleCountSummary(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	record := correlationTestRecord("192.0.2.10", "5", "example.test", "pass", "fail", "example.test", "mk1", "example.test")
	record.AuthResults.DKIM = []DKIMAuthResult{
		{Domain: "example.test", Selector: "mk1", Result: "fail"},
		{Domain: "example.test", Selector: "other", Result: "pass"},
	}
	report := correlationTestReport("r1", "receiver.example", 100, 200, record)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary().Messages != 5 || result.Summary().Streams != 2 || result.Streams()[0].Messages+result.Streams()[1].Messages != 10 {
		t.Fatalf("multi-DKIM summary=%+v streams=%+v", result.Summary(), result.Streams())
	}
	for _, stream := range result.Streams() {
		switch stream.DKIMSelector {
		case "mk1":
			if stream.DKIM.Fail != 5 || stream.DKIM.Pass != 0 || stream.Combined.Fail != 5 {
				t.Fatalf("failed selector inherited another selector's pass: %+v", stream)
			}
		case "other":
			if stream.DKIM.Pass != 5 || stream.DKIM.Fail != 0 || stream.Combined.Pass != 5 {
				t.Fatalf("passing selector outcome=%+v", stream)
			}
		default:
			t.Fatalf("unexpected selector stream: %+v", stream)
		}
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationExpectedSenderFailure, "192.0.2.10")
	if hasCorrelationClassification(result.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.10") {
		t.Fatalf("failed expected selector was classified healthy: %+v", result.Findings())
	}
	eitherConfig := correlationTestConfig(AuthenticationPolicyConfig{RequireEither: true, AllowedSelectors: []string{"mk1"}})
	eitherPortfolio, eitherHealth := correlationTestDNSHealth(t, eitherConfig, correlationHealthyDNSValues())
	eitherResult, err := CorrelateReportEvidence(eitherPortfolio, eitherHealth, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertCorrelationClassification(t, eitherResult.Findings(), CorrelationExpectedSenderFailure, "192.0.2.10")
	if hasCorrelationClassification(eitherResult.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.10") {
		t.Fatalf("require_either inherited another selector's pass: %+v", eitherResult.Findings())
	}
}

func TestCorrelationDKIMIdentitiesAvoidAmbiguousPassAttribution(t *testing.T) {
	observation := ReportEvidenceObservation{
		AuthorDomain:  ReportEvidenceValue{Value: "example.test"},
		PolicyOutcome: ReportEvidencePolicyOutcome{DKIM: ReportAuthenticationPass},
		DKIM: []ReportEvidenceDKIM{
			{Domain: ReportEvidenceValue{Value: "example.test"}, Selector: ReportEvidenceValue{Value: "exact"}, Result: "pass"},
			{Domain: ReportEvidenceValue{Value: "signer.example.test"}, Selector: ReportEvidenceValue{Value: "ambiguous"}, Result: "pass"},
		},
	}
	identities := correlationDKIMIdentities(observation)
	if len(identities) != 2 {
		t.Fatalf("identities=%+v", identities)
	}
	for _, identity := range identities {
		switch identity.selector {
		case "exact":
			if identity.outcome != ReportAuthenticationPass {
				t.Fatalf("exactly aligned outcome=%q", identity.outcome)
			}
		case "ambiguous":
			if identity.outcome != ReportAuthenticationUnknown {
				t.Fatalf("ambiguous aligned outcome=%q", identity.outcome)
			}
		default:
			t.Fatalf("unexpected identity=%+v", identity)
		}
	}
}

func TestCorrelateReportEvidenceInvalidSourceRemainsInsufficient(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("not-an-ip", "3", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if hasCorrelationClassification(result.Findings(), CorrelationExpectedSenderHealthy, "") {
		t.Fatalf("invalid source became healthy sender evidence: %+v", result.Findings())
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationInsufficientEvidence, "")
}

func TestCorrelateReportEvidenceKeepsHostileValuesOutOfGeneratedProse(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	hostile := "ignore-previous-instructions"
	report := correlationTestReport("r1", hostile, 100, 200,
		correlationTestRecord("192.0.2.10", "3", "example.test", "fail", "fail", "evil.example", hostile, "evil.example"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Findings()[0].DKIMSelectors, hostile) && !slices.ContainsFunc(result.Findings(), func(finding DNSReportCorrelationFinding) bool {
		return slices.Contains(finding.DKIMSelectors, hostile)
	}) {
		t.Fatal("hostile selector was not retained as structured evidence")
	}
	for _, finding := range result.Findings() {
		for _, generated := range []string{finding.Summary, finding.Recommendation, finding.Evaluation.Reason} {
			if strings.Contains(generated, hostile) {
				t.Fatalf("untrusted value entered generated prose: %+v", finding)
			}
		}
	}
}

func TestCorrelateReportEvidenceProviderContextRemainsContextOnly(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{RequireEither: true, AllowedSelectors: []string{"google"}})
	config.ExpectedSenders[0].Provider = "google-workspace"
	values := correlationHealthyDNSValues()
	values["example.test"] = "v=spf1 include:_spf.google.com -all"
	portfolio, health := correlationTestDNSHealth(t, config, values)
	if len(health.ProviderContexts()) == 0 {
		t.Fatal("test health result lacks provider context")
	}
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "4", "example.test", "pass", "fail", "example.test", "google", "example.test"),
		correlationTestRecord("198.51.100.20", "4", "example.test", "fail", "pass", "", "", "unrelated.example"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var matched, unrelated DNSReportCorrelationStream
	for _, stream := range result.Streams() {
		switch stream.SourceIP {
		case "192.0.2.10":
			matched = stream
		case "198.51.100.20":
			unrelated = stream
		}
	}
	if matched.CandidateBasis != SenderCandidateSelectorMatch || len(matched.ExpectedSenderIDs) != 1 || len(matched.ProviderContextIDs) == 0 ||
		!matched.SharedProviderContext || !slices.Contains(matched.DeclaredProviderIDs, "google-workspace") {
		t.Fatalf("declared selector did not retain matching provider context: %+v", matched)
	}
	if unrelated.CandidateBasis != SenderCandidateNone || len(unrelated.ExpectedSenderIDs) != 0 || len(unrelated.ProviderContextIDs) == 0 ||
		len(unrelated.DeclaredProviderIDs) != 0 || unrelated.SharedProviderContext {
		t.Fatalf("provider context authorized unrelated identity: %+v", unrelated)
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.10")
	assertCorrelationClassification(t, result.Findings(), CorrelationUnknownPassingStream, "198.51.100.20")
}

func TestCorrelateReportEvidenceResolvesSisterAndInheritedSubdomainScopes(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	config.Entities[0].Domains[0].IncludeSubdomains = true
	config.Entities = append(config.Entities, EntityConfig{ID: "sister", Owner: "mail-team", Domains: []DomainConfig{{
		Name: "sister.example.test", Owner: "mail-team", Records: config.Entities[0].Domains[0].Records, ExpectedSenders: []string{"marketing"},
	}}})
	values := correlationHealthyDNSValues()
	values["sister.example.test"] = "v=spf1 -all"
	values["mk1._domainkey.sister.example.test"] = values["mk1._domainkey.example.test"]
	values["_dmarc.sister.example.test"] = values["_dmarc.example.test"]
	config.Entities[1].Domains[0].Records = MonitoredRecordsConfig{
		SPF: []string{"sister.example.test"}, DKIM: []string{"mk1._domainkey.sister.example.test"}, DMARC: []string{"_dmarc.sister.example.test"},
	}
	portfolio, health := correlationTestDNSHealth(t, config, values)
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "3", "sister.example.test", "pass", "fail", "sister.example.test", "mk1", "sister.example.test"),
		correlationTestRecord("192.0.2.11", "3", "child.example.test", "pass", "fail", "example.test", "mk1", "child.example.test"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range result.Streams() {
		switch stream.SourceIP {
		case "192.0.2.10":
			if stream.EntityID != "sister" || stream.Domain != "sister.example.test" || stream.InheritedScope {
				t.Fatalf("sister scope=%+v", stream)
			}
		case "192.0.2.11":
			if stream.EntityID != "corporate" || stream.Domain != "example.test" || !stream.InheritedScope {
				t.Fatalf("inherited scope=%+v", stream)
			}
		}
	}
	assertCorrelationClassification(t, result.Findings(), CorrelationNewSubdomain, "192.0.2.11")
}

func TestCorrelateReportEvidencePriorResultDetectsDriftAndRetiredSelector(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealthAt(t, config, correlationHealthyDNSValues(), time.Unix(300, 0))
	passing := correlationTestReport("prior", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "8", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	prior, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{passing}, time.Unix(200, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	failing := correlationTestReport("current", "receiver.example", 201, 250,
		correlationTestRecord("192.0.2.10", "8", "example.test", "fail", "fail", "example.test", "mk1", "example.test"),
	)
	current, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{failing}, time.Unix(250, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(301, 0), Previous: &prior})
	if err != nil {
		t.Fatal(err)
	}
	if current.PreviousDigest() != prior.Digest() {
		t.Fatalf("previous digest=%q want %q", current.PreviousDigest(), prior.Digest())
	}
	driftFinding := findCorrelationClassification(t, current.Findings(), CorrelationExpectedSenderBeganFailing, "192.0.2.10")
	if driftFinding.PreviousDigest != prior.Digest() {
		t.Fatalf("drift finding previous digest=%q", driftFinding.PreviousDigest)
	}
	unknownPassing := correlationTestReport("unknown-prior", "receiver.example", 100, 200,
		correlationTestRecord("198.51.100.20", "8", "example.test", "pass", "fail", "unknown.example", "rogue", "unknown.example"),
	)
	unknownPrior, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{unknownPassing}, time.Unix(200, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	unknownFailing := correlationTestReport("unknown-current", "receiver.example", 201, 250,
		correlationTestRecord("198.51.100.20", "8", "example.test", "fail", "fail", "unknown.example", "rogue", "unknown.example"),
	)
	unknownCurrent, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{unknownFailing}, time.Unix(250, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(301, 0), Previous: &unknownPrior})
	if err != nil {
		t.Fatal(err)
	}
	assertCorrelationClassification(t, unknownCurrent.Findings(), CorrelationUnknownSourceFailure, "198.51.100.20")
	if hasCorrelationClassification(unknownCurrent.Findings(), CorrelationExpectedSenderBeganFailing, "198.51.100.20") {
		t.Fatalf("unattributed stream was reported as expected-sender drift: %+v", unknownCurrent.Findings())
	}
	alreadyFailing := correlationTestReport("already-failing", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.30", "4", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
		correlationTestRecord("192.0.2.30", "4", "example.test", "fail", "fail", "example.test", "mk1", "example.test"),
	)
	alreadyFailingPrior, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{alreadyFailing}, time.Unix(200, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	stillFailing := correlationTestReport("still-failing", "receiver.example", 201, 250,
		correlationTestRecord("192.0.2.30", "8", "example.test", "fail", "fail", "example.test", "mk1", "example.test"),
	)
	stillFailingCurrent, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{stillFailing}, time.Unix(250, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(301, 0), Previous: &alreadyFailingPrior})
	if err != nil {
		t.Fatal(err)
	}
	if hasCorrelationClassification(stillFailingCurrent.Findings(), CorrelationExpectedSenderBeganFailing, "192.0.2.30") {
		t.Fatalf("previously failing stream was reported as newly failing: %+v", stillFailingCurrent.Findings())
	}
	newSourceReport := correlationTestReport("new-source", "receiver.example", 201, 250,
		correlationTestRecord("192.0.2.11", "8", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	newSource, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{newSourceReport}, time.Unix(250, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(301, 0), Previous: &prior})
	if err != nil {
		t.Fatal(err)
	}
	if finding := findCorrelationClassification(t, newSource.Findings(), CorrelationNewSource, "192.0.2.11"); finding.PreviousDigest != prior.Digest() {
		t.Fatalf("new-source finding previous digest=%q", finding.PreviousDigest)
	}
	priorWithoutSourceReport := correlationTestReport("prior-without-source", "receiver.example", 100, 200,
		correlationTestRecord("", "8", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	priorWithoutSource, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{priorWithoutSourceReport}, time.Unix(200, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	firstObservedSource, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{newSourceReport}, time.Unix(250, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(301, 0), Previous: &priorWithoutSource})
	if err != nil {
		t.Fatal(err)
	}
	assertCorrelationClassification(t, firstObservedSource.Findings(), CorrelationNewSource, "192.0.2.11")

	newConfig := correlationTestConfig(AuthenticationPolicyConfig{RequireDKIM: true, AllowedSelectors: []string{"mk2"}})
	newConfig.Entities[0].Domains[0].Records.DKIM = []string{"mk2._domainkey.example.test"}
	values := correlationHealthyDNSValues()
	values["mk2._domainkey.example.test"] = values["mk1._domainkey.example.test"]
	delete(values, "mk1._domainkey.example.test")
	newPortfolio, newHealth := correlationTestDNSHealthAt(t, newConfig, values, time.Unix(400, 0))
	retired, err := CorrelateReportEvidence(newPortfolio, newHealth, correlationTestEvidence(t, []*AggregateReport{failing}, time.Unix(250, 0)), DNSReportCorrelationOptions{GeneratedAt: time.Unix(400, 0), Previous: &prior})
	if err != nil {
		t.Fatal(err)
	}
	assertCorrelationClassification(t, retired.Findings(), CorrelationRetiredConfigurationObserved, "192.0.2.10")
}

func TestCorrelateReportEvidenceThresholdsAndConfiguredSelectorCoverage(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{RequireDKIM: true, AllowedSelectors: []string{"mk1", "mk2"}})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "10", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	evidence := correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0))
	below, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{Thresholds: DNSReportCorrelationThresholds{MinMessages: 11}})
	if err != nil {
		t.Fatal(err)
	}
	if below.Streams()[0].ThresholdEvaluation.State != EvaluationStateNotEvaluated || hasCorrelationClassification(below.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.10") {
		t.Fatalf("below-threshold stream was classified: streams=%+v findings=%+v", below.Streams(), below.Findings())
	}
	if hasCorrelationClassification(below.Findings(), CorrelationConfiguredSelectorNotSeen, "") {
		t.Fatalf("below-threshold corpus claimed selector absence: %+v", below.Findings())
	}
	atBoundary, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{Thresholds: DNSReportCorrelationThresholds{MinMessages: 10, MinReports: 1, MinReporters: 1, MinDuration: 100 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	if atBoundary.Streams()[0].ThresholdEvaluation.State != EvaluationStateEvaluated {
		t.Fatalf("boundary stream=%+v", atBoundary.Streams()[0])
	}
	selectorFinding := findCorrelationClassification(t, atBoundary.Findings(), CorrelationConfiguredSelectorNotSeen, "")
	if !slices.Equal(selectorFinding.DKIMSelectors, []string{"mk2"}) {
		t.Fatalf("not-observed selector finding=%+v", selectorFinding)
	}
}

func TestCorrelateReportEvidencePreservesDNSReportTemporalRelationships(t *testing.T) {
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "2", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	evidence := correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0))
	for _, test := range []struct {
		name       string
		observedAt time.Time
		want       DNSReportTemporalRelationship
	}{
		{name: "before", observedAt: time.Unix(50, 0), want: DNSReportDNSBeforeReports},
		{name: "during", observedAt: time.Unix(150, 0), want: DNSReportDNSDuringReports},
		{name: "after", observedAt: time.Unix(300, 0), want: DNSReportDNSAfterReports},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := correlationTestConfig(AuthenticationPolicyConfig{})
			portfolio, health := correlationTestDNSHealthAt(t, config, correlationHealthyDNSValues(), test.observedAt)
			result, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if result.DNSObservedAt() != test.observedAt.UTC() || result.Streams()[0].TemporalRelationship != test.want || result.Findings()[0].TemporalRelationship == DNSReportTimeUnknown {
				t.Fatalf("observed_at=%s stream=%+v findings=%+v", result.DNSObservedAt(), result.Streams(), result.Findings())
			}
		})
	}
}

func TestCorrelateReportEvidenceUsesDNSObservationNotHealthEvaluationTime(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Unix(50, 0).UTC()
	authentication := dnsHealthTestAuthenticationFromValues(t, portfolio, observedAt, nil, nil, correlationHealthyDNSValues())
	health, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{
		Profile:     DNSHealthProfileBalanced,
		GeneratedAt: time.Unix(300, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "1", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	evidence := correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0))
	result, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DNSObservedAt().Equal(observedAt) || result.Streams()[0].TemporalRelationship != DNSReportDNSBeforeReports {
		t.Fatalf("observed_at=%s health_generated_at=%s relationship=%s", result.DNSObservedAt(), health.ResultMetadata().GeneratedAt, result.Streams()[0].TemporalRelationship)
	}
}

func TestCorrelateReportEvidenceDeterministicImmutableAndNoHiddenDNS(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	reports := []*AggregateReport{
		correlationTestReport("r1", "receiver-a.example", 100, 200, correlationTestRecord("192.0.2.10", "2", "example.test", "pass", "fail", "example.test", "mk1", "example.test")),
		correlationTestReport("r2", "receiver-b.example", 201, 250, correlationTestRecord("198.51.100.20", "3", "example.test", "fail", "fail", "unknown.example", "rogue", "unknown.example")),
	}
	generatedAt := time.Unix(1000, 0).UTC()
	evidenceA := correlationTestEvidence(t, reports, time.Unix(250, 0))
	reversed := append([]*AggregateReport(nil), reports...)
	slices.Reverse(reversed)
	evidenceB := correlationTestEvidence(t, reversed, time.Unix(250, 0))

	originalResolver := net.DefaultResolver
	var dnsCalls atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("unexpected DNS access")
	}}
	t.Cleanup(func() { net.DefaultResolver = originalResolver })

	resultA, err := CorrelateReportEvidence(portfolio, health, evidenceA, DNSReportCorrelationOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := CorrelateReportEvidence(portfolio, health, evidenceB, DNSReportCorrelationOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if dnsCalls.Load() != 0 {
		t.Fatalf("correlation performed %d DNS calls", dnsCalls.Load())
	}
	if resultA.Digest() != resultB.Digest() || !slices.EqualFunc(resultA.Streams(), resultB.Streams(), func(a, b DNSReportCorrelationStream) bool { return a.ID == b.ID }) {
		t.Fatalf("input order changed result: %q vs %q", resultA.Digest(), resultB.Digest())
	}
	extendedConfig := correlationTestConfig(AuthenticationPolicyConfig{})
	extendedConfig.Entities = append(extendedConfig.Entities, EntityConfig{ID: "reference", Membership: PortfolioMembershipReference, Domains: []DomainConfig{{Name: "unrelated.test"}}})
	extendedPortfolio, extendedHealth := correlationTestDNSHealth(t, extendedConfig, correlationHealthyDNSValues())
	extendedResult, err := CorrelateReportEvidence(extendedPortfolio, extendedHealth, evidenceA, DNSReportCorrelationOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(resultA.Streams(), extendedResult.Streams(), func(a, b DNSReportCorrelationStream) bool { return a.ID == b.ID }) {
		t.Fatalf("unrelated portfolio scope changed existing stream IDs: %+v vs %+v", resultA.Streams(), extendedResult.Streams())
	}
	streams := resultA.Streams()
	streams[0].ExpectedSenderIDs = append(streams[0].ExpectedSenderIDs, "changed")
	findings := resultA.Findings()
	findings[0].ObservationIDs = nil
	inventory := resultA.Inventory()
	inventory[0].ExpectedSelectors = nil
	summary := resultA.Summary()
	summary.Classifications = nil
	if slices.Contains(resultA.Streams()[0].ExpectedSenderIDs, "changed") || len(resultA.Findings()[0].ObservationIDs) == 0 || len(resultA.Inventory()[0].ExpectedSelectors) == 0 || len(resultA.Summary().Classifications) == 0 {
		t.Fatal("accessor mutation changed immutable result")
	}
}

func TestCorrelateReportEvidenceRejectsInvalidInputsAndOptions(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "1", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	evidence := correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0))
	if _, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{Thresholds: DNSReportCorrelationThresholds{MinMessages: -1}}); !errors.Is(err, ErrInvalidDNSReportCorrelationOptions) {
		t.Fatalf("negative threshold error=%v", err)
	}
	if _, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{GeneratedAt: time.Unix(199, 0)}); !errors.Is(err, ErrInvalidDNSReportCorrelationOptions) {
		t.Fatalf("predating generated_at error=%v", err)
	}
	otherConfig := correlationTestConfig(AuthenticationPolicyConfig{})
	otherConfig.Organization.ID = "other"
	otherPortfolio, err := NormalizePortfolio(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CorrelateReportEvidence(otherPortfolio, health, evidence, DNSReportCorrelationOptions{}); !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("mismatched portfolio error=%v", err)
	}
	valid, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{GeneratedAt: valid.ResultMetadata().GeneratedAt.Add(-time.Second), Previous: &valid}); !errors.Is(err, ErrInvalidDNSReportCorrelationOptions) {
		t.Fatalf("future previous result error=%v", err)
	}
	otherHealthPortfolio, otherHealth := correlationTestDNSHealth(t, otherConfig, correlationHealthyDNSValues())
	otherValid, err := CorrelateReportEvidence(otherHealthPortfolio, otherHealth, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{Previous: &otherValid}); !errors.Is(err, ErrInvalidDNSReportCorrelationOptions) {
		t.Fatalf("cross-organization previous result error=%v", err)
	}
}

func TestDNSReportCorrelationResultImplementsResult(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	report := correlationTestReport("r1", "receiver.example", 100, 200,
		correlationTestRecord("192.0.2.10", "1", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
	)
	result, err := CorrelateReportEvidence(portfolio, health, correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0)), DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var shared Result = result
	if shared.ResultMetadata().Mode != AnalysisModeDNSReportCorrelation {
		t.Fatalf("metadata=%+v", shared.ResultMetadata())
	}
}

func TestPrivatePortfolioLiveDNSReportCorrelationCompatibility(t *testing.T) {
	if os.Getenv("DMARCGO_LIVE_DNS_TEST") != "1" {
		t.Skip("set DMARCGO_LIVE_DNS_TEST=1 to run bounded private live DNS/report correlation checks")
	}
	paths, err := filepath.Glob("test_dmarc_reports/*-records.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("private DNS record notes are not present")
	}
	reports := make([]*AggregateReport, 0)
	entries, err := os.ReadDir("test_dmarc_reports")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !privateCorrelationReportFilename(entry.Name()) {
			continue
		}
		report, loadErr := LoadFile(filepath.Join("test_dmarc_reports", entry.Name()))
		if loadErr != nil {
			t.Log("skipping one unreadable private report artifact")
			continue
		}
		reports = append(reports, report)
	}
	if len(reports) == 0 {
		t.Skip("private report corpus is not present")
	}
	evidence, err := AnalyzeReportEvidence(reports, ReportEvidenceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	catalog := dnsHealthTestCatalog(t)
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
		observedAt := time.Now().UTC()
		snapshot, err := CollectDNSSnapshot(t.Context(), portfolio, NetTXTResolver{Resolver: net.DefaultResolver, ResolverID: "private-correlation-calibration"}, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return observedAt }), MaxConcurrency: 4, MaxAttempts: 2,
			QueryTimeout: 5 * time.Second, RetryDelay: 100 * time.Millisecond, FailurePolicy: DNSFailureCollectAll,
		})
		if err != nil {
			t.Fatal(err)
		}
		authentication, err := ParseAuthenticationRecords(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		health, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{Profile: DNSHealthProfileBalanced})
		if err != nil {
			t.Fatal(err)
		}
		result, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Digest() == "" || len(result.Streams()) == 0 || result.Summary().Messages != evidence.Summary().Messages {
			t.Fatalf("private correlation produced incomplete result: streams=%d findings=%d", len(result.Streams()), len(result.Findings()))
		}
		codes := map[DNSReportCorrelationClassification]int{}
		for _, finding := range result.Findings() {
			codes[finding.Classification]++
		}
		t.Logf("private correlation reports=%d streams=%d findings=%d classifications=%v", evidence.Summary().Reports, len(result.Streams()), len(result.Findings()), codes)
	}
}

func privateCorrelationReportFilename(name string) bool {
	name = strings.ToLower(name)
	for _, suffix := range []string{".xml", ".xml.gz", ".gz", ".zip", ".tar", ".tar.gz", ".tgz", ".zlib", ".zz"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func BenchmarkCorrelateReportEvidence(b *testing.B) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	portfolio, health := correlationTestDNSHealth(b, config, correlationHealthyDNSValues())
	reports := make([]*AggregateReport, 0, 200)
	for index := 0; index < 200; index++ {
		report := correlationTestReport("benchmark-"+itoa(index), "receiver.example", int64(100+index), int64(200+index),
			correlationTestRecord("192.0.2.10", "10", "example.test", "fail", "fail", "example.test", "mk1", "example.test"),
		)
		reports = append(reports, report)
	}
	evidence := correlationTestEvidence(b, reports, time.Unix(1000, 0))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{GeneratedAt: time.Unix(2000, 0)}); err != nil {
			b.Fatal(err)
		}
	}
}

func correlationTestConfig(policy AuthenticationPolicyConfig) PortfolioConfig {
	if !policy.RequireDKIM && !policy.RequireSPF && !policy.RequireEither {
		policy.RequireDKIM = true
		policy.AllowedSelectors = []string{"mk1"}
	}
	return PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example-group", Owner: "mail-team"},
		Owners:        []OwnerConfig{{ID: "mail-team"}},
		ExpectedSenders: []ExpectedSenderConfig{{
			ID: "marketing", Provider: "", RequireDKIM: policy.RequireDKIM, RequireSPF: policy.RequireSPF, RequireEither: policy.RequireEither, AllowedSelectors: policy.AllowedSelectors,
		}},
		Entities: []EntityConfig{{ID: "corporate", Owner: "mail-team", Domains: []DomainConfig{{
			Name: "example.test", Owner: "mail-team", Records: MonitoredRecordsConfig{
				SPF: []string{"example.test"}, DKIM: []string{"mk1._domainkey.example.test"}, DMARC: []string{"_dmarc.example.test"},
			}, ExpectedSenders: []string{"marketing"},
		}}}},
	}
}

func correlationHealthyDNSValues() map[string]string {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return map[string]string{
		"example.test":                "v=spf1 -all",
		"mk1._domainkey.example.test": "v=DKIM1; k=ed25519; p=" + key,
		"_dmarc.example.test":         "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:reports@example.test",
	}
}

func correlationTestDNSHealth(t testing.TB, config PortfolioConfig, values map[string]string) (Portfolio, DNSHealthResult) {
	return correlationTestDNSHealthAt(t, config, values, time.Unix(1000, 0).UTC())
}

func correlationTestDNSHealthAt(t testing.TB, config PortfolioConfig, values map[string]string, observedAt time.Time) (Portfolio, DNSHealthResult) {
	t.Helper()
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	authentication := dnsHealthTestAuthenticationFromValues(t, portfolio, observedAt, nil, nil, values)
	catalog := dnsHealthTestCatalog(t)
	health, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{Profile: DNSHealthProfileBalanced})
	if err != nil {
		t.Fatal(err)
	}
	return portfolio, health
}

func correlationTestEvidence(t testing.TB, reports []*AggregateReport, generatedAt time.Time) ReportEvidenceResult {
	t.Helper()
	result, err := AnalyzeReportEvidence(reports, ReportEvidenceOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func correlationTestReport(id, reporter string, begin, end int64, records ...Record) *AggregateReport {
	return &AggregateReport{
		ReportMetadata:  ReportMetadata{OrgName: reporter, Email: "reports@receiver.example", ReportID: id, DateRange: DateRange{Begin: itoa64(begin), End: itoa64(end)}},
		PolicyPublished: PolicyPublished{Domain: "example.test", P: "reject"}, Record: records,
	}
}

func correlationTestRecord(sourceIP, count, authorDomain, dkimOutcome, spfOutcome, dkimDomain, selector, spfDomain string) Record {
	value := Record{
		Row:         Row{SourceIP: sourceIP, Count: count, PolicyEvaluated: PolicyEvaluated{Disposition: "none", DKIM: dkimOutcome, SPF: spfOutcome}},
		Identifiers: Identifiers{HeaderFrom: authorDomain}, AuthResults: AuthResults{},
	}
	if dkimDomain != "" || selector != "" {
		value.AuthResults.DKIM = []DKIMAuthResult{{Domain: dkimDomain, Selector: selector, Result: dkimOutcome}}
	}
	if spfDomain != "" {
		value.AuthResults.SPF = &SPFAuthResult{Domain: spfDomain, Scope: "mfrom", Result: spfOutcome}
	}
	return value
}

func itoa64(value int64) string { return strconv.FormatInt(value, 10) }

func assertCorrelationClassification(t testing.TB, findings []DNSReportCorrelationFinding, classification DNSReportCorrelationClassification, sourceIP string) {
	t.Helper()
	_ = findCorrelationClassification(t, findings, classification, sourceIP)
}

func findCorrelationClassification(t testing.TB, findings []DNSReportCorrelationFinding, classification DNSReportCorrelationClassification, sourceIP string) DNSReportCorrelationFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.Classification == classification && (sourceIP == "" || slices.Contains(finding.SourceIPs, sourceIP)) {
			return finding
		}
	}
	t.Fatalf("classification %q source %q not found in %+v", classification, sourceIP, findings)
	return DNSReportCorrelationFinding{}
}

func hasCorrelationClassification(findings []DNSReportCorrelationFinding, classification DNSReportCorrelationClassification, sourceIP string) bool {
	for _, finding := range findings {
		if finding.Classification == classification && (sourceIP == "" || slices.Contains(finding.SourceIPs, sourceIP)) {
			return true
		}
	}
	return false
}
