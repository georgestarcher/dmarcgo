package dmarcgo

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestEvaluateDNSHealthDeterministicRollupsAndFindings(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	observedAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	authentication := dnsHealthTestAuthentication(t, portfolio, observedAt, nil)
	options := DNSHealthOptions{Profile: DNSHealthProfileBalanced, GeneratedAt: observedAt.Add(time.Hour)}

	first, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), options)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() || !reflect.DeepEqual(first, second) {
		t.Fatal("identical inputs must produce identical DNS health results")
	}
	metadata := first.ResultMetadata()
	if metadata.Mode != AnalysisModeDNSHealth || !metadata.GeneratedAt.Equal(options.GeneratedAt) || metadata.Evaluation.State != EvaluationStateEvaluated {
		t.Fatalf("metadata=%+v", metadata)
	}
	if first.PortfolioDigest() != portfolio.Digest() || first.AuthenticationDigest() != authentication.Digest() || first.SnapshotDigest() != authentication.SnapshotDigest() {
		t.Fatal("result provenance digests do not match inputs")
	}
	if len(first.Entities()) != 2 || len(first.Domains()) != 3 {
		t.Fatalf("entities=%d domains=%d", len(first.Entities()), len(first.Domains()))
	}
	for _, code := range []FindingCode{
		"dns.health.spf_non_enforcing_all",
		"dns.health.dmarc_monitoring_only",
		"dns.health.dmarc_child_policy_weaker",
		"dns.health.rollup_degraded",
	} {
		if !hasDNSHealthFinding(first.Findings(), code) {
			t.Fatalf("missing finding %q in %+v", code, first.Findings())
		}
	}
	for _, scope := range []DNSHealthScope{DNSHealthScopeRecord, DNSHealthScopeDomain, DNSHealthScopeEntity, DNSHealthScopePortfolio} {
		if !hasDNSHealthScope(first.Findings(), scope) {
			t.Fatalf("missing %q scope finding", scope)
		}
	}
	if score := first.PortfolioScore(); !score.Available || score.Value <= 0 || score.Value >= score.Maximum {
		t.Fatalf("portfolio score=%+v", score)
	}
	dmarc := findDNSRecordHealth(t, first.Records(), "_dmarc.marketing.example.test", DNSRecordDMARC, "corporate")
	if dmarc.Score.Value != 70 {
		t.Fatalf("balanced monitoring-only DMARC score=%d want=70 contributions=%+v", dmarc.Score.Value, dmarc.Score.Contributions)
	}
}

func TestEvaluateDNSHealthSharedRecordRetainsEveryScope(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var shared []DNSRecordHealth
	for _, record := range result.Records() {
		if record.Name == "shared._domainkey.shared-mail.example.test" {
			shared = append(shared, record)
		}
	}
	if len(shared) != 3 {
		t.Fatalf("shared record scopes=%d records=%+v", len(shared), shared)
	}
	ids := map[AnalysisID]bool{}
	for _, record := range shared {
		ids[record.ID] = true
		if len(record.EvidenceIDs) != 1 || record.EvidenceIDs[0] != shared[0].EvidenceIDs[0] {
			t.Fatalf("shared evidence not preserved: %+v", shared)
		}
	}
	if len(ids) != 3 {
		t.Fatalf("scope IDs collided: %+v", shared)
	}
}

func TestEvaluateDNSHealthUnknownEvidencePolicy(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	overrides := map[string]DNSObservationStatus{"sister.example.test": DNSObservationTimeout}
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, overrides)

	preserved, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	record := findDNSRecordHealth(t, preserved.Records(), "sister.example.test", DNSRecordSPF, "sister")
	if record.Score.Available || record.Score.Evaluation.State != EvaluationStateUnknown {
		t.Fatalf("preserved unknown score=%+v", record.Score)
	}
	penalized, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{UnknownPolicy: DNSHealthUnknownPenalize})
	if err != nil {
		t.Fatal(err)
	}
	record = findDNSRecordHealth(t, penalized.Records(), "sister.example.test", DNSRecordSPF, "sister")
	if !record.Score.Available || record.Score.Value != 90 || len(record.Score.Contributions) != 1 {
		t.Fatalf("penalized unknown score=%+v", record.Score)
	}
	if !hasDNSHealthFinding(preserved.Findings(), "dns.health.evidence_unknown") {
		t.Fatal("unknown evidence finding missing")
	}
}

func TestEvaluateDNSHealthProfilesStalenessAndExactContributions(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	conservative, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{
		Profile: DNSHealthProfileConservative, GeneratedAt: dnsHealthTestTime.Add(48 * time.Hour), MaxSnapshotAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	sensitive, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{
		Profile: DNSHealthProfileSensitive, GeneratedAt: dnsHealthTestTime.Add(48 * time.Hour), MaxSnapshotAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDNSHealthFinding(sensitive.Findings(), "dns.health.snapshot_stale") {
		t.Fatal("stale snapshot finding missing")
	}
	if sensitive.PortfolioScore().Value >= conservative.PortfolioScore().Value {
		t.Fatalf("sensitive=%d conservative=%d", sensitive.PortfolioScore().Value, conservative.PortfolioScore().Value)
	}
	spf := findDNSRecordHealth(t, sensitive.Records(), "marketing.example.test", DNSRecordSPF, "corporate")
	if !scoreHasContribution(spf.Score, "dns.health.spf_non_enforcing_all") {
		t.Fatalf("SPF score lacks explanation: %+v", spf.Score)
	}
	if got := recomputeDNSHealthScore(spf.Score); got != spf.Score.Value {
		t.Fatalf("recomputed score=%d want=%d contributions=%+v", got, spf.Score.Value, spf.Score.Contributions)
	}
}

func TestEvaluateDNSHealthPreservesOptionalDNSSECEvidence(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthenticationEvidence(t, portfolio, dnsHealthTestTime, nil, map[string]DNSSECEvidence{
		"_dmarc.example.test": {Available: true, AuthenticatedData: false},
	})
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	record := findDNSRecordHealth(t, result.Records(), "_dmarc.example.test", DNSRecordDMARC, "corporate")
	if !record.DNSSEC.Available || record.DNSSEC.AuthenticatedData || !hasDNSHealthFinding(result.Findings(), "dns.health.dnssec_not_authenticated") {
		t.Fatalf("record=%+v findings=%+v", record, result.Findings())
	}
}

func TestEvaluateDNSHealthMissingSelectorAndUnmonitoredPolicy(t *testing.T) {
	config := dnsHealthTestConfig()
	config.Entities[0].Domains[0].Records.DKIM = nil
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDNSHealthFinding(result.Findings(), "dns.health.dkim_required_not_monitored") ||
		!hasDNSHealthFinding(result.Findings(), "dns.health.dkim_required_selector_unmonitored") {
		t.Fatalf("selector configuration findings missing: %+v", result.Findings())
	}
	domain := findDNSDomainHealth(t, result.Domains(), "example.test", "corporate")
	if countDNSHealthScoreContributions(domain.Score, "dns.health.dkim_required_not_monitored", "dns.health.dkim_required_selector_unmonitored") != 1 {
		t.Fatalf("missing DKIM configuration was charged more than once: %+v", domain.Score.Contributions)
	}
}

func TestEvaluateDNSHealthWeakClassificationDoesNotDuplicateSpecificDeduction(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	values := dnsHealthTestRecordValues()
	values["_dmarc.marketing.example.test"] += "; t=y"
	authentication := dnsHealthTestAuthenticationFromValues(t, portfolio, dnsHealthTestTime, nil, nil, values)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dmarc := findDNSRecordHealth(t, result.Records(), "_dmarc.marketing.example.test", DNSRecordDMARC, "corporate")
	if !hasDNSHealthFinding(dnsHealthFindingsByID(result.Findings(), dmarc.FindingIDs), "dns.health.record_weak") ||
		!scoreHasContribution(dmarc.Score, "dns.health.dmarc_testing") {
		t.Fatalf("weak classification or specific contribution missing: record=%+v findings=%+v", dmarc, result.Findings())
	}
	if scoreHasContribution(dmarc.Score, "dns.health.record_weak") {
		t.Fatalf("generic weak classification duplicated a specific deduction: %+v", dmarc.Score.Contributions)
	}
}

func TestEvaluateDNSHealthBalancedMissingComponentScores(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, map[string]DNSObservationStatus{
		"example.test": DNSObservationNXDOMAIN,
		"shared._domainkey.shared-mail.example.test": DNSObservationNoData,
		"_dmarc.example.test":                        DNSObservationNXDOMAIN,
	})
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := findDNSRecordHealth(t, result.Records(), "example.test", DNSRecordSPF, "corporate").Score.Value; got != 0 {
		t.Fatalf("missing SPF score=%d want=0", got)
	}
	if got := findDNSRecordHealth(t, result.Records(), "shared._domainkey.shared-mail.example.test", DNSRecordDKIM, "corporate").Score.Value; got != 0 {
		t.Fatalf("missing DKIM score=%d want=0", got)
	}
	if got := findDNSRecordHealth(t, result.Records(), "_dmarc.example.test", DNSRecordDMARC, "corporate").Score.Value; got != 30 {
		t.Fatalf("missing DMARC score=%d want=30", got)
	}
}

func TestDNSHealthMaturityScaleAndManagedEvidenceBoundary(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	example := findDNSDomainHealth(t, result.Domains(), "example.test", "corporate")
	marketing := findDNSDomainHealth(t, result.Domains(), "marketing.example.test", "corporate")
	if example.Maturity.Level != DNSHealthMaturityEnforced || marketing.Maturity.Level != DNSHealthMaturityMonitored {
		t.Fatalf("example maturity=%+v marketing maturity=%+v", example.Maturity, marketing.Maturity)
	}
	if example.Maturity.MaximumObservableLevel != DNSHealthMaturityEnforced || !maturitySignalSatisfied(example.Maturity, "dns.maturity.managed_dns_ready") {
		t.Fatalf("managed readiness=%+v", example.Maturity)
	}
	if signal := findDNSHealthMaturitySignal(t, example.Maturity, "dns.maturity.report_handling_verified"); signal.Evaluation.State != EvaluationStateUnknown || signal.Satisfied {
		t.Fatalf("report-handling signal=%+v", signal)
	}
	portfolioMaturity := result.PortfolioMaturity()
	if portfolioMaturity.Level != DNSHealthMaturityMonitored || portfolioMaturity.Distribution.Monitored != 1 || portfolioMaturity.Distribution.Enforced != 2 {
		t.Fatalf("portfolio maturity=%+v", portfolioMaturity)
	}
}

func TestDNSHealthSPFOnlyBaselineSeparatesHealthCoverageAndMaturity(t *testing.T) {
	config := PortfolioConfig{
		SchemaVersion:   PortfolioSchemaVersion,
		Organization:    OrganizationConfig{ID: "spf-only"},
		ExpectedSenders: []ExpectedSenderConfig{{ID: "hosted", RequireSPF: true}},
		Entities: []EntityConfig{{ID: "primary", Domains: []DomainConfig{{
			Name: "brown.example.test", Records: MonitoredRecordsConfig{SPF: []string{"brown.example.test"}, DMARC: []string{"_dmarc.brown.example.test"}},
			ExpectedSenders: []string{"hosted"},
		}}}},
	}
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	authentication := dnsHealthTestAuthenticationFromValues(t, portfolio, dnsHealthTestTime, nil, nil, map[string]string{
		"brown.example.test": "v=spf1 -all",
	})
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	domain := findDNSDomainHealth(t, result.Domains(), "brown.example.test", "primary")
	if domain.Mechanisms.SPF.Value != 100 || domain.Mechanisms.SPF.Grade != DNSHealthGradeAPlus {
		t.Fatalf("SPF component=%+v", domain.Mechanisms.SPF)
	}
	if domain.Mechanisms.DKIM.Available || domain.Mechanisms.DKIM.Grade != DNSHealthGradeUnknown {
		t.Fatalf("DKIM component=%+v", domain.Mechanisms.DKIM)
	}
	if domain.Mechanisms.DMARC.Value != 30 || domain.Mechanisms.DMARC.Grade != DNSHealthGradeF || domain.Score.Value != 62 || domain.Score.Grade != DNSHealthGradeD {
		t.Fatalf("DMARC=%+v overall=%+v", domain.Mechanisms.DMARC, domain.Score)
	}
	if domain.Maturity.Level != DNSHealthMaturityBasic || domain.Maturity.Coverage.Percent != 100 {
		t.Fatalf("maturity=%+v", domain.Maturity)
	}
}

func TestDNSHealthReferenceEntityIsExcludedFromPortfolioRollups(t *testing.T) {
	config := dnsHealthTestConfig()
	config.Entities[1].Membership = PortfolioMembershipReference
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	entity := findDNSEntityHealth(t, result.Entities(), "sister")
	if entity.PortfolioIncluded || entity.PortfolioEvaluation.State != EvaluationStateNotApplicable {
		t.Fatalf("reference entity=%+v", entity)
	}
	distribution := result.PortfolioMaturity().Distribution
	if distribution.Monitored != 1 || distribution.Enforced != 1 {
		t.Fatalf("portfolio distribution includes reference entity: %+v", distribution)
	}
}

func TestDNSHealthCurrentPracticeDeductions(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	values := dnsHealthTestRecordValues()
	values["marketing.example.test"] = "v=spf1 ?all"
	values["_dmarc.marketing.example.test"] = "v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:reports@example.test"
	authentication := dnsHealthTestAuthenticationFromValues(t, portfolio, dnsHealthTestTime, nil, nil, values)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	spf := findDNSRecordHealth(t, result.Records(), "marketing.example.test", DNSRecordSPF, "corporate")
	dmarc := findDNSRecordHealth(t, result.Records(), "_dmarc.marketing.example.test", DNSRecordDMARC, "corporate")
	if spf.Score.Value != 70 || !scoreHasContribution(spf.Score, "dns.health.spf_neutral_all") {
		t.Fatalf("neutral SPF=%+v", spf.Score)
	}
	if dmarc.Score.Value != 88 || !scoreHasContribution(dmarc.Score, "dns.health.dmarc_quarantine") {
		t.Fatalf("quarantine DMARC=%+v", dmarc.Score)
	}
}

func TestEvaluateDNSHealthRejectsMismatchedAndInvalidOptions(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	otherConfig := dnsHealthTestConfig()
	otherConfig.Organization.ID = "other"
	other, err := NormalizePortfolio(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateDNSHealth(other, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{}); !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("mismatch error=%v", err)
	}
	if _, err := EvaluateDNSHealth(portfolio, authentication, ProviderCatalog{}, DNSHealthOptions{}); !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("empty provider catalog error=%v", err)
	}
	for _, options := range []DNSHealthOptions{
		{Profile: "future"},
		{UnknownPolicy: "future"},
		{MaxSnapshotAge: -time.Second},
		{GeneratedAt: dnsHealthTestTime.Add(-time.Second)},
	} {
		if _, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), options); !errors.Is(err, ErrInvalidDNSHealthOptions) {
			t.Fatalf("options=%+v error=%v", options, err)
		}
	}
}

func TestEvaluateDNSHealthProviderContextIsExactScopeAndScoreNeutral(t *testing.T) {
	config := dnsHealthTestConfig()
	config.ExpectedSenders[0].Provider = "google-apps"
	config.ExpectedSenders = append(config.ExpectedSenders, ExpectedSenderConfig{ID: "other", RequireSPF: true})
	config.Entities[1].Domains[0].ExpectedSenders = []string{"other"}
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	values := dnsHealthTestRecordValues()
	values["example.test"] = "v=spf1 include:_spf.google.com -all"
	values["marketing.example.test"] = "v=spf1 include:sender.unknown.example -all"
	values["sister.example.test"] = "v=spf1 include:_spf.google.com +all"
	authentication := dnsHealthTestAuthenticationFromValues(t, portfolio, dnsHealthTestTime, nil, nil, values)

	catalog := dnsHealthTestCatalog(t)
	withContext, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if withContext.ProviderCatalogDigest() != catalog.Digest() || withContext.ProviderCatalogProvenance().Digest != catalog.Digest() {
		t.Fatal("provider catalog provenance does not identify the evaluation input")
	}
	contexts := withContext.ProviderContexts()
	if len(contexts) != 3 {
		t.Fatalf("provider contexts=%+v", contexts)
	}
	declared := findDNSHealthProviderContext(t, contexts, "example.test", "google-workspace")
	if declared.InventoryState != DNSProviderInventoryDeclared || !reflect.DeepEqual(declared.ExpectedSenderIDs, []string{"workspace"}) || !declared.Provider.ContextOnly {
		t.Fatalf("declared provider context=%+v", declared)
	}
	notDeclared := findDNSHealthProviderContext(t, contexts, "sister.example.test", "google-workspace")
	if notDeclared.InventoryState != DNSProviderInventoryNotDeclared || len(notDeclared.ExpectedSenderIDs) != 0 {
		t.Fatalf("exact-domain provider inventory=%+v", notDeclared)
	}
	for _, context := range contexts {
		if context.Domain == "sister.example.test" && context.InventoryState != DNSProviderInventoryNotDeclared {
			t.Fatalf("inherited record changed exact-domain provider inventory: %+v", context)
		}
	}
	sisterSPF := findDNSRecordHealth(t, withContext.Records(), "sister.example.test", DNSRecordSPF, "sister")
	if !scoreHasContribution(sisterSPF.Score, "dns.health.spf_permissive_all") {
		t.Fatalf("provider recognition repaired weak SPF: %+v", sisterSPF.Score)
	}

	unrelatedCatalog, err := NormalizeProviderCatalog(providerCatalogConfig())
	if err != nil {
		t.Fatal(err)
	}
	withoutContext, err := EvaluateDNSHealth(portfolio, authentication, unrelatedCatalog, DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutContext.ProviderContexts()) != 0 {
		t.Fatalf("unrelated catalog produced contexts=%+v", withoutContext.ProviderContexts())
	}
	if !reflect.DeepEqual(withContext.PortfolioScore(), withoutContext.PortfolioScore()) ||
		!reflect.DeepEqual(withContext.Records(), withoutContext.Records()) ||
		!reflect.DeepEqual(withContext.Findings(), withoutContext.Findings()) {
		t.Fatal("provider recognition changed DNS health findings or scores")
	}

	contexts[0].ExpectedSenderIDs[0] = "changed"
	if reflect.DeepEqual(contexts, withContext.ProviderContexts()) {
		t.Fatal("mutating provider contexts changed completed DNS health data")
	}
}

func TestDNSHealthAccessorsReturnDefensiveCopies(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	records := result.Records()
	findings := result.Findings()
	entities := result.Entities()
	score := result.PortfolioScore()
	records[0].EvidenceIDs = append(records[0].EvidenceIDs, "changed")
	findings[0].EvidenceIDs = append(findings[0].EvidenceIDs, "changed")
	entities[0].DomainIDs[0] = "changed"
	if len(score.Contributions) > 0 {
		score.Contributions[0].FindingIDs = append(score.Contributions[0].FindingIDs, "changed")
	}
	if reflect.DeepEqual(records, result.Records()) || reflect.DeepEqual(findings, result.Findings()) || reflect.DeepEqual(entities, result.Entities()) || reflect.DeepEqual(score, result.PortfolioScore()) {
		t.Fatal("mutating accessor results changed or aliased completed DNS health data")
	}
}

func TestDNSHealthImplementationHasNoCollectionOrReportBoundary(t *testing.T) {
	for _, filename := range []string{"dns_health.go", "dns_maturity.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if path == "os" || path == "net" || strings.HasPrefix(path, "net/") {
				t.Fatalf("DNS health imports forbidden side-effect package %q", path)
			}
		}
		forbidden := map[string]bool{
			"CollectDNSSnapshot": true, "LookupTXT": true, "LoadFile": true, "LoadBytes": true, "LoadReader": true,
			"ParseBytes": true, "ParseReader": true, "Summary": true, "Rows": true, "ParseAuthenticationRecords": true,
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if forbidden[name] {
				t.Errorf("DNS health calls forbidden collection, parsing, or report function %s", name)
			}
			return true
		})
	}
}

func TestDNSHealthScoringProfilesAreStableAndInspectable(t *testing.T) {
	profiles := DNSHealthScoringProfiles()
	if len(profiles) != 3 || profiles[0].Name != DNSHealthProfileConservative || profiles[1].Name != DNSHealthProfileBalanced || profiles[2].Name != DNSHealthProfileSensitive {
		t.Fatalf("profiles=%+v", profiles)
	}
	for _, profile := range profiles {
		if profile.Version != DNSHealthScoringVersion || profile.MaximumScore != 100 || profile.InvalidRecord <= 0 {
			t.Fatalf("profile=%+v", profile)
		}
		if profile.Name == DNSHealthProfileBalanced && (profile.DKIMWeakKey != 15 || profile.DMARCNoAggregateReporting != 10 || profile.DMARCQuarantine != 12 || profile.SPFSoftFailAll != 10 || profile.SPFNeutralAll != 30) {
			t.Fatalf("balanced published-practice deductions=%+v", profile)
		}
		if got, ok := DNSHealthScoringProfileForName(profile.Name); !ok || got != profile {
			t.Fatalf("profile lookup=%+v ok=%v", got, ok)
		}
	}
}

func TestDNSAuthenticationResultPreservesPortfolioProvenance(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	if authentication.PortfolioDigest() != portfolio.Digest() {
		t.Fatalf("portfolio digest=%q want=%q", authentication.PortfolioDigest(), portfolio.Digest())
	}
}

func BenchmarkEvaluateDNSHealthLargePortfolio(b *testing.B) {
	data, err := os.ReadFile("testdata/portfolio/large-synthetic.yaml")
	if err != nil {
		b.Fatal(err)
	}
	portfolio, err := LoadPortfolioYAML(data)
	if err != nil {
		b.Fatal(err)
	}
	authentication := dnsHealthTestAuthentication(b, portfolio, dnsHealthTestTime, nil)
	catalog := dnsHealthTestCatalog(b)
	b.ReportAllocs()
	for range b.N {
		if _, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestPrivatePortfolioLiveDNSHealthCompatibility(t *testing.T) {
	if os.Getenv("DMARCGO_LIVE_DNS_TEST") != "1" {
		t.Skip("set DMARCGO_LIVE_DNS_TEST=1 to run bounded private live DNS health checks")
	}
	paths := []string{}
	if path := os.Getenv("DMARCGO_LIVE_DNS_PORTFOLIO"); path != "" {
		paths = append(paths, path)
	} else {
		var err error
		paths, err = filepath.Glob("test_dmarc_reports/*-records.yaml")
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(paths) == 0 {
		t.Skip("private DNS record notes are not present")
	}
	catalog := dnsHealthTestCatalog(t)
	for portfolioIndex, path := range paths {
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
		snapshot, err := CollectDNSSnapshot(t.Context(), portfolio, NetTXTResolver{
			Resolver: net.DefaultResolver, ResolverID: "private-live-calibration",
		}, DNSCollectionOptions{
			Clock: ClockFunc(func() time.Time { return dnsHealthTestTime }), MaxConcurrency: 4, MaxAttempts: 2,
			QueryTimeout: 5 * time.Second, RetryDelay: 100 * time.Millisecond, FailurePolicy: DNSFailureCollectAll,
		})
		if err != nil {
			t.Fatal(err)
		}
		authentication, err := ParseAuthenticationRecords(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range []DNSHealthProfileName{DNSHealthProfileConservative, DNSHealthProfileBalanced, DNSHealthProfileSensitive} {
			result, err := EvaluateDNSHealth(portfolio, authentication, catalog, DNSHealthOptions{Profile: profile})
			if err != nil {
				t.Fatal(err)
			}
			codes := map[FindingCode]int{}
			for _, finding := range result.Findings() {
				if finding.Scope == DNSHealthScopeRecord || finding.Scope == DNSHealthScopeDomain {
					codes[finding.Code]++
				}
			}
			t.Logf("private portfolio %d profile=%s score_available=%v score=%d records=%d domains=%d finding_codes=%v",
				portfolioIndex+1, profile, result.PortfolioScore().Available, result.PortfolioScore().Value, len(result.Records()), len(result.Domains()), codes)
		}
	}
}

const dnsHealthTestTimeString = "2026-07-12T12:00:00Z"

var dnsHealthTestTime = mustDNSHealthTestTime()

func mustDNSHealthTestTime() time.Time {
	value, err := time.Parse(time.RFC3339, dnsHealthTestTimeString)
	if err != nil {
		panic(err)
	}
	return value
}

func dnsHealthTestPortfolio(t testing.TB) Portfolio {
	t.Helper()
	portfolio, err := NormalizePortfolio(dnsHealthTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	return portfolio
}

func dnsHealthTestCatalog(t testing.TB) ProviderCatalog {
	t.Helper()
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func dnsHealthTestConfig() PortfolioConfig {
	return PortfolioConfig{
		SchemaVersion:   PortfolioSchemaVersion,
		Organization:    OrganizationConfig{ID: "example-group", Owner: "mail-team"},
		Owners:          []OwnerConfig{{ID: "mail-team"}},
		ExpectedSenders: []ExpectedSenderConfig{{ID: "workspace", RequireDKIM: true, AllowedSelectors: []string{"shared"}}},
		Entities: []EntityConfig{
			{ID: "corporate", Owner: "mail-team", Domains: []DomainConfig{
				{Name: "example.test", Records: MonitoredRecordsConfig{
					SPF: []string{"example.test"}, DKIM: []string{"shared._domainkey.shared-mail.example.test"}, DMARC: []string{"_dmarc.example.test"},
				}, ExpectedSenders: []string{"workspace"}},
				{Name: "marketing.example.test", Parent: "example.test", Records: MonitoredRecordsConfig{
					SPF: []string{"marketing.example.test"}, DMARC: []string{"_dmarc.marketing.example.test"},
				}},
			}},
			{ID: "sister", Owner: "mail-team", Domains: []DomainConfig{
				{Name: "sister.example.test", Records: MonitoredRecordsConfig{
					SPF: []string{"sister.example.test"}, DKIM: []string{"shared._domainkey.shared-mail.example.test"}, DMARC: []string{"_dmarc.sister.example.test"},
				}, ExpectedSenders: []string{"workspace"}},
			}},
		},
	}
}

func dnsHealthTestAuthentication(t testing.TB, portfolio Portfolio, observedAt time.Time, overrides map[string]DNSObservationStatus) DNSAuthenticationResult {
	return dnsHealthTestAuthenticationEvidence(t, portfolio, observedAt, overrides, nil)
}

func dnsHealthTestAuthenticationEvidence(t testing.TB, portfolio Portfolio, observedAt time.Time, overrides map[string]DNSObservationStatus, dnssec map[string]DNSSECEvidence) DNSAuthenticationResult {
	t.Helper()
	return dnsHealthTestAuthenticationFromValues(t, portfolio, observedAt, overrides, dnssec, dnsHealthTestRecordValues())
}

func dnsHealthTestRecordValues() map[string]string {
	ed25519Key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return map[string]string{
		"example.test":                               "v=spf1 -all",
		"marketing.example.test":                     "v=spf1 ~all",
		"sister.example.test":                        "v=spf1 -all",
		"shared._domainkey.shared-mail.example.test": "v=DKIM1; k=ed25519; p=" + ed25519Key,
		"_dmarc.example.test":                        "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:reports@example.test",
		"_dmarc.marketing.example.test":              "v=DMARC1; p=none; rua=mailto:reports@example.test",
		"_dmarc.sister.example.test":                 "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:reports@example.test",
	}
}

func dnsHealthTestAuthenticationFromValues(t testing.TB, portfolio Portfolio, observedAt time.Time, overrides map[string]DNSObservationStatus, dnssec map[string]DNSSECEvidence, values map[string]string) DNSAuthenticationResult {
	t.Helper()
	plan := buildDNSQueryPlan(portfolio)
	observations := make([]DNSObservation, 0, len(plan))
	for _, query := range plan {
		status := DNSObservationSuccess
		if override, ok := overrides[query.name]; ok {
			status = override
		}
		observation := DNSObservation{
			Name: query.name, References: cloneDNSReferences(query.references), Status: status,
			Records: []TXTRecord{}, TTL: DNSDurationEvidence{Available: true, Seconds: 300}, CNAMEPath: []string{},
			AnswerSource: DNSAnswerSourceAuthoritative, RCode: DNSRCodeEvidence{Available: true}, Attempts: 1,
		}
		if evidence, ok := dnssec[query.name]; ok {
			observation.DNSSEC = evidence
		}
		if status == DNSObservationSuccess {
			value, ok := values[query.name]
			if ok {
				observation.Records = []TXTRecord{{Fragments: []string{value}, FragmentsAvailable: true, Joined: value, TTL: observation.TTL}}
			}
		}
		observations = append(observations, observation)
	}
	snapshot := newDNSSnapshot(observedAt, portfolio.Digest(), observations, []DNSCollectionDiagnostic{})
	authentication, err := ParseAuthenticationRecords(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return authentication
}

func hasDNSHealthFinding(findings []DNSHealthFinding, code FindingCode) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func hasDNSHealthScope(findings []DNSHealthFinding, scope DNSHealthScope) bool {
	for _, finding := range findings {
		if finding.Scope == scope {
			return true
		}
	}
	return false
}

func findDNSRecordHealth(t testing.TB, records []DNSRecordHealth, name string, recordType DNSRecordType, entityID string) DNSRecordHealth {
	t.Helper()
	for _, record := range records {
		if record.Name == name && record.Type == recordType && record.EntityID == entityID {
			return record
		}
	}
	t.Fatalf("record %s/%s/%s not found", entityID, name, recordType)
	return DNSRecordHealth{}
}

func findDNSDomainHealth(t testing.TB, domains []DNSDomainHealth, name, entityID string) DNSDomainHealth {
	t.Helper()
	for _, domain := range domains {
		if domain.Domain == name && domain.EntityID == entityID {
			return domain
		}
	}
	t.Fatalf("domain %s/%s not found", entityID, name)
	return DNSDomainHealth{}
}

func findDNSEntityHealth(t testing.TB, entities []DNSEntityHealth, entityID string) DNSEntityHealth {
	t.Helper()
	for _, entity := range entities {
		if entity.EntityID == entityID {
			return entity
		}
	}
	t.Fatalf("entity %s not found", entityID)
	return DNSEntityHealth{}
}

func findDNSHealthMaturitySignal(t testing.TB, maturity DNSHealthMaturity, code string) DNSHealthMaturitySignal {
	t.Helper()
	for _, signal := range maturity.Signals {
		if signal.Code == code {
			return signal
		}
	}
	t.Fatalf("maturity signal %s not found", code)
	return DNSHealthMaturitySignal{}
}

func findDNSHealthProviderContext(t testing.TB, contexts []DNSHealthProviderContext, domain, providerID string) DNSHealthProviderContext {
	t.Helper()
	for _, context := range contexts {
		if context.Domain == domain && context.Provider.ProviderID == providerID {
			return context
		}
	}
	t.Fatalf("provider context %s/%s not found", domain, providerID)
	return DNSHealthProviderContext{}
}

func maturitySignalSatisfied(maturity DNSHealthMaturity, code string) bool {
	for _, signal := range maturity.Signals {
		if signal.Code == code {
			return signal.Satisfied
		}
	}
	return false
}

func dnsHealthFindingsByID(findings []DNSHealthFinding, ids []FindingID) []DNSHealthFinding {
	wanted := make(map[FindingID]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	selected := make([]DNSHealthFinding, 0, len(ids))
	for _, finding := range findings {
		if wanted[finding.ID] {
			selected = append(selected, finding)
		}
	}
	return selected
}

func countDNSHealthScoreContributions(score DNSHealthScore, codes ...FindingCode) int {
	wanted := make(map[FindingCode]bool, len(codes))
	for _, code := range codes {
		wanted[code] = true
	}
	count := 0
	for _, contribution := range score.Contributions {
		if wanted[contribution.Code] {
			count++
		}
	}
	return count
}

func scoreHasContribution(score DNSHealthScore, code FindingCode) bool {
	for _, contribution := range score.Contributions {
		if contribution.Code == code {
			return true
		}
	}
	return false
}

func recomputeDNSHealthScore(score DNSHealthScore) int {
	value := score.Maximum
	for _, contribution := range score.Contributions {
		value += contribution.Points
	}
	if value < 0 {
		return 0
	}
	if value > score.Maximum {
		return score.Maximum
	}
	return value
}

func TestDNSHealthResultJSONShapeIsStable(t *testing.T) {
	portfolio := dnsHealthTestPortfolio(t)
	authentication := dnsHealthTestAuthentication(t, portfolio, dnsHealthTestTime, nil)
	result, err := EvaluateDNSHealth(portfolio, authentication, dnsHealthTestCatalog(t), DNSHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct {
		Score    DNSHealthScore     `json:"score"`
		Findings []DNSHealthFinding `json:"findings"`
	}{result.PortfolioScore(), result.Findings()})
	if err != nil || !strings.Contains(string(encoded), `"evaluation":{"state":"evaluated"}`) || !strings.Contains(string(encoded), `"finding_ids"`) {
		t.Fatalf("encoded=%s error=%v", encoded, err)
	}
}
