STATICCHECK_VERSION ?= v0.7.0
GOVULNCHECK_VERSION ?= v1.6.0
COVERAGE_MIN ?= 80.0

.PHONY: build test race cover cover-check fuzz-smoke bench-smoke clean format-check lint vuln readme-check wiki-check release-notes-check api-check output-contract-check workflow-check portfolio-check dns-snapshot-check dns-perspective-check auth-record-check provider-catalog-check dns-health-check report-evidence-check correlation-check threat-candidate-check source-enrichment-check source-activity-check phishing-intelligence-check jurisdiction-context-check campaign-check stix-check stix-validator-check threatconnect-check misp-check threatstream-check ci

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

cover-check:
	go test -covermode=atomic -coverprofile=coverage.out ./...
	python3 scripts/check_coverage.py --profile coverage.out --min $(COVERAGE_MIN)

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

readme-check:
	python3 scripts/check_readme_examples.py

wiki-check:
	python3 scripts/check_wiki.py

release-notes-check:
	python3 scripts/extract_changelog.py >/dev/null

api-check:
	go test -run 'TestParse|TestLoadBytes|TestLoadReader|TestLoadReportsFromDir|TestSummary|TestWriteFeaturesJSONL|TestWriteFeaturesCSV|TestValidate|TestMergeSummaries|TestDateRange|TestBuildReportSummaryOutput|TestOutput|TestSourceReviewOutput|TestReportRowsOutput|TestAnalysisOutput' ./...

output-contract-check:
	go test -run 'Test.*Output|Test.*Schema|Test.*Redaction|Test.*Truncation' ./...

workflow-check:
	go test -run '^TestPhase1[34]' ./...

portfolio-check:
	go test -run 'Test.*Portfolio|Test.*Configuration|TestYAML' ./...

dns-snapshot-check:
	go test -run 'Test.*DNS|Test.*TXTResolver|TestCollectDNSSnapshot|TestPrivatePortfolioCanPlanOfflineDNSSnapshot' ./...

dns-perspective-check:
	go test -run 'Test.*DNSPerspective|TestCollectDNSPerspectives|TestPrivatePortfolioDNSPerspectiveCompatibility|ExampleCollectDNSPerspectives' ./...

auth-record-check:
	go test -run 'Test.*Authentication|TestParseSPF|TestParseDKIM|TestParseDMARC|TestDMARCPolicyDiscovery' ./...

dns-health-check:
	go test -run 'Test.*DNSHealth|TestEvaluateDNSHealth' ./...

report-evidence-check:
	go test -run 'Test.*ReportEvidence|TestAnalyzeReportEvidence' ./...

correlation-check:
	go test -run 'Test.*Correlate|Test.*Correlation' ./...

threat-candidate-check:
	go test -run 'Test.*ThreatCandidate|TestScoreThreatCandidates' ./...

source-enrichment-check:
	go test -run 'Test.*SourceEnrichment|TestEnrichThreatCandidates|ExampleEnrichThreatCandidates' ./...

source-activity-check:
	go test -run 'Test.*SourceActivity|TestCollectSourceActivity|ExampleCollectSourceActivity' ./...

phishing-intelligence-check:
	go test -run 'Test.*PhishingIntelligence|TestCorrelatePhishingIntelligence|ExampleCorrelatePhishingIntelligence' ./...

jurisdiction-context-check:
	go test -run 'Test.*Jurisdiction|TestEvaluateJurisdictionContext|ExampleEvaluateJurisdictionContext' ./...

campaign-check:
	go test -run 'Test.*Campaign|TestClassifyReportedMessage|TestCorrelateCampaignReportEvidence|ExampleLoadCampaignConfiguration|ExampleResolveCampaignConfiguration|ExampleClassifyReportedMessage' ./...

stix-check:
	go test -run 'Test.*STIX|TestBuildSTIXBundle|TestValidateAndWriteSTIXBundle|ExampleBuildSTIXBundle' ./...

stix-validator-check:
	@set -e; \
	command -v stix2_validator >/dev/null; \
	tmp_dir=$$(mktemp -d); \
	trap 'rm -rf "$${tmp_dir}"' EXIT; \
	cp schemas/stix/dmarcgo-evidence/v1.json "$${tmp_dir}/extension-definition--00d952ee-5f5b-55b4-bdda-8cf91c1785a8.json"; \
	stix2_validator --version 2.1 --enforce-refs --schemas "$${tmp_dir}" testdata/golden/stix_bundle*.json

threatconnect-check:
	go test -run 'Test.*ThreatConnect|TestBuildThreatConnectIndicatorPayloads|ExampleBuildThreatConnectIndicatorPayloads' ./...

misp-check:
	go test -run 'Test.*MISP|TestBuildMISP|ExampleBuildMISP' ./...

threatstream-check:
	go test -run 'Test.*ThreatStream|TestBuildThreatStream|ExampleBuildThreatStream' ./...

provider-catalog-check:
	DMARCGO_PROVIDER_CATALOG_AS_OF=$$(date -u +%F) go test -run 'Test.*ProviderCatalog|Test.*ProviderMatch|Test.*ProviderRecognition|TestEmbeddedProvider' ./...

mod-verify:
	@set -e; \
	tmp_dir=$$(mktemp -d); \
	trap 'rm -rf "$${tmp_dir}"' EXIT; \
	cp go.mod "$${tmp_dir}/go.mod"; \
	if [ -f go.sum ]; then cp go.sum "$${tmp_dir}/go.sum"; fi; \
	go mod tidy; \
	diff -u "$${tmp_dir}/go.mod" go.mod; \
	if [ -f "$${tmp_dir}/go.sum" ]; then \
		diff -u "$${tmp_dir}/go.sum" go.sum; \
	elif [ -f go.sum ]; then \
		echo "go mod tidy unexpectedly created go.sum"; \
		exit 1; \
	fi

mod-verify-local:
	go mod verify

format-check:
	@fmt_out=$$(gofmt -l .); \
	if [ -n "$${fmt_out}" ]; then \
		echo "gofmt must be run on:"; \
		echo "$${fmt_out}"; \
		exit 1; \
	fi

fuzz-smoke:
	go test -run=^$$ -fuzz=FuzzParseBytes -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzLoadBytes -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzOutputEnvelopeSerialization -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParsePortfolioYAML -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParseTXTResponse -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParseSPFRecord -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParseDKIMKeyRecord -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParseDMARCPolicyRecord -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzSPFDependencyGraph -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParseProviderCatalogYAML -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzAnalyzeReportEvidence -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzCorrelateReportEvidence -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzThreatCandidateAdjustmentBounds -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzSourceEnrichmentMetadata -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzDNSPerspectiveResponseNormalization -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzSourceActivityResponseNormalization -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzNormalizePhishingIntelligenceSnapshot -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzJurisdictionRiskPolicyNormalization -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzAnalysisOutputSerialization -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzParseCampaignConfiguration -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzCampaignConfigurationImports -fuzztime=5s -timeout=2m .
	go test -run=^$$ -fuzz=FuzzCampaignClassificationAndOutput -fuzztime=5s -timeout=2m .

bench-smoke:
	go test -run=^$$ -bench='BenchmarkLoadBytes|BenchmarkSummary|BenchmarkUnauthenticatedSources|BenchmarkNormalizePortfolio|BenchmarkCollectDNSSnapshotSharedPortfolio|BenchmarkCollectDNSPerspectives|BenchmarkParseAuthenticationRecords|BenchmarkEvaluateDNSHealthLargePortfolio|BenchmarkAnalyzeReportEvidence|BenchmarkCorrelateReportEvidence|BenchmarkScoreThreatCandidatesLargeSourceSet|BenchmarkEnrichThreatCandidatesLargeCandidateSet|BenchmarkCorrelatePhishingIntelligence|BenchmarkEvaluateJurisdictionContextLargeCandidateSet|BenchmarkNormalizeCampaignConfiguration|BenchmarkResolveCampaignConfigurationFragments|BenchmarkClassifyReportedMessageLargeInventory|BenchmarkBuildSTIXBundle|BenchmarkBuildThreatConnectIndicatorPayloads|BenchmarkBuildMISPAttributePayloads|BenchmarkBuildThreatStreamPayloads|BenchmarkPhase13NativeAnalysisOutputs' -benchtime=1x ./...

ci: format-check mod-verify mod-verify-local lint vuln readme-check wiki-check release-notes-check api-check output-contract-check workflow-check portfolio-check dns-snapshot-check dns-perspective-check auth-record-check provider-catalog-check dns-health-check report-evidence-check correlation-check threat-candidate-check source-enrichment-check source-activity-check phishing-intelligence-check jurisdiction-context-check campaign-check stix-check threatconnect-check misp-check threatstream-check test race cover-check fuzz-smoke bench-smoke build

clean:
	go clean
	rm -f coverage.out coverage.html
