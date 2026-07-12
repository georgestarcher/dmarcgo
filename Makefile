STATICCHECK_VERSION ?= v0.7.0
GOVULNCHECK_VERSION ?= v1.6.0
COVERAGE_MIN ?= 80.0

.PHONY: build test race cover cover-check fuzz-smoke bench-smoke clean format-check lint vuln readme-check release-notes-check api-check output-contract-check portfolio-check dns-snapshot-check auth-record-check dns-health-check ci

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

release-notes-check:
	python3 scripts/extract_changelog.py >/dev/null

api-check:
	go test -run 'TestParse|TestLoadBytes|TestLoadReader|TestLoadReportsFromDir|TestSummary|TestWriteFeaturesJSONL|TestWriteFeaturesCSV|TestValidate|TestMergeSummaries|TestDateRange|TestBuildReportSummaryOutput|TestOutput|TestSourceReviewOutput|TestReportRowsOutput' ./...

output-contract-check:
	go test -run 'Test.*Output|Test.*Schema|Test.*Redaction|Test.*Truncation' ./...

portfolio-check:
	go test -run 'Test.*Portfolio|Test.*Configuration|TestYAML' ./...

dns-snapshot-check:
	go test -run 'Test.*DNS|Test.*TXTResolver|TestCollectDNSSnapshot|TestPrivatePortfolioCanPlanOfflineDNSSnapshot' ./...

auth-record-check:
	go test -run 'Test.*Authentication|TestParseSPF|TestParseDKIM|TestParseDMARC|TestDMARCPolicyDiscovery' ./...

dns-health-check:
	go test -run 'Test.*DNSHealth|TestEvaluateDNSHealth' ./...

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

bench-smoke:
	go test -run=^$$ -bench='BenchmarkLoadBytes|BenchmarkSummary|BenchmarkUnauthenticatedSources|BenchmarkNormalizePortfolio|BenchmarkCollectDNSSnapshotSharedPortfolio|BenchmarkParseAuthenticationRecords|BenchmarkEvaluateDNSHealthLargePortfolio' -benchtime=1x ./...

ci: format-check mod-verify mod-verify-local lint vuln readme-check release-notes-check api-check output-contract-check portfolio-check dns-snapshot-check auth-record-check dns-health-check test race cover-check fuzz-smoke bench-smoke build

clean:
	go clean
	rm -f coverage.out coverage.html
