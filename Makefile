STATICCHECK_VERSION ?= v0.7.0
GOVULNCHECK_VERSION ?= v1.6.0
COVERAGE_MIN ?= 80.0

.PHONY: build test race cover cover-check fuzz-smoke bench-smoke clean format-check lint vuln readme-check release-notes-check api-check output-contract-check ci

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

mod-verify:
	go mod tidy
	@if [ -f go.sum ]; then \
		git diff --exit-code go.mod go.sum; \
	else \
		git diff --exit-code go.mod; \
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

bench-smoke:
	go test -run=^$$ -bench='BenchmarkLoadBytes|BenchmarkSummary|BenchmarkUnauthenticatedSources' -benchtime=1x ./...

ci: format-check mod-verify mod-verify-local lint vuln readme-check release-notes-check api-check output-contract-check test race cover-check fuzz-smoke bench-smoke build

clean:
	go clean
	rm -f coverage.out coverage.html
