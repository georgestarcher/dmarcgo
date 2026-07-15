package dmarcgo

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStableAnalysisIDIsDeterministicAndBoundarySafe(t *testing.T) {
	first := StableAnalysisID("finding", "ab", "c")
	second := StableAnalysisID("finding", "ab", "c")
	if first != second {
		t.Fatalf("stable IDs differ: %q != %q", first, second)
	}
	if first == StableAnalysisID("finding", "a", "bc") {
		t.Fatal("part boundaries must affect stable IDs")
	}
	if first == StableAnalysisID("evidence", "ab", "c") {
		t.Fatal("namespaces must isolate stable IDs")
	}
	if got, want := len(first), len("finding:")+sha256HexLength; got != want {
		t.Fatalf("ID length = %d, want %d", got, want)
	}
}

const sha256HexLength = 64

func TestClockFuncSupportsInjectedTime(t *testing.T) {
	want := time.Date(2026, 7, 12, 1, 2, 3, 0, time.FixedZone("test", -5*60*60))
	clock := ClockFunc(func() time.Time { return want })
	if got := clock.Now(); !got.Equal(want) || got.Location() != want.Location() {
		t.Fatalf("ClockFunc.Now() = %v, want exact injected value %v", got, want)
	}
}

func TestOutputEnvelopeImplementsResultWithoutChangingMetadata(t *testing.T) {
	generatedAt := time.Date(2026, 7, 12, 6, 2, 3, 0, time.UTC)
	output, err := BuildReportSummaryOutput(ReportSummary{}, OutputOptions{GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}

	var result Result = output
	metadata := result.ResultMetadata()
	if metadata.ContractVersion != AnalysisContractVersion || metadata.Mode != AnalysisModeReportSummary {
		t.Fatalf("unexpected result metadata: %+v", metadata)
	}
	if !metadata.GeneratedAt.Equal(generatedAt) || metadata.Evaluation.State != EvaluationStateEvaluated {
		t.Fatalf("result metadata changed: %+v", metadata)
	}
}

func TestCurrentOutputModesUseCanonicalAnalysisModes(t *testing.T) {
	want := []AnalysisMode{
		AnalysisModeConfigurationValidation,
		AnalysisModeDNSSnapshot,
		AnalysisModeDNSAuthentication,
		AnalysisModeDNSHealth,
		AnalysisModeDNSPerspectives,
		AnalysisModeReportValidation,
		AnalysisModeReportSummary,
		AnalysisModeAggregateSummary,
		AnalysisModeReportRows,
		AnalysisModeSourceReview,
		AnalysisModeReportEvidence,
		AnalysisModeDNSReportCorrelation,
		AnalysisModeThreatCandidates,
		AnalysisModeSourceEnrichment,
		AnalysisModeSourceActivity,
		AnalysisModePhishingIntelligence,
		AnalysisModeJurisdictionContext,
		AnalysisModeCampaignValidation,
		AnalysisModeCampaignClassification,
	}
	got := SupportedOutputModes()
	if len(got) != len(want) {
		t.Fatalf("SupportedOutputModes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SupportedOutputModes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReportAndOutputModesDoNotUseDefaultDNSResolver(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })

	resolverCalls := 0
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			resolverCalls++
			return nil, errors.New("unexpected DNS access")
		},
	}

	report, err := ParseBytes([]byte(helperReportXML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReportSummaryOutput(report.Summary(), OutputOptions{GeneratedAt: outputTestTime}); err != nil {
		t.Fatal(err)
	}
	if resolverCalls != 0 {
		t.Fatalf("report/output processing performed %d DNS lookups", resolverCalls)
	}
}

func TestOutputImplementationDoesNotInvokeAnalysisOrCollection(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "output.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if path == "os" || path == "net" || strings.HasPrefix(path, "net/") {
			t.Fatalf("output implementation imports forbidden side-effect package %q", path)
		}
	}

	file, err = parser.ParseFile(token.NewFileSet(), "output.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]struct{}{
		"LoadFile": {}, "LoadBytes": {}, "LoadReader": {}, "LoadReaderContext": {},
		"ParseBytes": {}, "ParseReader": {}, "Validate": {}, "ValidateWithMode": {},
		"Summary": {}, "Rows": {}, "SummarizeReports": {}, "MergeSummaries": {},
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
		if _, blocked := forbidden[name]; blocked {
			t.Errorf("output implementation calls forbidden analysis or collection function %s", name)
		}
		return true
	})
}
