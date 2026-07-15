// Command report-directory shows the shortest complete local-corpus journey.
// It is a copyable example application, not a dmarcgo CLI contract.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	dmarcgo "github.com/georgestarcher/dmarcgo/v2"
)

type runOptions struct {
	reportsPath  string
	evidencePath string
	jsonlPath    string
	csvPath      string
	agentPath    string
}

func main() {
	reportsPath := flag.String("reports", "data/dmarc-reports", "directory containing DMARC aggregate-report artifacts")
	evidencePath := flag.String("evidence-output", "output/report-evidence.json", "complete operational report-evidence JSON")
	jsonlPath := flag.String("jsonl-output", "output/report-rows.jsonl", "flattened report rows as JSON Lines")
	csvPath := flag.String("csv-output", "output/report-rows.csv", "flattened report rows as CSV")
	agentPath := flag.String("agent-output", "output/report-evidence-agent.json", "public agent-envelope JSON")
	flag.Parse()

	if err := run(os.Stdout, os.Stderr, runOptions{
		reportsPath:  *reportsPath,
		evidencePath: *evidencePath,
		jsonlPath:    *jsonlPath,
		csvPath:      *csvPath,
		agentPath:    *agentPath,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "report directory:", err)
		os.Exit(1)
	}
}

func run(summary, diagnostics io.Writer, options runOptions) error {
	results, err := dmarcgo.LoadReportsFromDir(options.reportsPath)
	if err != nil {
		return fmt.Errorf("load report directory: %w", err)
	}

	reports := make([]*dmarcgo.AggregateReport, 0, len(results))
	rows := make([]dmarcgo.FeatureRow, 0)
	skipped := 0
	filenameFindings := 0
	validationFindings := 0
	unauthenticatedSources := make(map[string]struct{})
	for _, result := range results {
		if result.Err != nil {
			skipped++
			if _, writeErr := fmt.Fprintf(diagnostics, "Skipped file=%q error=%q\n", filepath.Base(result.Path), result.Err.Error()); writeErr != nil {
				return fmt.Errorf("write file diagnostic: %w", writeErr)
			}
			continue
		}
		if _, parseErr := dmarcgo.ParseReportFilename(result.Path); parseErr != nil {
			filenameFindings++
		}
		validationFindings += len(result.Report.ValidateCompatibility())
		for _, source := range result.Report.UnauthenticatedSources(result.Report.PolicyPublished.Domain) {
			unauthenticatedSources[source.SourceIP] = struct{}{}
		}
		reports = append(reports, result.Report)
	}
	if len(reports) == 0 {
		return errors.New("no DMARC aggregate reports were loaded successfully")
	}

	loaded := len(reports)
	evidence, err := dmarcgo.AnalyzeReportEvidence(reports, dmarcgo.ReportEvidenceOptions{})
	if err != nil {
		return fmt.Errorf("analyze report evidence: %w", err)
	}
	reports = dmarcgo.DeduplicateReports(reports)
	duplicates := loaded - len(reports)
	for _, report := range reports {
		rows = append(rows, report.Rows()...)
	}
	corpus := dmarcgo.SummarizeReports(reports)

	if err := writeOutputFile(options.evidencePath, func(writer io.Writer) error {
		return dmarcgo.WriteReportEvidenceOutput(writer, evidence, dmarcgo.AnalysisOutputJSON, dmarcgo.AnalysisOutputOptions{
			Redaction: dmarcgo.OutputRedactionOperational,
		})
	}); err != nil {
		return fmt.Errorf("write report evidence: %w", err)
	}
	if err := writeOutputFile(options.jsonlPath, func(writer io.Writer) error {
		return dmarcgo.WriteFeaturesJSONL(writer, rows)
	}); err != nil {
		return fmt.Errorf("write JSON Lines rows: %w", err)
	}
	if err := writeOutputFile(options.csvPath, func(writer io.Writer) error {
		return dmarcgo.WriteFeaturesCSV(writer, rows)
	}); err != nil {
		return fmt.Errorf("write CSV rows: %w", err)
	}
	agentOutput, err := dmarcgo.BuildAnalysisOutput(evidence, dmarcgo.OutputOptions{
		Profile:   dmarcgo.OutputProfileAgent,
		Detail:    dmarcgo.OutputDetailStandard,
		Redaction: dmarcgo.OutputRedactionPublic,
	})
	if err != nil {
		return fmt.Errorf("build public agent output: %w", err)
	}
	if err := writeOutputFile(options.agentPath, func(writer io.Writer) error {
		return dmarcgo.WriteOutputJSON(writer, agentOutput)
	}); err != nil {
		return fmt.Errorf("write agent output: %w", err)
	}

	first := reports[0].Summary()
	if _, err := fmt.Fprintf(summary,
		"Files: %d; loaded: %d; skipped: %d; duplicates removed: %d\n",
		len(results), loaded, skipped, duplicates); err != nil {
		return fmt.Errorf("write corpus summary: %w", err)
	}
	if _, err := fmt.Fprintf(summary,
		"First successfully loaded report: records=%d messages=%d validation_findings=%d\n",
		first.TotalRecords, first.TotalMessages, len(reports[0].ValidateCompatibility())); err != nil {
		return fmt.Errorf("write report summary: %w", err)
	}
	if _, err := fmt.Fprintf(summary,
		"Corpus: reports=%d messages=%d pass=%d fail=%d rejected=%d sources=%d reporters=%d\n",
		corpus.Reports, corpus.TotalMessages, corpus.PassedMessages, corpus.FailedMessages,
		corpus.RejectedMessages, len(corpus.BySourceIP), len(corpus.ByReporter)); err != nil {
		return fmt.Errorf("write corpus summary: %w", err)
	}
	if _, err := fmt.Fprintf(summary,
		"Review context: unauthenticated_sources=%d compatibility_findings=%d filename_findings=%d evidence_diagnostics=%d\n",
		len(unauthenticatedSources), validationFindings, filenameFindings, len(evidence.Diagnostics())); err != nil {
		return fmt.Errorf("write review summary: %w", err)
	}
	if _, err := fmt.Fprintf(summary,
		"Outputs: evidence=%s rows_jsonl=%s rows_csv=%s agent=%s\n",
		options.evidencePath, options.jsonlPath, options.csvPath, options.agentPath); err != nil {
		return fmt.Errorf("write output destinations: %w", err)
	}
	return nil
}

func writeOutputFile(path string, write func(io.Writer) error) error {
	if path == "" {
		return nil
	}
	directory := filepath.Dir(path)
	if directory != "." {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := write(file)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}
