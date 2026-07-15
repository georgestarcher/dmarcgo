package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHandlesUnrelatedFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	inputDirectory := filepath.Join(directory, "reports")
	if err := os.Mkdir(inputDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile("testdata/reports/receiver.example!example.test!1782172800!1782259199!synthetic.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"receiver.example!example.test!1782172800!1782259199!synthetic.xml",
		"receiver.example!example.test!1782172800!1782259199!duplicate.xml",
	} {
		if err := os.WriteFile(filepath.Join(inputDirectory, name), report, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(inputDirectory, "notes.txt"), []byte("unrelated synthetic file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var summary bytes.Buffer
	var diagnostics bytes.Buffer
	err = run(&summary, &diagnostics, runOptions{
		reportsPath:  inputDirectory,
		evidencePath: filepath.Join(directory, "report-evidence.json"),
		jsonlPath:    filepath.Join(directory, "report-rows.jsonl"),
		csvPath:      filepath.Join(directory, "report-rows.csv"),
		agentPath:    filepath.Join(directory, "report-evidence-agent.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Files: 3; loaded: 2; skipped: 1; duplicates removed: 1",
		"Corpus: reports=1 messages=7 pass=6 fail=1 rejected=1 sources=2 reporters=1",
		"Review context: unauthenticated_sources=1 compatibility_findings=0 filename_findings=0 evidence_diagnostics=1",
	} {
		if !strings.Contains(summary.String(), expected) {
			t.Errorf("summary does not contain %q:\n%s", expected, summary.String())
		}
	}
	if !strings.Contains(diagnostics.String(), `Skipped file="notes.txt" error=`) {
		t.Errorf("mixed-directory diagnostic is missing:\n%s", diagnostics.String())
	}
	for _, name := range []string{
		"report-evidence.json",
		"report-rows.jsonl",
		"report-rows.csv",
		"report-evidence-agent.json",
	} {
		info, statErr := os.Stat(filepath.Join(directory, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}
