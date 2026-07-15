package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dmarcgo "github.com/georgestarcher/dmarcgo/v2"
)

type fixtureResolver struct {
	records map[string]string
}

func (resolver fixtureResolver) LookupTXT(_ context.Context, name string) (dmarcgo.TXTLookupResult, error) {
	value, ok := resolver.records[name]
	if !ok {
		return dmarcgo.TXTLookupResult{Name: name, Status: dmarcgo.DNSObservationNoData}, nil
	}
	return dmarcgo.TXTLookupResult{
		Name:   name,
		Status: dmarcgo.DNSObservationSuccess,
		Records: []dmarcgo.TXTRecord{{
			Joined: value,
		}},
		Resolver: "synthetic-fixture",
	}, nil
}

func TestRun(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	var summary bytes.Buffer
	err := run(t.Context(), &summary, runOptions{
		portfolioPath: "testdata/portfolio.yaml",
		nativePath:    filepath.Join(directory, "dns-health.json"),
		agentPath:     filepath.Join(directory, "dns-health-agent.json"),
		resolver: fixtureResolver{records: map[string]string{
			"example.test":                      "v=spf1 -all",
			"selector1._domainkey.example.test": "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"_dmarc.example.test":               "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:reports@example.test",
		}},
		clock: dmarcgo.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(summary.String())
	for _, expected := range []string{
		"Planned TXT lookups (3)",
		"Portfolio score:",
		"Native output:",
		"Public agent output:",
	} {
		if !strings.Contains(summary.String(), expected) {
			t.Errorf("summary does not contain %q:\n%s", expected, summary.String())
		}
	}
	for _, name := range []string{"dns-health.json", "dns-health-agent.json"} {
		data, readErr := os.ReadFile(filepath.Join(directory, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Contains(data, []byte(`"schema_version":"1"`)) {
			t.Errorf("%s does not contain the versioned output contract", name)
		}
	}
}
