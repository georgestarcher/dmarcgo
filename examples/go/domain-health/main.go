// Command domain-health shows the shortest complete portfolio-to-DNS-health
// journey. It is a copyable example application, not a dmarcgo CLI contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	dmarcgo "github.com/georgestarcher/dmarcgo/v3"
)

type runOptions struct {
	portfolioPath string
	nativePath    string
	agentPath     string
	resolver      dmarcgo.TXTResolver
	clock         dmarcgo.Clock
}

func main() {
	portfolioPath := flag.String("portfolio", "config/dmarcgo/portfolio.yaml", "strict organization portfolio YAML")
	nativePath := flag.String("native-output", "output/dns-health.json", "complete operational JSON output")
	agentPath := flag.String("agent-output", "output/dns-health-agent.json", "public agent-envelope JSON output")
	flag.Parse()

	err := run(context.Background(), os.Stdout, runOptions{
		portfolioPath: *portfolioPath,
		nativePath:    *nativePath,
		agentPath:     *agentPath,
		resolver: dmarcgo.NetTXTResolver{
			Resolver:   net.DefaultResolver,
			ResolverID: "system-default",
		},
		clock: dmarcgo.ClockFunc(time.Now),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "domain health:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, summary io.Writer, options runOptions) error {
	data, err := os.ReadFile(options.portfolioPath)
	if err != nil {
		return fmt.Errorf("read portfolio: %w", err)
	}
	portfolio, err := dmarcgo.LoadPortfolioYAML(data)
	if err != nil {
		return fmt.Errorf("load strict portfolio: %w", err)
	}
	if options.resolver == nil {
		return errors.New("an explicit TXT resolver is required")
	}
	if options.clock == nil {
		return errors.New("an explicit collection clock is required")
	}

	names := declaredTXTNames(portfolio)
	if _, err := fmt.Fprintf(summary, "Planned TXT lookups (%d):\n", len(names)); err != nil {
		return fmt.Errorf("write lookup preview: %w", err)
	}
	for _, name := range names {
		if _, err := fmt.Fprintln(summary, " -", name); err != nil {
			return fmt.Errorf("write lookup preview: %w", err)
		}
	}

	snapshot, err := dmarcgo.CollectDNSSnapshot(ctx, portfolio, options.resolver, dmarcgo.DNSCollectionOptions{
		MaxConcurrency: 4,
		MaxAttempts:    2,
		QueryTimeout:   5 * time.Second,
		RetryDelay:     100 * time.Millisecond,
		FailurePolicy:  dmarcgo.DNSFailureCollectAll,
		Clock:          options.clock,
		ResolverID:     "example-application",
	})
	if err != nil {
		return fmt.Errorf("collect DNS snapshot: %w", err)
	}
	authentication, err := dmarcgo.ParseAuthenticationRecords(snapshot)
	if err != nil {
		return fmt.Errorf("parse authentication records: %w", err)
	}
	catalog, err := dmarcgo.DefaultProviderCatalog()
	if err != nil {
		return fmt.Errorf("load provider catalog: %w", err)
	}
	health, err := dmarcgo.EvaluateDNSHealth(portfolio, authentication, catalog, dmarcgo.DNSHealthOptions{
		Profile:       dmarcgo.DNSHealthProfileBalanced,
		GeneratedAt:   snapshot.ObservedAt(),
		UnknownPolicy: dmarcgo.DNSHealthUnknownPreserve,
	})
	if err != nil {
		return fmt.Errorf("evaluate DNS health: %w", err)
	}

	if err := writeOutputFile(options.nativePath, func(writer io.Writer) error {
		return dmarcgo.WriteDNSHealthOutput(writer, health, dmarcgo.AnalysisOutputJSON, dmarcgo.AnalysisOutputOptions{
			Redaction: dmarcgo.OutputRedactionOperational,
		})
	}); err != nil {
		return fmt.Errorf("write native output: %w", err)
	}
	agentOutput, err := dmarcgo.BuildAnalysisOutput(health, dmarcgo.OutputOptions{
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

	score := health.PortfolioScore()
	maturity := health.PortfolioMaturity()
	if score.Available {
		_, err = fmt.Fprintf(summary,
			"Portfolio score: %d/%d (%s); maturity: %s; coverage: %d%%; findings: %d\n",
			score.Value, score.Maximum, score.Grade, maturity.Name, maturity.Coverage.Percent, len(health.Findings()))
	} else {
		_, err = fmt.Fprintf(summary, "Portfolio score unavailable; findings: %d\n", len(health.Findings()))
	}
	if err != nil {
		return fmt.Errorf("write health summary: %w", err)
	}
	if _, err := fmt.Fprintf(summary, "Native output: %s\nPublic agent output: %s\n", options.nativePath, options.agentPath); err != nil {
		return fmt.Errorf("write output destinations: %w", err)
	}
	return nil
}

func declaredTXTNames(portfolio dmarcgo.Portfolio) []string {
	set := make(map[string]struct{})
	for _, entity := range portfolio.Entities() {
		for _, domain := range entity.Domains {
			for _, name := range domain.Records.SPF {
				set[name] = struct{}{}
			}
			for _, name := range domain.Records.DKIM {
				set[name] = struct{}{}
			}
			for _, name := range domain.Records.DMARC {
				set[name] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
