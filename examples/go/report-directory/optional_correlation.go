package main

import (
	"fmt"

	dmarcgo "github.com/georgestarcher/dmarcgo/v2"
)

// CandidateReview demonstrates the optional pure composition step after an
// application has completed both newcomer journeys. It does not perform DNS,
// file loading, enrichment, or source-IP contact.
type CandidateReview struct {
	Correlation              dmarcgo.DNSReportCorrelationResult
	DefaultCandidates        dmarcgo.ThreatCandidateResult
	ExpectedSenderCandidates dmarcgo.ThreatCandidateResult
}

// CorrelateAndScore compares completed DNS and report evidence, then produces
// both the safe default review and an explicit expected-sender-inclusive view.
func CorrelateAndScore(
	portfolio dmarcgo.Portfolio,
	health dmarcgo.DNSHealthResult,
	evidence dmarcgo.ReportEvidenceResult,
) (CandidateReview, error) {
	correlation, err := dmarcgo.CorrelateReportEvidence(
		portfolio,
		health,
		evidence,
		dmarcgo.DNSReportCorrelationOptions{},
	)
	if err != nil {
		return CandidateReview{}, fmt.Errorf("correlate DNS and report evidence: %w", err)
	}
	defaultCandidates, err := dmarcgo.ScoreThreatCandidates(
		portfolio,
		evidence,
		correlation,
		dmarcgo.ThreatCandidateOptions{Profile: dmarcgo.ThreatCandidateProfileBalanced},
	)
	if err != nil {
		return CandidateReview{}, fmt.Errorf("score default threat candidates: %w", err)
	}
	expectedSenderCandidates, err := dmarcgo.ScoreThreatCandidates(
		portfolio,
		evidence,
		correlation,
		dmarcgo.ThreatCandidateOptions{
			Profile:                dmarcgo.ThreatCandidateProfileBalanced,
			IncludeExpectedSenders: true,
		},
	)
	if err != nil {
		return CandidateReview{}, fmt.Errorf("score candidates including expected senders: %w", err)
	}
	return CandidateReview{
		Correlation:              correlation,
		DefaultCandidates:        defaultCandidates,
		ExpectedSenderCandidates: expectedSenderCandidates,
	}, nil
}
