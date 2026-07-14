package dmarcgo

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPhase14CampaignWorkflowRemainsExplicitAndDisclosureSafe(t *testing.T) {
	data, err := os.ReadFile("testdata/fixtures/campaigns/security-simulations.yaml")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ResolveCampaignConfiguration(context.Background(), []CampaignConfigurationSourceSpec{{
		ID: "testing-team-feed", Source: NewCampaignBytesSource(data, CampaignConfigurationMetadata{}), Required: true,
	}}, CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time {
		return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	})})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NormalizeReportedMessageEvidence(ReportedMessageEvidenceInput{
		ExternalReference: "reported-message-1", Organization: "example-holdings", Entity: "primary-company", BusinessUnit: "corporate-security",
		HeaderFromDomain: "training.example.test", EnvelopeFromDomain: "bounce.training.example.test", MessageIDDomain: "training.example.test",
		DKIM:      []CampaignDKIMEvidenceInput{{Domain: "training.example.test", Selector: "simulation-2026", Outcome: ReportAuthenticationPass}},
		SPFDomain: "bounce.training.example.test", SPFOutcome: ReportAuthenticationPass, DKIMOutcome: ReportAuthenticationPass, DMARCOutcome: ReportAuthenticationPass,
		InfrastructureIDs: []string{"vendor-tenant-route"}, DeliveryExceptionIDs: []string{"gateway-exception-1001"},
		RecipientDomains: []string{"example.test"}, RecipientScopeIDs: []string{"all-employees"}, URLDomains: []string{"landing.example.test"},
		TokenDigests: []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		MessageTime:  time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
		Provenance: []CampaignEvidenceProvenanceInput{
			{SourceID: "header-parser", Type: CampaignEvidenceMessageHeaders, ObservedAt: time.Date(2026, 7, 15, 12, 1, 0, 0, time.UTC), Confidence: FindingConfidenceHigh},
			{SourceID: "token-verifier", Type: CampaignEvidenceVerifiedToken, ObservedAt: time.Date(2026, 7, 15, 12, 1, 1, 0, time.UTC), Confidence: FindingConfidenceHigh},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ClassifyReportedMessage(snapshot, evidence, CampaignClassificationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary().OverallClassification != CampaignAuthorizedHighConfidence || result.Summary().AutomaticDispositionReady != 0 {
		t.Fatalf("unexpected Phase 14 classification summary: %+v", result.Summary())
	}
	var safe bytes.Buffer
	if err := WriteCampaignClassificationOutput(&safe, result, CampaignOutputJSON, CampaignOutputOptions{View: CampaignOutputDisclosureSafe}); err != nil {
		t.Fatal(err)
	}
	for _, restricted := range []string{"commercial-simulation-2026-q3", "training.example.test", "vendor-tenant-route", "authorized_simulation_high_confidence"} {
		if strings.Contains(safe.String(), restricted) {
			t.Fatalf("disclosure-safe workflow leaked %q: %s", restricted, safe.String())
		}
	}
	if !strings.Contains(safe.String(), "suspicious-message-received") {
		t.Fatalf("neutral employee response template missing: %s", safe.String())
	}
}
