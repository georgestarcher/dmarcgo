package dmarcgo

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkNormalizeCampaignConfiguration(b *testing.B) {
	config := campaignTestConfig("benchmark", "training.example.test")
	b.ReportAllocs()
	for range b.N {
		if _, err := NormalizeCampaignConfiguration(config); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResolveCampaignConfigurationFragments(b *testing.B) {
	specs := make([]CampaignConfigurationSourceSpec, 0, 32)
	for index := range 32 {
		config := campaignTestConfig(fmt.Sprintf("campaign-%02d", index), fmt.Sprintf("training-%02d.example.test", index))
		specs = append(specs, CampaignConfigurationSourceSpec{
			ID: fmt.Sprintf("source-%02d", index), Source: NewCampaignBytesSource(mustMarshalFuzz(b, config), CampaignConfigurationMetadata{}), Priority: index,
		})
	}
	options := CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time { return time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC) })}
	b.ReportAllocs()
	for range b.N {
		if _, err := ResolveCampaignConfiguration(context.Background(), specs, options); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClassifyReportedMessageLargeInventory(b *testing.B) {
	config := campaignTestConfig("campaign-000", "training.example.test")
	for index := 1; index < defaultCampaignMaximumRelevant; index++ {
		campaign := campaignTestConfig(fmt.Sprintf("campaign-%03d", index), "training.example.test").SecuritySimulations[0]
		config.SecuritySimulations = append(config.SecuritySimulations, campaign)
	}
	snapshot, err := ResolveCampaignConfiguration(context.Background(), []CampaignConfigurationSourceSpec{{
		ID: "benchmark", Source: NewCampaignBytesSource(mustMarshalFuzz(b, config), CampaignConfigurationMetadata{}), Required: true,
	}}, CampaignConfigurationResolveOptions{Clock: ClockFunc(func() time.Time { return time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC) })})
	if err != nil {
		b.Fatal(err)
	}
	evidence, err := NormalizeReportedMessageEvidence(campaignTestEvidenceInput())
	if err != nil {
		b.Fatal(err)
	}
	options := CampaignClassificationOptions{
		GeneratedAt:               time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC),
		MaximumCampaignsEvaluated: defaultCampaignMaximumRelevant,
		MaximumRelevantRecords:    defaultCampaignMaximumRelevant,
	}
	b.ReportAllocs()
	for range b.N {
		if _, err := ClassifyReportedMessage(snapshot, evidence, options); err != nil {
			b.Fatal(err)
		}
	}
}
