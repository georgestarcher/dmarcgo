package dmarcgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedProviderCatalogIsStrictDeterministicAndCurrent(t *testing.T) {
	first, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	second, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if first.SchemaVersion() != ProviderCatalogSchemaVersion || first.CatalogVersion() != "2026-07-12" {
		t.Fatalf("unexpected versions: schema=%d catalog=%q", first.SchemaVersion(), first.CatalogVersion())
	}
	if first.Digest() == "" || first.Digest() != second.Digest() {
		t.Fatalf("catalog digest is not deterministic: %q != %q", first.Digest(), second.Digest())
	}
	if got := len(first.Providers()); got != 18 {
		t.Fatalf("provider count = %d, want 18", got)
	}
	if stale := ValidateProviderCatalogReviewDates(first, time.Date(2026, 7, 12, 23, 59, 0, 0, time.UTC), 365*24*time.Hour); len(stale) != 0 {
		t.Fatalf("embedded provider reviews are stale: %v", stale)
	}
	provenance := first.Provenance()
	if provenance.Source != ProviderCatalogSourceEmbedded || provenance.Digest != first.Digest() {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
}

func TestLoadProviderCatalogYAMLAndNormalizationAreDeterministic(t *testing.T) {
	loaded, err := LoadProviderCatalogYAML([]byte(validProviderYAML()))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Provenance().Source != ProviderCatalogSourceCaller || loaded.Digest() == "" {
		t.Fatalf("unexpected loaded catalog: %+v", loaded.Provenance())
	}

	firstConfig := providerCatalogConfig()
	firstConfig.Providers = append(firstConfig.Providers, providerConfig("second", "spf.second.example.test"))
	secondConfig := firstConfig
	secondConfig.Providers = []ProviderConfig{firstConfig.Providers[1], firstConfig.Providers[0]}
	first, err := NormalizeProviderCatalog(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeProviderCatalog(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() {
		t.Fatalf("input order changed catalog digest: %q != %q", first.Digest(), second.Digest())
	}
	providers := first.Providers()
	if providers[0].ID != "example-mail" || providers[1].ID != "second" {
		t.Fatalf("providers are not in stable ID order: %+v", providers)
	}
}

func TestProviderCatalogLoadingAndMatchingDoNotResolveDNS(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	resolverCalls := 0
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
		resolverCalls++
		return nil, errors.New("unexpected DNS access")
	}}
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProviderCatalogYAML([]byte(validProviderYAML())); err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.MatchSPFInclude("_spf.google.com"); !ok {
		t.Fatal("expected provider match")
	}
	if resolverCalls != 0 {
		t.Fatalf("provider catalog performed %d DNS lookups", resolverCalls)
	}
}

func TestEmbeddedProviderCatalogMaintenanceDate(t *testing.T) {
	asOfText := os.Getenv("DMARCGO_PROVIDER_CATALOG_AS_OF")
	if asOfText == "" {
		t.Skip("maintenance as-of date is supplied by provider-catalog-check")
	}
	asOf, err := time.Parse(providerCatalogDateLayout, asOfText)
	if err != nil {
		t.Fatalf("DMARCGO_PROVIDER_CATALOG_AS_OF is invalid: %v", err)
	}
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if stale := ValidateProviderCatalogReviewDates(catalog, asOf, defaultProviderReviewMaximumAge); len(stale) != 0 {
		t.Fatalf("provider reviews are stale as of %s: %v", asOfText, stale)
	}
}

func TestEmbeddedProviderCatalogUsesOnlyVerifiedStaticIncludes(t *testing.T) {
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"mktomail.com":                      "adobe-marketo",
		"_spf.google.com":                   "google-workspace",
		"spf.protection.outlook.com":        "microsoft-365",
		"spf.protection.office365.us":       "microsoft-365",
		"spf.protection.partner.outlook.cn": "microsoft-365",
		"amazonses.com":                     "amazon-ses",
		"_spf.salesforce.com":               "salesforce",
		"mail.zendesk.com":                  "zendesk",
		"_spf.createsend.com":               "campaign-monitor",
		"mailgun.org":                       "mailgun",
		"spf.mtasv.net":                     "postmark",
		"sendgrid.net":                      "twilio-sendgrid",
		"123456.spf03.hubspotemail.net":     "hubspot",
	}
	for name, providerID := range want {
		match, ok := catalog.MatchSPFInclude(strings.ToUpper(name) + ".")
		if !ok || match.ProviderID != providerID || !match.ContextOnly || match.MatchedInclude != name {
			t.Fatalf("MatchSPFInclude(%q) = %+v, %v", name, match, ok)
		}
	}
	for _, omitted := range []string{"servers.mcsv.net", "shops.shopify.com"} {
		if match, ok := catalog.MatchSPFInclude(omitted); ok {
			t.Fatalf("unverified legacy include %q unexpectedly matched %+v", omitted, match)
		}
	}
}

func TestProviderCatalogExactMatchingRejectsLookalikesAndDynamicTargets(t *testing.T) {
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"_spf.google.com.attacker.test",
		"attacker._spf.google.com",
		"spf.protection.outlook.com.attacker.test",
		"mail.zendesk.com.attacker.test",
	} {
		if match, ok := catalog.MatchSPFInclude(name); ok {
			t.Fatalf("lookalike %q matched %+v", name, match)
		}
	}
	if match, ok := catalog.MatchSPFRelationship(SPFRelationship{Type: "include", Target: "_spf.google.com", Dynamic: true}); ok {
		t.Fatalf("dynamic relationship matched %+v", match)
	}
	if match, ok := catalog.MatchSPFRelationship(SPFRelationship{Type: "a", Target: "_spf.google.com"}); ok {
		t.Fatalf("non-dependency relationship matched %+v", match)
	}
}

func TestProviderCatalogAliasesAndAccessorsAreImmutable(t *testing.T) {
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := catalog.LookupProvider(" Office-365 ")
	if !ok || provider.ID != "microsoft-365" {
		t.Fatalf("LookupProvider() = %+v, %v", provider, ok)
	}
	provider.Aliases[0] = "mutated"
	provider.SPF.Includes[0].Name = "mutated.example.test"
	again, _ := catalog.LookupProvider("microsoft-365")
	if again.Aliases[0] == "mutated" || again.SPF.Includes[0].Name == "mutated.example.test" {
		t.Fatal("provider accessor exposed mutable catalog state")
	}
	providers := catalog.Providers()
	providers[0].Documentation[0].Title = "mutated"
	providersAgain := catalog.Providers()
	if providersAgain[0].Documentation[0].Title == "mutated" {
		t.Fatal("Providers() exposed mutable documentation state")
	}
}

func TestProviderCatalogYAMLRejectsUntrustedStructure(t *testing.T) {
	tests := []struct {
		name string
		data string
		want error
	}{
		{name: "unknown", data: validProviderYAML() + "unexpected: do-not-copy\n", want: ErrInvalidProviderCatalogYAML},
		{name: "secret", data: strings.Replace(validProviderYAML(), "name: Example Mail", "name: Example Mail\n    api_token: do-not-copy", 1), want: ErrProviderCatalogSecretField},
		{name: "alias", data: strings.Replace(validProviderYAML(), "official_domains: [example.test]", "official_domains: &domains [example.test]\n    aliases: *domains", 1), want: ErrInvalidProviderCatalogYAML},
		{name: "environment", data: strings.Replace(validProviderYAML(), "Example Mail", "${PROVIDER_NAME}", 1), want: ErrInvalidProviderCatalogYAML},
		{name: "multiple", data: validProviderYAML() + "---\nschema_version: 1\n", want: ErrInvalidProviderCatalogYAML},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseProviderCatalogYAML([]byte(test.data))
			if !errors.Is(err, test.want) {
				t.Fatalf("ParseProviderCatalogYAML() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "do-not-copy") {
				t.Fatalf("error exposed an untrusted value: %v", err)
			}
		})
	}
	oversized := bytes.Repeat([]byte{'x'}, maxProviderCatalogYAMLBytes+1)
	if _, err := ParseProviderCatalogYAML(oversized); !errors.Is(err, ErrProviderCatalogTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestProviderCatalogValidationRejectsInvalidContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProviderCatalogConfig)
	}{
		{name: "bad catalog date", mutate: func(config *ProviderCatalogConfig) { config.CatalogVersion = "today" }},
		{name: "duplicate ID", mutate: func(config *ProviderCatalogConfig) { config.Providers = append(config.Providers, config.Providers[0]) }},
		{name: "invalid DNS", mutate: func(config *ProviderCatalogConfig) { config.Providers[0].SPF.Includes[0].Name = "not a domain" }},
		{name: "future review", mutate: func(config *ProviderCatalogConfig) { config.Providers[0].ReviewedAt = "2026-07-13" }},
		{name: "broken successor", mutate: func(config *ProviderCatalogConfig) {
			config.Providers[0].Status = ProviderStatusDeprecated
			config.Providers[0].Successor = "missing"
		}},
		{name: "secondary documentation", mutate: func(config *ProviderCatalogConfig) {
			config.Providers[0].Documentation[0].URL = "https://attacker.test/advice"
		}},
		{name: "suffix without evidence note", mutate: func(config *ProviderCatalogConfig) { config.Providers[0].SPF.Includes[0].Match = SPFIncludeMatchSuffix }},
		{name: "unknown capability", mutate: func(config *ProviderCatalogConfig) { config.Providers[0].Alignment.CustomMailFrom = "sometimes" }},
		{name: "unsupported capability required", mutate: func(config *ProviderCatalogConfig) {
			config.Providers[0].Alignment.CustomMailFrom = ProviderCapabilityNotSupported
			config.Providers[0].Alignment.CustomMailFromRequiredForSPFDMARC = true
		}},
		{name: "unsupported companion type", mutate: func(config *ProviderCatalogConfig) {
			config.Providers[0].CompanionRecords = []ProviderCompanionRecord{{ID: "address", Type: "A", Condition: "Always.", Purpose: "Not allowed."}}
		}},
		{name: "control character", mutate: func(config *ProviderCatalogConfig) { config.Providers[0].ContractNote = "data\ninstruction" }},
		{name: "alias collides with ID", mutate: func(config *ProviderCatalogConfig) {
			config.Providers[0].Aliases = []string{"second"}
			second := providerConfig("second", "second.example.test")
			config.Providers = append(config.Providers, second)
		}},
		{name: "overlapping include", mutate: func(config *ProviderCatalogConfig) {
			second := providerConfig("second", "mail.example.test")
			second.SPF.Includes[0].Match = SPFIncludeMatchSuffix
			second.SPF.Includes[0].Note = "Documented suffix ownership."
			config.Providers = append(config.Providers, second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := providerCatalogConfig()
			test.mutate(&config)
			if _, err := NormalizeProviderCatalog(config); !errors.Is(err, ErrInvalidProviderCatalog) {
				t.Fatalf("NormalizeProviderCatalog() error = %v", err)
			}
		})
	}
}

func TestProviderCatalogSuffixMatchingRequiresExplicitRule(t *testing.T) {
	config := providerCatalogConfig()
	config.Providers[0].SPF.Includes[0].Match = SPFIncludeMatchSuffix
	config.Providers[0].SPF.Includes[0].Note = "The first-party contract assigns subdomains of this include root."
	catalog, err := NormalizeProviderCatalog(config)
	if err != nil {
		t.Fatal(err)
	}
	if match, ok := catalog.MatchSPFInclude("regional.mail.example.test"); !ok || match.MatchRule != SPFIncludeMatchSuffix {
		t.Fatalf("documented suffix did not match: %+v, %v", match, ok)
	}
	if match, ok := catalog.MatchSPFInclude("mail.example.test.attacker.test"); ok {
		t.Fatalf("suffix lookalike matched: %+v", match)
	}
}

func TestProviderCatalogOverlayIsExplicitAndPreservesProvenance(t *testing.T) {
	base, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	privateConfig := ProviderCatalogConfig{SchemaVersion: 1, CatalogVersion: "2026-07-12", Providers: []ProviderConfig{providerConfig("internal-relay", "spf.relay.example.test")}}
	privateCatalog, err := NormalizeProviderCatalog(privateConfig)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := OverlayProviderCatalog(base, ProviderCatalogOverlay{Catalog: privateCatalog})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.LookupProvider("internal-relay"); ok {
		t.Fatal("overlay mutated the base catalog")
	}
	match, ok := effective.MatchSPFInclude("spf.relay.example.test")
	if !ok || match.ProviderID != "internal-relay" || !match.ContextOnly {
		t.Fatalf("private provider match = %+v, %v", match, ok)
	}
	provenance := effective.Provenance()
	if provenance.Source != ProviderCatalogSourceOverlay || provenance.BaseDigest != base.Digest() || provenance.OverlayDigest != privateCatalog.Digest() || len(provenance.AddedProviderIDs) != 1 || provenance.AddedProviderIDs[0] != "internal-relay" {
		t.Fatalf("unexpected overlay provenance: %+v", provenance)
	}

	replacement := providerConfig("google-workspace", "spf.workspace.example.test")
	replacement.Aliases = []string{"google-apps-private"}
	replacementCatalog, err := NormalizeProviderCatalog(ProviderCatalogConfig{SchemaVersion: 1, CatalogVersion: "2026-07-12", Providers: []ProviderConfig{replacement}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OverlayProviderCatalog(base, ProviderCatalogOverlay{Catalog: replacementCatalog}); !errors.Is(err, ErrInvalidProviderCatalog) {
		t.Fatalf("silent replacement error = %v", err)
	}
	replaced, err := OverlayProviderCatalog(base, ProviderCatalogOverlay{Catalog: replacementCatalog, ReplaceProviderIDs: []string{"google-workspace"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := replaced.MatchSPFInclude("_spf.google.com"); ok {
		t.Fatal("explicit replacement retained replaced SPF contract")
	}
	if got := replaced.Provenance().ReplacedProviderIDs; len(got) != 1 || got[0] != "google-workspace" {
		t.Fatalf("replacement provenance = %v", got)
	}
	if _, err := OverlayProviderCatalog(base, ProviderCatalogOverlay{Catalog: privateCatalog, ReplaceProviderIDs: []string{"google-workspace"}}); !errors.Is(err, ErrInvalidProviderCatalog) {
		t.Fatalf("unused replacement error = %v", err)
	}
}

func TestProviderMatchSerializationIsStableAndNeverGrantsAuthorization(t *testing.T) {
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	match, ok := catalog.MatchSPFInclude("_spf.google.com")
	if !ok {
		t.Fatal("expected Google Workspace match")
	}
	encoded, err := json.Marshal(match)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"provider_id":"google-workspace","provider_name":"Google Workspace","provider_status":"active","matched_include":"_spf.google.com","catalog_include":"_spf.google.com","include_status":"active","match_rule":"exact","evidence_confidence":"high","shared_infrastructure":true,"context_only":true,"catalog_version":"2026-07-12","provider_reviewed_at":"2026-07-12T00:00:00Z"}`
	if string(encoded) != want {
		t.Fatalf("provider match JSON = %s\nwant = %s", encoded, want)
	}
	if strings.Contains(string(encoded), "authorized") || !match.ContextOnly {
		t.Fatalf("provider recognition implied authorization: %s", encoded)
	}
}

func TestProviderCatalogDeprecationAndSuccessorContext(t *testing.T) {
	config := providerCatalogConfig()
	old := providerConfig("old-mail", "spf.old.example.test")
	old.Status = ProviderStatusDeprecated
	old.Successor = "example-mail"
	old.SPF.Includes[0].Status = ProviderStatusDeprecated
	config.Providers = append(config.Providers, old)
	catalog, err := NormalizeProviderCatalog(config)
	if err != nil {
		t.Fatal(err)
	}
	match, ok := catalog.MatchSPFInclude("spf.old.example.test")
	if !ok || match.ProviderStatus != ProviderStatusDeprecated || match.IncludeStatus != ProviderStatusDeprecated || match.Successor != "example-mail" || !match.ContextOnly {
		t.Fatalf("deprecated provider context = %+v, %v", match, ok)
	}
}

func TestProviderCatalogReviewDateValidation(t *testing.T) {
	catalog, err := NormalizeProviderCatalog(providerCatalogConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got := ValidateProviderCatalogReviewDates(catalog, time.Date(2027, 8, 20, 0, 0, 0, 0, time.UTC), 365*24*time.Hour); len(got) != 1 || got[0] != "example-mail" {
		t.Fatalf("stale reviews = %v", got)
	}
	if got := ValidateProviderCatalogReviewDates(catalog, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), 365*24*time.Hour); len(got) != 1 || got[0] != "example-mail" {
		t.Fatalf("future reviews = %v", got)
	}
}

func TestProviderRecognitionIsIndependentOfLiveSPFContents(t *testing.T) {
	catalog, err := DefaultProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"v=spf1 include:_spf.google.com ip4:192.0.2.1 -all",
		"v=spf1 ip6:2001:db8::/32 include:_spf.google.com ~all",
	} {
		record, diagnostics := ParseSPFRecord(value)
		if record.Status != AuthenticationRecordValid || len(diagnostics) != 0 {
			t.Fatalf("ParseSPFRecord() = %s, %v", record.Status, diagnostics)
		}
		match, ok := catalog.MatchSPFRelationship(record.Relationships[0])
		if !ok || match.ProviderID != "google-workspace" || !match.ContextOnly {
			t.Fatalf("provider context = %+v, %v", match, ok)
		}
	}

	unknown, diagnostics := ParseSPFRecord("v=spf1 include:sender.example.test -all")
	if unknown.Status != AuthenticationRecordValid || len(diagnostics) != 0 {
		t.Fatalf("unknown provider SPF stopped being analyzable: %s, %v", unknown.Status, diagnostics)
	}
	if match, ok := catalog.MatchSPFRelationship(unknown.Relationships[0]); ok {
		t.Fatalf("unknown provider received catalog context: %+v", match)
	}
}

func providerCatalogConfig() ProviderCatalogConfig {
	return ProviderCatalogConfig{SchemaVersion: ProviderCatalogSchemaVersion, CatalogVersion: "2026-07-12", Providers: []ProviderConfig{providerConfig("example-mail", "mail.example.test")}}
}

func providerConfig(id, include string) ProviderConfig {
	return ProviderConfig{
		ID: id, Name: "Example Mail", Status: ProviderStatusActive,
		OfficialDomains: []string{"example.test"},
		SPF:             ProviderSPFConfig{Includes: []ProviderSPFInclude{{Name: include, Status: ProviderStatusActive, Match: SPFIncludeMatchExact, EvidenceConfidence: ProviderEvidenceHigh}}, LiveExpansionRequired: true},
		Alignment:       ProviderAlignmentConfig{CustomMailFrom: ProviderCapabilityUnknown},
		Infrastructure:  ProviderInfrastructureConfig{Shared: true},
		Documentation:   []ProviderDocumentation{{URL: "https://docs.example.test/email", Title: "Example Mail authentication"}},
		ReviewedAt:      "2026-07-12", EvidenceConfidence: ProviderEvidenceHigh,
	}
}

func validProviderYAML() string {
	return `schema_version: 1
catalog_version: "2026-07-12"
providers:
  - id: example-mail
    name: Example Mail
    status: active
    official_domains: [example.test]
    spf:
      includes:
        - name: mail.example.test
          status: active
          match: exact
          evidence_confidence: high
      live_expansion_required: true
    infrastructure:
      shared: true
    alignment:
      custom_mail_from: unknown
      custom_mail_from_required_for_spf_dmarc_alignment: false
    documentation:
      - url: https://docs.example.test/email
        title: Example Mail authentication
    reviewed_at: "2026-07-12"
    evidence_confidence: high
`
}
