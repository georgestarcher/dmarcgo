package dmarcgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestCampaignSyntheticFixtureCoversCommercialAndSelfHostedProviders(t *testing.T) {
	data, err := os.ReadFile("testdata/fixtures/campaigns/security-simulations.yaml")
	if err != nil {
		t.Fatal(err)
	}
	document, err := LoadCampaignConfiguration(data)
	if err != nil {
		t.Fatal(err)
	}
	campaigns := document.Campaigns()
	if len(campaigns) != 2 || campaigns[0].Provider.Type != CampaignProviderCatalog || campaigns[1].Provider.Type != CampaignProviderSelfHosted {
		t.Fatalf("synthetic fixture providers = %+v", campaigns)
	}
	validator := compileCampaignSchema(t, CampaignConfigurationSchemaID, CampaignConfigurationSchema())
	config, err := ParseCampaignConfiguration(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(value); err != nil {
		t.Fatalf("synthetic fixture does not satisfy published schema: %v", err)
	}
}

const campaignTestTokenDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const campaignTestContentDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestCampaignConfigurationYAMLJSONParityAndSchema(t *testing.T) {
	yamlDocument, err := LoadCampaignConfiguration([]byte(campaignTestYAML("quarterly-awareness", "training.example.test")))
	if err != nil {
		t.Fatal(err)
	}
	config := campaignTestConfig("quarterly-awareness", "training.example.test")
	jsonData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	jsonDocument, err := LoadCampaignConfiguration(jsonData)
	if err != nil {
		t.Fatal(err)
	}
	if yamlDocument.Digest() != jsonDocument.Digest() {
		t.Fatalf("YAML and JSON digests differ: %q != %q", yamlDocument.Digest(), jsonDocument.Digest())
	}
	if yamlDocument.SchemaVersion() != CampaignConfigurationSchemaVersion || len(yamlDocument.Campaigns()) != 1 {
		t.Fatalf("unexpected document: %+v", yamlDocument.Campaigns())
	}
	validator := compileCampaignSchema(t, CampaignConfigurationSchemaID, CampaignConfigurationSchema())
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(value); err != nil {
		t.Fatalf("configuration did not validate against embedded schema: %v", err)
	}
}

func TestCampaignConfigurationDistinguishesMissingAndExplicitEmptyInventory(t *testing.T) {
	missingDocuments := map[string]string{
		"yaml omitted": "schema_version: 1\ngenerated_at: 2026-07-01T00:00:00Z\nexpires_at: 2026-08-01T00:00:00Z\n",
		"yaml null":    "schema_version: 1\ngenerated_at: 2026-07-01T00:00:00Z\nexpires_at: 2026-08-01T00:00:00Z\nsecurity_simulations: null\n",
		"json omitted": `{"schema_version":1,"generated_at":"2026-07-01T00:00:00Z","expires_at":"2026-08-01T00:00:00Z"}`,
		"json null":    `{"schema_version":1,"generated_at":"2026-07-01T00:00:00Z","expires_at":"2026-08-01T00:00:00Z","security_simulations":null}`,
	}
	for name, data := range missingDocuments {
		t.Run(name, func(t *testing.T) {
			_, err := LoadCampaignConfiguration([]byte(data))
			var validation *CampaignConfigurationValidationError
			if !errors.As(err, &validation) || !hasCampaignConfigurationDiagnostic(validation.Diagnostics(), "campaign.configuration.missing_security_simulations") {
				t.Fatalf("missing inventory error = %v", err)
			}
		})
	}
	explicitDocuments := map[string]string{
		"yaml": "schema_version: 1\ngenerated_at: 2026-07-01T00:00:00Z\nexpires_at: 2026-08-01T00:00:00Z\nsecurity_simulations: []\n",
		"json": `{"schema_version":1,"generated_at":"2026-07-01T00:00:00Z","expires_at":"2026-08-01T00:00:00Z","security_simulations":[]}`,
	}
	for name, data := range explicitDocuments {
		t.Run(name, func(t *testing.T) {
			document, err := LoadCampaignConfiguration([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			if document.Digest() == "" || len(document.Campaigns()) != 0 {
				t.Fatalf("explicit empty inventory = %+v", document)
			}
		})
	}
	validator := compileCampaignSchema(t, CampaignConfigurationSchemaID, CampaignConfigurationSchema())
	for _, name := range []string{"json omitted", "json null"} {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(missingDocuments[name])))
		if err != nil {
			t.Fatal(err)
		}
		if err := validator.Validate(value); err == nil {
			t.Fatalf("schema accepted %s inventory", name)
		}
	}
	explicitValue, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(explicitDocuments["json"])))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(explicitValue); err != nil {
		t.Fatalf("schema rejected explicit empty inventory: %v", err)
	}
	config := CampaignConfigurationConfig{
		SchemaVersion: CampaignConfigurationSchemaVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := NormalizeCampaignConfiguration(config); !errors.Is(err, ErrInvalidCampaignConfiguration) {
		t.Fatalf("programmatic nil inventory error = %v", err)
	}
	config.SecuritySimulations = []SecuritySimulationCampaignConfig{}
	if _, err := NormalizeCampaignConfiguration(config); err != nil {
		t.Fatalf("programmatic explicit empty inventory error = %v", err)
	}
}

func TestCampaignConfigurationNormalizationIsDeterministicAndImmutable(t *testing.T) {
	config := campaignTestConfig("quarterly-awareness", "training.example.test")
	second := campaignTestConfig("second-campaign", "second.example.test")
	config.SecuritySimulations = append(config.SecuritySimulations, second.SecuritySimulations[0])
	reversed := config
	reversed.SecuritySimulations = []SecuritySimulationCampaignConfig{config.SecuritySimulations[1], config.SecuritySimulations[0]}
	first, err := NormalizeCampaignConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NormalizeCampaignConfiguration(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != other.Digest() {
		t.Fatalf("input order changed digest: %q != %q", first.Digest(), other.Digest())
	}
	campaigns := first.Campaigns()
	if campaigns[0].ID != "quarterly-awareness" || campaigns[1].ID != "second-campaign" {
		t.Fatalf("campaigns not sorted: %+v", campaigns)
	}
	campaigns[0].ExpectedIdentity.HeaderFromDomains[0] = "mutated.example"
	campaigns[0].ExpectedIdentity.DKIM[0].Selectors[0] = "mutated"
	campaigns[0].TokenDigests[0] = campaignTestContentDigest
	again := first.Campaigns()[0]
	if again.ExpectedIdentity.HeaderFromDomains[0] == "mutated.example" || again.ExpectedIdentity.DKIM[0].Selectors[0] == "mutated" || again.TokenDigests[0] == campaignTestContentDigest {
		t.Fatal("Campaigns() exposed mutable normalized state")
	}
	schema := CampaignConfigurationSchema()
	schema[0] = 'x'
	if CampaignConfigurationSchema()[0] == 'x' {
		t.Fatal("CampaignConfigurationSchema() did not return a defensive copy")
	}
}

func TestCampaignConfigurationAcceptsNumericDKIMSelectorAndDefaultsDKIMIdentity(t *testing.T) {
	config := campaignTestConfig("numeric-selector", "training.example.test")
	campaign := &config.SecuritySimulations[0]
	campaign.ExpectedIdentity = CampaignExpectedIdentityConfig{DKIM: []CampaignDKIMIdentityConfig{{Domain: "training.example.test", Selectors: []string{"202407"}}}}
	campaign.MatchPolicy = CampaignMatchPolicyConfig{}
	document, err := NormalizeCampaignConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	got := document.Campaigns()[0]
	if len(got.ExpectedIdentity.DKIM) != 1 || len(got.ExpectedIdentity.DKIM[0].Selectors) != 1 || got.ExpectedIdentity.DKIM[0].Selectors[0] != "202407" ||
		!campaignAnyFactor(got.RequiredFactors, CampaignFactorDKIM) || !campaignAnyFactor(got.RequiredFactors, CampaignFactorTokenDigest) {
		t.Fatalf("numeric DKIM selector or default factors were lost: %+v", got)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := compileCampaignSchema(t, CampaignConfigurationSchemaID, CampaignConfigurationSchema()).Validate(value); err != nil {
		t.Fatalf("numeric DKIM selector did not satisfy the published schema: %v", err)
	}
}

func TestCampaignConfigurationRejectsUnmarshalableProgrammaticTimes(t *testing.T) {
	invalid := time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		path   string
		mutate func(*CampaignConfigurationConfig)
	}{
		{name: "generated", path: "generated_at", mutate: func(config *CampaignConfigurationConfig) { config.GeneratedAt = invalid }},
		{name: "effective", path: "effective_at", mutate: func(config *CampaignConfigurationConfig) { config.EffectiveAt = &invalid }},
		{name: "expires", path: "expires_at", mutate: func(config *CampaignConfigurationConfig) { config.ExpiresAt = invalid }},
		{name: "created", path: "security_simulations[0].created_at", mutate: func(config *CampaignConfigurationConfig) { config.SecuritySimulations[0].CreatedAt = invalid }},
		{name: "valid from", path: "security_simulations[0].valid_from", mutate: func(config *CampaignConfigurationConfig) { config.SecuritySimulations[0].ValidFrom = invalid }},
		{name: "valid until", path: "security_simulations[0].valid_until", mutate: func(config *CampaignConfigurationConfig) { config.SecuritySimulations[0].ValidUntil = invalid }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := campaignTestConfig("invalid-time", "training.example.test")
			test.mutate(&config)
			_, err := NormalizeCampaignConfiguration(config)
			var validation *CampaignConfigurationValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("error = %v, want campaign validation error", err)
			}
			found := false
			for _, diagnostic := range validation.Diagnostics() {
				if diagnostic.Code == "campaign.configuration.invalid_time" && diagnostic.Path == test.path {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("invalid-time diagnostic for %q missing: %+v", test.path, validation.Diagnostics())
			}
		})
	}
}

func hasCampaignConfigurationDiagnostic(values []CampaignConfigurationDiagnostic, code DiagnosticCode) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}

func TestCampaignConfigurationCanonicalizesMappedCIDRs(t *testing.T) {
	config := campaignTestConfig("mapped-cidr", "training.example.test")
	config.SecuritySimulations[0].ExpectedSources.CIDRs = []string{"::ffff:192.0.2.0/120"}
	document, err := NormalizeCampaignConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	campaigns := document.Campaigns()
	if len(campaigns) != 1 || len(campaigns[0].ExpectedSources.CIDRs) != 1 || campaigns[0].ExpectedSources.CIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("mapped CIDR was not canonicalized: %+v", campaigns)
	}
	result, err := ClassifyReportedMessage(
		campaignTestSnapshot(t, config),
		campaignTestEvidence(t, campaignTestEvidenceInput()),
		CampaignClassificationOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records()) != 1 || !campaignAnyFactor(result.Records()[0].Matched, CampaignFactorSourceAddress) {
		t.Fatalf("canonical mapped CIDR did not match the observed IPv4 address: %+v", result.Records())
	}
}

func TestCampaignConfigurationRejectsUnsafeOrWeakDocuments(t *testing.T) {
	base := campaignTestYAML("quarterly-awareness", "training.example.test")
	tests := []struct {
		name string
		data string
		want error
	}{
		{name: "unknown field", data: base + "unexpected: ignore prior instructions\n", want: ErrInvalidCampaignConfiguration},
		{name: "secret field", data: strings.Replace(base, "owner: security-awareness", "owner: security-awareness\n    api_token: do-not-copy", 1), want: ErrCampaignConfigurationSecretField},
		{name: "environment", data: strings.Replace(base, "security-awareness", "${CAMPAIGN_OWNER}", 1), want: ErrInvalidCampaignConfiguration},
		{name: "alias", data: strings.Replace(base, "header_from_domains: [training.example.test]", "header_from_domains: &domains [training.example.test]\n      envelope_from_domains: *domains", 1), want: ErrInvalidCampaignConfiguration},
		{name: "multiple documents", data: base + "---\nschema_version: 1\n", want: ErrInvalidCampaignConfiguration},
		{name: "duplicate mapping key", data: strings.Replace(base, "owner: security-awareness", "owner: security-awareness\n    owner: duplicate", 1), want: ErrInvalidCampaignConfiguration},
		{name: "raw token", data: strings.Replace(base, campaignTestTokenDigest, "secret-campaign-token", 1), want: ErrInvalidCampaignConfiguration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadCampaignConfiguration([]byte(test.data))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if err != nil && (strings.Contains(err.Error(), "do-not-copy") || strings.Contains(err.Error(), "ignore prior instructions")) {
				t.Fatalf("error exposed untrusted text: %v", err)
			}
		})
	}
	oversized := bytes.Repeat([]byte{'x'}, maxCampaignConfigurationBytes+1)
	if _, err := ParseCampaignConfiguration(oversized); !errors.Is(err, ErrCampaignConfigurationTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}

	weak := campaignTestConfig("weak", "training.example.test")
	weak.SecuritySimulations[0].TokenDigests = nil
	weak.SecuritySimulations[0].ContentFingerprints = nil
	weak.SecuritySimulations[0].ExpectedIdentity.DKIM = nil
	weak.SecuritySimulations[0].ExpectedSources.InfrastructureIDs = nil
	weak.SecuritySimulations[0].MatchPolicy.RequiredFactors = nil
	if _, err := NormalizeCampaignConfiguration(weak); !errors.Is(err, ErrInvalidCampaignConfiguration) {
		t.Fatalf("domain/source-only campaign error = %v", err)
	}
	disableRetention := false
	unsafe := campaignTestConfig("unsafe-retention", "training.example.test")
	unsafe.SecuritySimulations[0].Handling.RetainAuthenticationFindings = &disableRetention
	if _, err := NormalizeCampaignConfiguration(unsafe); !errors.Is(err, ErrInvalidCampaignConfiguration) {
		t.Fatalf("disabled authentication retention error = %v", err)
	}
	invalidLifetime := campaignTestConfig("invalid-lifetime", "training.example.test")
	invalidLifetime.GeneratedAt = invalidLifetime.ExpiresAt.Add(time.Hour)
	if _, err := NormalizeCampaignConfiguration(invalidLifetime); !errors.Is(err, ErrInvalidCampaignConfiguration) {
		t.Fatalf("generation-after-expiration error = %v", err)
	}
}

func TestCampaignConfigurationReaderPropagatesReadErrors(t *testing.T) {
	reader := &campaignErrorReader{data: []byte(campaignTestYAML("reader", "training.example.test")), err: errors.New("read failed")}
	if _, err := ParseCampaignConfigurationReader(reader); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("reader error = %v", err)
	}
	if _, err := ParseCampaignConfigurationReader(nil); !errors.Is(err, ErrInvalidCampaignConfiguration) {
		t.Fatalf("nil reader error = %v", err)
	}
}

type campaignErrorReader struct {
	data []byte
	err  error
	done bool
}

func (reader *campaignErrorReader) Read(buffer []byte) (int, error) {
	if !reader.done {
		reader.done = true
		return copy(buffer, reader.data), reader.err
	}
	return 0, reader.err
}

func campaignTestConfig(id, headerFrom string) CampaignConfigurationConfig {
	generatedAt := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	effectiveAt := generatedAt
	return CampaignConfigurationConfig{
		SchemaVersion: CampaignConfigurationSchemaVersion,
		GeneratedAt:   generatedAt,
		EffectiveAt:   &effectiveAt,
		ExpiresAt:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		SecuritySimulations: []SecuritySimulationCampaignConfig{{
			ID: id, ExternalCampaignID: "campaign-1234",
			Provider:     CampaignProviderConfig{Type: CampaignProviderSelfHosted, ID: "corporate-awareness", Name: "Corporate Awareness"},
			Organization: "primary", Entity: "corporate", BusinessUnit: "security", Owner: "security-awareness", ApprovalReference: "SEC-1234",
			Status: CampaignStatusActive, CreatedAt: generatedAt,
			ValidFrom: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2026, 7, 20, 23, 59, 59, 0, time.UTC),
			RecipientDomains: []string{"example.test"}, RecipientScopeIDs: []string{"all-employees"},
			ExpectedIdentity: CampaignExpectedIdentityConfig{
				HeaderFromDomains: []string{headerFrom}, EnvelopeFromDomains: []string{"bounce.training.example.test"},
				DKIM:             []CampaignDKIMIdentityConfig{{Domain: headerFrom, Selectors: []string{"simulation-2026"}}},
				MessageIDDomains: []string{headerFrom},
			},
			ExpectedSources: CampaignExpectedSourcesConfig{CIDRs: []string{"192.0.2.0/24"}, Hostnames: []string{"outbound.training.example.test"}, InfrastructureIDs: []string{"tenant-route-1"}},
			TokenDigests:    []string{campaignTestTokenDigest}, URLDomains: []string{"landing.example.test"}, ContentFingerprints: []string{campaignTestContentDigest},
			Authentication:     CampaignAuthenticationConfig{DMARC: CampaignAuthenticationRequired, SPF: CampaignAuthenticationRequired, DKIM: CampaignAuthenticationRequired},
			DeliveryExceptions: []string{"advanced-delivery-1"},
			ResponsePolicy:     CampaignResponsePolicyConfig{EmployeeDisclosure: CampaignDisclosureProhibited, EmployeeTemplateID: "suspicious-message-received", AnalystVisibility: CampaignVisibilityFull, CampaignOwnerVisibility: CampaignVisibilityFull},
			Handling:           CampaignHandlingConfig{WorkflowID: "simulation-reported-message", AutomaticDispositionEligible: true},
			MatchPolicy: CampaignMatchPolicyConfig{RequiredFactors: []CampaignMatchFactor{
				CampaignFactorWindow, CampaignFactorOrganizationScope, CampaignFactorHeaderFrom, CampaignFactorDKIM, CampaignFactorTokenDigest, CampaignFactorAuthentication,
			}},
		}},
	}
}

func campaignTestYAML(id, headerFrom string) string {
	return "schema_version: 1\n" +
		"generated_at: 2026-07-01T00:00:00Z\n" +
		"effective_at: 2026-07-01T00:00:00Z\n" +
		"expires_at: 2026-08-01T00:00:00Z\n" +
		"security_simulations:\n" +
		"  - id: " + id + "\n" +
		"    external_campaign_id: campaign-1234\n" +
		"    provider:\n" +
		"      type: self_hosted\n" +
		"      id: corporate-awareness\n" +
		"      name: Corporate Awareness\n" +
		"    organization: primary\n" +
		"    entity: corporate\n" +
		"    business_unit: security\n" +
		"    owner: security-awareness\n" +
		"    approval_reference: SEC-1234\n" +
		"    status: active\n" +
		"    created_at: 2026-07-01T00:00:00Z\n" +
		"    valid_from: 2026-07-10T00:00:00Z\n" +
		"    valid_until: 2026-07-20T23:59:59Z\n" +
		"    recipient_domains: [example.test]\n" +
		"    recipient_scope_ids: [all-employees]\n" +
		"    expected_identity:\n" +
		"      header_from_domains: [" + headerFrom + "]\n" +
		"      envelope_from_domains: [bounce.training.example.test]\n" +
		"      dkim:\n" +
		"        - domain: " + headerFrom + "\n" +
		"          selectors: [simulation-2026]\n" +
		"      message_id_domains: [" + headerFrom + "]\n" +
		"    expected_sources:\n" +
		"      cidrs: [192.0.2.0/24]\n" +
		"      hostnames: [outbound.training.example.test]\n" +
		"      infrastructure_ids: [tenant-route-1]\n" +
		"    campaign_token_digests: [" + campaignTestTokenDigest + "]\n" +
		"    url_domains: [landing.example.test]\n" +
		"    content_fingerprints: [" + campaignTestContentDigest + "]\n" +
		"    authentication: {dmarc: required, spf: required, dkim: required}\n" +
		"    delivery_exception_ids: [advanced-delivery-1]\n" +
		"    response_policy:\n" +
		"      employee_disclosure: prohibited\n" +
		"      employee_template_id: suspicious-message-received\n" +
		"      analyst_visibility: full\n" +
		"      campaign_owner_visibility: full\n" +
		"    handling:\n" +
		"      workflow_id: simulation-reported-message\n" +
		"      retain_authentication_findings: true\n" +
		"      automatic_disposition_eligible: true\n" +
		"    match_policy:\n" +
		"      required_factors: [campaign_window, organization_scope, header_from_domain, dkim_identity, campaign_token_digest, authentication]\n"
}

func compileCampaignSchema(t *testing.T, id string, data []byte) *jsonschema.Schema {
	t.Helper()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(id, document); err != nil {
		t.Fatal(err)
	}
	validator, err := compiler.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}
