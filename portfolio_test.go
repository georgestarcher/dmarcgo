package dmarcgo

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadSyntheticPortfolioAndInheritance(t *testing.T) {
	portfolio := loadSyntheticPortfolio(t)
	if portfolio.SchemaVersion() != PortfolioSchemaVersion || portfolio.Digest() == "" {
		t.Fatalf("unexpected portfolio metadata: version=%d digest=%q", portfolio.SchemaVersion(), portfolio.Digest())
	}
	if got := portfolio.Organization().ID; got != "example-group" {
		t.Fatalf("organization ID = %q", got)
	}
	entities := portfolio.Entities()
	if len(entities) != 3 {
		t.Fatalf("entity count = %d, want 3", len(entities))
	}

	corporate := findEntity(t, entities, "corporate")
	root := findDomain(t, corporate.Domains, "example.test")
	child := findDomain(t, corporate.Domains, "marketing.example.test")
	if child.Owner != root.Owner || child.Owner != "mail-team" {
		t.Fatalf("child owner = %q, root owner = %q", child.Owner, root.Owner)
	}
	if child.Policy != "dkim-required" {
		t.Fatalf("child policy = %q", child.Policy)
	}
	if !slices.Equal(child.Records.SPF, []string{"example.test", "marketing.example.test"}) {
		t.Fatalf("inherited SPF names = %v", child.Records.SPF)
	}
	if !slices.Equal(child.ExpectedSenders, []string{"shared-workspace", "transactional-mail"}) {
		t.Fatalf("inherited expected senders = %v", child.ExpectedSenders)
	}
	if len(child.Exclusions) != 1 || child.Exclusions[0].ID != "accepted-transition" {
		t.Fatalf("inherited exclusions = %+v", child.Exclusions)
	}

	sister := findEntity(t, entities, "sister-company")
	sisterDomain := findDomain(t, sister.Domains, "example-sister.test")
	if !slices.Contains(sisterDomain.ExpectedSenders, "shared-workspace") || !slices.Contains(sisterDomain.Records.DKIM, "shared._domainkey.shared-mail.example.test") {
		t.Fatalf("sister shared configuration missing: %+v", sisterDomain)
	}

	acquired := findEntity(t, entities, "acquired-unit")
	if acquired.Owner != "mail-team" || !slices.Equal(acquired.Tags, []string{"central", "migration", "production"}) {
		t.Fatalf("entity inheritance = %+v", acquired)
	}
}

func TestPortfolioAccessorsReturnDefensiveCopies(t *testing.T) {
	portfolio := loadSyntheticPortfolio(t)
	entities := portfolio.Entities()
	entities[0].Tags[0] = "changed"
	entities[0].Domains[0].Records.SPF[0] = "changed.example"
	owners := portfolio.Owners()
	owners[0].Tags = append(owners[0].Tags, "changed")
	policies := portfolio.Policies()
	policies[0].AllowedSelectors[0] = "changed"
	senders := portfolio.ExpectedSenders()
	senders[0].Policy.AllowedSelectors = append(senders[0].Policy.AllowedSelectors, "changed")

	fresh := portfolio.Entities()
	if slices.Contains(fresh[0].Tags, "changed") || slices.Contains(fresh[0].Domains[0].Records.SPF, "changed.example") {
		t.Fatal("entity accessor exposed internal slices")
	}
	if slices.Contains(portfolio.Owners()[0].Tags, "changed") || slices.Contains(portfolio.Policies()[0].AllowedSelectors, "changed") || slices.Contains(portfolio.ExpectedSenders()[0].Policy.AllowedSelectors, "changed") {
		t.Fatal("portfolio accessor exposed internal slices")
	}
}

func TestYAMLAndProgrammaticPortfolioNormalizationMatch(t *testing.T) {
	data, err := os.ReadFile("testdata/portfolio/large-synthetic.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParsePortfolioYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	fromConfig, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := LoadPortfolioYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	if fromConfig.Digest() != fromYAML.Digest() {
		t.Fatalf("normalization digests differ: %q != %q", fromConfig.Digest(), fromYAML.Digest())
	}

	reversePortfolioConfig(&config)
	reordered, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	if reordered.Digest() != fromYAML.Digest() {
		t.Fatalf("input ordering changed digest: %q != %q", reordered.Digest(), fromYAML.Digest())
	}
}

func TestDomainCollectionReplacement(t *testing.T) {
	config := minimalPortfolioConfig()
	config.Entities[0].Domains = append(config.Entities[0].Domains, DomainConfig{
		Name:   "child.example.test",
		Parent: "example.test",
		Records: MonitoredRecordsConfig{
			SPF: []string{"child.example.test"},
		},
		ExpectedSenders: []string{},
		Inheritance: DomainInheritanceConfig{
			Records:         CollectionModeReplace,
			ExpectedSenders: CollectionModeReplace,
			Tags:            CollectionModeReplace,
			Exclusions:      CollectionModeReplace,
		},
	})
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	child := findDomain(t, portfolio.Entities()[0].Domains, "child.example.test")
	if !slices.Equal(child.Records.SPF, []string{"child.example.test"}) || len(child.Records.DMARC) != 0 || len(child.ExpectedSenders) != 0 || len(child.Tags) != 0 || len(child.Exclusions) != 0 {
		t.Fatalf("replace semantics failed: %+v", child)
	}
}

func TestPortfolioInternationalizedNamesNormalize(t *testing.T) {
	config := minimalPortfolioConfig()
	config.Entities[0].Domains[0] = DomainConfig{
		Name: "BÜCHER.Example.",
		Records: MonitoredRecordsConfig{
			SPF:   []string{"BÜCHER.Example."},
			DKIM:  []string{"S1._domainkey.BÜCHER.Example."},
			DMARC: []string{"_dmarc.BÜCHER.Example."},
		},
		ExpectedSenders: []string{"sender"},
	}
	portfolio, err := NormalizePortfolio(config)
	if err != nil {
		t.Fatal(err)
	}
	domain := portfolio.Entities()[0].Domains[0]
	if domain.Name != "xn--bcher-kva.example" || domain.Records.DKIM[0] != "s1._domainkey.xn--bcher-kva.example" {
		t.Fatalf("internationalized normalization = %+v", domain)
	}
}

func TestPortfolioEnvironmentExpansionIsExplicit(t *testing.T) {
	data := []byte("schema_version: 1\norganization:\n  id: ${ORG_ID}\nentities:\n  - id: primary\n    domains:\n      - name: ${DOMAIN}\n        records:\n          spf: [\"${DOMAIN}\"]\n          dmarc: [\"_dmarc.${DOMAIN}\"]\n        expected_senders: [sender]\nexpected_senders:\n  - id: sender\n    require_either: true\n")
	if _, err := LoadPortfolioYAML(data); !errors.Is(err, ErrPortfolioEnvironmentDisabled) {
		t.Fatalf("disabled expansion error = %v", err)
	}
	missing := WithPortfolioEnvironment(func(string) (string, bool) { return "", false })
	if _, err := LoadPortfolioYAML(data, missing); !errors.Is(err, ErrPortfolioEnvironmentMissing) {
		t.Fatalf("missing expansion error = %v", err)
	}
	values := map[string]string{"ORG_ID": "example-org", "DOMAIN": "example.test"}
	portfolio, err := LoadPortfolioYAML(data, WithPortfolioEnvironment(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}))
	if err != nil {
		t.Fatal(err)
	}
	if portfolio.Organization().ID != "example-org" || portfolio.Entities()[0].Domains[0].Name != "example.test" {
		t.Fatalf("expanded portfolio = %+v", portfolio.Entities())
	}
}

func TestPortfolioYAMLRejectsUnknownSecretAliasAndMultipleDocuments(t *testing.T) {
	tests := []struct {
		name string
		data string
		want error
	}{
		{name: "unknown", data: "schema_version: 1\norganization: {id: example}\nentities: [{id: primary}]\nuntrusted_value: do-not-copy\n", want: ErrInvalidPortfolioYAML},
		{name: "secret", data: "schema_version: 1\norganization: {id: example, api_token: do-not-copy}\nentities: [{id: primary}]\n", want: ErrPortfolioSecretField},
		{name: "alias", data: "schema_version: 1\norganization: &org {id: example}\nentities: [{id: primary, name: *org}]\n", want: ErrInvalidPortfolioYAML},
		{name: "multiple", data: "schema_version: 1\norganization: {id: example}\nentities: [{id: primary}]\n---\nschema_version: 1\n", want: ErrInvalidPortfolioYAML},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParsePortfolioYAML([]byte(test.data))
			if !errors.Is(err, test.want) {
				t.Fatalf("ParsePortfolioYAML() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "do-not-copy") {
				t.Fatalf("error exposed an untrusted value: %v", err)
			}
		})
	}
}

func TestPortfolioValidationDiagnostics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PortfolioConfig)
		code   DiagnosticCode
	}{
		{name: "duplicate IDs", mutate: func(config *PortfolioConfig) {
			config.ExpectedSenders = append(config.ExpectedSenders, config.ExpectedSenders[0])
		}, code: "configuration.sender.duplicate_id"},
		{name: "contradictory policy", mutate: func(config *PortfolioConfig) { config.ExpectedSenders[0].RequireDKIM = true }, code: "configuration.policy.contradictory_requirements"},
		{name: "duplicate record identity", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.SPF = append(config.Entities[0].Domains[0].Records.SPF, "EXAMPLE.TEST.")
		}, code: "configuration.record.duplicate_name"},
		{name: "unknown sender", mutate: func(config *PortfolioConfig) { config.Entities[0].Domains[0].ExpectedSenders = []string{"missing"} }, code: "configuration.domain.unknown_sender"},
		{name: "invalid DKIM name", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.DKIM = []string{"not-dkim.example.test"}
		}, code: "configuration.record.invalid_name"},
		{name: "DMARC marker before DKIM marker", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.DMARC = []string{"_dmarc._domainkey.example.test"}
		}, code: "configuration.record.invalid_name"},
		{name: "DMARC marker in DKIM domain", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.DKIM = []string{"s1._domainkey._dmarc.example.test"}
		}, code: "configuration.record.invalid_name"},
		{name: "IP record name", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.SPF = []string{"192.0.2.1"}
		}, code: "configuration.record.invalid_name"},
		{name: "IDN record name expanded beyond DNS limit", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.SPF = []string{strings.Repeat("é.", 40) + "example"}
		}, code: "configuration.record.invalid_name"},
		{name: "IDN record label expanded beyond DNS limit", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Records.SPF = []string{"一俷凮句嗜埓姊寁嶸徯憦掝斔枋概歹浰潧煞獕.example"}
		}, code: "configuration.record.invalid_name"},
		{name: "entity parent cycle", mutate: func(config *PortfolioConfig) {
			config.Entities = append(config.Entities, EntityConfig{ID: "second", Parent: "primary"})
			config.Entities[0].Parent = "second"
		}, code: "configuration.entity.parent_cycle"},
		{name: "domain parent cycle", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains = append(config.Entities[0].Domains, DomainConfig{Name: "child.example.test", Parent: "example.test"})
			config.Entities[0].Domains[0].Parent = "child.example.test"
		}, code: "configuration.domain.parent_cycle"},
		{name: "invalid exclusion", mutate: func(config *PortfolioConfig) {
			config.Entities[0].Domains[0].Exclusions = []ScopedExclusionConfig{{ID: "exception", Scope: ExclusionScopeSender}}
		}, code: "configuration.exclusion.missing_owner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := minimalPortfolioConfig()
			test.mutate(&config)
			_, err := NormalizePortfolio(config)
			var validationError *PortfolioValidationError
			if !errors.As(err, &validationError) || !hasDiagnosticCode(validationError.Diagnostics(), test.code) {
				t.Fatalf("NormalizePortfolio() error = %v diagnostics=%+v, want code %q", err, diagnosticsFromError(err), test.code)
			}
		})
	}
}

func TestPortfolioConflictingOwnership(t *testing.T) {
	config := minimalPortfolioConfig()
	config.Owners = []OwnerConfig{{ID: "one"}, {ID: "two"}}
	config.Entities[0].Owner = "one"
	config.Entities = append(config.Entities, EntityConfig{ID: "aaa-unowned", Domains: []DomainConfig{{Name: "unowned.example.test", Records: MonitoredRecordsConfig{DKIM: []string{"s1._domainkey.shared.example.test"}}}}})
	config.Entities = append(config.Entities, EntityConfig{ID: "second", Owner: "two", Domains: []DomainConfig{{Name: "second.example.test", Records: MonitoredRecordsConfig{DKIM: []string{"s1._domainkey.shared.example.test"}}}}})
	config.Entities[0].Domains[0].Records.DKIM = []string{"s1._domainkey.shared.example.test"}
	_, err := NormalizePortfolio(config)
	var validationError *PortfolioValidationError
	if !errors.As(err, &validationError) || !hasDiagnosticCode(validationError.Diagnostics(), "configuration.ownership.record_conflict") {
		t.Fatalf("ownership error = %v diagnostics=%+v", err, diagnosticsFromError(err))
	}
}

func TestConfigurationValidationResultIsDeterministicAndValueSafe(t *testing.T) {
	config := minimalPortfolioConfig()
	config.Organization.ID = "DO NOT DISCLOSE THIS VALUE"
	first := ValidatePortfolio(config, outputTestTime)
	second := ValidatePortfolio(config, outputTestTime)
	if first.Metadata.Mode != AnalysisModeConfigurationValidation || first.Metadata.Evaluation.State != EvaluationStateEvaluated || !first.Metadata.GeneratedAt.Equal(outputTestTime) {
		t.Fatalf("validation metadata = %+v", first.Metadata)
	}
	if len(first.Diagnostics) == 0 || !slices.Equal(first.Diagnostics, second.Diagnostics) {
		t.Fatalf("validation diagnostics are not deterministic: %+v %+v", first.Diagnostics, second.Diagnostics)
	}
	for _, diagnostic := range first.Diagnostics {
		if strings.Contains(diagnostic.Message, config.Organization.ID) {
			t.Fatalf("diagnostic exposed configuration value: %+v", diagnostic)
		}
	}
}

func TestPortfolioErrorAndResultContracts(t *testing.T) {
	config := minimalPortfolioConfig()
	config.SchemaVersion = PortfolioSchemaVersion + 1
	_, err := NormalizePortfolio(config)
	if !errors.Is(err, ErrInvalidPortfolio) {
		t.Fatalf("NormalizePortfolio() error = %v, want ErrInvalidPortfolio", err)
	}
	var validationError *PortfolioValidationError
	if !errors.As(err, &validationError) || !hasDiagnosticCode(validationError.Diagnostics(), "configuration.schema.unsupported") {
		t.Fatalf("validation error diagnostics = %+v", diagnosticsFromError(err))
	}
	if strings.Contains(err.Error(), config.Organization.ID) {
		t.Fatalf("validation error exposed configuration data: %v", err)
	}

	_, err = ParsePortfolioYAML([]byte("schema_version: 2\norganization: {id: example}\nentities: [{id: primary}]\n"))
	if !errors.Is(err, ErrUnsupportedPortfolioSchema) {
		t.Fatalf("schema error = %v, want ErrUnsupportedPortfolioSchema", err)
	}

	result := ValidatePortfolio(minimalPortfolioConfig(), outputTestTime)
	var shared Result = result
	if metadata := shared.ResultMetadata(); metadata.Mode != AnalysisModeConfigurationValidation || metadata.ContractVersion != AnalysisContractVersion {
		t.Fatalf("configuration result metadata = %+v", metadata)
	}
}

func TestPrivateDNSRecordNotesLoadWithoutNetwork(t *testing.T) {
	paths, err := filepath.Glob("test_dmarc_reports/*-records.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("private DNS record notes are not present")
	}

	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	calls := 0
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("unexpected DNS access")
	}}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var config PortfolioConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		portfolioOnly, err := yaml.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		portfolio, err := LoadPortfolioYAML(portfolioOnly)
		if err != nil {
			t.Fatal(err)
		}
		entities := portfolio.Entities()
		if len(entities) == 0 || len(entities[0].Domains) == 0 || portfolio.Digest() == "" {
			t.Fatal("private DNS record notes did not produce a complete portfolio")
		}
	}
	if calls != 0 {
		t.Fatalf("portfolio loading performed %d DNS lookups", calls)
	}
}

func TestPortfolioYAMLSizeLimit(t *testing.T) {
	_, err := ParsePortfolioYAML(make([]byte, maxPortfolioYAMLBytes+1))
	if !errors.Is(err, ErrPortfolioTooLarge) {
		t.Fatalf("size error = %v", err)
	}
}

func FuzzParsePortfolioYAML(f *testing.F) {
	data, err := os.ReadFile("testdata/portfolio/large-synthetic.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte("schema_version: 1\norganization: {id: example}\nentities: [{id: primary}]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPortfolioYAMLBytes+1 {
			return
		}
		_, _ = ParsePortfolioYAML(data)
	})
}

func BenchmarkNormalizePortfolio(b *testing.B) {
	data, err := os.ReadFile("testdata/portfolio/large-synthetic.yaml")
	if err != nil {
		b.Fatal(err)
	}
	config, err := ParsePortfolioYAML(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NormalizePortfolio(config); err != nil {
			b.Fatal(err)
		}
	}
}

func loadSyntheticPortfolio(t *testing.T) Portfolio {
	t.Helper()
	data, err := os.ReadFile("testdata/portfolio/large-synthetic.yaml")
	if err != nil {
		t.Fatal(err)
	}
	portfolio, err := LoadPortfolioYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	return portfolio
}

func minimalPortfolioConfig() PortfolioConfig {
	return PortfolioConfig{
		SchemaVersion: PortfolioSchemaVersion,
		Organization:  OrganizationConfig{ID: "example"},
		ExpectedSenders: []ExpectedSenderConfig{{
			ID:            "sender",
			RequireEither: true,
		}},
		Entities: []EntityConfig{{
			ID: "primary",
			Domains: []DomainConfig{{
				Name: "example.test",
				Records: MonitoredRecordsConfig{
					SPF:   []string{"example.test"},
					DKIM:  []string{"s1._domainkey.example.test"},
					DMARC: []string{"_dmarc.example.test"},
				},
				ExpectedSenders: []string{"sender"},
			}},
		}},
	}
}

func reversePortfolioConfig(config *PortfolioConfig) {
	slices.Reverse(config.Owners)
	slices.Reverse(config.Policies)
	slices.Reverse(config.ExpectedSenders)
	slices.Reverse(config.Entities)
	for entityIndex := range config.Entities {
		slices.Reverse(config.Entities[entityIndex].Tags)
		slices.Reverse(config.Entities[entityIndex].Domains)
		for domainIndex := range config.Entities[entityIndex].Domains {
			domain := &config.Entities[entityIndex].Domains[domainIndex]
			slices.Reverse(domain.Tags)
			slices.Reverse(domain.Records.SPF)
			slices.Reverse(domain.Records.DKIM)
			slices.Reverse(domain.Records.DMARC)
			slices.Reverse(domain.ExpectedSenders)
			slices.Reverse(domain.Exclusions)
		}
	}
}

func findEntity(t *testing.T, entities []Entity, id string) Entity {
	t.Helper()
	for _, entity := range entities {
		if entity.ID == id {
			return entity
		}
	}
	t.Fatalf("entity %q not found", id)
	return Entity{}
}

func findDomain(t *testing.T, domains []MonitoredDomain, name string) MonitoredDomain {
	t.Helper()
	for _, domain := range domains {
		if domain.Name == name {
			return domain
		}
	}
	t.Fatalf("domain %q not found", name)
	return MonitoredDomain{}
}

func hasDiagnosticCode(diagnostics []ConfigurationDiagnostic, code DiagnosticCode) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func diagnosticsFromError(err error) []ConfigurationDiagnostic {
	var validationError *PortfolioValidationError
	if errors.As(err, &validationError) {
		return validationError.Diagnostics()
	}
	return nil
}
