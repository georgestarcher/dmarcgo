package dmarcgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// PortfolioSchemaVersion is the supported organization-portfolio schema.
const PortfolioSchemaVersion = 1

var (
	// ErrInvalidPortfolio identifies a portfolio that cannot be normalized.
	ErrInvalidPortfolio = errors.New("invalid portfolio configuration")
	// ErrUnsupportedPortfolioSchema identifies an unsupported schema version.
	ErrUnsupportedPortfolioSchema = errors.New("unsupported portfolio schema version")
)

// CollectionMode controls how a child domain combines an inherited collection.
type CollectionMode string

const (
	// CollectionModeMerge combines, deduplicates, and sorts parent and child values.
	CollectionModeMerge CollectionMode = "merge"
	// CollectionModeReplace discards the inherited collection before applying child values.
	CollectionModeReplace CollectionMode = "replace"
)

// ExclusionScope identifies what a caller-owned exclusion applies to.
type ExclusionScope string

const (
	ExclusionScopeDomain     ExclusionScope = "domain"
	ExclusionScopeSubdomains ExclusionScope = "subdomains"
	ExclusionScopeRecord     ExclusionScope = "record"
	ExclusionScopeSender     ExclusionScope = "sender"
)

// PortfolioConfig is the mutable programmatic and YAML input model.
type PortfolioConfig struct {
	SchemaVersion   int                          `json:"schema_version" yaml:"schema_version"`
	Organization    OrganizationConfig           `json:"organization" yaml:"organization"`
	Owners          []OwnerConfig                `json:"owners,omitempty" yaml:"owners,omitempty"`
	Policies        []AuthenticationPolicyConfig `json:"policies,omitempty" yaml:"policies,omitempty"`
	ExpectedSenders []ExpectedSenderConfig       `json:"expected_senders,omitempty" yaml:"expected_senders,omitempty"`
	Entities        []EntityConfig               `json:"entities" yaml:"entities"`
}

// OrganizationConfig identifies the organization represented by a portfolio.
type OrganizationConfig struct {
	ID    string   `json:"id" yaml:"id"`
	Name  string   `json:"name,omitempty" yaml:"name,omitempty"`
	Owner string   `json:"owner,omitempty" yaml:"owner,omitempty"`
	Tags  []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// OwnerConfig defines reusable ownership metadata. Contact may contain an
// internal routing address; validation diagnostics never copy it.
type OwnerConfig struct {
	ID      string   `json:"id" yaml:"id"`
	Name    string   `json:"name,omitempty" yaml:"name,omitempty"`
	Contact string   `json:"contact,omitempty" yaml:"contact,omitempty"`
	Tags    []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// AuthenticationPolicyConfig defines reusable sender authentication requirements.
type AuthenticationPolicyConfig struct {
	ID               string   `json:"id" yaml:"id"`
	RequireDKIM      bool     `json:"require_dkim,omitempty" yaml:"require_dkim,omitempty"`
	RequireSPF       bool     `json:"require_spf,omitempty" yaml:"require_spf,omitempty"`
	RequireEither    bool     `json:"require_either,omitempty" yaml:"require_either,omitempty"`
	AllowedSelectors []string `json:"allowed_selectors,omitempty" yaml:"allowed_selectors,omitempty"`
}

// ExpectedSenderConfig defines a reusable sending service. Policy references a
// reusable policy; when empty, the requirement fields define an inline policy.
type ExpectedSenderConfig struct {
	ID               string   `json:"id" yaml:"id"`
	Name             string   `json:"name,omitempty" yaml:"name,omitempty"`
	Provider         string   `json:"provider,omitempty" yaml:"provider,omitempty"`
	Owner            string   `json:"owner,omitempty" yaml:"owner,omitempty"`
	Tags             []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Policy           string   `json:"policy,omitempty" yaml:"policy,omitempty"`
	RequireDKIM      bool     `json:"require_dkim,omitempty" yaml:"require_dkim,omitempty"`
	RequireSPF       bool     `json:"require_spf,omitempty" yaml:"require_spf,omitempty"`
	RequireEither    bool     `json:"require_either,omitempty" yaml:"require_either,omitempty"`
	AllowedSelectors []string `json:"allowed_selectors,omitempty" yaml:"allowed_selectors,omitempty"`
}

// EntityConfig defines a business unit, subsidiary, acquisition, or sister organization.
type EntityConfig struct {
	ID      string         `json:"id" yaml:"id"`
	Name    string         `json:"name,omitempty" yaml:"name,omitempty"`
	Parent  string         `json:"parent,omitempty" yaml:"parent,omitempty"`
	Owner   string         `json:"owner,omitempty" yaml:"owner,omitempty"`
	Tags    []string       `json:"tags,omitempty" yaml:"tags,omitempty"`
	Domains []DomainConfig `json:"domains,omitempty" yaml:"domains,omitempty"`
}

// DomainConfig defines one root or explicit subdomain and the record names to monitor.
type DomainConfig struct {
	Name              string                  `json:"name" yaml:"name"`
	Parent            string                  `json:"parent,omitempty" yaml:"parent,omitempty"`
	IncludeSubdomains bool                    `json:"include_subdomains,omitempty" yaml:"include_subdomains,omitempty"`
	Owner             string                  `json:"owner,omitempty" yaml:"owner,omitempty"`
	Tags              []string                `json:"tags,omitempty" yaml:"tags,omitempty"`
	Policy            string                  `json:"policy,omitempty" yaml:"policy,omitempty"`
	Records           MonitoredRecordsConfig  `json:"records,omitempty" yaml:"records,omitempty"`
	ExpectedSenders   []string                `json:"expected_senders,omitempty" yaml:"expected_senders,omitempty"`
	Exclusions        []ScopedExclusionConfig `json:"exclusions,omitempty" yaml:"exclusions,omitempty"`
	Inheritance       DomainInheritanceConfig `json:"inheritance,omitempty" yaml:"inheritance,omitempty"`
}

// DomainInheritanceConfig controls inherited collection behavior. Empty values mean merge.
type DomainInheritanceConfig struct {
	Tags            CollectionMode `json:"tags,omitempty" yaml:"tags,omitempty"`
	Records         CollectionMode `json:"records,omitempty" yaml:"records,omitempty"`
	ExpectedSenders CollectionMode `json:"expected_senders,omitempty" yaml:"expected_senders,omitempty"`
	Exclusions      CollectionMode `json:"exclusions,omitempty" yaml:"exclusions,omitempty"`
}

// MonitoredRecordsConfig lists complete DNS names, never record values.
type MonitoredRecordsConfig struct {
	SPF   []string `json:"spf,omitempty" yaml:"spf,omitempty"`
	DKIM  []string `json:"dkim,omitempty" yaml:"dkim,omitempty"`
	DMARC []string `json:"dmarc,omitempty" yaml:"dmarc,omitempty"`
}

// ScopedExclusionConfig records a caller-owned exception with accountability metadata.
type ScopedExclusionConfig struct {
	ID        string         `json:"id" yaml:"id"`
	Owner     string         `json:"owner" yaml:"owner"`
	Reason    string         `json:"reason" yaml:"reason"`
	Scope     ExclusionScope `json:"scope" yaml:"scope"`
	Target    string         `json:"target,omitempty" yaml:"target,omitempty"`
	CreatedAt time.Time      `json:"created_at" yaml:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// ConfigurationDiagnostic is a value-safe portfolio validation finding.
type ConfigurationDiagnostic struct {
	Code     DiagnosticCode     `json:"code"`
	Severity ValidationSeverity `json:"severity"`
	Path     string             `json:"path"`
	Message  string             `json:"message"`
}

// ConfigurationValidationResult is a completed configuration-validation result.
type ConfigurationValidationResult struct {
	Metadata    ResultMetadata            `json:"metadata"`
	Diagnostics []ConfigurationDiagnostic `json:"diagnostics"`
}

// ResultMetadata returns configuration-validation metadata without I/O.
func (result ConfigurationValidationResult) ResultMetadata() ResultMetadata { return result.Metadata }

// PortfolioValidationError contains value-safe diagnostics for an invalid portfolio.
type PortfolioValidationError struct {
	diagnostics []ConfigurationDiagnostic
}

// Error reports the number of diagnostics without copying configuration values.
func (err *PortfolioValidationError) Error() string {
	return fmt.Sprintf("%s: %d diagnostic(s)", ErrInvalidPortfolio, len(err.diagnostics))
}

// Unwrap supports errors.Is with ErrInvalidPortfolio.
func (err *PortfolioValidationError) Unwrap() error { return ErrInvalidPortfolio }

// Diagnostics returns a defensive copy of value-safe diagnostics.
func (err *PortfolioValidationError) Diagnostics() []ConfigurationDiagnostic {
	return append([]ConfigurationDiagnostic(nil), err.diagnostics...)
}

// Organization is normalized organization metadata.
type Organization struct {
	ID    string   `json:"id"`
	Name  string   `json:"name,omitempty"`
	Owner string   `json:"owner,omitempty"`
	Tags  []string `json:"tags"`
}

// Owner is normalized reusable ownership metadata.
type Owner struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Contact string   `json:"contact,omitempty"`
	Tags    []string `json:"tags"`
}

// AuthenticationPolicy is a normalized authentication requirement.
type AuthenticationPolicy struct {
	ID               string   `json:"id"`
	RequireDKIM      bool     `json:"require_dkim"`
	RequireSPF       bool     `json:"require_spf"`
	RequireEither    bool     `json:"require_either"`
	AllowedSelectors []string `json:"allowed_selectors"`
}

// ExpectedSender is a normalized reusable sending service.
type ExpectedSender struct {
	ID       string               `json:"id"`
	Name     string               `json:"name,omitempty"`
	Provider string               `json:"provider,omitempty"`
	Owner    string               `json:"owner,omitempty"`
	Tags     []string             `json:"tags"`
	Policy   AuthenticationPolicy `json:"policy"`
}

// Entity is a normalized organizational entity.
type Entity struct {
	ID      string            `json:"id"`
	Name    string            `json:"name,omitempty"`
	Parent  string            `json:"parent,omitempty"`
	Owner   string            `json:"owner,omitempty"`
	Tags    []string          `json:"tags"`
	Domains []MonitoredDomain `json:"domains"`
}

// MonitoredDomain is a normalized effective domain configuration.
type MonitoredDomain struct {
	Name              string            `json:"name"`
	Parent            string            `json:"parent,omitempty"`
	IncludeSubdomains bool              `json:"include_subdomains"`
	Owner             string            `json:"owner,omitempty"`
	Tags              []string          `json:"tags"`
	Policy            string            `json:"policy,omitempty"`
	Records           MonitoredRecords  `json:"records"`
	ExpectedSenders   []string          `json:"expected_senders"`
	Exclusions        []ScopedExclusion `json:"exclusions"`
}

// MonitoredRecords contains normalized complete record names.
type MonitoredRecords struct {
	SPF   []string `json:"spf"`
	DKIM  []string `json:"dkim"`
	DMARC []string `json:"dmarc"`
}

// ScopedExclusion is a normalized caller-owned exception.
type ScopedExclusion struct {
	ID        string         `json:"id"`
	Owner     string         `json:"owner"`
	Reason    string         `json:"reason"`
	Scope     ExclusionScope `json:"scope"`
	Target    string         `json:"target,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
}

// Portfolio is a normalized organization portfolio. Its accessors return deep copies.
type Portfolio struct {
	schemaVersion   int
	organization    Organization
	owners          []Owner
	policies        []AuthenticationPolicy
	expectedSenders []ExpectedSender
	entities        []Entity
	digest          AnalysisID
}

// SchemaVersion returns the normalized portfolio schema version.
func (portfolio Portfolio) SchemaVersion() int { return portfolio.schemaVersion }

// Organization returns a defensive copy of organization metadata.
func (portfolio Portfolio) Organization() Organization {
	result := portfolio.organization
	result.Tags = cloneStrings(result.Tags)
	return result
}

// Owners returns normalized owners in stable ID order.
func (portfolio Portfolio) Owners() []Owner { return cloneOwners(portfolio.owners) }

// Policies returns normalized reusable policies in stable ID order.
func (portfolio Portfolio) Policies() []AuthenticationPolicy {
	return clonePolicies(portfolio.policies)
}

// ExpectedSenders returns normalized senders in stable ID order.
func (portfolio Portfolio) ExpectedSenders() []ExpectedSender {
	return cloneExpectedSenders(portfolio.expectedSenders)
}

// Entities returns normalized entities and domains in stable order.
func (portfolio Portfolio) Entities() []Entity { return cloneEntities(portfolio.entities) }

// Digest returns a deterministic identifier for the complete normalized portfolio.
func (portfolio Portfolio) Digest() AnalysisID { return portfolio.digest }

// NormalizePortfolio validates and normalizes a programmatic portfolio configuration.
func NormalizePortfolio(config PortfolioConfig) (Portfolio, error) {
	portfolio, diagnostics := normalizePortfolio(config)
	if hasConfigurationErrors(diagnostics) {
		return Portfolio{}, &PortfolioValidationError{diagnostics: diagnostics}
	}
	return portfolio, nil
}

// ValidatePortfolio returns value-safe diagnostics without performing I/O.
func ValidatePortfolio(config PortfolioConfig, generatedAt time.Time) ConfigurationValidationResult {
	_, diagnostics := normalizePortfolio(config)
	return ConfigurationValidationResult{
		Metadata: ResultMetadata{
			ContractVersion: AnalysisContractVersion,
			Mode:            AnalysisModeConfigurationValidation,
			GeneratedAt:     generatedAt.UTC(),
			Evaluation:      Evaluation{State: EvaluationStateEvaluated},
		},
		Diagnostics: append([]ConfigurationDiagnostic(nil), diagnostics...),
	}
}

type portfolioNormalizer struct {
	config      PortfolioConfig
	diagnostics []ConfigurationDiagnostic
	ownerIDs    map[string]struct{}
	policies    map[string]AuthenticationPolicy
	senders     map[string]ExpectedSender
}

func normalizePortfolio(config PortfolioConfig) (Portfolio, []ConfigurationDiagnostic) {
	normalizer := &portfolioNormalizer{config: config, ownerIDs: map[string]struct{}{}, policies: map[string]AuthenticationPolicy{}, senders: map[string]ExpectedSender{}}
	portfolio := Portfolio{schemaVersion: config.SchemaVersion}
	if config.SchemaVersion != PortfolioSchemaVersion {
		normalizer.add("configuration.schema.unsupported", "schema_version", "The portfolio schema version is not supported.")
	}
	portfolio.organization = normalizer.normalizeOrganization(config.Organization)
	portfolio.owners = normalizer.normalizeOwners(config.Owners)
	normalizer.validateOwnerReference(portfolio.organization.Owner, "organization.owner")
	portfolio.policies = normalizer.normalizePolicies(config.Policies)
	portfolio.expectedSenders = normalizer.normalizeSenders(config.ExpectedSenders)
	portfolio.entities = normalizer.normalizeEntities(config.Entities, portfolio.organization)
	normalizer.validateOwnership(portfolio.entities)
	if !hasConfigurationErrors(normalizer.diagnostics) {
		snapshot, _ := json.Marshal(struct {
			SchemaVersion   int                    `json:"schema_version"`
			Organization    Organization           `json:"organization"`
			Owners          []Owner                `json:"owners"`
			Policies        []AuthenticationPolicy `json:"policies"`
			ExpectedSenders []ExpectedSender       `json:"expected_senders"`
			Entities        []Entity               `json:"entities"`
		}{portfolio.schemaVersion, portfolio.organization, portfolio.owners, portfolio.policies, portfolio.expectedSenders, portfolio.entities})
		portfolio.digest = StableAnalysisID("portfolio", string(snapshot))
	}
	sort.SliceStable(normalizer.diagnostics, func(i, j int) bool {
		if normalizer.diagnostics[i].Path != normalizer.diagnostics[j].Path {
			return normalizer.diagnostics[i].Path < normalizer.diagnostics[j].Path
		}
		return normalizer.diagnostics[i].Code < normalizer.diagnostics[j].Code
	})
	return portfolio, normalizer.diagnostics
}

func (normalizer *portfolioNormalizer) add(code DiagnosticCode, path, message string) {
	normalizer.diagnostics = append(normalizer.diagnostics, ConfigurationDiagnostic{Code: code, Severity: ValidationError, Path: path, Message: message})
}

func (normalizer *portfolioNormalizer) normalizeOrganization(config OrganizationConfig) Organization {
	id, ok := normalizeConfigID(config.ID)
	if !ok {
		normalizer.add("configuration.organization.invalid_id", "organization.id", "The organization ID is missing or invalid.")
	}
	return Organization{ID: id, Name: strings.TrimSpace(config.Name), Owner: normalizer.normalizeReferenceField(config.Owner, "organization.owner", "configuration.organization.invalid_owner"), Tags: normalizeTags(config.Tags)}
}

func (normalizer *portfolioNormalizer) normalizeOwners(configs []OwnerConfig) []Owner {
	owners := make([]Owner, 0, len(configs))
	for index, config := range configs {
		path := fmt.Sprintf("owners[%d]", index)
		id, ok := normalizeConfigID(config.ID)
		if !ok {
			normalizer.add("configuration.owner.invalid_id", path+".id", "The owner ID is missing or invalid.")
			continue
		}
		if _, exists := normalizer.ownerIDs[id]; exists {
			normalizer.add("configuration.owner.duplicate_id", path+".id", "The owner ID duplicates another normalized owner ID.")
			continue
		}
		normalizer.ownerIDs[id] = struct{}{}
		owners = append(owners, Owner{ID: id, Name: strings.TrimSpace(config.Name), Contact: strings.TrimSpace(config.Contact), Tags: normalizeTags(config.Tags)})
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].ID < owners[j].ID })
	return owners
}

func (normalizer *portfolioNormalizer) normalizePolicies(configs []AuthenticationPolicyConfig) []AuthenticationPolicy {
	policies := make([]AuthenticationPolicy, 0, len(configs))
	for index, config := range configs {
		path := fmt.Sprintf("policies[%d]", index)
		id, ok := normalizeConfigID(config.ID)
		if !ok {
			normalizer.add("configuration.policy.invalid_id", path+".id", "The policy ID is missing or invalid.")
			continue
		}
		if _, exists := normalizer.policies[id]; exists {
			normalizer.add("configuration.policy.duplicate_id", path+".id", "The policy ID duplicates another normalized policy ID.")
			continue
		}
		policy := normalizer.normalizePolicy(id, config.RequireDKIM, config.RequireSPF, config.RequireEither, config.AllowedSelectors, path+".allowed_selectors")
		normalizer.validatePolicy(policy, path)
		normalizer.policies[id] = policy
		policies = append(policies, policy)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	return policies
}

func (normalizer *portfolioNormalizer) validatePolicy(policy AuthenticationPolicy, path string) {
	if policy.RequireEither && (policy.RequireDKIM || policy.RequireSPF) {
		normalizer.add("configuration.policy.contradictory_requirements", path, "Require-either cannot be combined with specific DKIM or SPF requirements.")
	}
	if !policy.RequireEither && !policy.RequireDKIM && !policy.RequireSPF {
		normalizer.add("configuration.policy.missing_requirement", path, "The policy must require DKIM, SPF, or either mechanism.")
	}
	if len(policy.AllowedSelectors) > 0 && !policy.RequireEither && !policy.RequireDKIM {
		normalizer.add("configuration.policy.selector_without_dkim", path+".allowed_selectors", "Allowed selectors require DKIM or either-mechanism authentication.")
	}
}

func (normalizer *portfolioNormalizer) normalizeSenders(configs []ExpectedSenderConfig) []ExpectedSender {
	senders := make([]ExpectedSender, 0, len(configs))
	for index, config := range configs {
		path := fmt.Sprintf("expected_senders[%d]", index)
		id, ok := normalizeConfigID(config.ID)
		if !ok {
			normalizer.add("configuration.sender.invalid_id", path+".id", "The expected-sender ID is missing or invalid.")
			continue
		}
		if _, exists := normalizer.senders[id]; exists {
			normalizer.add("configuration.sender.duplicate_id", path+".id", "The expected-sender ID duplicates another normalized sender ID.")
			continue
		}
		owner := normalizer.normalizeReferenceField(config.Owner, path+".owner", "configuration.sender.invalid_owner")
		normalizer.validateOwnerReference(owner, path+".owner")
		policyID := normalizer.normalizeReferenceField(config.Policy, path+".policy", "configuration.sender.invalid_policy")
		provider := normalizer.normalizeReferenceField(config.Provider, path+".provider", "configuration.sender.invalid_provider")
		inlineSet := config.RequireDKIM || config.RequireSPF || config.RequireEither || len(config.AllowedSelectors) > 0
		var policy AuthenticationPolicy
		if policyID != "" {
			if inlineSet {
				normalizer.add("configuration.sender.conflicting_policy", path, "A sender cannot combine a reusable policy reference with inline requirements.")
			}
			var exists bool
			policy, exists = normalizer.policies[policyID]
			if !exists {
				normalizer.add("configuration.sender.unknown_policy", path+".policy", "The sender references an unknown policy ID.")
				policy = AuthenticationPolicy{ID: policyID, AllowedSelectors: []string{}}
			}
		} else {
			policy = normalizer.normalizePolicy("inline."+id, config.RequireDKIM, config.RequireSPF, config.RequireEither, config.AllowedSelectors, path+".allowed_selectors")
			normalizer.validatePolicy(policy, path)
		}
		sender := ExpectedSender{ID: id, Name: strings.TrimSpace(config.Name), Provider: provider, Owner: owner, Tags: normalizeTags(config.Tags), Policy: policy}
		normalizer.senders[id] = sender
		senders = append(senders, sender)
	}
	sort.Slice(senders, func(i, j int) bool { return senders[i].ID < senders[j].ID })
	return senders
}

func (normalizer *portfolioNormalizer) normalizeEntities(configs []EntityConfig, organization Organization) []Entity {
	byID := map[string]EntityConfig{}
	paths := map[string]string{}
	for index, config := range configs {
		path := fmt.Sprintf("entities[%d]", index)
		id, ok := normalizeConfigID(config.ID)
		if !ok {
			normalizer.add("configuration.entity.invalid_id", path+".id", "The entity ID is missing or invalid.")
			continue
		}
		if _, exists := byID[id]; exists {
			normalizer.add("configuration.entity.duplicate_id", path+".id", "The entity ID duplicates another normalized entity ID.")
			continue
		}
		config.ID = id
		config.Parent = normalizer.normalizeReferenceField(config.Parent, path+".parent", "configuration.entity.invalid_parent")
		byID[id] = config
		paths[id] = path
	}
	if len(byID) == 0 {
		normalizer.add("configuration.entity.missing", "entities", "At least one organizational entity is required.")
	}
	resolved := map[string]Entity{}
	visiting := map[string]bool{}
	var resolve func(string) Entity
	resolve = func(id string) Entity {
		if entity, ok := resolved[id]; ok {
			return entity
		}
		config, ok := byID[id]
		if !ok {
			return Entity{}
		}
		if visiting[id] {
			normalizer.add("configuration.entity.parent_cycle", paths[id]+".parent", "The entity parent relationship contains a cycle.")
			return Entity{ID: id, Tags: []string{}, Domains: []MonitoredDomain{}}
		}
		visiting[id] = true
		entity := Entity{ID: id, Name: strings.TrimSpace(config.Name), Parent: config.Parent, Owner: organization.Owner, Tags: cloneStrings(organization.Tags), Domains: []MonitoredDomain{}}
		if config.Parent != "" {
			if _, exists := byID[config.Parent]; !exists {
				normalizer.add("configuration.entity.unknown_parent", paths[id]+".parent", "The entity references an unknown parent ID.")
			} else {
				parent := resolve(config.Parent)
				entity.Owner = parent.Owner
				entity.Tags = cloneStrings(parent.Tags)
			}
		}
		if owner := normalizer.normalizeReferenceField(config.Owner, paths[id]+".owner", "configuration.entity.invalid_owner"); owner != "" {
			entity.Owner = owner
		}
		normalizer.validateOwnerReference(entity.Owner, paths[id]+".owner")
		entity.Tags = mergeStrings(entity.Tags, normalizeTags(config.Tags), CollectionModeMerge)
		entity.Domains = normalizer.normalizeDomains(config.Domains, entity, paths[id]+".domains")
		delete(visiting, id)
		resolved[id] = entity
		return entity
	}
	entities := make([]Entity, 0, len(byID))
	for id := range byID {
		entities = append(entities, resolve(id))
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].ID < entities[j].ID })
	return entities
}

func (normalizer *portfolioNormalizer) normalizeDomains(configs []DomainConfig, entity Entity, basePath string) []MonitoredDomain {
	byName := map[string]DomainConfig{}
	paths := map[string]string{}
	for index, config := range configs {
		path := fmt.Sprintf("%s[%d]", basePath, index)
		name, err := normalizeDomainName(config.Name)
		if err != nil {
			normalizer.add("configuration.domain.invalid_name", path+".name", "The domain name is missing or invalid.")
			continue
		}
		if _, exists := byName[name]; exists {
			normalizer.add("configuration.domain.duplicate_name", path+".name", "The domain duplicates another normalized domain in the entity.")
			continue
		}
		config.Name = name
		if config.Parent != "" {
			parent, err := normalizeDomainName(config.Parent)
			if err != nil {
				normalizer.add("configuration.domain.invalid_parent", path+".parent", "The parent domain name is invalid.")
			} else {
				config.Parent = parent
			}
		}
		byName[name] = config
		paths[name] = path
	}
	resolved := map[string]MonitoredDomain{}
	visiting := map[string]bool{}
	var resolve func(string) MonitoredDomain
	resolve = func(name string) MonitoredDomain {
		if domain, ok := resolved[name]; ok {
			return domain
		}
		config, ok := byName[name]
		if !ok {
			return MonitoredDomain{}
		}
		if visiting[name] {
			normalizer.add("configuration.domain.parent_cycle", paths[name]+".parent", "The domain parent relationship contains a cycle.")
			return emptyMonitoredDomain(name, entity.Owner)
		}
		visiting[name] = true
		domain := emptyMonitoredDomain(name, entity.Owner)
		domain.Tags = cloneStrings(entity.Tags)
		domain.Parent = config.Parent
		if config.Parent != "" {
			parentConfig, exists := byName[config.Parent]
			if !exists {
				normalizer.add("configuration.domain.unknown_parent", paths[name]+".parent", "The domain references an unknown parent in the same entity.")
			} else {
				parent := resolve(config.Parent)
				if !strings.HasSuffix(name, "."+parentConfig.Name) {
					normalizer.add("configuration.domain.parent_not_ancestor", paths[name]+".parent", "The configured parent is not an ancestor of the child domain.")
				} else {
					domain = cloneDomain(parent)
					domain.Name = name
					domain.Parent = config.Parent
				}
			}
		}
		domain.IncludeSubdomains = config.IncludeSubdomains
		if owner := normalizer.normalizeReferenceField(config.Owner, paths[name]+".owner", "configuration.domain.invalid_owner"); owner != "" {
			domain.Owner = owner
		}
		normalizer.validateOwnerReference(domain.Owner, paths[name]+".owner")
		if policy := normalizer.normalizeReferenceField(config.Policy, paths[name]+".policy", "configuration.domain.invalid_policy"); policy != "" {
			domain.Policy = policy
			if _, exists := normalizer.policies[policy]; !exists {
				normalizer.add("configuration.domain.unknown_policy", paths[name]+".policy", "The domain references an unknown policy ID.")
			}
		}
		tagMode := normalizer.collectionMode(config.Inheritance.Tags, paths[name]+".inheritance.tags")
		recordMode := normalizer.collectionMode(config.Inheritance.Records, paths[name]+".inheritance.records")
		senderMode := normalizer.collectionMode(config.Inheritance.ExpectedSenders, paths[name]+".inheritance.expected_senders")
		exclusionMode := normalizer.collectionMode(config.Inheritance.Exclusions, paths[name]+".inheritance.exclusions")
		domain.Tags = mergeStrings(domain.Tags, normalizeTags(config.Tags), tagMode)
		records := normalizer.normalizeRecords(config.Records, paths[name]+".records")
		domain.Records = mergeRecords(domain.Records, records, recordMode)
		senders := normalizer.normalizeSenderReferences(config.ExpectedSenders, paths[name]+".expected_senders")
		domain.ExpectedSenders = mergeStrings(domain.ExpectedSenders, senders, senderMode)
		exclusions := normalizer.normalizeExclusions(config.Exclusions, paths[name]+".exclusions")
		domain.Exclusions = mergeExclusions(domain.Exclusions, exclusions, exclusionMode)
		delete(visiting, name)
		resolved[name] = domain
		return domain
	}
	domains := make([]MonitoredDomain, 0, len(byName))
	for name := range byName {
		domains = append(domains, resolve(name))
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
	return domains
}

func (normalizer *portfolioNormalizer) collectionMode(mode CollectionMode, path string) CollectionMode {
	if mode == "" {
		return CollectionModeMerge
	}
	if mode != CollectionModeMerge && mode != CollectionModeReplace {
		normalizer.add("configuration.inheritance.invalid_mode", path, "The inheritance mode must be merge or replace.")
		return CollectionModeMerge
	}
	return mode
}

func (normalizer *portfolioNormalizer) normalizeRecords(config MonitoredRecordsConfig, path string) MonitoredRecords {
	return MonitoredRecords{
		SPF:   normalizer.normalizeRecordList(config.SPF, path+".spf", "spf"),
		DKIM:  normalizer.normalizeRecordList(config.DKIM, path+".dkim", "dkim"),
		DMARC: normalizer.normalizeRecordList(config.DMARC, path+".dmarc", "dmarc"),
	}
}

func (normalizer *portfolioNormalizer) normalizeRecordList(values []string, path, kind string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		name, err := normalizeRecordName(value)
		if err != nil || (kind == "dmarc" && !strings.HasPrefix(name, "_dmarc.")) || (kind == "dkim" && !strings.Contains(name, "._domainkey.")) {
			normalizer.add("configuration.record.invalid_name", fmt.Sprintf("%s[%d]", path, index), "The monitored record name is invalid for its record type.")
			continue
		}
		if _, exists := seen[name]; exists {
			normalizer.add("configuration.record.duplicate_name", fmt.Sprintf("%s[%d]", path, index), "The exact record name is duplicated in this collection.")
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (normalizer *portfolioNormalizer) normalizeSenderReferences(values []string, path string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		id, ok := normalizeConfigID(value)
		if !ok {
			normalizer.add("configuration.domain.invalid_sender", fmt.Sprintf("%s[%d]", path, index), "The expected-sender reference is invalid.")
			continue
		}
		if _, exists := normalizer.senders[id]; !exists {
			normalizer.add("configuration.domain.unknown_sender", fmt.Sprintf("%s[%d]", path, index), "The domain references an unknown expected-sender ID.")
		}
		if _, exists := seen[id]; exists {
			normalizer.add("configuration.domain.duplicate_sender", fmt.Sprintf("%s[%d]", path, index), "The expected-sender reference is duplicated.")
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func (normalizer *portfolioNormalizer) normalizeExclusions(configs []ScopedExclusionConfig, path string) []ScopedExclusion {
	result := make([]ScopedExclusion, 0, len(configs))
	seen := map[string]struct{}{}
	for index, config := range configs {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		id, ok := normalizeConfigID(config.ID)
		if !ok {
			normalizer.add("configuration.exclusion.invalid_id", itemPath+".id", "The exclusion ID is missing or invalid.")
			continue
		}
		if _, exists := seen[id]; exists {
			normalizer.add("configuration.exclusion.duplicate_id", itemPath+".id", "The exclusion ID duplicates another exclusion on the domain.")
			continue
		}
		seen[id] = struct{}{}
		owner := normalizer.normalizeReferenceField(config.Owner, itemPath+".owner", "configuration.exclusion.invalid_owner")
		normalizer.validateOwnerReference(owner, itemPath+".owner")
		if owner == "" {
			normalizer.add("configuration.exclusion.missing_owner", itemPath+".owner", "The exclusion requires an accountable owner.")
		}
		reason := strings.TrimSpace(config.Reason)
		if reason == "" {
			normalizer.add("configuration.exclusion.missing_reason", itemPath+".reason", "The exclusion requires a reason.")
		}
		if config.CreatedAt.IsZero() {
			normalizer.add("configuration.exclusion.missing_created_at", itemPath+".created_at", "The exclusion requires a creation time.")
		}
		createdAt := config.CreatedAt.UTC()
		var expiresAt *time.Time
		if config.ExpiresAt != nil {
			value := config.ExpiresAt.UTC()
			expiresAt = &value
			if !createdAt.IsZero() && !value.After(createdAt) {
				normalizer.add("configuration.exclusion.invalid_expiration", itemPath+".expires_at", "The exclusion expiration must be after its creation time.")
			}
		}
		target := strings.TrimSpace(config.Target)
		switch config.Scope {
		case ExclusionScopeDomain, ExclusionScopeSubdomains:
			if target != "" {
				normalizer.add("configuration.exclusion.unexpected_target", itemPath+".target", "Domain-scoped exclusions must not include a target.")
			}
		case ExclusionScopeRecord:
			name, err := normalizeRecordName(target)
			if err != nil {
				normalizer.add("configuration.exclusion.invalid_target", itemPath+".target", "A record-scoped exclusion requires a valid record name target.")
			} else {
				target = name
			}
		case ExclusionScopeSender:
			id, ok := normalizeConfigID(target)
			if !ok {
				normalizer.add("configuration.exclusion.invalid_target", itemPath+".target", "A sender-scoped exclusion requires a valid sender ID target.")
			} else {
				target = id
				if _, exists := normalizer.senders[id]; !exists {
					normalizer.add("configuration.exclusion.unknown_sender", itemPath+".target", "The exclusion references an unknown sender ID.")
				}
			}
		default:
			normalizer.add("configuration.exclusion.invalid_scope", itemPath+".scope", "The exclusion scope is invalid.")
		}
		result = append(result, ScopedExclusion{ID: id, Owner: owner, Reason: reason, Scope: config.Scope, Target: target, CreatedAt: createdAt, ExpiresAt: expiresAt})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (normalizer *portfolioNormalizer) validateOwnerReference(owner, path string) {
	if owner == "" {
		return
	}
	if _, exists := normalizer.ownerIDs[owner]; !exists {
		normalizer.add("configuration.owner.unknown_reference", path, "The configuration references an unknown owner ID.")
	}
}

func (normalizer *portfolioNormalizer) normalizeReferenceField(value, path string, code DiagnosticCode) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	result, ok := normalizeConfigID(value)
	if !ok {
		normalizer.add(code, path, "The configuration reference is invalid.")
		return ""
	}
	return result
}

func (normalizer *portfolioNormalizer) validateOwnership(entities []Entity) {
	domainOwners := map[string]string{}
	recordOwners := map[string]string{}
	for _, entity := range entities {
		for _, domain := range entity.Domains {
			if existing, ok := domainOwners[domain.Name]; !ok || existing == "" {
				domainOwners[domain.Name] = domain.Owner
			} else if domain.Owner != "" && existing != domain.Owner {
				normalizer.add("configuration.ownership.domain_conflict", "entities", "The same normalized domain has conflicting owners.")
			}
			for _, name := range append(append(cloneStrings(domain.Records.SPF), domain.Records.DKIM...), domain.Records.DMARC...) {
				if existing, ok := recordOwners[name]; !ok || existing == "" {
					recordOwners[name] = domain.Owner
				} else if domain.Owner != "" && existing != domain.Owner {
					normalizer.add("configuration.ownership.record_conflict", "entities", "The same normalized record name has conflicting owners.")
				}
			}
		}
	}
}

var configIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
var underscoredLabelPattern = regexp.MustCompile(`^_[a-z0-9_-]+$`)
var selectorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func normalizeConfigID(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	return value, value != "" && len(value) <= 128 && configIDPattern.MatchString(value)
}

func normalizeTags(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result = append(result, value)
		}
	}
	return compactSortedStrings(result)
}

func (normalizer *portfolioNormalizer) normalizePolicy(id string, requireDKIM, requireSPF, requireEither bool, selectors []string, path string) AuthenticationPolicy {
	normalizedSelectors := make([]string, 0, len(selectors))
	for index, selector := range selectors {
		selector = strings.ToLower(strings.TrimSpace(selector))
		if selectorPattern.MatchString(selector) {
			normalizedSelectors = append(normalizedSelectors, selector)
		} else {
			normalizer.add("configuration.policy.invalid_selector", fmt.Sprintf("%s[%d]", path, index), "The DKIM selector is invalid.")
		}
	}
	return AuthenticationPolicy{ID: id, RequireDKIM: requireDKIM, RequireSPF: requireSPF, RequireEither: requireEither, AllowedSelectors: compactSortedStrings(normalizedSelectors)}
}

func normalizeDomainName(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" || net.ParseIP(value) != nil {
		return "", errors.New("invalid domain")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", err
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", errors.New("invalid domain")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid domain")
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return "", errors.New("public suffix is not an organizational domain")
	}
	return ascii, nil
}

func normalizeRecordName(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || net.ParseIP(value) != nil {
		return "", errors.New("invalid record name")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", errors.New("record name requires a DNS suffix")
	}
	for index, label := range labels {
		if label == "" {
			return "", errors.New("invalid record name")
		}
		if strings.HasPrefix(label, "_") {
			if len(label) > 63 || !underscoredLabelPattern.MatchString(label) {
				return "", errors.New("invalid record name")
			}
			continue
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil || ascii == "" || len(ascii) > 63 || strings.HasPrefix(ascii, "-") || strings.HasSuffix(ascii, "-") {
			return "", errors.New("invalid record name")
		}
		labels[index] = strings.ToLower(ascii)
	}
	normalized := strings.Join(labels, ".")
	if len(normalized) > 253 {
		return "", errors.New("invalid record name")
	}
	return normalized, nil
}

func hasConfigurationErrors(diagnostics []ConfigurationDiagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == ValidationError {
			return true
		}
	}
	return false
}

func emptyMonitoredDomain(name, owner string) MonitoredDomain {
	return MonitoredDomain{Name: name, Owner: owner, Tags: []string{}, Records: MonitoredRecords{SPF: []string{}, DKIM: []string{}, DMARC: []string{}}, ExpectedSenders: []string{}, Exclusions: []ScopedExclusion{}}
}

func mergeStrings(parent, child []string, mode CollectionMode) []string {
	if mode == CollectionModeReplace {
		return compactSortedStrings(cloneStrings(child))
	}
	return compactSortedStrings(append(cloneStrings(parent), child...))
}

func mergeRecords(parent, child MonitoredRecords, mode CollectionMode) MonitoredRecords {
	return MonitoredRecords{SPF: mergeStrings(parent.SPF, child.SPF, mode), DKIM: mergeStrings(parent.DKIM, child.DKIM, mode), DMARC: mergeStrings(parent.DMARC, child.DMARC, mode)}
}

func mergeExclusions(parent, child []ScopedExclusion, mode CollectionMode) []ScopedExclusion {
	values := cloneExclusions(child)
	if mode != CollectionModeReplace {
		values = append(cloneExclusions(parent), values...)
	}
	byID := map[string]ScopedExclusion{}
	for _, value := range values {
		byID[value.ID] = value
	}
	result := make([]ScopedExclusion, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func cloneStrings(values []string) []string { return append([]string(nil), values...) }

func cloneOwners(values []Owner) []Owner {
	result := append([]Owner(nil), values...)
	for index := range result {
		result[index].Tags = cloneStrings(result[index].Tags)
	}
	return result
}

func clonePolicies(values []AuthenticationPolicy) []AuthenticationPolicy {
	result := append([]AuthenticationPolicy(nil), values...)
	for index := range result {
		result[index].AllowedSelectors = cloneStrings(result[index].AllowedSelectors)
	}
	return result
}

func cloneExpectedSenders(values []ExpectedSender) []ExpectedSender {
	result := append([]ExpectedSender(nil), values...)
	for index := range result {
		result[index].Tags = cloneStrings(result[index].Tags)
		result[index].Policy.AllowedSelectors = cloneStrings(result[index].Policy.AllowedSelectors)
	}
	return result
}

func cloneEntities(values []Entity) []Entity {
	result := append([]Entity(nil), values...)
	for index := range result {
		result[index].Tags = cloneStrings(result[index].Tags)
		result[index].Domains = make([]MonitoredDomain, len(values[index].Domains))
		for domainIndex := range values[index].Domains {
			result[index].Domains[domainIndex] = cloneDomain(values[index].Domains[domainIndex])
		}
	}
	return result
}

func cloneDomain(value MonitoredDomain) MonitoredDomain {
	value.Tags = cloneStrings(value.Tags)
	value.Records = MonitoredRecords{SPF: cloneStrings(value.Records.SPF), DKIM: cloneStrings(value.Records.DKIM), DMARC: cloneStrings(value.Records.DMARC)}
	value.ExpectedSenders = cloneStrings(value.ExpectedSenders)
	value.Exclusions = cloneExclusions(value.Exclusions)
	return value
}

func cloneExclusions(values []ScopedExclusion) []ScopedExclusion {
	result := append([]ScopedExclusion(nil), values...)
	for index := range result {
		if result[index].ExpiresAt != nil {
			value := *result[index].ExpiresAt
			result[index].ExpiresAt = &value
		}
	}
	return result
}
