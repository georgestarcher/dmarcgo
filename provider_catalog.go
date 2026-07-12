package dmarcgo

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

// ProviderCatalogSchemaVersion is the supported provider-catalog schema.
const ProviderCatalogSchemaVersion = 1

const (
	maxProviderCatalogProviders     = 256
	maxProviderCatalogListItems     = 128
	maxProviderCatalogStringBytes   = 2048
	defaultProviderReviewMaximumAge = 400 * 24 * time.Hour
	providerCatalogDateLayout       = "2006-01-02"
)

var (
	// ErrInvalidProviderCatalog identifies a catalog that cannot be normalized.
	ErrInvalidProviderCatalog = errors.New("invalid provider catalog")
	// ErrUnsupportedProviderCatalogSchema identifies an unsupported schema version.
	ErrUnsupportedProviderCatalogSchema = errors.New("unsupported provider catalog schema version")
)

// ProviderStatus describes whether a catalog entry is current.
type ProviderStatus string

const (
	ProviderStatusActive     ProviderStatus = "active"
	ProviderStatusDeprecated ProviderStatus = "deprecated"
)

// ProviderEvidenceConfidence describes the strength of first-party provider evidence.
type ProviderEvidenceConfidence string

const (
	ProviderEvidenceHigh   ProviderEvidenceConfidence = "high"
	ProviderEvidenceMedium ProviderEvidenceConfidence = "medium"
	ProviderEvidenceLow    ProviderEvidenceConfidence = "low"
)

// ProviderCapabilityStatus distinguishes supported, unsupported, and
// not-established capabilities in the reviewed provider contract.
type ProviderCapabilityStatus string

const (
	ProviderCapabilityUnknown      ProviderCapabilityStatus = "unknown"
	ProviderCapabilitySupported    ProviderCapabilityStatus = "supported"
	ProviderCapabilityNotSupported ProviderCapabilityStatus = "not_supported"
)

// ProviderSPFTerminalBehavior is a documented recommended terminal qualifier.
type ProviderSPFTerminalBehavior string

const (
	ProviderSPFTerminalSoftFail ProviderSPFTerminalBehavior = "softfail"
	ProviderSPFTerminalHardFail ProviderSPFTerminalBehavior = "hardfail"
	ProviderSPFTerminalNeutral  ProviderSPFTerminalBehavior = "neutral"
)

// ProviderDNSRecordType is a non-secret companion DNS record kind.
type ProviderDNSRecordType string

const (
	ProviderDNSRecordTXT   ProviderDNSRecordType = "TXT"
	ProviderDNSRecordCNAME ProviderDNSRecordType = "CNAME"
	ProviderDNSRecordMX    ProviderDNSRecordType = "MX"
	ProviderDNSRecordNS    ProviderDNSRecordType = "NS"
)

// SPFIncludeMatchRule controls how an SPF include name is recognized.
type SPFIncludeMatchRule string

const (
	// SPFIncludeMatchExact recognizes only the normalized DNS name itself.
	SPFIncludeMatchExact SPFIncludeMatchRule = "exact"
	// SPFIncludeMatchSuffix recognizes the name and its DNS subdomains. It must
	// be explicitly declared and supported by the provider documentation.
	SPFIncludeMatchSuffix SPFIncludeMatchRule = "suffix"
)

// ProviderCatalogSource identifies the origin of normalized catalog data.
type ProviderCatalogSource string

const (
	ProviderCatalogSourceEmbedded ProviderCatalogSource = "embedded"
	ProviderCatalogSourceCaller   ProviderCatalogSource = "caller"
	ProviderCatalogSourceOverlay  ProviderCatalogSource = "overlay"
)

// ProviderCatalogConfig is the mutable programmatic and YAML catalog model.
type ProviderCatalogConfig struct {
	SchemaVersion  int              `json:"schema_version" yaml:"schema_version"`
	CatalogVersion string           `json:"catalog_version" yaml:"catalog_version"`
	Providers      []ProviderConfig `json:"providers" yaml:"providers"`
}

// ProviderConfig describes one provider in caller-owned input.
type ProviderConfig struct {
	ID                 string                       `json:"id" yaml:"id"`
	Name               string                       `json:"name" yaml:"name"`
	Aliases            []string                     `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Status             ProviderStatus               `json:"status" yaml:"status"`
	Successor          string                       `json:"successor,omitempty" yaml:"successor,omitempty"`
	OfficialDomains    []string                     `json:"official_domains" yaml:"official_domains"`
	SPF                ProviderSPFConfig            `json:"spf,omitempty" yaml:"spf,omitempty"`
	DKIM               ProviderDKIMConfig           `json:"dkim,omitempty" yaml:"dkim,omitempty"`
	Alignment          ProviderAlignmentConfig      `json:"alignment,omitempty" yaml:"alignment,omitempty"`
	Infrastructure     ProviderInfrastructureConfig `json:"infrastructure" yaml:"infrastructure"`
	CompanionRecords   []ProviderCompanionRecord    `json:"companion_records,omitempty" yaml:"companion_records,omitempty"`
	Documentation      []ProviderDocumentation      `json:"documentation" yaml:"documentation"`
	ReviewedAt         string                       `json:"reviewed_at" yaml:"reviewed_at"`
	ContractNote       string                       `json:"contract_note,omitempty" yaml:"contract_note,omitempty"`
	EvidenceConfidence ProviderEvidenceConfidence   `json:"evidence_confidence" yaml:"evidence_confidence"`
}

// ProviderSPFConfig describes documented SPF dependency behavior.
type ProviderSPFConfig struct {
	Includes              []ProviderSPFInclude `json:"includes,omitempty" yaml:"includes,omitempty"`
	LiveExpansionRequired bool                 `json:"live_expansion_required" yaml:"live_expansion_required"`
}

// ProviderSPFInclude describes one documented SPF include or redirect target.
type ProviderSPFInclude struct {
	Name                     string                      `json:"name" yaml:"name"`
	Status                   ProviderStatus              `json:"status" yaml:"status"`
	Match                    SPFIncludeMatchRule         `json:"match" yaml:"match"`
	Region                   string                      `json:"region,omitempty" yaml:"region,omitempty"`
	ExpectedTerminalBehavior ProviderSPFTerminalBehavior `json:"expected_terminal_behavior,omitempty" yaml:"expected_terminal_behavior,omitempty"`
	EvidenceConfidence       ProviderEvidenceConfidence  `json:"evidence_confidence" yaml:"evidence_confidence"`
	Note                     string                      `json:"note,omitempty" yaml:"note,omitempty"`
}

// ProviderDKIMConfig describes a provider's documented DKIM setup model.
type ProviderDKIMConfig struct {
	SetupModel                  string   `json:"setup_model,omitempty" yaml:"setup_model,omitempty"`
	CustomDomainSigningExpected bool     `json:"custom_domain_signing_expected" yaml:"custom_domain_signing_expected"`
	SelectorPatterns            []string `json:"selector_patterns,omitempty" yaml:"selector_patterns,omitempty"`
	PreferredRSABits            int      `json:"preferred_rsa_bits,omitempty" yaml:"preferred_rsa_bits,omitempty"`
	TenantSpecific              bool     `json:"tenant_specific" yaml:"tenant_specific"`
	ProviderManagedRotation     bool     `json:"provider_managed_rotation" yaml:"provider_managed_rotation"`
	Note                        string   `json:"note,omitempty" yaml:"note,omitempty"`
}

// ProviderAlignmentConfig describes documented custom-domain alignment behavior.
type ProviderAlignmentConfig struct {
	CustomMailFrom                    ProviderCapabilityStatus `json:"custom_mail_from" yaml:"custom_mail_from"`
	CustomMailFromRequiredForSPFDMARC bool                     `json:"custom_mail_from_required_for_spf_dmarc_alignment" yaml:"custom_mail_from_required_for_spf_dmarc_alignment"`
	Note                              string                   `json:"note,omitempty" yaml:"note,omitempty"`
}

// ProviderInfrastructureConfig records shared-infrastructure context. Shared
// infrastructure is counter-evidence about attribution, not proof of safety.
type ProviderInfrastructureConfig struct {
	Shared bool `json:"shared" yaml:"shared"`
}

// ProviderCompanionRecord describes a documented onboarding requirement. It
// intentionally contains no executable DNS value template.
type ProviderCompanionRecord struct {
	ID        string                `json:"id" yaml:"id"`
	Type      ProviderDNSRecordType `json:"type" yaml:"type"`
	Condition string                `json:"condition" yaml:"condition"`
	Purpose   string                `json:"purpose" yaml:"purpose"`
}

// ProviderDocumentation is a first-party source reviewed for an entry.
type ProviderDocumentation struct {
	URL   string `json:"url" yaml:"url"`
	Title string `json:"title" yaml:"title"`
}

// Provider is one immutable normalized provider value.
type Provider struct {
	ID                 string                       `json:"id"`
	Name               string                       `json:"name"`
	Aliases            []string                     `json:"aliases"`
	Status             ProviderStatus               `json:"status"`
	Successor          string                       `json:"successor,omitempty"`
	OfficialDomains    []string                     `json:"official_domains"`
	SPF                ProviderSPFConfig            `json:"spf"`
	DKIM               ProviderDKIMConfig           `json:"dkim"`
	Alignment          ProviderAlignmentConfig      `json:"alignment"`
	Infrastructure     ProviderInfrastructureConfig `json:"infrastructure"`
	CompanionRecords   []ProviderCompanionRecord    `json:"companion_records"`
	Documentation      []ProviderDocumentation      `json:"documentation"`
	ReviewedAt         time.Time                    `json:"reviewed_at"`
	ContractNote       string                       `json:"contract_note,omitempty"`
	EvidenceConfidence ProviderEvidenceConfidence   `json:"evidence_confidence"`
}

// ProviderCatalogOverlay explicitly adds or replaces providers. Existing IDs
// may be replaced only when listed in ReplaceProviderIDs.
type ProviderCatalogOverlay struct {
	Catalog            ProviderCatalog
	ReplaceProviderIDs []string
}

// ProviderCatalogProvenance describes where the effective catalog came from.
type ProviderCatalogProvenance struct {
	Source              ProviderCatalogSource `json:"source"`
	CatalogVersion      string                `json:"catalog_version"`
	Digest              AnalysisID            `json:"digest"`
	BaseDigest          AnalysisID            `json:"base_digest,omitempty"`
	OverlayVersion      string                `json:"overlay_version,omitempty"`
	OverlayDigest       AnalysisID            `json:"overlay_digest,omitempty"`
	AddedProviderIDs    []string              `json:"added_provider_ids"`
	ReplacedProviderIDs []string              `json:"replaced_provider_ids"`
}

// ProviderMatch is context for one recognized SPF dependency. ContextOnly is
// always true: a match never authorizes a sender or changes DNS health.
type ProviderMatch struct {
	ProviderID           string                     `json:"provider_id"`
	ProviderName         string                     `json:"provider_name"`
	ProviderStatus       ProviderStatus             `json:"provider_status"`
	Successor            string                     `json:"successor,omitempty"`
	MatchedInclude       string                     `json:"matched_include"`
	CatalogInclude       string                     `json:"catalog_include"`
	IncludeStatus        ProviderStatus             `json:"include_status"`
	MatchRule            SPFIncludeMatchRule        `json:"match_rule"`
	EvidenceConfidence   ProviderEvidenceConfidence `json:"evidence_confidence"`
	SharedInfrastructure bool                       `json:"shared_infrastructure"`
	ContextOnly          bool                       `json:"context_only"`
	CatalogVersion       string                     `json:"catalog_version"`
	ProviderReviewedAt   time.Time                  `json:"provider_reviewed_at"`
}

// ProviderCatalog is normalized immutable provider metadata. Its accessors
// return defensive copies and perform no network access.
type ProviderCatalog struct {
	schemaVersion  int
	catalogVersion string
	providers      []Provider
	aliases        map[string]string
	digest         AnalysisID
	provenance     ProviderCatalogProvenance
}

//go:embed providers/default.yaml
var embeddedProviderCatalogFS embed.FS

// DefaultProviderCatalog loads and validates the reviewed embedded catalog.
// Each call returns independent immutable state; it performs no network access.
func DefaultProviderCatalog() (ProviderCatalog, error) {
	data, err := embeddedProviderCatalogFS.ReadFile("providers/default.yaml")
	if err != nil {
		return ProviderCatalog{}, errors.Join(ErrInvalidProviderCatalog, err)
	}
	config, err := ParseProviderCatalogYAML(data)
	if err != nil {
		return ProviderCatalog{}, err
	}
	return normalizeProviderCatalog(config, ProviderCatalogSourceEmbedded)
}

// NormalizeProviderCatalog validates caller-owned programmatic input.
func NormalizeProviderCatalog(config ProviderCatalogConfig) (ProviderCatalog, error) {
	return normalizeProviderCatalog(config, ProviderCatalogSourceCaller)
}

// SchemaVersion returns the normalized schema version.
func (catalog ProviderCatalog) SchemaVersion() int { return catalog.schemaVersion }

// CatalogVersion returns the reviewed catalog version.
func (catalog ProviderCatalog) CatalogVersion() string { return catalog.catalogVersion }

// Digest returns a deterministic digest of normalized provider data.
func (catalog ProviderCatalog) Digest() AnalysisID { return catalog.digest }

// Providers returns providers in stable ID order.
func (catalog ProviderCatalog) Providers() []Provider { return cloneProviders(catalog.providers) }

// Provenance returns defensive-copy origin and overlay metadata.
func (catalog ProviderCatalog) Provenance() ProviderCatalogProvenance {
	result := catalog.provenance
	result.AddedProviderIDs = cloneStrings(result.AddedProviderIDs)
	result.ReplacedProviderIDs = cloneStrings(result.ReplacedProviderIDs)
	return result
}

// LookupProvider resolves a stable ID or alias without network access.
func (catalog ProviderCatalog) LookupProvider(idOrAlias string) (Provider, bool) {
	id, ok := normalizeConfigID(idOrAlias)
	if !ok {
		return Provider{}, false
	}
	if canonical, exists := catalog.aliases[id]; exists {
		id = canonical
	}
	index := sort.Search(len(catalog.providers), func(index int) bool { return catalog.providers[index].ID >= id })
	if index == len(catalog.providers) || catalog.providers[index].ID != id {
		return Provider{}, false
	}
	return cloneProvider(catalog.providers[index]), true
}

// MatchSPFInclude recognizes a normalized static include or redirect target.
// Dynamic SPF macro targets do not match. Recognition is context only and does
// not authorize the provider, validate live DNS, or add health points.
func (catalog ProviderCatalog) MatchSPFInclude(name string) (ProviderMatch, bool) {
	normalized, err := normalizeRecordName(name)
	if err != nil {
		return ProviderMatch{}, false
	}
	for _, provider := range catalog.providers {
		for _, include := range provider.SPF.Includes {
			matched := normalized == include.Name
			if include.Match == SPFIncludeMatchSuffix {
				matched = matched || strings.HasSuffix(normalized, "."+include.Name)
			}
			if matched {
				return ProviderMatch{
					ProviderID: provider.ID, ProviderName: provider.Name, ProviderStatus: provider.Status, Successor: provider.Successor,
					MatchedInclude: normalized, CatalogInclude: include.Name, IncludeStatus: include.Status, MatchRule: include.Match,
					EvidenceConfidence:   include.EvidenceConfidence,
					SharedInfrastructure: provider.Infrastructure.Shared, ContextOnly: true,
					CatalogVersion: catalog.catalogVersion, ProviderReviewedAt: provider.ReviewedAt,
				}, true
			}
		}
	}
	return ProviderMatch{}, false
}

// MatchSPFRelationship recognizes a parsed static SPF include or redirect.
// Macro-controlled targets are intentionally never treated as catalog matches.
func (catalog ProviderCatalog) MatchSPFRelationship(relationship SPFRelationship) (ProviderMatch, bool) {
	if relationship.Dynamic || (relationship.Type != "include" && relationship.Type != "redirect") {
		return ProviderMatch{}, false
	}
	return catalog.MatchSPFInclude(relationship.Target)
}

// OverlayProviderCatalog returns a new catalog. It never mutates base or any
// package-global state. Replacement requires an exact, explicit ID allowlist.
func OverlayProviderCatalog(base ProviderCatalog, overlay ProviderCatalogOverlay) (ProviderCatalog, error) {
	if base.digest == "" {
		return ProviderCatalog{}, ErrInvalidProviderCatalog
	}
	overlayCatalog := overlay.Catalog
	if overlayCatalog.digest == "" {
		return ProviderCatalog{}, ErrInvalidProviderCatalog
	}
	replacements := make(map[string]struct{}, len(overlay.ReplaceProviderIDs))
	for _, value := range overlay.ReplaceProviderIDs {
		id, ok := normalizeConfigID(value)
		if !ok {
			return ProviderCatalog{}, fmt.Errorf("%w: overlay replacement ID is invalid", ErrInvalidProviderCatalog)
		}
		if _, exists := replacements[id]; exists {
			return ProviderCatalog{}, fmt.Errorf("%w: overlay replacement ID is duplicated", ErrInvalidProviderCatalog)
		}
		replacements[id] = struct{}{}
	}

	combined := make(map[string]Provider, len(base.providers)+len(overlayCatalog.providers))
	for _, provider := range base.providers {
		combined[provider.ID] = cloneProvider(provider)
	}
	added := make([]string, 0)
	replaced := make([]string, 0)
	usedReplacements := make(map[string]struct{}, len(replacements))
	for _, provider := range overlayCatalog.providers {
		_, exists := combined[provider.ID]
		_, explicit := replacements[provider.ID]
		if exists && !explicit {
			return ProviderCatalog{}, fmt.Errorf("%w: overlay would silently replace an existing provider", ErrInvalidProviderCatalog)
		}
		if !exists && explicit {
			return ProviderCatalog{}, fmt.Errorf("%w: overlay replacement does not exist in the base catalog", ErrInvalidProviderCatalog)
		}
		combined[provider.ID] = cloneProvider(provider)
		if exists {
			replaced = append(replaced, provider.ID)
			usedReplacements[provider.ID] = struct{}{}
		} else {
			added = append(added, provider.ID)
		}
	}
	for id := range replacements {
		if _, ok := usedReplacements[id]; !ok {
			return ProviderCatalog{}, fmt.Errorf("%w: overlay replacement is missing", ErrInvalidProviderCatalog)
		}
	}

	effectiveVersion := base.catalogVersion
	if overlayCatalog.catalogVersion > effectiveVersion {
		effectiveVersion = overlayCatalog.catalogVersion
	}
	config := providerConfigFromNormalized(base.schemaVersion, effectiveVersion, combined)
	result, err := normalizeProviderCatalog(config, ProviderCatalogSourceOverlay)
	if err != nil {
		return ProviderCatalog{}, err
	}
	sort.Strings(added)
	sort.Strings(replaced)
	result.provenance.BaseDigest = base.digest
	result.provenance.OverlayVersion = overlayCatalog.catalogVersion
	result.provenance.OverlayDigest = overlayCatalog.digest
	result.provenance.AddedProviderIDs = added
	result.provenance.ReplacedProviderIDs = replaced
	return result, nil
}

// ValidateProviderCatalogReviewDates reports providers whose review dates are
// newer than asOf or older than maxAge. The default maximum is 400 days.
func ValidateProviderCatalogReviewDates(catalog ProviderCatalog, asOf time.Time, maxAge time.Duration) []string {
	if maxAge <= 0 {
		maxAge = defaultProviderReviewMaximumAge
	}
	asOf = asOf.UTC()
	stale := make([]string, 0)
	for _, provider := range catalog.providers {
		if provider.ReviewedAt.After(asOf) || asOf.Sub(provider.ReviewedAt) > maxAge {
			stale = append(stale, provider.ID)
		}
	}
	return stale
}

func normalizeProviderCatalog(config ProviderCatalogConfig, source ProviderCatalogSource) (ProviderCatalog, error) {
	if config.SchemaVersion != ProviderCatalogSchemaVersion {
		return ProviderCatalog{}, ErrUnsupportedProviderCatalogSchema
	}
	if _, err := time.Parse(providerCatalogDateLayout, config.CatalogVersion); err != nil {
		return ProviderCatalog{}, fmt.Errorf("%w: catalog_version must be an ISO date", ErrInvalidProviderCatalog)
	}
	if len(config.Providers) == 0 || len(config.Providers) > maxProviderCatalogProviders {
		return ProviderCatalog{}, fmt.Errorf("%w: provider count is outside the supported bounds", ErrInvalidProviderCatalog)
	}
	providers := make([]Provider, 0, len(config.Providers))
	ids := make(map[string]struct{}, len(config.Providers))
	aliases := make(map[string]string)
	ownedIncludes := make([]ProviderSPFInclude, 0)
	for index, input := range config.Providers {
		provider, err := normalizeProvider(input, config.CatalogVersion)
		if err != nil {
			return ProviderCatalog{}, fmt.Errorf("%w: providers[%d] is invalid", err, index)
		}
		if _, exists := ids[provider.ID]; exists {
			return ProviderCatalog{}, fmt.Errorf("%w: provider ID is duplicated", ErrInvalidProviderCatalog)
		}
		ids[provider.ID] = struct{}{}
		providers = append(providers, provider)
		for _, include := range provider.SPF.Includes {
			for _, existing := range ownedIncludes {
				if providerIncludeRulesOverlap(existing, include) {
					return ProviderCatalog{}, fmt.Errorf("%w: SPF include matching rules overlap", ErrInvalidProviderCatalog)
				}
			}
			ownedIncludes = append(ownedIncludes, include)
		}
	}
	for _, provider := range providers {
		if provider.Successor != "" {
			if _, exists := ids[provider.Successor]; !exists || provider.Successor == provider.ID {
				return ProviderCatalog{}, fmt.Errorf("%w: provider successor is invalid", ErrInvalidProviderCatalog)
			}
		}
		for _, alias := range provider.Aliases {
			if _, exists := ids[alias]; exists {
				return ProviderCatalog{}, fmt.Errorf("%w: provider alias collides with an ID", ErrInvalidProviderCatalog)
			}
			if _, exists := aliases[alias]; exists {
				return ProviderCatalog{}, fmt.Errorf("%w: provider alias is duplicated", ErrInvalidProviderCatalog)
			}
			aliases[alias] = provider.ID
		}
	}
	if providerSuccessorCycle(providers) {
		return ProviderCatalog{}, fmt.Errorf("%w: provider successor relationship contains a cycle", ErrInvalidProviderCatalog)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID < providers[j].ID })
	canonical, err := json.Marshal(struct {
		SchemaVersion  int        `json:"schema_version"`
		CatalogVersion string     `json:"catalog_version"`
		Providers      []Provider `json:"providers"`
	}{config.SchemaVersion, config.CatalogVersion, providers})
	if err != nil {
		return ProviderCatalog{}, errors.Join(ErrInvalidProviderCatalog, err)
	}
	digest := StableAnalysisID("provider_catalog", string(canonical))
	return ProviderCatalog{
		schemaVersion: config.SchemaVersion, catalogVersion: config.CatalogVersion,
		providers: cloneProviders(providers), aliases: aliases, digest: digest,
		provenance: ProviderCatalogProvenance{Source: source, CatalogVersion: config.CatalogVersion, Digest: digest, AddedProviderIDs: []string{}, ReplacedProviderIDs: []string{}},
	}, nil
}

func normalizeProvider(input ProviderConfig, catalogVersion string) (Provider, error) {
	if len(input.ID) > 128 || len(input.Successor) > 128 || len(input.ReviewedAt) != len(providerCatalogDateLayout) {
		return Provider{}, ErrInvalidProviderCatalog
	}
	id, ok := normalizeConfigID(input.ID)
	if !ok || !boundedProviderString(input.Name) || strings.TrimSpace(input.Name) == "" || !boundedProviderString(input.ContractNote) {
		return Provider{}, ErrInvalidProviderCatalog
	}
	if input.Status != ProviderStatusActive && input.Status != ProviderStatusDeprecated {
		return Provider{}, ErrInvalidProviderCatalog
	}
	successor := ""
	if input.Successor != "" {
		successor, ok = normalizeConfigID(input.Successor)
		if !ok || input.Status != ProviderStatusDeprecated {
			return Provider{}, ErrInvalidProviderCatalog
		}
	}
	if input.EvidenceConfidence != ProviderEvidenceHigh && input.EvidenceConfidence != ProviderEvidenceMedium && input.EvidenceConfidence != ProviderEvidenceLow {
		return Provider{}, ErrInvalidProviderCatalog
	}
	aliases, err := normalizeProviderIDs(input.Aliases)
	if err != nil || len(aliases) > maxProviderCatalogListItems {
		return Provider{}, ErrInvalidProviderCatalog
	}
	officialDomains, err := normalizeProviderDomains(input.OfficialDomains)
	if err != nil || len(officialDomains) == 0 || len(officialDomains) > maxProviderCatalogListItems {
		return Provider{}, ErrInvalidProviderCatalog
	}
	spf, err := normalizeProviderSPF(input.SPF)
	if err != nil {
		return Provider{}, err
	}
	dkim, err := normalizeProviderDKIM(input.DKIM)
	if err != nil {
		return Provider{}, err
	}
	companion, err := normalizeProviderCompanion(input.CompanionRecords)
	if err != nil {
		return Provider{}, err
	}
	documentation, err := normalizeProviderDocumentation(input.Documentation, officialDomains)
	if err != nil || len(documentation) == 0 {
		return Provider{}, ErrInvalidProviderCatalog
	}
	reviewedAt, err := time.Parse(providerCatalogDateLayout, input.ReviewedAt)
	if err != nil {
		return Provider{}, ErrInvalidProviderCatalog
	}
	catalogAt, _ := time.Parse(providerCatalogDateLayout, catalogVersion)
	if reviewedAt.After(catalogAt) {
		return Provider{}, ErrInvalidProviderCatalog
	}
	if !boundedProviderString(input.Alignment.Note) {
		return Provider{}, ErrInvalidProviderCatalog
	}
	if input.Alignment.CustomMailFrom != ProviderCapabilityUnknown && input.Alignment.CustomMailFrom != ProviderCapabilitySupported && input.Alignment.CustomMailFrom != ProviderCapabilityNotSupported {
		return Provider{}, ErrInvalidProviderCatalog
	}
	if input.Alignment.CustomMailFromRequiredForSPFDMARC && input.Alignment.CustomMailFrom != ProviderCapabilitySupported {
		return Provider{}, ErrInvalidProviderCatalog
	}
	return Provider{
		ID: id, Name: strings.TrimSpace(input.Name), Aliases: aliases, Status: input.Status,
		Successor: successor, OfficialDomains: officialDomains, SPF: spf, DKIM: dkim,
		Alignment:      ProviderAlignmentConfig{CustomMailFrom: input.Alignment.CustomMailFrom, CustomMailFromRequiredForSPFDMARC: input.Alignment.CustomMailFromRequiredForSPFDMARC, Note: strings.TrimSpace(input.Alignment.Note)},
		Infrastructure: input.Infrastructure, CompanionRecords: companion, Documentation: documentation,
		ReviewedAt: reviewedAt.UTC(), ContractNote: strings.TrimSpace(input.ContractNote), EvidenceConfidence: input.EvidenceConfidence,
	}, nil
}

func normalizeProviderSPF(input ProviderSPFConfig) (ProviderSPFConfig, error) {
	if len(input.Includes) > maxProviderCatalogListItems {
		return ProviderSPFConfig{}, ErrInvalidProviderCatalog
	}
	includes := make([]ProviderSPFInclude, 0, len(input.Includes))
	seen := map[string]struct{}{}
	for _, value := range input.Includes {
		if len(value.Name) > 254 {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		name, err := normalizeRecordName(value.Name)
		if err != nil || (value.Status != ProviderStatusActive && value.Status != ProviderStatusDeprecated) || (value.Match != SPFIncludeMatchExact && value.Match != SPFIncludeMatchSuffix) {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		if value.EvidenceConfidence != ProviderEvidenceHigh && value.EvidenceConfidence != ProviderEvidenceMedium && value.EvidenceConfidence != ProviderEvidenceLow {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		terminal := ProviderSPFTerminalBehavior(strings.ToLower(strings.TrimSpace(string(value.ExpectedTerminalBehavior))))
		if terminal != "" && terminal != ProviderSPFTerminalSoftFail && terminal != ProviderSPFTerminalHardFail && terminal != ProviderSPFTerminalNeutral {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		if !boundedProviderString(value.Region) || !boundedProviderString(value.Note) {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		if value.Match == SPFIncludeMatchSuffix && strings.TrimSpace(value.Note) == "" {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		key := string(value.Match) + ":" + name
		if _, exists := seen[key]; exists {
			return ProviderSPFConfig{}, ErrInvalidProviderCatalog
		}
		seen[key] = struct{}{}
		includes = append(includes, ProviderSPFInclude{Name: name, Status: value.Status, Match: value.Match, Region: strings.TrimSpace(value.Region), ExpectedTerminalBehavior: terminal, EvidenceConfidence: value.EvidenceConfidence, Note: strings.TrimSpace(value.Note)})
	}
	sort.Slice(includes, func(i, j int) bool {
		if includes[i].Name != includes[j].Name {
			return includes[i].Name < includes[j].Name
		}
		return includes[i].Match < includes[j].Match
	})
	return ProviderSPFConfig{Includes: includes, LiveExpansionRequired: input.LiveExpansionRequired}, nil
}

func normalizeProviderDKIM(input ProviderDKIMConfig) (ProviderDKIMConfig, error) {
	if !boundedProviderString(input.SetupModel) || !boundedProviderString(input.Note) || len(input.SelectorPatterns) > maxProviderCatalogListItems {
		return ProviderDKIMConfig{}, ErrInvalidProviderCatalog
	}
	selectors := make([]string, 0, len(input.SelectorPatterns))
	for _, value := range input.SelectorPatterns {
		if len(value) > 128 {
			return ProviderDKIMConfig{}, ErrInvalidProviderCatalog
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if !selectorPattern.MatchString(value) {
			return ProviderDKIMConfig{}, ErrInvalidProviderCatalog
		}
		selectors = append(selectors, value)
	}
	selectors = compactSortedStrings(selectors)
	if input.PreferredRSABits != 0 && input.PreferredRSABits != 1024 && input.PreferredRSABits != 2048 {
		return ProviderDKIMConfig{}, ErrInvalidProviderCatalog
	}
	input.SetupModel = strings.TrimSpace(input.SetupModel)
	input.Note = strings.TrimSpace(input.Note)
	input.SelectorPatterns = selectors
	return input, nil
}

func normalizeProviderCompanion(values []ProviderCompanionRecord) ([]ProviderCompanionRecord, error) {
	if len(values) > maxProviderCatalogListItems {
		return nil, ErrInvalidProviderCatalog
	}
	result := make([]ProviderCompanionRecord, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if len(value.ID) > 128 || !boundedProviderString(value.Condition) || !boundedProviderString(value.Purpose) {
			return nil, ErrInvalidProviderCatalog
		}
		id, ok := normalizeConfigID(value.ID)
		recordType := ProviderDNSRecordType(strings.ToUpper(strings.TrimSpace(string(value.Type))))
		if !ok || (recordType != ProviderDNSRecordMX && recordType != ProviderDNSRecordCNAME && recordType != ProviderDNSRecordTXT && recordType != ProviderDNSRecordNS) || strings.TrimSpace(value.Condition) == "" || strings.TrimSpace(value.Purpose) == "" || !boundedProviderString(value.Condition) || !boundedProviderString(value.Purpose) {
			return nil, ErrInvalidProviderCatalog
		}
		if _, exists := seen[id]; exists {
			return nil, ErrInvalidProviderCatalog
		}
		seen[id] = struct{}{}
		result = append(result, ProviderCompanionRecord{ID: id, Type: recordType, Condition: strings.TrimSpace(value.Condition), Purpose: strings.TrimSpace(value.Purpose)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func normalizeProviderDocumentation(values []ProviderDocumentation, officialDomains []string) ([]ProviderDocumentation, error) {
	if len(values) > maxProviderCatalogListItems {
		return nil, ErrInvalidProviderCatalog
	}
	result := make([]ProviderDocumentation, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if !boundedProviderString(value.URL) || !boundedProviderString(value.Title) {
			return nil, ErrInvalidProviderCatalog
		}
		parsed, err := url.Parse(strings.TrimSpace(value.URL))
		host, hostErr := normalizeDomainName(parsed.Hostname())
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || hostErr != nil || !domainWithinAny(host, officialDomains) || strings.TrimSpace(value.Title) == "" || !boundedProviderString(value.Title) || !boundedProviderString(value.URL) {
			return nil, ErrInvalidProviderCatalog
		}
		canonical := parsed.String()
		if _, exists := seen[canonical]; exists {
			return nil, ErrInvalidProviderCatalog
		}
		seen[canonical] = struct{}{}
		result = append(result, ProviderDocumentation{URL: canonical, Title: strings.TrimSpace(value.Title)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	return result, nil
}

func normalizeProviderIDs(values []string) ([]string, error) {
	if len(values) > maxProviderCatalogListItems {
		return nil, ErrInvalidProviderCatalog
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(value) > 128 {
			return nil, ErrInvalidProviderCatalog
		}
		id, ok := normalizeConfigID(value)
		if !ok {
			return nil, ErrInvalidProviderCatalog
		}
		result = append(result, id)
	}
	result = compactSortedStrings(result)
	if len(result) != len(values) {
		return nil, ErrInvalidProviderCatalog
	}
	return result, nil
}

func normalizeProviderDomains(values []string) ([]string, error) {
	if len(values) > maxProviderCatalogListItems {
		return nil, ErrInvalidProviderCatalog
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(value) > 254 {
			return nil, ErrInvalidProviderCatalog
		}
		domain, err := normalizeDomainName(value)
		if err != nil {
			return nil, ErrInvalidProviderCatalog
		}
		result = append(result, domain)
	}
	result = compactSortedStrings(result)
	if len(result) != len(values) {
		return nil, ErrInvalidProviderCatalog
	}
	return result, nil
}

func domainWithinAny(host string, domains []string) bool {
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func providerIncludeRulesOverlap(left, right ProviderSPFInclude) bool {
	if left.Name == right.Name {
		return true
	}
	if left.Match == SPFIncludeMatchSuffix && strings.HasSuffix(right.Name, "."+left.Name) {
		return true
	}
	return right.Match == SPFIncludeMatchSuffix && strings.HasSuffix(left.Name, "."+right.Name)
}

func boundedProviderString(value string) bool {
	return len(value) <= maxProviderCatalogStringBytes && strings.IndexFunc(value, unicode.IsControl) < 0
}

func providerSuccessorCycle(providers []Provider) bool {
	next := map[string]string{}
	for _, provider := range providers {
		next[provider.ID] = provider.Successor
	}
	for id := range next {
		seen := map[string]bool{}
		for id != "" {
			if seen[id] {
				return true
			}
			seen[id] = true
			id = next[id]
		}
	}
	return false
}

func cloneProviders(values []Provider) []Provider {
	result := make([]Provider, len(values))
	for index, value := range values {
		result[index] = cloneProvider(value)
	}
	return result
}

func cloneProvider(value Provider) Provider {
	value.Aliases = cloneStrings(value.Aliases)
	value.OfficialDomains = cloneStrings(value.OfficialDomains)
	value.SPF.Includes = append([]ProviderSPFInclude(nil), value.SPF.Includes...)
	value.DKIM.SelectorPatterns = cloneStrings(value.DKIM.SelectorPatterns)
	value.CompanionRecords = append([]ProviderCompanionRecord(nil), value.CompanionRecords...)
	value.Documentation = append([]ProviderDocumentation(nil), value.Documentation...)
	return value
}

func providerConfigFromNormalized(schema int, version string, providers map[string]Provider) ProviderCatalogConfig {
	configs := make([]ProviderConfig, 0, len(providers))
	for _, provider := range providers {
		configs = append(configs, ProviderConfig{
			ID: provider.ID, Name: provider.Name, Aliases: cloneStrings(provider.Aliases), Status: provider.Status,
			Successor: provider.Successor, OfficialDomains: cloneStrings(provider.OfficialDomains), SPF: provider.SPF,
			DKIM: provider.DKIM, Alignment: provider.Alignment, Infrastructure: provider.Infrastructure,
			CompanionRecords: append([]ProviderCompanionRecord(nil), provider.CompanionRecords...),
			Documentation:    append([]ProviderDocumentation(nil), provider.Documentation...),
			ReviewedAt:       provider.ReviewedAt.Format(providerCatalogDateLayout), ContractNote: provider.ContractNote,
			EvidenceConfidence: provider.EvidenceConfidence,
		})
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].ID < configs[j].ID })
	return ProviderCatalogConfig{SchemaVersion: schema, CatalogVersion: version, Providers: configs}
}
