package dmarcgo

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CampaignConfigurationSchemaVersion is the supported security-simulation
// campaign inventory schema.
const CampaignConfigurationSchemaVersion = 1

// CampaignConfigurationSchemaID is the published YAML/JSON data model. YAML
// documents use the same field contract after decoding.
const CampaignConfigurationSchemaID = "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/campaign/configuration/v1.json"

//go:embed schemas/campaign/configuration/v1.json
var campaignConfigurationSchema []byte

const (
	maxCampaignConfigurationBytes = 2 << 20
	maxCampaignDefinitions        = 4096
	maxCampaignListValues         = 512
	maxCampaignStringBytes        = 4096
)

var (
	// ErrInvalidCampaignConfiguration identifies a campaign document that
	// cannot be normalized safely.
	ErrInvalidCampaignConfiguration = errors.New("invalid campaign configuration")
	// ErrUnsupportedCampaignConfigurationSchema identifies an unsupported
	// campaign configuration schema version.
	ErrUnsupportedCampaignConfigurationSchema = errors.New("unsupported campaign configuration schema version")
	// ErrCampaignConfigurationTooLarge identifies an oversized campaign
	// configuration document.
	ErrCampaignConfigurationTooLarge = errors.New("campaign configuration exceeds the size limit")
	// ErrCampaignConfigurationSecretField identifies a forbidden
	// credential-bearing field.
	ErrCampaignConfigurationSecretField = errors.New("campaign configuration contains a secret-bearing field")
)

var campaignDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// CampaignProviderType distinguishes a reviewed catalog provider reference
// from an organization-owned self-hosted system.
type CampaignProviderType string

const (
	CampaignProviderCatalog    CampaignProviderType = "catalog"
	CampaignProviderSelfHosted CampaignProviderType = "self_hosted"
)

// CampaignStatus is caller-owned lifecycle metadata. Historical completed
// campaigns can still match evidence from their authorized window.
type CampaignStatus string

const (
	CampaignStatusScheduled CampaignStatus = "scheduled"
	CampaignStatusActive    CampaignStatus = "active"
	CampaignStatusCompleted CampaignStatus = "completed"
	CampaignStatusCanceled  CampaignStatus = "canceled"
)

// CampaignAuthenticationExpectation describes one expected message-level
// authentication outcome.
type CampaignAuthenticationExpectation string

const (
	CampaignAuthenticationRequired    CampaignAuthenticationExpectation = "required"
	CampaignAuthenticationOptional    CampaignAuthenticationExpectation = "optional"
	CampaignAuthenticationNotExpected CampaignAuthenticationExpectation = "not_expected"
)

// CampaignEmployeeDisclosure controls whether campaign status may be revealed
// through an employee-facing workflow. The safe default is prohibited.
type CampaignEmployeeDisclosure string

const (
	CampaignDisclosureProhibited CampaignEmployeeDisclosure = "prohibited"
	CampaignDisclosurePermitted  CampaignEmployeeDisclosure = "permitted"
)

// CampaignVisibility describes who may receive restricted campaign details.
type CampaignVisibility string

const (
	CampaignVisibilityFull     CampaignVisibility = "full"
	CampaignVisibilityRedacted CampaignVisibility = "redacted"
)

// CampaignMatchFactor is one independently evaluated campaign signal.
type CampaignMatchFactor string

const (
	CampaignFactorWindow             CampaignMatchFactor = "campaign_window"
	CampaignFactorOrganizationScope  CampaignMatchFactor = "organization_scope"
	CampaignFactorRecipientScope     CampaignMatchFactor = "recipient_scope"
	CampaignFactorHeaderFrom         CampaignMatchFactor = "header_from_domain"
	CampaignFactorEnvelopeFrom       CampaignMatchFactor = "envelope_from_domain"
	CampaignFactorDKIM               CampaignMatchFactor = "dkim_identity"
	CampaignFactorSourceAddress      CampaignMatchFactor = "source_address"
	CampaignFactorSourceHostname     CampaignMatchFactor = "source_hostname"
	CampaignFactorMessageID          CampaignMatchFactor = "message_id_domain"
	CampaignFactorInfrastructure     CampaignMatchFactor = "infrastructure_id"
	CampaignFactorTokenDigest        CampaignMatchFactor = "campaign_token_digest"
	CampaignFactorURLDomain          CampaignMatchFactor = "url_domain"
	CampaignFactorContentFingerprint CampaignMatchFactor = "content_fingerprint"
	CampaignFactorAuthentication     CampaignMatchFactor = "authentication"
	CampaignFactorDeliveryException  CampaignMatchFactor = "delivery_exception"
	CampaignFactorEvidenceConfidence CampaignMatchFactor = "evidence_confidence"
)

// CampaignConfigurationConfig is mutable YAML/JSON input for one independently
// maintained campaign document.
type CampaignConfigurationConfig struct {
	SchemaVersion       int                                `json:"schema_version" yaml:"schema_version"`
	GeneratedAt         time.Time                          `json:"generated_at" yaml:"generated_at"`
	EffectiveAt         *time.Time                         `json:"effective_at,omitempty" yaml:"effective_at,omitempty"`
	ExpiresAt           time.Time                          `json:"expires_at" yaml:"expires_at"`
	Imports             []CampaignImportConfig             `json:"imports,omitempty" yaml:"imports,omitempty"`
	SecuritySimulations []SecuritySimulationCampaignConfig `json:"security_simulations" yaml:"security_simulations"`
}

// CampaignImportConfig references another caller-supplied source by stable ID.
// Resolution never discovers or fetches an import that the caller did not
// explicitly supply.
type CampaignImportConfig struct {
	SourceID string `json:"source_id" yaml:"source_id"`
	Required bool   `json:"required,omitempty" yaml:"required,omitempty"`
}

// CampaignProviderConfig identifies a commercial catalog entry or self-hosted
// platform. Name is untrusted display data and never becomes generated prose.
type CampaignProviderConfig struct {
	Type CampaignProviderType `json:"type" yaml:"type"`
	ID   string               `json:"id" yaml:"id"`
	Name string               `json:"name,omitempty" yaml:"name,omitempty"`
}

// CampaignDKIMIdentityConfig is an exact signing-domain and selector set.
type CampaignDKIMIdentityConfig struct {
	Domain    string   `json:"domain" yaml:"domain"`
	Selectors []string `json:"selectors" yaml:"selectors"`
}

// CampaignExpectedIdentityConfig contains message identities that may be used
// for bounded matching. A domain alone is never sufficient authorization.
type CampaignExpectedIdentityConfig struct {
	HeaderFromDomains   []string                     `json:"header_from_domains,omitempty" yaml:"header_from_domains,omitempty"`
	EnvelopeFromDomains []string                     `json:"envelope_from_domains,omitempty" yaml:"envelope_from_domains,omitempty"`
	DKIM                []CampaignDKIMIdentityConfig `json:"dkim,omitempty" yaml:"dkim,omitempty"`
	MessageIDDomains    []string                     `json:"message_id_domains,omitempty" yaml:"message_id_domains,omitempty"`
}

// CampaignExpectedSourcesConfig retains stable infrastructure evidence when
// the campaign operator can supply it. Dynamic providers may leave it empty.
type CampaignExpectedSourcesConfig struct {
	CIDRs             []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty"`
	Hostnames         []string `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	InfrastructureIDs []string `json:"infrastructure_ids,omitempty" yaml:"infrastructure_ids,omitempty"`
}

// CampaignAuthenticationConfig records expected message authentication. It
// never changes DNS health or hides the observed outcomes.
type CampaignAuthenticationConfig struct {
	DMARC CampaignAuthenticationExpectation `json:"dmarc,omitempty" yaml:"dmarc,omitempty"`
	SPF   CampaignAuthenticationExpectation `json:"spf,omitempty" yaml:"spf,omitempty"`
	DKIM  CampaignAuthenticationExpectation `json:"dkim,omitempty" yaml:"dkim,omitempty"`
}

// CampaignResponsePolicyConfig contains restricted analyst workflow metadata.
// Disclosure-safe output uses a fixed neutral employee response identifier and
// does not expose these caller-controlled strings.
type CampaignResponsePolicyConfig struct {
	EmployeeDisclosure      CampaignEmployeeDisclosure `json:"employee_disclosure,omitempty" yaml:"employee_disclosure,omitempty"`
	EmployeeTemplateID      string                     `json:"employee_template_id,omitempty" yaml:"employee_template_id,omitempty"`
	AnalystVisibility       CampaignVisibility         `json:"analyst_visibility,omitempty" yaml:"analyst_visibility,omitempty"`
	CampaignOwnerVisibility CampaignVisibility         `json:"campaign_owner_visibility,omitempty" yaml:"campaign_owner_visibility,omitempty"`
}

// CampaignHandlingConfig controls review routing. Automatic disposition
// remains disabled unless both this document and classification options opt in.
type CampaignHandlingConfig struct {
	WorkflowID                   string `json:"workflow_id,omitempty" yaml:"workflow_id,omitempty"`
	RetainAuthenticationFindings *bool  `json:"retain_authentication_findings,omitempty" yaml:"retain_authentication_findings,omitempty"`
	AutomaticDispositionEligible bool   `json:"automatic_disposition_eligible,omitempty" yaml:"automatic_disposition_eligible,omitempty"`
}

// CampaignMatchPolicyConfig selects factors that must match in addition to the
// library's non-bypassable time, scope, identity, and campaign-signal rules.
type CampaignMatchPolicyConfig struct {
	RequiredFactors       []CampaignMatchFactor `json:"required_factors,omitempty" yaml:"required_factors,omitempty"`
	MinimumMatchedFactors int                   `json:"minimum_matched_factors,omitempty" yaml:"minimum_matched_factors,omitempty"`
}

// SecuritySimulationCampaignConfig is one mutable campaign definition.
type SecuritySimulationCampaignConfig struct {
	ID                  string                         `json:"id" yaml:"id"`
	ExternalCampaignID  string                         `json:"external_campaign_id,omitempty" yaml:"external_campaign_id,omitempty"`
	Provider            CampaignProviderConfig         `json:"provider" yaml:"provider"`
	Organization        string                         `json:"organization" yaml:"organization"`
	Entity              string                         `json:"entity,omitempty" yaml:"entity,omitempty"`
	BusinessUnit        string                         `json:"business_unit,omitempty" yaml:"business_unit,omitempty"`
	Owner               string                         `json:"owner" yaml:"owner"`
	ApprovalReference   string                         `json:"approval_reference" yaml:"approval_reference"`
	Status              CampaignStatus                 `json:"status" yaml:"status"`
	CreatedAt           time.Time                      `json:"created_at" yaml:"created_at"`
	ValidFrom           time.Time                      `json:"valid_from" yaml:"valid_from"`
	ValidUntil          time.Time                      `json:"valid_until" yaml:"valid_until"`
	RecipientDomains    []string                       `json:"recipient_domains,omitempty" yaml:"recipient_domains,omitempty"`
	RecipientScopeIDs   []string                       `json:"recipient_scope_ids,omitempty" yaml:"recipient_scope_ids,omitempty"`
	ExpectedIdentity    CampaignExpectedIdentityConfig `json:"expected_identity" yaml:"expected_identity"`
	ExpectedSources     CampaignExpectedSourcesConfig  `json:"expected_sources,omitempty" yaml:"expected_sources,omitempty"`
	TokenDigests        []string                       `json:"campaign_token_digests,omitempty" yaml:"campaign_token_digests,omitempty"`
	URLDomains          []string                       `json:"url_domains,omitempty" yaml:"url_domains,omitempty"`
	ContentFingerprints []string                       `json:"content_fingerprints,omitempty" yaml:"content_fingerprints,omitempty"`
	Authentication      CampaignAuthenticationConfig   `json:"authentication,omitempty" yaml:"authentication,omitempty"`
	DeliveryExceptions  []string                       `json:"delivery_exception_ids,omitempty" yaml:"delivery_exception_ids,omitempty"`
	ResponsePolicy      CampaignResponsePolicyConfig   `json:"response_policy,omitempty" yaml:"response_policy,omitempty"`
	Handling            CampaignHandlingConfig         `json:"handling,omitempty" yaml:"handling,omitempty"`
	MatchPolicy         CampaignMatchPolicyConfig      `json:"match_policy,omitempty" yaml:"match_policy,omitempty"`
}

// CampaignConfigurationDiagnostic is value-safe and never contains campaign-
// or source-controlled text.
type CampaignConfigurationDiagnostic struct {
	Code     DiagnosticCode  `json:"code"`
	Severity FindingSeverity `json:"severity"`
	Path     string          `json:"path"`
	Message  string          `json:"message"`
}

// CampaignConfigurationValidationError returns deterministic value-safe
// diagnostics for invalid configuration.
type CampaignConfigurationValidationError struct {
	diagnostics []CampaignConfigurationDiagnostic
}

func (err *CampaignConfigurationValidationError) Error() string {
	return fmt.Sprintf("%s: %d diagnostic(s)", ErrInvalidCampaignConfiguration, len(err.diagnostics))
}

func (err *CampaignConfigurationValidationError) Unwrap() error {
	return ErrInvalidCampaignConfiguration
}

// Diagnostics returns a defensive copy.
func (err *CampaignConfigurationValidationError) Diagnostics() []CampaignConfigurationDiagnostic {
	return append([]CampaignConfigurationDiagnostic(nil), err.diagnostics...)
}

// CampaignProvider is normalized provider metadata.
type CampaignProvider struct {
	Type CampaignProviderType `json:"type"`
	ID   string               `json:"id"`
	Name string               `json:"name,omitempty"`
}

// CampaignDKIMIdentity is a normalized exact signing identity.
type CampaignDKIMIdentity struct {
	Domain    string   `json:"domain"`
	Selectors []string `json:"selectors"`
}

// CampaignExpectedIdentity is normalized message identity evidence.
type CampaignExpectedIdentity struct {
	HeaderFromDomains   []string               `json:"header_from_domains"`
	EnvelopeFromDomains []string               `json:"envelope_from_domains"`
	DKIM                []CampaignDKIMIdentity `json:"dkim"`
	MessageIDDomains    []string               `json:"message_id_domains"`
}

// CampaignExpectedSources is normalized stable infrastructure evidence.
type CampaignExpectedSources struct {
	CIDRs             []string `json:"cidrs"`
	Hostnames         []string `json:"hostnames"`
	InfrastructureIDs []string `json:"infrastructure_ids"`
}

// CampaignAuthentication records normalized expectations.
type CampaignAuthentication struct {
	DMARC CampaignAuthenticationExpectation `json:"dmarc"`
	SPF   CampaignAuthenticationExpectation `json:"spf"`
	DKIM  CampaignAuthenticationExpectation `json:"dkim"`
}

// CampaignResponsePolicy is restricted workflow metadata.
type CampaignResponsePolicy struct {
	EmployeeDisclosure      CampaignEmployeeDisclosure `json:"employee_disclosure"`
	EmployeeTemplateID      string                     `json:"employee_template_id,omitempty"`
	AnalystVisibility       CampaignVisibility         `json:"analyst_visibility"`
	CampaignOwnerVisibility CampaignVisibility         `json:"campaign_owner_visibility"`
}

// CampaignHandling is normalized caller policy.
type CampaignHandling struct {
	WorkflowID                   string `json:"workflow_id,omitempty"`
	RetainAuthenticationFindings bool   `json:"retain_authentication_findings"`
	AutomaticDispositionEligible bool   `json:"automatic_disposition_eligible"`
}

// SecuritySimulationCampaign is one normalized campaign definition. Source
// provenance is attached only when documents are resolved into a snapshot.
type SecuritySimulationCampaign struct {
	ID                    string                   `json:"id"`
	ExternalCampaignID    string                   `json:"external_campaign_id,omitempty"`
	Provider              CampaignProvider         `json:"provider"`
	Organization          string                   `json:"organization"`
	Entity                string                   `json:"entity,omitempty"`
	BusinessUnit          string                   `json:"business_unit,omitempty"`
	Owner                 string                   `json:"owner"`
	ApprovalReference     string                   `json:"approval_reference"`
	Status                CampaignStatus           `json:"status"`
	CreatedAt             time.Time                `json:"created_at"`
	ValidFrom             time.Time                `json:"valid_from"`
	ValidUntil            time.Time                `json:"valid_until"`
	RecipientDomains      []string                 `json:"recipient_domains"`
	RecipientScopeIDs     []string                 `json:"recipient_scope_ids"`
	ExpectedIdentity      CampaignExpectedIdentity `json:"expected_identity"`
	ExpectedSources       CampaignExpectedSources  `json:"expected_sources"`
	TokenDigests          []string                 `json:"campaign_token_digests"`
	URLDomains            []string                 `json:"url_domains"`
	ContentFingerprints   []string                 `json:"content_fingerprints"`
	Authentication        CampaignAuthentication   `json:"authentication"`
	DeliveryExceptions    []string                 `json:"delivery_exception_ids"`
	ResponsePolicy        CampaignResponsePolicy   `json:"response_policy"`
	Handling              CampaignHandling         `json:"handling"`
	RequiredFactors       []CampaignMatchFactor    `json:"required_factors"`
	MinimumMatchedFactors int                      `json:"minimum_matched_factors"`
	SourceID              string                   `json:"source_id,omitempty"`
	SourcePriority        int                      `json:"source_priority,omitempty"`
	Digest                AnalysisID               `json:"digest"`
}

// CampaignConfigurationDocument is an immutable normalized single-source
// document. It performs no imports or I/O.
type CampaignConfigurationDocument struct {
	schemaVersion int
	generatedAt   time.Time
	effectiveAt   time.Time
	expiresAt     time.Time
	imports       []CampaignImportConfig
	campaigns     []SecuritySimulationCampaign
	digest        AnalysisID
}

func (document CampaignConfigurationDocument) SchemaVersion() int     { return document.schemaVersion }
func (document CampaignConfigurationDocument) GeneratedAt() time.Time { return document.generatedAt }
func (document CampaignConfigurationDocument) EffectiveAt() time.Time { return document.effectiveAt }
func (document CampaignConfigurationDocument) ExpiresAt() time.Time   { return document.expiresAt }
func (document CampaignConfigurationDocument) Digest() AnalysisID     { return document.digest }

// Imports returns source references in stable source-ID order.
func (document CampaignConfigurationDocument) Imports() []CampaignImportConfig {
	return append([]CampaignImportConfig(nil), document.imports...)
}

// Campaigns returns deep defensive copies in stable campaign-ID order.
func (document CampaignConfigurationDocument) Campaigns() []SecuritySimulationCampaign {
	return cloneSecuritySimulationCampaigns(document.campaigns)
}

// CampaignConfigurationSchema returns a defensive copy of the published
// YAML/JSON configuration schema.
func CampaignConfigurationSchema() []byte {
	return append([]byte(nil), campaignConfigurationSchema...)
}

// ParseCampaignConfiguration strictly decodes one bounded YAML or JSON
// document. JSON is a supported YAML subset, so both formats share identical
// field, alias, secret, and duplicate-key validation.
func ParseCampaignConfiguration(data []byte) (CampaignConfigurationConfig, error) {
	if len(data) > maxCampaignConfigurationBytes {
		return CampaignConfigurationConfig{}, ErrCampaignConfigurationTooLarge
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return CampaignConfigurationConfig{}, fmt.Errorf("%w: document could not be decoded", ErrInvalidCampaignConfiguration)
	}
	if len(document.Content) == 0 {
		return CampaignConfigurationConfig{}, fmt.Errorf("%w: document is empty", ErrInvalidCampaignConfiguration)
	}
	var additional yaml.Node
	if err := decoder.Decode(&additional); err != io.EOF {
		return CampaignConfigurationConfig{}, fmt.Errorf("%w: exactly one document is required", ErrInvalidCampaignConfiguration)
	}
	if err := inspectCampaignConfigurationNode(&document, false); err != nil {
		return CampaignConfigurationConfig{}, err
	}
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	var config CampaignConfigurationConfig
	if err := strict.Decode(&config); err != nil {
		return CampaignConfigurationConfig{}, fmt.Errorf("%w: syntax or field validation failed", ErrInvalidCampaignConfiguration)
	}
	if config.SchemaVersion != CampaignConfigurationSchemaVersion {
		return CampaignConfigurationConfig{}, ErrUnsupportedCampaignConfigurationSchema
	}
	return config, nil
}

// ParseCampaignConfigurationReader reads one bounded YAML or JSON document and
// propagates non-cleanup reader errors.
func ParseCampaignConfigurationReader(reader io.Reader) (CampaignConfigurationConfig, error) {
	if reader == nil {
		return CampaignConfigurationConfig{}, fmt.Errorf("%w: nil reader", ErrInvalidCampaignConfiguration)
	}
	limited := io.LimitReader(reader, maxCampaignConfigurationBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return CampaignConfigurationConfig{}, errors.Join(ErrInvalidCampaignConfiguration, err)
	}
	return ParseCampaignConfiguration(data)
}

// LoadCampaignConfiguration parses and normalizes one caller-supplied
// document without loading imports or performing network access.
func LoadCampaignConfiguration(data []byte) (CampaignConfigurationDocument, error) {
	config, err := ParseCampaignConfiguration(data)
	if err != nil {
		return CampaignConfigurationDocument{}, err
	}
	return NormalizeCampaignConfiguration(config)
}

// NormalizeCampaignConfiguration validates programmatic input and returns an
// immutable single-source document.
func NormalizeCampaignConfiguration(config CampaignConfigurationConfig) (CampaignConfigurationDocument, error) {
	normalizer := campaignConfigurationNormalizer{}
	document := normalizer.normalize(config)
	if len(normalizer.diagnostics) != 0 {
		sort.Slice(normalizer.diagnostics, func(i, j int) bool {
			if normalizer.diagnostics[i].Path != normalizer.diagnostics[j].Path {
				return normalizer.diagnostics[i].Path < normalizer.diagnostics[j].Path
			}
			return normalizer.diagnostics[i].Code < normalizer.diagnostics[j].Code
		})
		return CampaignConfigurationDocument{}, &CampaignConfigurationValidationError{diagnostics: normalizer.diagnostics}
	}
	return document, nil
}

type campaignConfigurationNormalizer struct {
	diagnostics []CampaignConfigurationDiagnostic
}

func (normalizer *campaignConfigurationNormalizer) add(code DiagnosticCode, path, message string) {
	normalizer.diagnostics = append(normalizer.diagnostics, CampaignConfigurationDiagnostic{
		Code: code, Severity: FindingSeverityHigh, Path: path, Message: message,
	})
}

func (normalizer *campaignConfigurationNormalizer) normalize(config CampaignConfigurationConfig) CampaignConfigurationDocument {
	document := CampaignConfigurationDocument{schemaVersion: config.SchemaVersion}
	if config.SchemaVersion != CampaignConfigurationSchemaVersion {
		normalizer.add("campaign.configuration.schema.unsupported", "schema_version", "The campaign configuration schema version is not supported.")
	}
	document.generatedAt = normalizeCampaignTime(config.GeneratedAt, "generated_at", normalizer)
	document.effectiveAt = document.generatedAt
	if config.EffectiveAt != nil {
		document.effectiveAt = normalizeCampaignTime(*config.EffectiveAt, "effective_at", normalizer)
	}
	document.expiresAt = normalizeCampaignTime(config.ExpiresAt, "expires_at", normalizer)
	if !document.effectiveAt.IsZero() && !document.expiresAt.IsZero() && !document.expiresAt.After(document.effectiveAt) {
		normalizer.add("campaign.configuration.invalid_lifetime", "expires_at", "The configuration expiration must be after its effective time.")
	}
	if !document.generatedAt.IsZero() && !document.expiresAt.IsZero() && !document.expiresAt.After(document.generatedAt) {
		normalizer.add("campaign.configuration.invalid_generation_lifetime", "expires_at", "The configuration expiration must be after its generation time.")
	}
	document.imports = normalizer.normalizeImports(config.Imports)
	if len(config.SecuritySimulations) > maxCampaignDefinitions {
		normalizer.add("campaign.configuration.too_many_campaigns", "security_simulations", "The campaign count exceeds the supported limit.")
		return document
	}
	seen := map[string]struct{}{}
	for index, value := range config.SecuritySimulations {
		path := fmt.Sprintf("security_simulations[%d]", index)
		campaign, ok := normalizer.normalizeCampaign(value, path)
		if !ok {
			continue
		}
		if _, duplicate := seen[campaign.ID]; duplicate {
			normalizer.add("campaign.configuration.duplicate_id", path+".id", "The campaign ID duplicates another normalized campaign ID.")
			continue
		}
		seen[campaign.ID] = struct{}{}
		document.campaigns = append(document.campaigns, campaign)
	}
	sort.Slice(document.campaigns, func(i, j int) bool { return document.campaigns[i].ID < document.campaigns[j].ID })
	if len(normalizer.diagnostics) == 0 {
		canonical, _ := json.Marshal(struct {
			SchemaVersion int                          `json:"schema_version"`
			GeneratedAt   time.Time                    `json:"generated_at"`
			EffectiveAt   time.Time                    `json:"effective_at"`
			ExpiresAt     time.Time                    `json:"expires_at"`
			Imports       []CampaignImportConfig       `json:"imports"`
			Campaigns     []SecuritySimulationCampaign `json:"security_simulations"`
		}{document.schemaVersion, document.generatedAt, document.effectiveAt, document.expiresAt, document.imports, document.campaigns})
		document.digest = StableAnalysisID("campaign_configuration_document", string(canonical))
	}
	return document
}

func (normalizer *campaignConfigurationNormalizer) normalizeImports(values []CampaignImportConfig) []CampaignImportConfig {
	if len(values) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_imports", "imports", "The import count exceeds the supported limit.")
		return nil
	}
	result := make([]CampaignImportConfig, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		id, ok := normalizeConfigID(value.SourceID)
		if !ok {
			normalizer.add("campaign.configuration.invalid_import", fmt.Sprintf("imports[%d].source_id", index), "The import source ID is invalid.")
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			normalizer.add("campaign.configuration.duplicate_import", fmt.Sprintf("imports[%d].source_id", index), "The import source ID is duplicated.")
			continue
		}
		seen[id] = struct{}{}
		result = append(result, CampaignImportConfig{SourceID: id, Required: value.Required})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SourceID < result[j].SourceID })
	return result
}

func (normalizer *campaignConfigurationNormalizer) normalizeCampaign(config SecuritySimulationCampaignConfig, path string) (SecuritySimulationCampaign, bool) {
	id, ok := normalizeConfigID(config.ID)
	if !ok {
		normalizer.add("campaign.configuration.invalid_id", path+".id", "The campaign ID is invalid.")
		return SecuritySimulationCampaign{}, false
	}
	campaign := SecuritySimulationCampaign{ID: id}
	campaign.ExternalCampaignID = normalizeCampaignOpaque(config.ExternalCampaignID, path+".external_campaign_id", false, normalizer)
	campaign.Provider = normalizer.normalizeProvider(config.Provider, path+".provider")
	campaign.Organization = normalizeCampaignID(config.Organization, path+".organization", true, normalizer)
	campaign.Entity = normalizeCampaignID(config.Entity, path+".entity", false, normalizer)
	campaign.BusinessUnit = normalizeCampaignID(config.BusinessUnit, path+".business_unit", false, normalizer)
	campaign.Owner = normalizeCampaignID(config.Owner, path+".owner", true, normalizer)
	campaign.ApprovalReference = normalizeCampaignOpaque(config.ApprovalReference, path+".approval_reference", true, normalizer)
	if !validCampaignStatus(config.Status) {
		normalizer.add("campaign.configuration.invalid_status", path+".status", "The campaign status is invalid.")
	} else {
		campaign.Status = config.Status
	}
	campaign.CreatedAt = normalizeCampaignTime(config.CreatedAt, path+".created_at", normalizer)
	campaign.ValidFrom = normalizeCampaignTime(config.ValidFrom, path+".valid_from", normalizer)
	campaign.ValidUntil = normalizeCampaignTime(config.ValidUntil, path+".valid_until", normalizer)
	if !campaign.ValidFrom.IsZero() && !campaign.ValidUntil.IsZero() && campaign.ValidUntil.Before(campaign.ValidFrom) {
		normalizer.add("campaign.configuration.invalid_window", path+".valid_until", "The campaign end must not precede its start.")
	}
	if !campaign.CreatedAt.IsZero() && !campaign.ValidUntil.IsZero() && campaign.CreatedAt.After(campaign.ValidUntil) {
		normalizer.add("campaign.configuration.created_after_window", path+".created_at", "The campaign creation time must not follow its authorization window.")
	}
	campaign.RecipientDomains = normalizeCampaignDomains(config.RecipientDomains, path+".recipient_domains", normalizer)
	campaign.RecipientScopeIDs = normalizeCampaignIDs(config.RecipientScopeIDs, path+".recipient_scope_ids", normalizer)
	campaign.ExpectedIdentity = normalizer.normalizeExpectedIdentity(config.ExpectedIdentity, path+".expected_identity")
	campaign.ExpectedSources = normalizer.normalizeExpectedSources(config.ExpectedSources, path+".expected_sources")
	campaign.TokenDigests = normalizeCampaignDigests(config.TokenDigests, path+".campaign_token_digests", normalizer)
	campaign.URLDomains = normalizeCampaignDomains(config.URLDomains, path+".url_domains", normalizer)
	campaign.ContentFingerprints = normalizeCampaignDigests(config.ContentFingerprints, path+".content_fingerprints", normalizer)
	campaign.Authentication = normalizeCampaignAuthentication(config.Authentication, path+".authentication", normalizer)
	campaign.DeliveryExceptions = normalizeCampaignIDs(config.DeliveryExceptions, path+".delivery_exception_ids", normalizer)
	campaign.ResponsePolicy = normalizeCampaignResponsePolicy(config.ResponsePolicy, path+".response_policy", normalizer)
	campaign.Handling = normalizeCampaignHandling(config.Handling, path+".handling", normalizer)
	campaign.RequiredFactors = normalizer.normalizeRequiredFactors(config.MatchPolicy.RequiredFactors, campaign, path+".match_policy.required_factors")
	campaign.MinimumMatchedFactors = config.MatchPolicy.MinimumMatchedFactors
	if campaign.MinimumMatchedFactors == 0 {
		campaign.MinimumMatchedFactors = 4
	}
	if campaign.MinimumMatchedFactors < 1 || campaign.MinimumMatchedFactors > 16 {
		normalizer.add("campaign.configuration.invalid_match_threshold", path+".match_policy.minimum_matched_factors", "The minimum matched-factor threshold is invalid.")
	}
	canonical, _ := json.Marshal(struct {
		Campaign SecuritySimulationCampaign `json:"campaign"`
	}{campaign})
	campaign.Digest = StableAnalysisID("security_simulation_campaign", string(canonical))
	return campaign, true
}

func (normalizer *campaignConfigurationNormalizer) normalizeProvider(config CampaignProviderConfig, path string) CampaignProvider {
	provider := CampaignProvider{Type: config.Type, ID: normalizeCampaignID(config.ID, path+".id", true, normalizer)}
	if config.Type != CampaignProviderCatalog && config.Type != CampaignProviderSelfHosted {
		normalizer.add("campaign.configuration.invalid_provider_type", path+".type", "The campaign provider type is invalid.")
	}
	provider.Name = normalizeCampaignOpaque(config.Name, path+".name", config.Type == CampaignProviderSelfHosted, normalizer)
	return provider
}

func (normalizer *campaignConfigurationNormalizer) normalizeExpectedIdentity(config CampaignExpectedIdentityConfig, path string) CampaignExpectedIdentity {
	result := CampaignExpectedIdentity{
		HeaderFromDomains:   normalizeCampaignDomains(config.HeaderFromDomains, path+".header_from_domains", normalizer),
		EnvelopeFromDomains: normalizeCampaignDomains(config.EnvelopeFromDomains, path+".envelope_from_domains", normalizer),
		MessageIDDomains:    normalizeCampaignDomains(config.MessageIDDomains, path+".message_id_domains", normalizer),
	}
	if len(config.DKIM) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_dkim_identities", path+".dkim", "The DKIM identity count exceeds the supported limit.")
		return result
	}
	seen := map[string]struct{}{}
	for index, value := range config.DKIM {
		domain, err := normalizeRecordName(value.Domain)
		if err != nil {
			normalizer.add("campaign.configuration.invalid_dkim_domain", fmt.Sprintf("%s.dkim[%d].domain", path, index), "The DKIM signing domain is invalid.")
			continue
		}
		selectors := normalizeCampaignIDs(value.Selectors, fmt.Sprintf("%s.dkim[%d].selectors", path, index), normalizer)
		if len(selectors) == 0 {
			normalizer.add("campaign.configuration.missing_dkim_selector", fmt.Sprintf("%s.dkim[%d].selectors", path, index), "At least one exact DKIM selector is required.")
			continue
		}
		if _, duplicate := seen[domain]; duplicate {
			normalizer.add("campaign.configuration.duplicate_dkim_domain", fmt.Sprintf("%s.dkim[%d].domain", path, index), "The DKIM signing domain is duplicated.")
			continue
		}
		seen[domain] = struct{}{}
		result.DKIM = append(result.DKIM, CampaignDKIMIdentity{Domain: domain, Selectors: selectors})
	}
	sort.Slice(result.DKIM, func(i, j int) bool { return result.DKIM[i].Domain < result.DKIM[j].Domain })
	return result
}

func (normalizer *campaignConfigurationNormalizer) normalizeExpectedSources(config CampaignExpectedSourcesConfig, path string) CampaignExpectedSources {
	result := CampaignExpectedSources{
		Hostnames:         normalizeCampaignDomains(config.Hostnames, path+".hostnames", normalizer),
		InfrastructureIDs: normalizeCampaignIDs(config.InfrastructureIDs, path+".infrastructure_ids", normalizer),
	}
	if len(config.CIDRs) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_cidrs", path+".cidrs", "The source CIDR count exceeds the supported limit.")
		return result
	}
	seen := map[string]struct{}{}
	for index, raw := range config.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Addr().Zone() != "" {
			normalizer.add("campaign.configuration.invalid_cidr", fmt.Sprintf("%s.cidrs[%d]", path, index), "The source CIDR is invalid.")
			continue
		}
		prefix = prefix.Masked()
		value := prefix.String()
		if _, duplicate := seen[value]; !duplicate {
			seen[value] = struct{}{}
			result.CIDRs = append(result.CIDRs, value)
		}
	}
	sort.Strings(result.CIDRs)
	return result
}

func (normalizer *campaignConfigurationNormalizer) normalizeRequiredFactors(values []CampaignMatchFactor, campaign SecuritySimulationCampaign, path string) []CampaignMatchFactor {
	if len(values) == 0 {
		values = []CampaignMatchFactor{CampaignFactorWindow, CampaignFactorOrganizationScope}
		if len(campaign.ExpectedIdentity.HeaderFromDomains) != 0 {
			values = append(values, CampaignFactorHeaderFrom)
		} else if len(campaign.ExpectedIdentity.EnvelopeFromDomains) != 0 {
			values = append(values, CampaignFactorEnvelopeFrom)
		} else if len(campaign.ExpectedIdentity.MessageIDDomains) != 0 {
			values = append(values, CampaignFactorMessageID)
		}
		if len(campaign.TokenDigests) != 0 {
			values = append(values, CampaignFactorTokenDigest)
		} else if len(campaign.ContentFingerprints) != 0 {
			values = append(values, CampaignFactorContentFingerprint)
		} else if len(campaign.ExpectedIdentity.DKIM) != 0 {
			values = append(values, CampaignFactorDKIM)
		} else if len(campaign.ExpectedSources.InfrastructureIDs) != 0 {
			values = append(values, CampaignFactorInfrastructure)
		}
	}
	if len(values) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_required_factors", path, "The required-factor count exceeds the supported limit.")
		return nil
	}
	seen := map[CampaignMatchFactor]struct{}{}
	result := make([]CampaignMatchFactor, 0, len(values))
	for index, value := range values {
		if !validCampaignMatchFactor(value) {
			normalizer.add("campaign.configuration.invalid_required_factor", fmt.Sprintf("%s[%d]", path, index), "The required campaign factor is invalid.")
			continue
		}
		if !campaignFactorConfigured(campaign, value) {
			normalizer.add("campaign.configuration.unavailable_required_factor", fmt.Sprintf("%s[%d]", path, index), "A required campaign factor has no configured expected evidence.")
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if _, ok := seen[CampaignFactorWindow]; !ok {
		normalizer.add("campaign.configuration.window_not_required", path, "Campaign time must be a required match factor.")
	}
	if _, ok := seen[CampaignFactorOrganizationScope]; !ok {
		normalizer.add("campaign.configuration.scope_not_required", path, "Organization scope must be a required match factor.")
	}
	if !hasCampaignIdentityFactor(seen) {
		normalizer.add("campaign.configuration.identity_not_required", path, "At least one message identity must be a required match factor.")
	}
	if !hasCampaignSpecificFactor(seen) {
		normalizer.add("campaign.configuration.signal_not_required", path, "At least one campaign-specific signal must be a required match factor.")
	}
	return result
}

func campaignFactorConfigured(campaign SecuritySimulationCampaign, factor CampaignMatchFactor) bool {
	switch factor {
	case CampaignFactorWindow, CampaignFactorOrganizationScope:
		return true
	case CampaignFactorRecipientScope:
		return len(campaign.RecipientDomains) != 0 || len(campaign.RecipientScopeIDs) != 0
	case CampaignFactorHeaderFrom:
		return len(campaign.ExpectedIdentity.HeaderFromDomains) != 0
	case CampaignFactorEnvelopeFrom:
		return len(campaign.ExpectedIdentity.EnvelopeFromDomains) != 0
	case CampaignFactorDKIM:
		return len(campaign.ExpectedIdentity.DKIM) != 0
	case CampaignFactorSourceAddress:
		return len(campaign.ExpectedSources.CIDRs) != 0
	case CampaignFactorSourceHostname:
		return len(campaign.ExpectedSources.Hostnames) != 0
	case CampaignFactorMessageID:
		return len(campaign.ExpectedIdentity.MessageIDDomains) != 0
	case CampaignFactorInfrastructure:
		return len(campaign.ExpectedSources.InfrastructureIDs) != 0
	case CampaignFactorTokenDigest:
		return len(campaign.TokenDigests) != 0
	case CampaignFactorURLDomain:
		return len(campaign.URLDomains) != 0
	case CampaignFactorContentFingerprint:
		return len(campaign.ContentFingerprints) != 0
	case CampaignFactorAuthentication:
		return campaignAuthenticationIsRequired(campaign.Authentication)
	case CampaignFactorDeliveryException:
		return len(campaign.DeliveryExceptions) != 0
	case CampaignFactorEvidenceConfidence:
		return true
	default:
		return false
	}
}

func normalizeCampaignTime(value time.Time, path string, normalizer *campaignConfigurationNormalizer) time.Time {
	if value.IsZero() {
		normalizer.add("campaign.configuration.missing_time", path, "The required timestamp is missing.")
		return time.Time{}
	}
	return value.UTC()
}

func normalizeCampaignID(value, path string, required bool, normalizer *campaignConfigurationNormalizer) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" && !required {
		return ""
	}
	normalized, ok := normalizeConfigID(trimmed)
	if !ok || len(normalized) > maxCampaignStringBytes {
		normalizer.add("campaign.configuration.invalid_identifier", path, "The campaign identifier is missing or invalid.")
		return ""
	}
	return normalized
}

func normalizeCampaignOpaque(value, path string, required bool, normalizer *campaignConfigurationNormalizer) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		if required {
			normalizer.add("campaign.configuration.missing_value", path, "The required campaign value is missing.")
		}
		return ""
	}
	if len(trimmed) > maxCampaignStringBytes || strings.ContainsRune(trimmed, '\x00') {
		normalizer.add("campaign.configuration.invalid_value", path, "The campaign value exceeds the supported limits.")
		return ""
	}
	return trimmed
}

func normalizeCampaignIDs(values []string, path string, normalizer *campaignConfigurationNormalizer) []string {
	if len(values) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_values", path, "The campaign value count exceeds the supported limit.")
		return nil
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		normalized := normalizeCampaignID(value, fmt.Sprintf("%s[%d]", path, index), true, normalizer)
		if normalized == "" {
			continue
		}
		if _, duplicate := seen[normalized]; !duplicate {
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result
}

func normalizeCampaignDomains(values []string, path string, normalizer *campaignConfigurationNormalizer) []string {
	if len(values) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_domains", path, "The campaign domain count exceeds the supported limit.")
		return nil
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		domain, err := normalizeRecordName(value)
		if err != nil {
			normalizer.add("campaign.configuration.invalid_domain", fmt.Sprintf("%s[%d]", path, index), "The campaign domain is invalid.")
			continue
		}
		if _, duplicate := seen[domain]; !duplicate {
			seen[domain] = struct{}{}
			result = append(result, domain)
		}
	}
	sort.Strings(result)
	return result
}

func normalizeCampaignDigests(values []string, path string, normalizer *campaignConfigurationNormalizer) []string {
	if len(values) > maxCampaignListValues {
		normalizer.add("campaign.configuration.too_many_digests", path, "The digest count exceeds the supported limit.")
		return nil
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		digest := strings.ToLower(strings.TrimSpace(value))
		if !campaignDigestPattern.MatchString(digest) {
			normalizer.add("campaign.configuration.invalid_digest", fmt.Sprintf("%s[%d]", path, index), "Only complete SHA-256 digests are supported.")
			continue
		}
		if _, duplicate := seen[digest]; !duplicate {
			seen[digest] = struct{}{}
			result = append(result, digest)
		}
	}
	sort.Strings(result)
	return result
}

func normalizeCampaignAuthentication(value CampaignAuthenticationConfig, path string, normalizer *campaignConfigurationNormalizer) CampaignAuthentication {
	result := CampaignAuthentication(value)
	for name, expectation := range map[string]CampaignAuthenticationExpectation{"dmarc": result.DMARC, "spf": result.SPF, "dkim": result.DKIM} {
		if expectation == "" {
			expectation = CampaignAuthenticationOptional
			switch name {
			case "dmarc":
				result.DMARC = expectation
			case "spf":
				result.SPF = expectation
			case "dkim":
				result.DKIM = expectation
			}
		}
		if expectation != CampaignAuthenticationRequired && expectation != CampaignAuthenticationOptional && expectation != CampaignAuthenticationNotExpected {
			normalizer.add("campaign.configuration.invalid_authentication_expectation", path+"."+name, "The authentication expectation is invalid.")
		}
	}
	return result
}

func normalizeCampaignResponsePolicy(value CampaignResponsePolicyConfig, path string, normalizer *campaignConfigurationNormalizer) CampaignResponsePolicy {
	result := CampaignResponsePolicy{
		EmployeeDisclosure: value.EmployeeDisclosure, EmployeeTemplateID: normalizeCampaignID(value.EmployeeTemplateID, path+".employee_template_id", false, normalizer),
		AnalystVisibility: value.AnalystVisibility, CampaignOwnerVisibility: value.CampaignOwnerVisibility,
	}
	if result.EmployeeDisclosure == "" {
		result.EmployeeDisclosure = CampaignDisclosureProhibited
	}
	if result.EmployeeDisclosure != CampaignDisclosureProhibited && result.EmployeeDisclosure != CampaignDisclosurePermitted {
		normalizer.add("campaign.configuration.invalid_employee_disclosure", path+".employee_disclosure", "The employee disclosure policy is invalid.")
	}
	if result.AnalystVisibility == "" {
		result.AnalystVisibility = CampaignVisibilityFull
	}
	if result.CampaignOwnerVisibility == "" {
		result.CampaignOwnerVisibility = CampaignVisibilityFull
	}
	if !validCampaignVisibility(result.AnalystVisibility) {
		normalizer.add("campaign.configuration.invalid_analyst_visibility", path+".analyst_visibility", "The analyst visibility is invalid.")
	}
	if !validCampaignVisibility(result.CampaignOwnerVisibility) {
		normalizer.add("campaign.configuration.invalid_owner_visibility", path+".campaign_owner_visibility", "The campaign-owner visibility is invalid.")
	}
	return result
}

func normalizeCampaignHandling(value CampaignHandlingConfig, path string, normalizer *campaignConfigurationNormalizer) CampaignHandling {
	retainAuthentication := true
	if value.RetainAuthenticationFindings != nil {
		retainAuthentication = *value.RetainAuthenticationFindings
		if !retainAuthentication {
			normalizer.add("campaign.configuration.authentication_retention_required", path+".retain_authentication_findings", "Authentication findings cannot be disabled for campaign classification.")
		}
	}
	return CampaignHandling{
		WorkflowID:                   normalizeCampaignID(value.WorkflowID, path+".workflow_id", false, normalizer),
		RetainAuthenticationFindings: retainAuthentication,
		AutomaticDispositionEligible: value.AutomaticDispositionEligible,
	}
}

func validCampaignStatus(value CampaignStatus) bool {
	return value == CampaignStatusScheduled || value == CampaignStatusActive || value == CampaignStatusCompleted || value == CampaignStatusCanceled
}

func validCampaignVisibility(value CampaignVisibility) bool {
	return value == CampaignVisibilityFull || value == CampaignVisibilityRedacted
}

func validCampaignMatchFactor(value CampaignMatchFactor) bool {
	switch value {
	case CampaignFactorWindow, CampaignFactorOrganizationScope, CampaignFactorRecipientScope, CampaignFactorHeaderFrom,
		CampaignFactorEnvelopeFrom, CampaignFactorDKIM, CampaignFactorSourceAddress, CampaignFactorSourceHostname,
		CampaignFactorMessageID, CampaignFactorInfrastructure, CampaignFactorTokenDigest, CampaignFactorURLDomain,
		CampaignFactorContentFingerprint, CampaignFactorAuthentication, CampaignFactorDeliveryException, CampaignFactorEvidenceConfidence:
		return true
	default:
		return false
	}
}

func hasCampaignIdentityFactor(values map[CampaignMatchFactor]struct{}) bool {
	for _, factor := range []CampaignMatchFactor{CampaignFactorHeaderFrom, CampaignFactorEnvelopeFrom, CampaignFactorDKIM, CampaignFactorMessageID} {
		if _, ok := values[factor]; ok {
			return true
		}
	}
	return false
}

func hasCampaignSpecificFactor(values map[CampaignMatchFactor]struct{}) bool {
	for _, factor := range []CampaignMatchFactor{CampaignFactorDKIM, CampaignFactorInfrastructure, CampaignFactorTokenDigest, CampaignFactorContentFingerprint} {
		if _, ok := values[factor]; ok {
			return true
		}
	}
	return false
}

func inspectCampaignConfigurationNode(node *yaml.Node, mappingKey bool) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("%w: aliases and anchors are not supported", ErrInvalidCampaignConfiguration)
	}
	if mappingKey && node.Kind == yaml.ScalarNode && isSecretBearingKey(node.Value) {
		return ErrCampaignConfigurationSecretField
	}
	if node.Kind == yaml.ScalarNode && environmentPlaceholder.MatchString(node.Value) {
		return fmt.Errorf("%w: environment placeholders are not supported inside documents", ErrInvalidCampaignConfiguration)
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%w: duplicate mapping keys are not supported", ErrInvalidCampaignConfiguration)
			}
			seen[key.Value] = struct{}{}
			if err := inspectCampaignConfigurationNode(key, true); err != nil {
				return err
			}
			if index+1 < len(node.Content) {
				if err := inspectCampaignConfigurationNode(node.Content[index+1], false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := inspectCampaignConfigurationNode(child, false); err != nil {
			return err
		}
	}
	return nil
}

func cloneSecuritySimulationCampaigns(values []SecuritySimulationCampaign) []SecuritySimulationCampaign {
	result := make([]SecuritySimulationCampaign, len(values))
	for index, value := range values {
		result[index] = cloneSecuritySimulationCampaign(value)
	}
	return result
}

func cloneSecuritySimulationCampaign(value SecuritySimulationCampaign) SecuritySimulationCampaign {
	value.RecipientDomains = cloneStrings(value.RecipientDomains)
	value.RecipientScopeIDs = cloneStrings(value.RecipientScopeIDs)
	value.ExpectedIdentity.HeaderFromDomains = cloneStrings(value.ExpectedIdentity.HeaderFromDomains)
	value.ExpectedIdentity.EnvelopeFromDomains = cloneStrings(value.ExpectedIdentity.EnvelopeFromDomains)
	value.ExpectedIdentity.MessageIDDomains = cloneStrings(value.ExpectedIdentity.MessageIDDomains)
	dkim := value.ExpectedIdentity.DKIM
	value.ExpectedIdentity.DKIM = make([]CampaignDKIMIdentity, len(dkim))
	for index, identity := range dkim {
		value.ExpectedIdentity.DKIM[index] = CampaignDKIMIdentity{Domain: identity.Domain, Selectors: cloneStrings(identity.Selectors)}
	}
	value.ExpectedSources.CIDRs = cloneStrings(value.ExpectedSources.CIDRs)
	value.ExpectedSources.Hostnames = cloneStrings(value.ExpectedSources.Hostnames)
	value.ExpectedSources.InfrastructureIDs = cloneStrings(value.ExpectedSources.InfrastructureIDs)
	value.TokenDigests = cloneStrings(value.TokenDigests)
	value.URLDomains = cloneStrings(value.URLDomains)
	value.ContentFingerprints = cloneStrings(value.ContentFingerprints)
	value.DeliveryExceptions = cloneStrings(value.DeliveryExceptions)
	value.RequiredFactors = append([]CampaignMatchFactor(nil), value.RequiredFactors...)
	return value
}
