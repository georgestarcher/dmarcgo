package dmarcgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

var (
	// ErrInvalidReportedMessageEvidence identifies caller-supplied message
	// evidence that cannot be normalized safely.
	ErrInvalidReportedMessageEvidence = errors.New("invalid reported-message evidence")
)

// CampaignEvidenceSourceType describes the origin of one caller assertion.
// It does not grant trust by itself.
type CampaignEvidenceSourceType string

const (
	CampaignEvidenceMessageHeaders  CampaignEvidenceSourceType = "message_headers"
	CampaignEvidenceMailGateway     CampaignEvidenceSourceType = "mail_gateway"
	CampaignEvidenceUserReport      CampaignEvidenceSourceType = "user_report"
	CampaignEvidenceAggregateReport CampaignEvidenceSourceType = "aggregate_report"
	CampaignEvidenceVerifiedToken   CampaignEvidenceSourceType = "verified_token"
	CampaignEvidenceContentScanner  CampaignEvidenceSourceType = "content_scanner"
)

// CampaignEvidenceProvenanceInput is mutable caller provenance. SourceID is
// data, not an instruction or trust decision.
type CampaignEvidenceProvenanceInput struct {
	SourceID   string                     `json:"source_id"`
	Type       CampaignEvidenceSourceType `json:"type"`
	ObservedAt time.Time                  `json:"observed_at"`
	Confidence FindingConfidence          `json:"confidence"`
}

// CampaignEvidenceProvenance is one normalized evidence assertion source.
type CampaignEvidenceProvenance struct {
	ID          ProvenanceID               `json:"id"`
	SourceID    string                     `json:"source_id"`
	Type        CampaignEvidenceSourceType `json:"type"`
	ObservedAt  time.Time                  `json:"observed_at"`
	Confidence  FindingConfidence          `json:"confidence"`
	Sensitivity Sensitivity                `json:"sensitivity"`
}

// CampaignDKIMEvidenceInput is one observed DKIM identity and result.
type CampaignDKIMEvidenceInput struct {
	Domain   string                      `json:"domain"`
	Selector string                      `json:"selector"`
	Outcome  ReportAuthenticationOutcome `json:"outcome"`
}

// CampaignDKIMEvidence is one normalized observed DKIM identity.
type CampaignDKIMEvidence struct {
	Domain   string                      `json:"domain"`
	Selector string                      `json:"selector"`
	Outcome  ReportAuthenticationOutcome `json:"outcome"`
}

// ReportedMessageEvidenceInput is mutable caller-supplied evidence for one
// reported message or one explicitly marked aggregate observation. It contains
// no message body and accepts only digests for tokens and content fingerprints.
type ReportedMessageEvidenceInput struct {
	ExternalReference    string                            `json:"external_reference,omitempty"`
	Organization         string                            `json:"organization"`
	Entity               string                            `json:"entity,omitempty"`
	BusinessUnit         string                            `json:"business_unit,omitempty"`
	HeaderFromDomain     string                            `json:"header_from_domain,omitempty"`
	EnvelopeFromDomain   string                            `json:"envelope_from_domain,omitempty"`
	MessageIDDomain      string                            `json:"message_id_domain,omitempty"`
	DKIM                 []CampaignDKIMEvidenceInput       `json:"dkim,omitempty"`
	SPFDomain            string                            `json:"spf_domain,omitempty"`
	SPFOutcome           ReportAuthenticationOutcome       `json:"spf_outcome"`
	DKIMOutcome          ReportAuthenticationOutcome       `json:"dkim_outcome"`
	DMARCOutcome         ReportAuthenticationOutcome       `json:"dmarc_outcome"`
	SourceAddresses      []string                          `json:"source_addresses,omitempty"`
	SourceHostnames      []string                          `json:"source_hostnames,omitempty"`
	InfrastructureIDs    []string                          `json:"infrastructure_ids,omitempty"`
	DeliveryExceptionIDs []string                          `json:"delivery_exception_ids,omitempty"`
	RecipientDomains     []string                          `json:"recipient_domains,omitempty"`
	RecipientScopeIDs    []string                          `json:"recipient_scope_ids,omitempty"`
	URLDomains           []string                          `json:"url_domains,omitempty"`
	TokenDigests         []string                          `json:"campaign_token_digests,omitempty"`
	ContentFingerprints  []string                          `json:"content_fingerprints,omitempty"`
	MessageTime          time.Time                         `json:"message_time,omitempty"`
	PeriodStart          time.Time                         `json:"period_start,omitempty"`
	PeriodEnd            time.Time                         `json:"period_end,omitempty"`
	AggregateOnly        bool                              `json:"aggregate_only,omitempty"`
	Provenance           []CampaignEvidenceProvenanceInput `json:"provenance"`
}

// ReportedMessageEvidenceValue is the complete normalized message evidence.
// All fields are untrusted data and must remain structurally separated from
// generated explanations and actions.
type ReportedMessageEvidenceValue struct {
	ID                   EvidenceID                   `json:"id"`
	ExternalReference    string                       `json:"external_reference,omitempty"`
	Organization         string                       `json:"organization"`
	Entity               string                       `json:"entity,omitempty"`
	BusinessUnit         string                       `json:"business_unit,omitempty"`
	HeaderFromDomain     string                       `json:"header_from_domain,omitempty"`
	EnvelopeFromDomain   string                       `json:"envelope_from_domain,omitempty"`
	MessageIDDomain      string                       `json:"message_id_domain,omitempty"`
	DKIM                 []CampaignDKIMEvidence       `json:"dkim"`
	SPFDomain            string                       `json:"spf_domain,omitempty"`
	SPFOutcome           ReportAuthenticationOutcome  `json:"spf_outcome"`
	DKIMOutcome          ReportAuthenticationOutcome  `json:"dkim_outcome"`
	DMARCOutcome         ReportAuthenticationOutcome  `json:"dmarc_outcome"`
	SourceAddresses      []string                     `json:"source_addresses"`
	SourceHostnames      []string                     `json:"source_hostnames"`
	InfrastructureIDs    []string                     `json:"infrastructure_ids"`
	DeliveryExceptionIDs []string                     `json:"delivery_exception_ids"`
	RecipientDomains     []string                     `json:"recipient_domains"`
	RecipientScopeIDs    []string                     `json:"recipient_scope_ids"`
	URLDomains           []string                     `json:"url_domains"`
	TokenDigests         []string                     `json:"campaign_token_digests"`
	ContentFingerprints  []string                     `json:"content_fingerprints"`
	MessageTime          time.Time                    `json:"message_time,omitempty"`
	PeriodStart          time.Time                    `json:"period_start,omitempty"`
	PeriodEnd            time.Time                    `json:"period_end,omitempty"`
	AggregateOnly        bool                         `json:"aggregate_only"`
	Provenance           []CampaignEvidenceProvenance `json:"provenance"`
	Sensitivity          Sensitivity                  `json:"sensitivity"`
}

// ReportedMessageEvidence is an immutable normalized message/header evidence
// object. Accessors return defensive copies and perform no parsing or I/O.
type ReportedMessageEvidence struct {
	value  ReportedMessageEvidenceValue
	digest AnalysisID
}

// Value returns a complete defensive copy.
func (evidence ReportedMessageEvidence) Value() ReportedMessageEvidenceValue {
	return cloneReportedMessageEvidenceValue(evidence.value)
}

// Digest identifies the complete normalized evidence.
func (evidence ReportedMessageEvidence) Digest() AnalysisID { return evidence.digest }

// NormalizeReportedMessageEvidence validates caller-supplied message/header
// evidence. It never parses a body, reads a file, resolves DNS, or contacts a
// source address.
func NormalizeReportedMessageEvidence(input ReportedMessageEvidenceInput) (ReportedMessageEvidence, error) {
	value := ReportedMessageEvidenceValue{Sensitivity: SensitivityRestricted}
	var err error
	value.ExternalReference, err = normalizeCampaignEvidenceOpaque(input.ExternalReference, false)
	if err != nil {
		return ReportedMessageEvidence{}, err
	}
	value.Organization, err = normalizeCampaignEvidenceID(input.Organization, true)
	if err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.Entity, err = normalizeCampaignEvidenceID(input.Entity, false); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.BusinessUnit, err = normalizeCampaignEvidenceID(input.BusinessUnit, false); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.HeaderFromDomain, err = normalizeCampaignEvidenceDomain(input.HeaderFromDomain, false); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.EnvelopeFromDomain, err = normalizeCampaignEvidenceDomain(input.EnvelopeFromDomain, false); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.MessageIDDomain, err = normalizeCampaignEvidenceDomain(input.MessageIDDomain, false); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.SPFDomain, err = normalizeCampaignEvidenceDomain(input.SPFDomain, false); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.DKIM, err = normalizeCampaignDKIMEvidence(input.DKIM); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.SPFOutcome, err = normalizeCampaignEvidenceOutcome(input.SPFOutcome); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.DKIMOutcome, err = normalizeCampaignEvidenceOutcome(input.DKIMOutcome); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.DMARCOutcome, err = normalizeCampaignEvidenceOutcome(input.DMARCOutcome); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.SourceAddresses, err = normalizeCampaignEvidenceAddresses(input.SourceAddresses); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.SourceHostnames, err = normalizeCampaignEvidenceDomains(input.SourceHostnames); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.InfrastructureIDs, err = normalizeCampaignEvidenceIDs(input.InfrastructureIDs); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.DeliveryExceptionIDs, err = normalizeCampaignEvidenceIDs(input.DeliveryExceptionIDs); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.RecipientDomains, err = normalizeCampaignEvidenceDomains(input.RecipientDomains); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.RecipientScopeIDs, err = normalizeCampaignEvidenceIDs(input.RecipientScopeIDs); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.URLDomains, err = normalizeCampaignEvidenceDomains(input.URLDomains); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.TokenDigests, err = normalizeCampaignEvidenceDigests(input.TokenDigests); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if value.ContentFingerprints, err = normalizeCampaignEvidenceDigests(input.ContentFingerprints); err != nil {
		return ReportedMessageEvidence{}, err
	}
	value.AggregateOnly = input.AggregateOnly
	if !input.MessageTime.IsZero() {
		value.MessageTime = input.MessageTime.UTC()
	}
	if !input.PeriodStart.IsZero() {
		value.PeriodStart = input.PeriodStart.UTC()
	}
	if !input.PeriodEnd.IsZero() {
		value.PeriodEnd = input.PeriodEnd.UTC()
	}
	if value.AggregateOnly {
		if value.PeriodStart.IsZero() || value.PeriodEnd.IsZero() || value.PeriodEnd.Before(value.PeriodStart) || !value.MessageTime.IsZero() {
			return ReportedMessageEvidence{}, fmt.Errorf("%w: aggregate evidence requires valid period bounds and no exact message time", ErrInvalidReportedMessageEvidence)
		}
	} else if !value.PeriodStart.IsZero() || !value.PeriodEnd.IsZero() {
		return ReportedMessageEvidence{}, fmt.Errorf("%w: message evidence cannot claim aggregate period bounds", ErrInvalidReportedMessageEvidence)
	}
	if value.Provenance, err = normalizeCampaignEvidenceProvenance(input.Provenance); err != nil {
		return ReportedMessageEvidence{}, err
	}
	if len(value.Provenance) == 0 {
		return ReportedMessageEvidence{}, fmt.Errorf("%w: evidence provenance is required", ErrInvalidReportedMessageEvidence)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ReportedMessageEvidence{}, errors.Join(ErrInvalidReportedMessageEvidence, err)
	}
	value.ID = EvidenceID(StableAnalysisID("reported_message_evidence", string(canonical)))
	canonical, _ = json.Marshal(value)
	return ReportedMessageEvidence{value: value, digest: StableAnalysisID("reported_message_evidence_document", string(canonical))}, nil
}

func normalizeCampaignDKIMEvidence(values []CampaignDKIMEvidenceInput) ([]CampaignDKIMEvidence, error) {
	if len(values) > maxCampaignListValues {
		return nil, fmt.Errorf("%w: too many DKIM identities", ErrInvalidReportedMessageEvidence)
	}
	result := make([]CampaignDKIMEvidence, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		domain, err := normalizeCampaignEvidenceDomain(value.Domain, true)
		if err != nil {
			return nil, err
		}
		selector, ok := normalizeCampaignSelector(value.Selector)
		if !ok {
			return nil, fmt.Errorf("%w: DKIM selector is invalid", ErrInvalidReportedMessageEvidence)
		}
		outcome, err := normalizeCampaignEvidenceOutcome(value.Outcome)
		if err != nil {
			return nil, err
		}
		key := domain + "\x00" + selector + "\x00" + string(outcome)
		if _, duplicate := seen[key]; !duplicate {
			seen[key] = struct{}{}
			result = append(result, CampaignDKIMEvidence{Domain: domain, Selector: selector, Outcome: outcome})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Domain != result[j].Domain {
			return result[i].Domain < result[j].Domain
		}
		if result[i].Selector != result[j].Selector {
			return result[i].Selector < result[j].Selector
		}
		return result[i].Outcome < result[j].Outcome
	})
	return result, nil
}

func normalizeCampaignEvidenceOutcome(value ReportAuthenticationOutcome) (ReportAuthenticationOutcome, error) {
	if value == "" {
		return ReportAuthenticationUnknown, nil
	}
	if !validReportAuthenticationOutcome(value) {
		return "", fmt.Errorf("%w: authentication outcome is invalid", ErrInvalidReportedMessageEvidence)
	}
	return value, nil
}

func normalizeCampaignEvidenceID(value string, required bool) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" && !required {
		return "", nil
	}
	normalized, ok := normalizeConfigID(trimmed)
	if !ok || len(normalized) > maxCampaignStringBytes {
		return "", fmt.Errorf("%w: identifier is invalid", ErrInvalidReportedMessageEvidence)
	}
	return normalized, nil
}

func normalizeCampaignEvidenceOpaque(value string, required bool) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" && !required {
		return "", nil
	}
	if trimmed == "" || len(trimmed) > maxCampaignStringBytes || strings.ContainsRune(trimmed, '\x00') {
		return "", fmt.Errorf("%w: opaque value is invalid", ErrInvalidReportedMessageEvidence)
	}
	return trimmed, nil
}

func normalizeCampaignEvidenceDomain(value string, required bool) (string, error) {
	if strings.TrimSpace(value) == "" && !required {
		return "", nil
	}
	domain, err := normalizeRecordName(value)
	if err != nil {
		return "", fmt.Errorf("%w: domain is invalid", ErrInvalidReportedMessageEvidence)
	}
	return domain, nil
}

func normalizeCampaignEvidenceIDs(values []string) ([]string, error) {
	if len(values) > maxCampaignListValues {
		return nil, fmt.Errorf("%w: too many identifier values", ErrInvalidReportedMessageEvidence)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized, err := normalizeCampaignEvidenceID(value, true)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[normalized]; !duplicate {
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

func normalizeCampaignEvidenceDomains(values []string) ([]string, error) {
	if len(values) > maxCampaignListValues {
		return nil, fmt.Errorf("%w: too many domain values", ErrInvalidReportedMessageEvidence)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized, err := normalizeCampaignEvidenceDomain(value, true)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[normalized]; !duplicate {
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

func normalizeCampaignEvidenceAddresses(values []string) ([]string, error) {
	if len(values) > maxCampaignListValues {
		return nil, fmt.Errorf("%w: too many source addresses", ErrInvalidReportedMessageEvidence)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("%w: source address is invalid", ErrInvalidReportedMessageEvidence)
		}
		normalized := address.Unmap().String()
		if _, duplicate := seen[normalized]; !duplicate {
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

func normalizeCampaignEvidenceDigests(values []string) ([]string, error) {
	if len(values) > maxCampaignListValues {
		return nil, fmt.Errorf("%w: too many digest values", ErrInvalidReportedMessageEvidence)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		digest := strings.ToLower(strings.TrimSpace(value))
		if !campaignDigestPattern.MatchString(digest) {
			return nil, fmt.Errorf("%w: only complete SHA-256 digests are supported", ErrInvalidReportedMessageEvidence)
		}
		if _, duplicate := seen[digest]; !duplicate {
			seen[digest] = struct{}{}
			result = append(result, digest)
		}
	}
	sort.Strings(result)
	return result, nil
}

func normalizeCampaignEvidenceProvenance(values []CampaignEvidenceProvenanceInput) ([]CampaignEvidenceProvenance, error) {
	if len(values) > maxCampaignListValues {
		return nil, fmt.Errorf("%w: too many provenance values", ErrInvalidReportedMessageEvidence)
	}
	result := make([]CampaignEvidenceProvenance, 0, len(values))
	seen := map[ProvenanceID]struct{}{}
	for _, value := range values {
		sourceID, err := normalizeCampaignEvidenceOpaque(value.SourceID, true)
		if err != nil || value.ObservedAt.IsZero() || !validCampaignEvidenceSourceType(value.Type) || !validFindingConfidence(value.Confidence) {
			return nil, fmt.Errorf("%w: provenance is invalid", ErrInvalidReportedMessageEvidence)
		}
		observedAt := value.ObservedAt.UTC()
		id := ProvenanceID(StableAnalysisID("campaign_evidence_provenance", sourceID, string(value.Type), observedAt.Format(time.RFC3339Nano), string(value.Confidence)))
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, CampaignEvidenceProvenance{
			ID: id, SourceID: sourceID, Type: value.Type, ObservedAt: observedAt, Confidence: value.Confidence, Sensitivity: SensitivityRestricted,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func validCampaignEvidenceSourceType(value CampaignEvidenceSourceType) bool {
	switch value {
	case CampaignEvidenceMessageHeaders, CampaignEvidenceMailGateway, CampaignEvidenceUserReport,
		CampaignEvidenceAggregateReport, CampaignEvidenceVerifiedToken, CampaignEvidenceContentScanner:
		return true
	default:
		return false
	}
}

func validFindingConfidence(value FindingConfidence) bool {
	return value == FindingConfidenceLow || value == FindingConfidenceMedium || value == FindingConfidenceHigh
}

func cloneReportedMessageEvidenceValue(value ReportedMessageEvidenceValue) ReportedMessageEvidenceValue {
	value.DKIM = append([]CampaignDKIMEvidence(nil), value.DKIM...)
	value.SourceAddresses = cloneStrings(value.SourceAddresses)
	value.SourceHostnames = cloneStrings(value.SourceHostnames)
	value.InfrastructureIDs = cloneStrings(value.InfrastructureIDs)
	value.DeliveryExceptionIDs = cloneStrings(value.DeliveryExceptionIDs)
	value.RecipientDomains = cloneStrings(value.RecipientDomains)
	value.RecipientScopeIDs = cloneStrings(value.RecipientScopeIDs)
	value.URLDomains = cloneStrings(value.URLDomains)
	value.TokenDigests = cloneStrings(value.TokenDigests)
	value.ContentFingerprints = cloneStrings(value.ContentFingerprints)
	value.Provenance = append([]CampaignEvidenceProvenance(nil), value.Provenance...)
	return value
}
