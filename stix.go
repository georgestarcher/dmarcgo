package dmarcgo

import (
	"crypto/sha1" // #nosec G505 -- UUIDv5 requires SHA-1; it is not used for security.
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed schemas/stix/dmarcgo-evidence/v1.json
var stixEvidenceExtensionSchemaV1 []byte

const (
	// STIXSpecificationVersion is the standards-native payload version emitted
	// by BuildSTIXBundle.
	STIXSpecificationVersion = "2.1"

	// STIXExportVersion identifies the dmarcgo-to-STIX mapping carried in custom
	// evidence properties. It is independent of STIX and Go module versions.
	STIXExportVersion = "1"

	// STIXEvidenceExtensionSchemaID identifies the normative JSON Schema for
	// the dmarcgo STIX 2.1 property extension.
	STIXEvidenceExtensionSchemaID = "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/stix/dmarcgo-evidence/v1.json"

	// STIXMaximumNumberObserved is the inclusive upper bound imposed by STIX
	// 2.1 on Observed Data number_observed.
	STIXMaximumNumberObserved int64 = 999_999_999

	stixReviewNote = "This object records DMARC aggregate authentication evidence for human review. It does not assert malicious activity or authorize blocking."
)

var (
	// ErrInvalidSTIXExportOptions identifies invalid producer, timestamp,
	// marking, promotion, or mismatched completed-result input.
	ErrInvalidSTIXExportOptions = errors.New("invalid STIX export options")
	// ErrInvalidSTIXBundle identifies a malformed or internally inconsistent
	// supported STIX 2.1 bundle.
	ErrInvalidSTIXBundle = errors.New("invalid STIX bundle")
	// ErrSTIXObservationCountOutOfRange identifies a candidate count that STIX
	// 2.1 cannot represent in one Observed Data object without losing meaning.
	ErrSTIXObservationCountOutOfRange = errors.New("STIX number_observed out of range")
)

// STIXIdentityClass is the producer identity class emitted in a bundle.
type STIXIdentityClass string

const (
	STIXIdentityIndividual    STIXIdentityClass = "individual"
	STIXIdentityGroup         STIXIdentityClass = "group"
	STIXIdentitySystem        STIXIdentityClass = "system"
	STIXIdentityOrganization  STIXIdentityClass = "organization"
	STIXIdentityClassCategory STIXIdentityClass = "class"
	STIXIdentityUnknown       STIXIdentityClass = "unknown"
)

// STIXTLP selects one of the four standard marking definitions defined by
// STIX 2.1. A zero value emits no TLP marking.
type STIXTLP string

const (
	STIXTLPWhite STIXTLP = "white"
	STIXTLPGreen STIXTLP = "green"
	STIXTLPAmber STIXTLP = "amber"
	STIXTLPRed   STIXTLP = "red"
)

// STIXProducer identifies the application or organization that creates the
// STIX objects. Name is caller-controlled data and is never used in generated
// notes, labels, patterns, or instructions. IdentityClass defaults to
// organization.
type STIXProducer struct {
	Name          string
	IdentityClass STIXIdentityClass
	// CreatedAt makes the producer identity stable across bundles. A zero value
	// uses the export GeneratedAt, which creates a per-export identity when
	// generation times differ. The selected marking is also part of the
	// deterministic identity because it changes the emitted object.
	CreatedAt time.Time
}

// STIXIndicatorPromotion is an explicit caller-owned decision to represent one
// review-eligible, non-excluded candidate as a STIX Indicator. Its presence
// does not mutate the candidate, enable automatic action, or imply malicious
// attribution. ValidFrom is required; ValidUntil, when present, must be later.
type STIXIndicatorPromotion struct {
	CandidateID AnalysisID
	ValidFrom   time.Time
	ValidUntil  *time.Time
}

// STIXExportOptions controls a pure standards-native export. GeneratedAt
// defaults to the latest supplied completed-result timestamp. IncludeReviewNotes
// adds fixed library-controlled safety text. Promotions are explicit and
// deterministic; there is no callback, implicit threshold, or automatic policy.
type STIXExportOptions struct {
	GeneratedAt        time.Time
	Producer           STIXProducer
	TLP                STIXTLP
	IncludeReviewNotes bool
	Promotions         []STIXIndicatorPromotion
}

// STIXEvidenceExtensionSchema returns a defensive copy of the JSON Schema for
// the dmarcgo STIX 2.1 property extension.
func STIXEvidenceExtensionSchema() []byte {
	return append([]byte(nil), stixEvidenceExtensionSchemaV1...)
}

// STIXObject is one immutable standards-native object in a STIXBundle. MarshalJSON
// returns the complete STIX representation. Type and ID are safe discovery
// accessors; callers that need type-specific fields can unmarshal the object.
type STIXObject struct {
	objectType string
	id         string
	raw        []byte
}

func (object STIXObject) Type() string { return object.objectType }
func (object STIXObject) ID() string   { return object.id }

// MarshalJSON implements json.Marshaler without exposing mutable bundle state.
func (object STIXObject) MarshalJSON() ([]byte, error) {
	if object.objectType == "" || object.id == "" || len(object.raw) == 0 {
		return nil, ErrInvalidSTIXBundle
	}
	return append([]byte{}, object.raw...), nil
}

// STIXBundle is an immutable STIX 2.1 bundle. It is standards-native rather
// than wrapped in a dmarcgo analysis-output document.
type STIXBundle struct {
	id      string
	objects []STIXObject
}

func (bundle STIXBundle) ID() string { return bundle.id }

// Objects returns defensive copies in deterministic type-and-ID order.
func (bundle STIXBundle) Objects() []STIXObject {
	result := make([]STIXObject, len(bundle.objects))
	for index, object := range bundle.objects {
		object.raw = append([]byte{}, object.raw...)
		result[index] = object
	}
	return result
}

// MarshalJSON implements json.Marshaler and validates all supported object and
// reference constraints before returning the standards-native bundle.
func (bundle STIXBundle) MarshalJSON() ([]byte, error) {
	if err := ValidateSTIXBundle(bundle); err != nil {
		return nil, err
	}
	return marshalSTIXBundle(bundle)
}

// WriteSTIXBundle writes one validated STIX 2.1 bundle followed by a newline.
// It performs no analysis, enrichment, network access, submission, or retry.
func WriteSTIXBundle(writer io.Writer, bundle STIXBundle) error {
	if writer == nil {
		return ErrInvalidSTIXBundle
	}
	encoded, err := bundle.MarshalJSON()
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	written, err := writer.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

// BuildSTIXBundle converts completed threat-candidate evidence and optional
// matching source enrichment into a deterministic STIX 2.1 bundle. The default
// is SCOs plus Observed Data. Indicators appear only for explicit Promotions.
// The function is pure and performs no DNS, HTTP, PTR, SMTP, ICMP, filesystem,
// enrichment, submission, system-clock lookup, or direct subject-IP activity.
func BuildSTIXBundle(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, options STIXExportOptions) (STIXBundle, error) {
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return STIXBundle{}, errors.Join(ErrInvalidSTIXExportOptions, err)
	}
	normalized, err := normalizeSTIXExportOptions(candidates, enrichment, options)
	if err != nil {
		return STIXBundle{}, err
	}

	markingRefs := []string{}
	objects := []STIXObject{}
	if normalized.TLP != "" {
		definition := stixTLPMarkingDefinition(normalized.TLP)
		marking, objectErr := newSTIXObject(definition)
		if objectErr != nil {
			return STIXBundle{}, objectErr
		}
		objects = append(objects, marking)
		markingRefs = []string{definition.ID}
	}

	producer := stixIdentity{
		Type: "identity", SpecVersion: STIXSpecificationVersion,
		ID:      stixObjectID("identity", normalized.Producer.Name, string(normalized.Producer.IdentityClass), normalized.Producer.CreatedAt.Format(time.RFC3339Nano), strings.Join(markingRefs, ",")),
		Created: newSTIXTimestamp(normalized.Producer.CreatedAt), Modified: newSTIXTimestamp(normalized.Producer.CreatedAt),
		Name: normalized.Producer.Name, IdentityClass: normalized.Producer.IdentityClass,
		ObjectMarkingRefs: cloneStrings(markingRefs),
	}
	producerObject, err := newSTIXObject(producer)
	if err != nil {
		return STIXBundle{}, err
	}
	objects = append(objects, producerObject)
	libraryIdentity := stixLibraryIdentity()
	libraryIdentityObject, err := newSTIXObject(libraryIdentity)
	if err != nil {
		return STIXBundle{}, err
	}
	objects = append(objects, libraryIdentityObject)
	extensionDefinition := stixEvidenceExtensionDefinition(libraryIdentity.ID)
	extensionDefinitionObject, err := newSTIXObject(extensionDefinition)
	if err != nil {
		return STIXBundle{}, err
	}
	objects = append(objects, extensionDefinitionObject)
	extensionID := extensionDefinition.ID

	enrichedByCandidate := map[AnalysisID]EnrichedThreatCandidate{}
	asnRefsByIP := map[string][]string{}
	assertionRefsByCandidate := map[AnalysisID][]AnalysisID{}
	if enrichment != nil {
		for _, value := range enrichment.Candidates() {
			enrichedByCandidate[value.Candidate.ID] = value
			for _, assertion := range value.Metadata.Assertions {
				assertionRefsByCandidate[value.Candidate.ID] = append(assertionRefsByCandidate[value.Candidate.ID], assertion.ID)
			}
			assertionRefsByCandidate[value.Candidate.ID] = compactSortedAnalysisIDs(assertionRefsByCandidate[value.Candidate.ID])
		}
		for _, asn := range enrichment.ASNs() {
			asnID := stixSCOID("autonomous-system", struct {
				Number uint32 `json:"number"`
			}{asn.ASN})
			value := stixAutonomousSystem{
				Type: "autonomous-system", SpecVersion: STIXSpecificationVersion, ID: asnID, Number: asn.ASN,
				ObjectMarkingRefs: cloneStrings(markingRefs), Extensions: map[string]stixDMARCASNExtension{extensionID: {
					ExtensionType: "property-extension", ContextType: "asn_context", AssertionIDs: stixAnalysisIDArray(asn.AssertionIDs),
					Names: stixStringArray(asn.Names), Organizations: stixStringArray(asn.Organizations), NetworkPrefixes: stixStringArray(asn.NetworkPrefixes),
					CountryCodes: stixStringArray(asn.CountryCodes), Providers: stixStringArray(asn.Providers), StaleSourceIPs: stixStringArray(asn.StaleSourceIPs),
					ConflictingSourceIPs: stixStringArray(asn.ConflictingSourceIPs),
				}},
			}
			object, objectErr := newSTIXObject(value)
			if objectErr != nil {
				return STIXBundle{}, objectErr
			}
			objects = append(objects, object)
			for _, sourceIP := range asn.SourceIPs {
				asnRefsByIP[sourceIP] = append(asnRefsByIP[sourceIP], asnID)
			}
		}
	}
	for sourceIP := range asnRefsByIP {
		sort.Strings(asnRefsByIP[sourceIP])
		asnRefsByIP[sourceIP] = compactSortedStrings(asnRefsByIP[sourceIP])
	}

	promotions := make(map[AnalysisID]STIXIndicatorPromotion, len(normalized.Promotions))
	for _, promotion := range normalized.Promotions {
		promotions[promotion.CandidateID] = promotion
	}
	for _, baseCandidate := range candidates.Candidates() {
		candidate := baseCandidate
		metadata := IPMetadata{Assertions: []IPMetadataAssertion{}, ConflictFields: []string{}}
		enrichmentStatus := SourceEnrichmentNotEvaluated
		if enriched, ok := enrichedByCandidate[candidate.ID]; ok {
			candidate = enriched.Candidate
			metadata = enriched.Metadata
			enrichmentStatus = enriched.Status
		}
		address, parseErr := netip.ParseAddr(candidate.SourceIP)
		if parseErr != nil || address != address.Unmap() || !candidate.FirstSeen.Available || !candidate.LastSeen.Available ||
			candidate.FirstSeen.Value.After(candidate.LastSeen.Value) || candidate.DualFailureMessages < 1 {
			return STIXBundle{}, errors.Join(ErrInvalidSTIXExportOptions, ErrInvalidAnalysisResult)
		}
		if candidate.DualFailureMessages > STIXMaximumNumberObserved {
			return STIXBundle{}, &STIXObservationCountError{CandidateID: candidate.ID, NumberObserved: candidate.DualFailureMessages}
		}

		addressType := "ipv6-addr"
		if address.Is4() {
			addressType = "ipv4-addr"
		}
		addressID := stixSCOID(addressType, struct {
			Value string `json:"value"`
		}{candidate.SourceIP})
		addressObject, objectErr := newSTIXObject(stixIPAddress{
			Type: addressType, SpecVersion: STIXSpecificationVersion, ID: addressID, Value: candidate.SourceIP,
			BelongsToRefs: cloneStrings(asnRefsByIP[candidate.SourceIP]), ObjectMarkingRefs: cloneStrings(markingRefs),
		})
		if objectErr != nil {
			return STIXBundle{}, objectErr
		}
		objects = append(objects, addressObject)

		evidence := stixDMARCEvidence{
			Version: STIXExportVersion, CandidateID: candidate.ID, ThreatCandidateDigest: candidates.Digest(),
			ObservationIDs: append([]EvidenceID{}, candidate.ObservationIDs...), ReportEvidenceIDs: append([]EvidenceID{}, candidate.ReportEvidenceIDs...),
			CorrelationFindingIDs: append([]FindingID{}, candidate.CorrelationFindingIDs...), AffectedDomains: cloneStrings(candidate.Domains),
			EntityIDs: cloneStrings(candidate.EntityIDs), AssertionIDs: append([]AnalysisID{}, assertionRefsByCandidate[candidate.ID]...),
			Score: candidate.Score, DualFailureMessages: candidate.DualFailureMessages, PassingMessages: candidate.PassingMessages,
			ExpectedSenderFailureMessages: candidate.ExpectedSenderFailureMessages, ReviewEligible: candidate.ReviewEligible,
			Excluded: candidate.Excluded, RecommendedUsage: candidate.RecommendedUsage, EnrichmentStatus: enrichmentStatus,
		}
		if enrichment != nil {
			evidence.SourceEnrichmentDigest = enrichment.Digest()
		}
		externalReferences := stixCandidateExternalReferences(candidate.ID, metadata)
		observedID := stixObjectID("observed-data", string(candidate.ID), producer.ID, normalized.GeneratedAt.Format(time.RFC3339Nano),
			candidate.FirstSeen.Value.UTC().Format(time.RFC3339Nano), candidate.LastSeen.Value.UTC().Format(time.RFC3339Nano),
			fmt.Sprint(candidate.DualFailureMessages), addressID, string(candidates.Digest()), string(evidence.SourceEnrichmentDigest), strings.Join(markingRefs, ","))
		observed := stixObservedData{
			Type: "observed-data", SpecVersion: STIXSpecificationVersion, ID: observedID, CreatedByRef: producer.ID,
			Created: newSTIXTimestamp(normalized.GeneratedAt), Modified: newSTIXTimestamp(normalized.GeneratedAt), FirstObserved: newSTIXTimestamp(candidate.FirstSeen.Value),
			LastObserved: newSTIXTimestamp(candidate.LastSeen.Value), NumberObserved: candidate.DualFailureMessages, ObjectRefs: []string{addressID},
			Labels: []string{"dmarcgo", "dmarc-aggregate-report", "authentication-failure-candidate"}, Confidence: candidate.Confidence,
			ExternalReferences: externalReferences, ObjectMarkingRefs: cloneStrings(markingRefs),
			Extensions: map[string]stixDMARCEvidenceExtension{extensionID: {ExtensionType: "property-extension", ContextType: "candidate_evidence", Evidence: evidence}},
		}
		observedObject, objectErr := newSTIXObject(observed)
		if objectErr != nil {
			return STIXBundle{}, objectErr
		}
		objects = append(objects, observedObject)

		noteRefs := []string{observedID}
		if promotion, ok := promotions[candidate.ID]; ok {
			pattern := fmt.Sprintf("[%s:value = '%s']", addressType, candidate.SourceIP)
			validUntil := cloneTimePointer(promotion.ValidUntil)
			indicatorID := stixObjectID("indicator", string(candidate.ID), producer.ID, normalized.GeneratedAt.Format(time.RFC3339Nano),
				observedID, pattern, promotion.ValidFrom.Format(time.RFC3339Nano), formatOptionalSTIXTime(validUntil), strings.Join(markingRefs, ","))
			indicator := stixIndicator{
				Type: "indicator", SpecVersion: STIXSpecificationVersion, ID: indicatorID, CreatedByRef: producer.ID,
				Name:        "DMARC authentication-failure source review indicator",
				Description: "Explicitly promoted DMARC aggregate evidence for human review. This object does not assert malicious activity or authorize blocking.",
				Created:     newSTIXTimestamp(normalized.GeneratedAt), Modified: newSTIXTimestamp(normalized.GeneratedAt), Pattern: pattern, PatternType: "stix", PatternVersion: STIXSpecificationVersion,
				ValidFrom: newSTIXTimestamp(promotion.ValidFrom), ValidUntil: newOptionalSTIXTimestamp(validUntil), Confidence: candidate.Confidence,
				Labels: []string{"dmarcgo", "explicitly-promoted", "review-required"}, ExternalReferences: externalReferences,
				ObjectMarkingRefs: cloneStrings(markingRefs),
				Extensions:        map[string]stixDMARCEvidenceExtension{extensionID: {ExtensionType: "property-extension", ContextType: "candidate_evidence", Evidence: evidence}},
			}
			indicatorObject, indicatorErr := newSTIXObject(indicator)
			if indicatorErr != nil {
				return STIXBundle{}, indicatorErr
			}
			objects = append(objects, indicatorObject)
			relationship := stixRelationship{
				Type: "relationship", SpecVersion: STIXSpecificationVersion,
				ID:           stixObjectID("relationship", "based-on", indicatorID, observedID, producer.ID, normalized.GeneratedAt.Format(time.RFC3339Nano), strings.Join(markingRefs, ",")),
				CreatedByRef: producer.ID, Created: newSTIXTimestamp(normalized.GeneratedAt), Modified: newSTIXTimestamp(normalized.GeneratedAt),
				RelationshipType: "based-on", SourceRef: indicatorID, TargetRef: observedID,
				ObjectMarkingRefs: cloneStrings(markingRefs),
				Extensions:        map[string]stixDMARCReferenceExtension{extensionID: {ExtensionType: "property-extension", ContextType: "candidate_reference", CandidateID: candidate.ID}},
			}
			relationshipObject, relationshipErr := newSTIXObject(relationship)
			if relationshipErr != nil {
				return STIXBundle{}, relationshipErr
			}
			objects = append(objects, relationshipObject)
			noteRefs = append(noteRefs, indicatorID)
		}

		if normalized.IncludeReviewNotes {
			note := stixNote{
				Type: "note", SpecVersion: STIXSpecificationVersion,
				ID:           stixObjectID("note", string(candidate.ID), strings.Join(noteRefs, ","), producer.ID, normalized.GeneratedAt.Format(time.RFC3339Nano), strings.Join(markingRefs, ",")),
				CreatedByRef: producer.ID, Created: newSTIXTimestamp(normalized.GeneratedAt), Modified: newSTIXTimestamp(normalized.GeneratedAt),
				Content: stixReviewNote, ObjectRefs: noteRefs, Labels: []string{"dmarcgo", "review-limitation"},
				ObjectMarkingRefs: cloneStrings(markingRefs),
				Extensions:        map[string]stixDMARCReferenceExtension{extensionID: {ExtensionType: "property-extension", ContextType: "candidate_reference", CandidateID: candidate.ID}},
			}
			noteObject, noteErr := newSTIXObject(note)
			if noteErr != nil {
				return STIXBundle{}, noteErr
			}
			objects = append(objects, noteObject)
		}
	}

	sort.Slice(objects, func(i, j int) bool {
		leftOrder, rightOrder := stixObjectOrder(objects[i].objectType), stixObjectOrder(objects[j].objectType)
		if leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		return objects[i].id < objects[j].id
	})
	objectIDs := make([]string, len(objects))
	for index := range objects {
		objectIDs[index] = objects[index].id
	}
	bundle := STIXBundle{id: stixObjectID("bundle", objectIDs...), objects: objects}
	if err := ValidateSTIXBundle(bundle); err != nil {
		return STIXBundle{}, err
	}
	return bundle, nil
}

// STIXObservationCountError preserves the candidate identifier and rejected
// count without copying a source address or other untrusted report text.
type STIXObservationCountError struct {
	CandidateID    AnalysisID
	NumberObserved int64
}

func (err *STIXObservationCountError) Error() string {
	return fmt.Sprintf("%s for candidate %s: %d", ErrSTIXObservationCountOutOfRange, err.CandidateID, err.NumberObserved)
}

func (err *STIXObservationCountError) Unwrap() error { return ErrSTIXObservationCountOutOfRange }

func normalizeSTIXExportOptions(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, options STIXExportOptions) (STIXExportOptions, error) {
	options.Producer.Name = strings.TrimSpace(options.Producer.Name)
	if options.Producer.IdentityClass == "" {
		options.Producer.IdentityClass = STIXIdentityOrganization
	}
	if options.Producer.Name == "" || !validSTIXText(options.Producer.Name) || !validSTIXIdentityClass(options.Producer.IdentityClass) || !validSTIXTLP(options.TLP) {
		return STIXExportOptions{}, ErrInvalidSTIXExportOptions
	}
	latestInput := candidates.ResultMetadata().GeneratedAt
	if enrichment != nil {
		if err := validateSTIXEnrichment(candidates, *enrichment); err != nil {
			return STIXExportOptions{}, errors.Join(ErrInvalidSTIXExportOptions, err)
		}
		if enrichment.ResultMetadata().GeneratedAt.After(latestInput) {
			latestInput = enrichment.ResultMetadata().GeneratedAt
		}
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = latestInput
	} else {
		options.GeneratedAt = options.GeneratedAt.UTC()
	}
	if options.GeneratedAt.IsZero() || !sourceEnrichmentTimeMarshalable(options.GeneratedAt) || options.GeneratedAt.Before(latestInput) {
		return STIXExportOptions{}, ErrInvalidSTIXExportOptions
	}
	options.GeneratedAt = options.GeneratedAt.UTC()
	if options.Producer.CreatedAt.IsZero() {
		options.Producer.CreatedAt = options.GeneratedAt
	} else {
		options.Producer.CreatedAt = options.Producer.CreatedAt.UTC()
	}
	if !sourceEnrichmentTimeMarshalable(options.Producer.CreatedAt) || options.Producer.CreatedAt.After(options.GeneratedAt) {
		return STIXExportOptions{}, ErrInvalidSTIXExportOptions
	}

	candidateByID := make(map[AnalysisID]ThreatCandidate, len(candidates.candidates))
	for _, candidate := range candidates.Candidates() {
		candidateByID[candidate.ID] = candidate
	}
	normalizedPromotions := append([]STIXIndicatorPromotion{}, options.Promotions...)
	sort.Slice(normalizedPromotions, func(i, j int) bool { return normalizedPromotions[i].CandidateID < normalizedPromotions[j].CandidateID })
	for index := range normalizedPromotions {
		promotion := &normalizedPromotions[index]
		candidate, exists := candidateByID[promotion.CandidateID]
		if !exists || !candidate.ReviewEligible || candidate.Excluded || promotion.ValidFrom.IsZero() || !sourceEnrichmentTimeMarshalable(promotion.ValidFrom) {
			return STIXExportOptions{}, ErrInvalidSTIXExportOptions
		}
		promotion.ValidFrom = promotion.ValidFrom.UTC()
		promotion.ValidUntil = cloneTimePointer(promotion.ValidUntil)
		if promotion.ValidUntil != nil {
			*promotion.ValidUntil = promotion.ValidUntil.UTC()
			if !sourceEnrichmentTimeMarshalable(*promotion.ValidUntil) || !promotion.ValidUntil.After(promotion.ValidFrom) {
				return STIXExportOptions{}, ErrInvalidSTIXExportOptions
			}
		}
		if index > 0 && normalizedPromotions[index-1].CandidateID == promotion.CandidateID {
			return STIXExportOptions{}, ErrInvalidSTIXExportOptions
		}
	}
	options.Promotions = normalizedPromotions
	return options, nil
}

func validateSTIXEnrichment(candidates ThreatCandidateResult, enrichment SourceEnrichmentResult) error {
	metadata := enrichment.ResultMetadata()
	if enrichment.Digest() == "" || enrichment.Version() != SourceEnrichmentVersion || enrichment.OrganizationID() != candidates.OrganizationID() ||
		enrichment.ThreatCandidateDigest() != candidates.Digest() || metadata.ContractVersion != AnalysisContractVersion ||
		metadata.Mode != AnalysisModeSourceEnrichment || (metadata.Evaluation.State != EvaluationStateEvaluated && metadata.Evaluation.State != EvaluationStateNotEvaluated) {
		return ErrInvalidAnalysisResult
	}
	base := candidates.Candidates()
	enriched := enrichment.Candidates()
	if len(base) != len(enriched) {
		return ErrInvalidAnalysisResult
	}
	byID := make(map[AnalysisID]ThreatCandidate, len(base))
	for _, candidate := range base {
		byID[candidate.ID] = candidate
	}
	for _, value := range enriched {
		original, ok := byID[value.Candidate.ID]
		if !ok || original.SourceIP != value.Candidate.SourceIP || value.Candidate.PromotionEligible {
			return ErrInvalidAnalysisResult
		}
	}
	return nil
}

func validSTIXText(value string) bool {
	return len(value) <= maxSourceEnrichmentTextBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validSTIXIdentityClass(value STIXIdentityClass) bool {
	switch value {
	case STIXIdentityIndividual, STIXIdentityGroup, STIXIdentitySystem, STIXIdentityOrganization, STIXIdentityClassCategory, STIXIdentityUnknown:
		return true
	default:
		return false
	}
}

func validSTIXTLP(value STIXTLP) bool {
	switch value {
	case "", STIXTLPWhite, STIXTLPGreen, STIXTLPAmber, STIXTLPRed:
		return true
	default:
		return false
	}
}

func stixCandidateExternalReferences(candidateID AnalysisID, metadata IPMetadata) []stixExternalReference {
	result := []stixExternalReference{{SourceName: "dmarcgo", ExternalID: string(candidateID)}}
	for _, assertion := range metadata.Assertions {
		reference := stixExternalReference{SourceName: assertion.Provenance.Provider, ExternalID: assertion.Provenance.ReferenceID}
		if parsed, err := url.Parse(assertion.Provenance.Source); err == nil && parsed.Scheme == "https" && parsed.Host != "" {
			reference.URL = assertion.Provenance.Source
		} else if reference.ExternalID == "" {
			reference.ExternalID = assertion.Provenance.Source
		}
		if reference.SourceName != "" && (reference.URL != "" || reference.ExternalID != "") {
			result = append(result, reference)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left, _ := json.Marshal(result[i])
		right, _ := json.Marshal(result[j])
		return string(left) < string(right)
	})
	deduplicated := result[:0]
	for _, value := range result {
		if len(deduplicated) == 0 || deduplicated[len(deduplicated)-1] != value {
			deduplicated = append(deduplicated, value)
		}
	}
	return deduplicated
}

func newSTIXObject(value any) (STIXObject, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return STIXObject{}, errors.Join(ErrInvalidSTIXBundle, err)
	}
	var header struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Type == "" || header.ID == "" {
		return STIXObject{}, ErrInvalidSTIXBundle
	}
	return STIXObject{objectType: header.Type, id: header.ID, raw: raw}, nil
}

func marshalSTIXBundle(bundle STIXBundle) ([]byte, error) {
	objects := make([]json.RawMessage, len(bundle.objects))
	for index, object := range bundle.objects {
		objects[index] = append(json.RawMessage{}, object.raw...)
	}
	return json.Marshal(struct {
		Type    string            `json:"type"`
		ID      string            `json:"id"`
		Objects []json.RawMessage `json:"objects"`
	}{Type: "bundle", ID: bundle.id, Objects: objects})
}

func stixObjectOrder(objectType string) int {
	switch objectType {
	case "marking-definition":
		return 0
	case "identity":
		return 1
	case "extension-definition":
		return 2
	case "autonomous-system":
		return 3
	case "ipv4-addr":
		return 4
	case "ipv6-addr":
		return 5
	case "observed-data":
		return 6
	case "indicator":
		return 7
	case "relationship":
		return 8
	case "note":
		return 9
	default:
		return 99
	}
}

func formatOptionalSTIXTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func stixStringArray(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func stixAnalysisIDArray(values []AnalysisID) []AnalysisID {
	result := make([]AnalysisID, len(values))
	copy(result, values)
	return result
}

func stixSCOID(objectType string, contributing any) string {
	canonical, _ := json.Marshal(contributing)
	return objectType + "--" + formatSTIXUUID(stixUUIDv5(stixSCONamespace, canonical))
}

func stixObjectID(objectType string, parts ...string) string {
	canonical, _ := json.Marshal(struct {
		Type  string   `json:"type"`
		Parts []string `json:"parts"`
	}{objectType, parts})
	return objectType + "--" + formatSTIXUUID(stixUUIDv5(dmarcgoSTIXNamespace, canonical))
}

// These fixed namespaces implement OASIS STIX 2.1 section 3.4. The dmarcgo
// namespace is UUIDv5(URL, "https://github.com/georgestarcher/dmarcgo/v2/stix-2.1")
// and is deliberately distinct from the OASIS SCO namespace.
var (
	stixSCONamespace     = [16]byte{0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7}
	dmarcgoSTIXNamespace = [16]byte{0xe1, 0xd3, 0x36, 0x3e, 0xb3, 0xb4, 0x5d, 0x88, 0x8f, 0x66, 0x58, 0x1c, 0xfc, 0x87, 0xac, 0x9f}
)

func stixUUIDv5(namespace [16]byte, name []byte) [16]byte {
	hash := sha1.New() // #nosec G401 -- UUIDv5 is a namespacing algorithm, not a security hash.
	_, _ = hash.Write(namespace[:])
	_, _ = hash.Write(name)
	sum := hash.Sum(nil)
	var result [16]byte
	copy(result[:], sum[:16])
	result[6] = (result[6] & 0x0f) | 0x50
	result[8] = (result[8] & 0x3f) | 0x80
	return result
}

func formatSTIXUUID(value [16]byte) string {
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

type stixExternalReference struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

type stixIdentity struct {
	Type              string            `json:"type"`
	SpecVersion       string            `json:"spec_version"`
	ID                string            `json:"id"`
	Created           stixTimestamp     `json:"created"`
	Modified          stixTimestamp     `json:"modified"`
	Name              string            `json:"name"`
	IdentityClass     STIXIdentityClass `json:"identity_class"`
	ObjectMarkingRefs []string          `json:"object_marking_refs,omitempty"`
}

type stixIPAddress struct {
	Type              string   `json:"type"`
	SpecVersion       string   `json:"spec_version"`
	ID                string   `json:"id"`
	Value             string   `json:"value"`
	BelongsToRefs     []string `json:"belongs_to_refs,omitempty"`
	ObjectMarkingRefs []string `json:"object_marking_refs,omitempty"`
}

type stixAutonomousSystem struct {
	Type              string                           `json:"type"`
	SpecVersion       string                           `json:"spec_version"`
	ID                string                           `json:"id"`
	Number            uint32                           `json:"number"`
	ObjectMarkingRefs []string                         `json:"object_marking_refs,omitempty"`
	Extensions        map[string]stixDMARCASNExtension `json:"extensions"`
}

type stixDMARCASNExtension struct {
	ExtensionType        string       `json:"extension_type"`
	ContextType          string       `json:"context_type"`
	AssertionIDs         []AnalysisID `json:"assertion_ids"`
	Names                []string     `json:"names,omitempty"`
	Organizations        []string     `json:"organizations,omitempty"`
	NetworkPrefixes      []string     `json:"network_prefixes,omitempty"`
	CountryCodes         []string     `json:"country_codes,omitempty"`
	Providers            []string     `json:"providers,omitempty"`
	StaleSourceIPs       []string     `json:"stale_source_ips,omitempty"`
	ConflictingSourceIPs []string     `json:"conflicting_source_ips,omitempty"`
}

type stixDMARCEvidence struct {
	Version                       string                          `json:"version"`
	CandidateID                   AnalysisID                      `json:"candidate_id"`
	ThreatCandidateDigest         AnalysisID                      `json:"threat_candidate_digest"`
	SourceEnrichmentDigest        AnalysisID                      `json:"source_enrichment_digest,omitempty"`
	ObservationIDs                []EvidenceID                    `json:"observation_ids"`
	ReportEvidenceIDs             []EvidenceID                    `json:"report_evidence_ids"`
	CorrelationFindingIDs         []FindingID                     `json:"correlation_finding_ids"`
	AssertionIDs                  []AnalysisID                    `json:"source_enrichment_assertion_ids"`
	AffectedDomains               []string                        `json:"affected_domains"`
	EntityIDs                     []string                        `json:"entity_ids"`
	Score                         int                             `json:"score"`
	DualFailureMessages           int64                           `json:"dual_failure_messages"`
	PassingMessages               int64                           `json:"passing_messages"`
	ExpectedSenderFailureMessages int64                           `json:"expected_sender_failure_messages"`
	ReviewEligible                bool                            `json:"review_eligible"`
	Excluded                      bool                            `json:"excluded"`
	RecommendedUsage              ThreatCandidateRecommendedUsage `json:"recommended_usage"`
	EnrichmentStatus              SourceEnrichmentStatus          `json:"source_enrichment_status"`
}

type stixDMARCEvidenceExtension struct {
	ExtensionType string            `json:"extension_type"`
	ContextType   string            `json:"context_type"`
	Evidence      stixDMARCEvidence `json:"evidence"`
}

type stixDMARCReferenceExtension struct {
	ExtensionType string     `json:"extension_type"`
	ContextType   string     `json:"context_type"`
	CandidateID   AnalysisID `json:"candidate_id"`
}

type stixObservedData struct {
	Type               string                                `json:"type"`
	SpecVersion        string                                `json:"spec_version"`
	ID                 string                                `json:"id"`
	CreatedByRef       string                                `json:"created_by_ref"`
	Created            stixTimestamp                         `json:"created"`
	Modified           stixTimestamp                         `json:"modified"`
	FirstObserved      stixTimestamp                         `json:"first_observed"`
	LastObserved       stixTimestamp                         `json:"last_observed"`
	NumberObserved     int64                                 `json:"number_observed"`
	ObjectRefs         []string                              `json:"object_refs"`
	Labels             []string                              `json:"labels,omitempty"`
	Confidence         int                                   `json:"confidence"`
	ExternalReferences []stixExternalReference               `json:"external_references,omitempty"`
	ObjectMarkingRefs  []string                              `json:"object_marking_refs,omitempty"`
	Extensions         map[string]stixDMARCEvidenceExtension `json:"extensions"`
}

type stixIndicator struct {
	Type               string                                `json:"type"`
	SpecVersion        string                                `json:"spec_version"`
	ID                 string                                `json:"id"`
	CreatedByRef       string                                `json:"created_by_ref"`
	Created            stixTimestamp                         `json:"created"`
	Modified           stixTimestamp                         `json:"modified"`
	Name               string                                `json:"name"`
	Description        string                                `json:"description"`
	Pattern            string                                `json:"pattern"`
	PatternType        string                                `json:"pattern_type"`
	PatternVersion     string                                `json:"pattern_version"`
	ValidFrom          stixTimestamp                         `json:"valid_from"`
	ValidUntil         *stixTimestamp                        `json:"valid_until,omitempty"`
	Labels             []string                              `json:"labels,omitempty"`
	Confidence         int                                   `json:"confidence"`
	ExternalReferences []stixExternalReference               `json:"external_references,omitempty"`
	ObjectMarkingRefs  []string                              `json:"object_marking_refs,omitempty"`
	Extensions         map[string]stixDMARCEvidenceExtension `json:"extensions"`
}

type stixRelationship struct {
	Type              string                                 `json:"type"`
	SpecVersion       string                                 `json:"spec_version"`
	ID                string                                 `json:"id"`
	CreatedByRef      string                                 `json:"created_by_ref"`
	Created           stixTimestamp                          `json:"created"`
	Modified          stixTimestamp                          `json:"modified"`
	RelationshipType  string                                 `json:"relationship_type"`
	SourceRef         string                                 `json:"source_ref"`
	TargetRef         string                                 `json:"target_ref"`
	ObjectMarkingRefs []string                               `json:"object_marking_refs,omitempty"`
	Extensions        map[string]stixDMARCReferenceExtension `json:"extensions"`
}

type stixNote struct {
	Type              string                                 `json:"type"`
	SpecVersion       string                                 `json:"spec_version"`
	ID                string                                 `json:"id"`
	CreatedByRef      string                                 `json:"created_by_ref"`
	Created           stixTimestamp                          `json:"created"`
	Modified          stixTimestamp                          `json:"modified"`
	Content           string                                 `json:"content"`
	ObjectRefs        []string                               `json:"object_refs"`
	Labels            []string                               `json:"labels,omitempty"`
	ObjectMarkingRefs []string                               `json:"object_marking_refs,omitempty"`
	Extensions        map[string]stixDMARCReferenceExtension `json:"extensions"`
}

type stixTLPDefinition struct {
	TLP string `json:"tlp"`
}

type stixMarkingDefinition struct {
	Type           string            `json:"type"`
	SpecVersion    string            `json:"spec_version"`
	ID             string            `json:"id"`
	Created        stixTimestamp     `json:"created"`
	DefinitionType string            `json:"definition_type"`
	Name           string            `json:"name"`
	Definition     stixTLPDefinition `json:"definition"`
}

type stixExtensionDefinition struct {
	Type           string        `json:"type"`
	SpecVersion    string        `json:"spec_version"`
	ID             string        `json:"id"`
	CreatedByRef   string        `json:"created_by_ref"`
	Created        stixTimestamp `json:"created"`
	Modified       stixTimestamp `json:"modified"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Schema         string        `json:"schema"`
	Version        string        `json:"version"`
	ExtensionTypes []string      `json:"extension_types"`
}

func stixLibraryIdentity() stixIdentity {
	created := time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC)
	return stixIdentity{
		Type: "identity", SpecVersion: STIXSpecificationVersion,
		ID:      stixObjectID("identity", "dmarcgo-extension-author", "dmarcgo", string(STIXIdentitySystem), created.Format(time.RFC3339Nano)),
		Created: newSTIXTimestamp(created), Modified: newSTIXTimestamp(created), Name: "dmarcgo", IdentityClass: STIXIdentitySystem,
	}
}

func stixEvidenceExtensionDefinition(createdByRef string) stixExtensionDefinition {
	created := time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC)
	return stixExtensionDefinition{
		Type: "extension-definition", SpecVersion: STIXSpecificationVersion,
		ID:           stixObjectID("extension-definition", STIXEvidenceExtensionSchemaID, "1.0.0", createdByRef, created.Format(time.RFC3339Nano)),
		CreatedByRef: createdByRef, Created: newSTIXTimestamp(created), Modified: newSTIXTimestamp(created),
		Name: "dmarcgo DMARC evidence", Description: "Structured provenance and review context for DMARC-derived STIX objects.",
		Schema: STIXEvidenceExtensionSchemaID, Version: "1.0.0", ExtensionTypes: []string{"property-extension"},
	}
}

func stixTLPMarkingDefinition(tlp STIXTLP) stixMarkingDefinition {
	ids := map[STIXTLP]string{
		STIXTLPWhite: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
		STIXTLPGreen: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
		STIXTLPAmber: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
		STIXTLPRed:   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
	}
	return stixMarkingDefinition{
		Type: "marking-definition", SpecVersion: STIXSpecificationVersion, ID: ids[tlp],
		Created: newSTIXTimestamp(time.Date(2017, time.January, 20, 0, 0, 0, 0, time.UTC)), DefinitionType: "tlp",
		Name: "TLP:" + strings.ToUpper(string(tlp)), Definition: stixTLPDefinition{TLP: string(tlp)},
	}
}

// stixTimestamp always emits UTC fractional seconds. OASIS STIX 2.1 common
// property schemas require at least millisecond precision. Whole-second values
// use the exact millisecond precision of the fixed TLP objects; other values
// retain nanosecond precision so distinct inputs never serialize identically.
type stixTimestamp struct {
	time.Time
}

func newSTIXTimestamp(value time.Time) stixTimestamp {
	return stixTimestamp{Time: value.UTC()}
}

func newOptionalSTIXTimestamp(value *time.Time) *stixTimestamp {
	if value == nil {
		return nil
	}
	result := newSTIXTimestamp(*value)
	return &result
}

func (value stixTimestamp) MarshalJSON() ([]byte, error) {
	if value.IsZero() || !sourceEnrichmentTimeMarshalable(value.Time) {
		return nil, ErrInvalidSTIXBundle
	}
	format := "2006-01-02T15:04:05.000000000Z"
	if value.Nanosecond() == 0 {
		format = "2006-01-02T15:04:05.000Z"
	}
	return []byte(`"` + value.UTC().Format(format) + `"`), nil
}

func (value *stixTimestamp) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	decimal := strings.LastIndexByte(encoded, '.')
	if !strings.HasSuffix(encoded, "Z") || decimal < 0 || len(encoded)-decimal-2 < 3 || len(encoded)-decimal-2 > 9 {
		return ErrInvalidSTIXBundle
	}
	for _, digit := range encoded[decimal+1 : len(encoded)-1] {
		if digit < '0' || digit > '9' {
			return ErrInvalidSTIXBundle
		}
	}
	parsed, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil {
		return err
	}
	value.Time = parsed.UTC()
	return nil
}
