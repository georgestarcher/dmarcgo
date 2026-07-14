package dmarcgo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// ValidateSTIXBundle validates the complete subset of STIX 2.1 objects emitted
// by BuildSTIXBundle, including deterministic identifiers, required fields,
// timestamps, count bounds, markings, and all intra-bundle references. It does
// not accept arbitrary third-party STIX extensions as a general-purpose parser.
func ValidateSTIXBundle(bundle STIXBundle) error {
	if bundle.id == "" || len(bundle.objects) == 0 || validateSTIXIdentifier(bundle.id, "bundle", true) != nil {
		return ErrInvalidSTIXBundle
	}

	objectsByID := make(map[string]stixValidationCommon, len(bundle.objects))
	identityIDs := map[string]struct{}{}
	markingIDs := map[string]struct{}{}
	extensionIDs := map[string]struct{}{}
	observedByCandidate := map[AnalysisID]string{}
	indicatorByCandidate := map[AnalysisID]string{}
	relationshipsByIndicator := map[string]int{}
	previousOrder, previousID := -1, ""
	for _, object := range bundle.objects {
		var common stixValidationCommon
		if object.objectType == "" || object.id == "" || len(object.raw) == 0 || json.Unmarshal(object.raw, &common) != nil ||
			common.Type != object.objectType || common.ID != object.id || common.SpecVersion != STIXSpecificationVersion || stixObjectOrder(common.Type) == 99 ||
			validateSTIXIdentifier(common.ID, common.Type, common.Type != "marking-definition") != nil {
			return ErrInvalidSTIXBundle
		}
		if _, exists := objectsByID[common.ID]; exists {
			return ErrInvalidSTIXBundle
		}
		order := stixObjectOrder(common.Type)
		if order < previousOrder || order == previousOrder && common.ID <= previousID {
			return ErrInvalidSTIXBundle
		}
		previousOrder, previousID = order, common.ID
		objectsByID[common.ID] = common
		switch common.Type {
		case "identity":
			identityIDs[common.ID] = struct{}{}
		case "marking-definition":
			markingIDs[common.ID] = struct{}{}
		case "extension-definition":
			extensionIDs[common.ID] = struct{}{}
		}
	}
	if len(identityIDs) != 2 || len(markingIDs) > 1 || len(extensionIDs) != 1 {
		return ErrInvalidSTIXBundle
	}

	for _, object := range bundle.objects {
		common := objectsByID[object.id]
		if err := validateSTIXCommonReferences(common, objectsByID, identityIDs, markingIDs, extensionIDs); err != nil {
			return err
		}
		switch common.Type {
		case "marking-definition":
			if err := validateSTIXMarkingDefinition(object.raw); err != nil {
				return err
			}
		case "identity":
			var value stixIdentity
			if decodeSTIXStrict(object.raw, &value) != nil || value.Name == "" || !validSTIXText(value.Name) || !validSTIXIdentityClass(value.IdentityClass) ||
				!validSTIXVersionedTimes(value.Created, value.Modified) {
				return ErrInvalidSTIXBundle
			}
			library := stixLibraryIdentity()
			if value.ID == library.ID && (value.Type != library.Type || value.SpecVersion != library.SpecVersion || !value.Created.Equal(library.Created.Time) ||
				!value.Modified.Equal(library.Modified.Time) || value.Name != library.Name || value.IdentityClass != library.IdentityClass || len(value.ObjectMarkingRefs) != 0) {
				return ErrInvalidSTIXBundle
			}
		case "extension-definition":
			if err := validateSTIXExtensionDefinition(object.raw); err != nil {
				return err
			}
		case "autonomous-system":
			var value stixAutonomousSystem
			if decodeSTIXStrict(object.raw, &value) != nil {
				return ErrInvalidSTIXBundle
			}
			extension, extensionErr := stixASNExtension(value.Extensions, extensionIDs)
			if extensionErr != nil || value.Number == 0 || value.ID != stixSCOID("autonomous-system", struct {
				Number uint32 `json:"number"`
			}{value.Number}) || extension.ExtensionType != "property-extension" || extension.ContextType != "asn_context" || len(extension.AssertionIDs) == 0 ||
				!validSTIXStringCollections(extension.Names, extension.Organizations, extension.NetworkPrefixes, extension.CountryCodes, extension.Providers,
					extension.StaleSourceIPs, extension.ConflictingSourceIPs) || !sortedUniqueAnalysisIDs(extension.AssertionIDs) {
				return ErrInvalidSTIXBundle
			}
		case "ipv4-addr", "ipv6-addr":
			if err := validateSTIXIPAddress(object.raw, common.Type, objectsByID); err != nil {
				return err
			}
		case "observed-data":
			var value stixObservedData
			if decodeSTIXStrict(object.raw, &value) != nil {
				return ErrInvalidSTIXBundle
			}
			evidence, extensionErr := stixCandidateEvidence(value.Extensions, extensionIDs)
			if extensionErr != nil || !validSTIXVersionedTimes(value.Created, value.Modified) ||
				value.FirstObserved.IsZero() || value.LastObserved.IsZero() || value.FirstObserved.After(value.LastObserved.Time) ||
				value.NumberObserved < 1 || value.NumberObserved > STIXMaximumNumberObserved || len(value.ObjectRefs) != 1 ||
				(objectsByID[value.ObjectRefs[0]].Type != "ipv4-addr" && objectsByID[value.ObjectRefs[0]].Type != "ipv6-addr") ||
				value.Confidence < 0 || value.Confidence > 100 || !slices.Equal(value.Labels, []string{"dmarcgo", "dmarc-aggregate-report", "authentication-failure-candidate"}) ||
				validateSTIXEvidence(evidence) != nil || validateSTIXExternalReferences(value.ExternalReferences, evidence.CandidateID) != nil {
				return ErrInvalidSTIXBundle
			}
			if previous, exists := observedByCandidate[evidence.CandidateID]; exists && previous != value.ID {
				return ErrInvalidSTIXBundle
			}
			observedByCandidate[evidence.CandidateID] = value.ID
		case "indicator":
			var value stixIndicator
			if decodeSTIXStrict(object.raw, &value) != nil {
				return ErrInvalidSTIXBundle
			}
			evidence, extensionErr := stixCandidateEvidence(value.Extensions, extensionIDs)
			if extensionErr != nil || !validSTIXVersionedTimes(value.Created, value.Modified) ||
				value.Name != "DMARC authentication-failure source review indicator" ||
				value.Description != "Explicitly promoted DMARC aggregate evidence for human review. This object does not assert malicious activity or authorize blocking." ||
				value.PatternType != "stix" || value.PatternVersion != STIXSpecificationVersion || !validSTIXPattern(value.Pattern) ||
				value.ValidFrom.IsZero() || !sourceEnrichmentTimeMarshalable(value.ValidFrom.Time) ||
				(value.ValidUntil != nil && (!sourceEnrichmentTimeMarshalable(value.ValidUntil.Time) || !value.ValidUntil.After(value.ValidFrom.Time))) ||
				value.Confidence < 0 || value.Confidence > 100 || !slices.Equal(value.Labels, []string{"dmarcgo", "explicitly-promoted", "review-required"}) ||
				validateSTIXEvidence(evidence) != nil || !evidence.ReviewEligible || evidence.Excluded ||
				validateSTIXExternalReferences(value.ExternalReferences, evidence.CandidateID) != nil {
				return ErrInvalidSTIXBundle
			}
			if previous, exists := indicatorByCandidate[evidence.CandidateID]; exists && previous != value.ID {
				return ErrInvalidSTIXBundle
			}
			indicatorByCandidate[evidence.CandidateID] = value.ID
		case "relationship":
			var value stixRelationship
			if decodeSTIXStrict(object.raw, &value) != nil {
				return ErrInvalidSTIXBundle
			}
			candidateID, extensionErr := stixCandidateReference(value.Extensions, extensionIDs)
			if extensionErr != nil || !validSTIXVersionedTimes(value.Created, value.Modified) || value.RelationshipType != "based-on" ||
				objectsByID[value.SourceRef].Type != "indicator" || objectsByID[value.TargetRef].Type != "observed-data" || candidateID == "" {
				return ErrInvalidSTIXBundle
			}
			var source stixIndicator
			var target stixObservedData
			if decodeSTIXStrict(findSTIXObject(bundle.objects, value.SourceRef), &source) != nil || decodeSTIXStrict(findSTIXObject(bundle.objects, value.TargetRef), &target) != nil {
				return ErrInvalidSTIXBundle
			}
			sourceEvidence, sourceErr := stixCandidateEvidence(source.Extensions, extensionIDs)
			targetEvidence, targetErr := stixCandidateEvidence(target.Extensions, extensionIDs)
			if sourceErr != nil || targetErr != nil || sourceEvidence.CandidateID != candidateID || targetEvidence.CandidateID != candidateID {
				return ErrInvalidSTIXBundle
			}
			relationshipsByIndicator[value.SourceRef]++
		case "note":
			var value stixNote
			if decodeSTIXStrict(object.raw, &value) != nil {
				return ErrInvalidSTIXBundle
			}
			candidateID, extensionErr := stixCandidateReference(value.Extensions, extensionIDs)
			if extensionErr != nil || !validSTIXVersionedTimes(value.Created, value.Modified) || value.Content != stixReviewNote ||
				candidateID == "" || len(value.ObjectRefs) < 1 || len(value.ObjectRefs) > 2 ||
				!slices.Equal(value.Labels, []string{"dmarcgo", "review-limitation"}) {
				return ErrInvalidSTIXBundle
			}
			seenReferences := make(map[string]struct{}, len(value.ObjectRefs))
			for _, reference := range value.ObjectRefs {
				if _, duplicate := seenReferences[reference]; duplicate {
					return ErrInvalidSTIXBundle
				}
				seenReferences[reference] = struct{}{}
				objectType := objectsByID[reference].Type
				if objectType != "observed-data" && objectType != "indicator" {
					return ErrInvalidSTIXBundle
				}
				var referenceEvidence stixDMARCEvidence
				if objectType == "observed-data" {
					var referenced stixObservedData
					if decodeSTIXStrict(findSTIXObject(bundle.objects, reference), &referenced) != nil {
						return ErrInvalidSTIXBundle
					}
					referenceEvidence, extensionErr = stixCandidateEvidence(referenced.Extensions, extensionIDs)
				} else {
					var referenced stixIndicator
					if decodeSTIXStrict(findSTIXObject(bundle.objects, reference), &referenced) != nil {
						return ErrInvalidSTIXBundle
					}
					referenceEvidence, extensionErr = stixCandidateEvidence(referenced.Extensions, extensionIDs)
				}
				if extensionErr != nil || referenceEvidence.CandidateID != candidateID {
					return ErrInvalidSTIXBundle
				}
			}
		default:
			return ErrInvalidSTIXBundle
		}
	}
	for candidateID, indicatorID := range indicatorByCandidate {
		if relationshipsByIndicator[indicatorID] != 1 || observedByCandidate[candidateID] == "" {
			return ErrInvalidSTIXBundle
		}
	}

	objectIDs := make([]string, len(bundle.objects))
	for index, object := range bundle.objects {
		objectIDs[index] = object.id
	}
	if bundle.id != stixObjectID("bundle", objectIDs...) {
		return ErrInvalidSTIXBundle
	}
	return nil
}

type stixValidationCommon struct {
	Type              string                     `json:"type"`
	SpecVersion       string                     `json:"spec_version"`
	ID                string                     `json:"id"`
	CreatedByRef      string                     `json:"created_by_ref,omitempty"`
	ObjectMarkingRefs []string                   `json:"object_marking_refs,omitempty"`
	Extensions        map[string]json.RawMessage `json:"extensions,omitempty"`
}

func validateSTIXCommonReferences(common stixValidationCommon, objects map[string]stixValidationCommon, identities, markings, extensions map[string]struct{}) error {
	switch common.Type {
	case "observed-data", "indicator", "relationship", "note", "extension-definition":
		if common.CreatedByRef == "" {
			return ErrInvalidSTIXBundle
		}
	}
	if common.CreatedByRef != "" {
		if _, ok := identities[common.CreatedByRef]; !ok {
			return ErrInvalidSTIXBundle
		}
	}
	if len(markings) == 0 {
		if len(common.ObjectMarkingRefs) != 0 {
			return ErrInvalidSTIXBundle
		}
	} else {
		exempt := common.Type == "marking-definition" || common.Type == "extension-definition" || common.ID == stixLibraryIdentity().ID
		if exempt {
			if len(common.ObjectMarkingRefs) != 0 {
				return ErrInvalidSTIXBundle
			}
		} else if len(common.ObjectMarkingRefs) != 1 {
			return ErrInvalidSTIXBundle
		} else if _, ok := markings[common.ObjectMarkingRefs[0]]; !ok || objects[common.ObjectMarkingRefs[0]].Type != "marking-definition" {
			return ErrInvalidSTIXBundle
		}
	}
	for extensionID := range common.Extensions {
		if _, ok := extensions[extensionID]; !ok || objects[extensionID].Type != "extension-definition" {
			return ErrInvalidSTIXBundle
		}
	}
	return nil
}

func validateSTIXMarkingDefinition(raw []byte) error {
	var value stixMarkingDefinition
	if decodeSTIXStrict(raw, &value) != nil || !validSTIXTLP(STIXTLP(value.Definition.TLP)) || value.Definition.TLP == "" || value.DefinitionType != "tlp" {
		return ErrInvalidSTIXBundle
	}
	want := stixTLPMarkingDefinition(STIXTLP(value.Definition.TLP))
	if value != want {
		return ErrInvalidSTIXBundle
	}
	return nil
}

func validateSTIXExtensionDefinition(raw []byte) error {
	var value stixExtensionDefinition
	if decodeSTIXStrict(raw, &value) != nil {
		return ErrInvalidSTIXBundle
	}
	want := stixEvidenceExtensionDefinition(stixLibraryIdentity().ID)
	if value.Type != want.Type || value.SpecVersion != want.SpecVersion || value.ID != want.ID || value.CreatedByRef != want.CreatedByRef ||
		!value.Created.Equal(want.Created.Time) || !value.Modified.Equal(want.Modified.Time) || value.Name != want.Name || value.Description != want.Description ||
		value.Schema != want.Schema || value.Version != want.Version || !slices.Equal(value.ExtensionTypes, want.ExtensionTypes) {
		return ErrInvalidSTIXBundle
	}
	return nil
}

func stixASNExtension(values map[string]stixDMARCASNExtension, extensionIDs map[string]struct{}) (stixDMARCASNExtension, error) {
	if len(values) != 1 {
		return stixDMARCASNExtension{}, ErrInvalidSTIXBundle
	}
	for id, value := range values {
		if _, ok := extensionIDs[id]; !ok || id != stixEvidenceExtensionDefinition(stixLibraryIdentity().ID).ID {
			return stixDMARCASNExtension{}, ErrInvalidSTIXBundle
		}
		return value, nil
	}
	return stixDMARCASNExtension{}, ErrInvalidSTIXBundle
}

func stixCandidateEvidence(values map[string]stixDMARCEvidenceExtension, extensionIDs map[string]struct{}) (stixDMARCEvidence, error) {
	if len(values) != 1 {
		return stixDMARCEvidence{}, ErrInvalidSTIXBundle
	}
	for id, value := range values {
		if _, ok := extensionIDs[id]; !ok || id != stixEvidenceExtensionDefinition(stixLibraryIdentity().ID).ID ||
			value.ExtensionType != "property-extension" || value.ContextType != "candidate_evidence" {
			return stixDMARCEvidence{}, ErrInvalidSTIXBundle
		}
		return value.Evidence, nil
	}
	return stixDMARCEvidence{}, ErrInvalidSTIXBundle
}

func stixCandidateReference(values map[string]stixDMARCReferenceExtension, extensionIDs map[string]struct{}) (AnalysisID, error) {
	if len(values) != 1 {
		return "", ErrInvalidSTIXBundle
	}
	for id, value := range values {
		if _, ok := extensionIDs[id]; !ok || id != stixEvidenceExtensionDefinition(stixLibraryIdentity().ID).ID ||
			value.ExtensionType != "property-extension" || value.ContextType != "candidate_reference" || value.CandidateID == "" {
			return "", ErrInvalidSTIXBundle
		}
		return value.CandidateID, nil
	}
	return "", ErrInvalidSTIXBundle
}

func decodeSTIXStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidSTIXBundle
	}
	return nil
}

func validateSTIXIPAddress(raw []byte, objectType string, objects map[string]stixValidationCommon) error {
	var value stixIPAddress
	if decodeSTIXStrict(raw, &value) != nil {
		return ErrInvalidSTIXBundle
	}
	address, err := netip.ParseAddr(value.Value)
	if err != nil || address != address.Unmap() || address.String() != value.Value || address.Is4() != (objectType == "ipv4-addr") ||
		value.ID != stixSCOID(objectType, struct {
			Value string `json:"value"`
		}{value.Value}) || !sort.StringsAreSorted(value.BelongsToRefs) || hasDuplicateStrings(value.BelongsToRefs) {
		return ErrInvalidSTIXBundle
	}
	for _, reference := range value.BelongsToRefs {
		if objects[reference].Type != "autonomous-system" {
			return ErrInvalidSTIXBundle
		}
	}
	return nil
}

func validateSTIXEvidence(value stixDMARCEvidence) error {
	if value.Version != STIXExportVersion || value.CandidateID == "" || value.ThreatCandidateDigest == "" || value.Score < 0 || value.Score > 100 ||
		value.DualFailureMessages < 1 || value.DualFailureMessages > STIXMaximumNumberObserved || value.PassingMessages < 0 || value.ExpectedSenderFailureMessages < 0 ||
		!validSTIXRecommendedUsage(value.RecommendedUsage) || !validSTIXEnrichmentStatus(value.EnrichmentStatus) ||
		value.ObservationIDs == nil || value.ReportEvidenceIDs == nil || value.CorrelationFindingIDs == nil || value.AssertionIDs == nil ||
		value.AffectedDomains == nil || value.EntityIDs == nil || !sortedUniqueEvidenceIDs(value.ObservationIDs) || !sortedUniqueEvidenceIDs(value.ReportEvidenceIDs) ||
		!sortedUniqueFindingIDs(value.CorrelationFindingIDs) || !sortedUniqueAnalysisIDs(value.AssertionIDs) || !sortedUniqueStrings(value.AffectedDomains) || !sortedUniqueStrings(value.EntityIDs) {
		return ErrInvalidSTIXBundle
	}
	return nil
}

func validateSTIXExternalReferences(values []stixExternalReference, candidateID AnalysisID) error {
	if len(values) == 0 || !sort.SliceIsSorted(values, func(i, j int) bool {
		left, _ := json.Marshal(values[i])
		right, _ := json.Marshal(values[j])
		return string(left) < string(right)
	}) {
		return ErrInvalidSTIXBundle
	}
	hasCandidate := false
	seen := map[stixExternalReference]struct{}{}
	for _, value := range values {
		if value.SourceName == "" || !validSTIXText(value.SourceName) || value.URL == "" && value.ExternalID == "" || !validSTIXText(value.ExternalID) {
			return ErrInvalidSTIXBundle
		}
		if value.URL != "" {
			parsed, err := url.Parse(value.URL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				return ErrInvalidSTIXBundle
			}
		}
		if _, exists := seen[value]; exists {
			return ErrInvalidSTIXBundle
		}
		seen[value] = struct{}{}
		hasCandidate = hasCandidate || value.SourceName == "dmarcgo" && value.ExternalID == string(candidateID)
	}
	if !hasCandidate {
		return ErrInvalidSTIXBundle
	}
	return nil
}

func validateSTIXIdentifier(value, objectType string, requireVersionFive bool) error {
	prefix := objectType + "--"
	if !strings.HasPrefix(value, prefix) {
		return ErrInvalidSTIXBundle
	}
	encoded := strings.ReplaceAll(strings.TrimPrefix(value, prefix), "-", "")
	if len(encoded) != 32 {
		return ErrInvalidSTIXBundle
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 16 || decoded[8]&0xc0 != 0x80 {
		return ErrInvalidSTIXBundle
	}
	version := decoded[6] >> 4
	if requireVersionFive && version != 5 || !requireVersionFive && (version < 1 || version > 5) {
		return ErrInvalidSTIXBundle
	}
	return nil
}

func validSTIXVersionedTimes(created, modified stixTimestamp) bool {
	return !created.IsZero() && created.Equal(modified.Time) && sourceEnrichmentTimeMarshalable(created.Time) && sourceEnrichmentTimeMarshalable(modified.Time)
}

func validSTIXPattern(value string) bool {
	for _, objectType := range []string{"ipv4-addr", "ipv6-addr"} {
		prefix := "[" + objectType + ":value = '"
		if strings.HasPrefix(value, prefix) && strings.HasSuffix(value, "']") {
			address, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(value, prefix), "']"))
			return err == nil && address == address.Unmap() && address.String() == strings.TrimSuffix(strings.TrimPrefix(value, prefix), "']") && address.Is4() == (objectType == "ipv4-addr")
		}
	}
	return false
}

func validSTIXStringCollections(values ...[]string) bool {
	for _, collection := range values {
		if !sortedUniqueStrings(collection) {
			return false
		}
		for _, value := range collection {
			if value == "" || !validSTIXText(value) {
				return false
			}
		}
	}
	return true
}

func validSTIXRecommendedUsage(value ThreatCandidateRecommendedUsage) bool {
	switch value {
	case ThreatCandidateUsageReviewOnly, ThreatCandidateUsageMonitorOnly, ThreatCandidateUsageRetainEvidence:
		return true
	default:
		return false
	}
}

func validSTIXEnrichmentStatus(value SourceEnrichmentStatus) bool {
	switch value {
	case SourceEnrichmentNotEvaluated, SourceEnrichmentNotEligible, SourceEnrichmentSuccess, SourceEnrichmentUnavailable,
		SourceEnrichmentStale, SourceEnrichmentConflicting, SourceEnrichmentFailed, SourceEnrichmentCanceled, SourceEnrichmentTimeout:
		return true
	default:
		return false
	}
}

func sortedUniqueStrings(values []string) bool {
	return sort.StringsAreSorted(values) && !hasDuplicateStrings(values)
}

func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func sortedUniqueAnalysisIDs(values []AnalysisID) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

func sortedUniqueEvidenceIDs(values []EvidenceID) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

func sortedUniqueFindingIDs(values []FindingID) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

func hasAdjacentDuplicate[T comparable](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func findSTIXObject(objects []STIXObject, id string) []byte {
	for _, object := range objects {
		if object.id == id {
			return object.raw
		}
	}
	return nil
}
