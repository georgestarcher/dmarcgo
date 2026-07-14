package dmarcgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestBuildSTIXBundleDefaultsToObservedData(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20", "2001:db8::20")
	options := STIXExportOptions{
		Producer:           STIXProducer{Name: "Example SOC"},
		TLP:                STIXTLPAmber,
		IncludeReviewNotes: true,
	}
	first, err := BuildSTIXBundle(candidates, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSTIXBundle(candidates, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) || first.ID() != second.ID() || !strings.HasPrefix(first.ID(), "bundle--") {
		t.Fatalf("STIX export is not deterministic: first=%s second=%s", first.ID(), second.ID())
	}
	if err := ValidateSTIXBundle(first); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(firstJSON), `"objects":{`) || strings.Contains(string(firstJSON), `"type":"indicator"`) || strings.Contains(string(firstJSON), `"indicator_types":["malicious-activity"]`) {
		t.Fatalf("default bundle used deprecated objects, emitted an indicator, or asserted malice: %s", firstJSON)
	}

	counts := stixObjectCounts(first)
	wantCounts := map[string]int{
		"marking-definition": 1, "identity": 2, "extension-definition": 1, "ipv4-addr": 1, "ipv6-addr": 1,
		"observed-data": 2, "note": 2,
	}
	if !mapsEqual(counts, wantCounts) {
		t.Fatalf("object counts=%v want=%v", counts, wantCounts)
	}
	for _, object := range first.Objects() {
		switch object.Type() {
		case "observed-data":
			var observed stixObservedData
			if err := json.Unmarshal(object.raw, &observed); err != nil {
				t.Fatal(err)
			}
			evidence := stixTestCandidateEvidence(t, observed.Extensions)
			if observed.NumberObserved != 140 || len(observed.ObjectRefs) != 1 || observed.Confidence != 70 ||
				evidence.DualFailureMessages != 140 || evidence.EnrichmentStatus != SourceEnrichmentNotEvaluated ||
				len(observed.ExternalReferences) != 1 || observed.ExternalReferences[0].SourceName != "dmarcgo" {
				t.Fatalf("observed data=%+v", observed)
			}
		case "note":
			var note stixNote
			if err := json.Unmarshal(object.raw, &note); err != nil {
				t.Fatal(err)
			}
			if note.Content != stixReviewNote || len(note.ObjectRefs) != 1 {
				t.Fatalf("note=%+v", note)
			}
		}
	}

	objects := first.Objects()
	objects[0].raw[0] = 'x'
	unchanged, err := json.Marshal(first)
	if err != nil || !bytes.Equal(firstJSON, unchanged) {
		t.Fatal("Objects returned mutable bundle state")
	}
}

func TestBuildSTIXBundleIncludesASNContextWithoutSelectingConflicts(t *testing.T) {
	generatedAt := time.Unix(200_000, 0).UTC()
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20", "2001:db8::20")
	expiresAt := generatedAt.Add(time.Hour)
	metadata4 := sourceTestMetadata(64500, "Primary Name", "198.51.100.0/24", "Primary Org", "US", "provider A", generatedAt.Add(-time.Minute), &expiresAt)
	metadata4.Assertions = append(metadata4.Assertions, sourceTestMetadata(64501, "Conflicting Name", "198.51.100.0/24", "Other Org", "CA", "provider B", generatedAt.Add(-time.Minute), &expiresAt).Assertions[0])
	metadata6 := sourceTestMetadata(64500, "Primary Name", "2001:db8::/32", "Primary Org", "US", "provider A", generatedAt.Add(-time.Minute), &expiresAt)
	enrichment, err := EnrichThreatCandidates(context.Background(), candidates, &sourceFixtureEnricher{metadata: map[string]IPMetadata{
		"198.51.100.20": metadata4,
		"2001:db8::20":  metadata6,
	}}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return generatedAt })})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildSTIXBundle(candidates, &enrichment, STIXExportOptions{Producer: STIXProducer{Name: "Example SOC"}, TLP: STIXTLPGreen})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIXBundle(bundle); err != nil {
		t.Fatal(err)
	}
	counts := stixObjectCounts(bundle)
	if counts["autonomous-system"] != 2 || counts["observed-data"] != 2 {
		t.Fatalf("object counts=%v", counts)
	}

	wantASNRefs := map[string][]string{
		"198.51.100.20": {
			stixSCOID("autonomous-system", struct {
				Number uint32 `json:"number"`
			}{64500}),
			stixSCOID("autonomous-system", struct {
				Number uint32 `json:"number"`
			}{64501}),
		},
		"2001:db8::20": {
			stixSCOID("autonomous-system", struct {
				Number uint32 `json:"number"`
			}{64500}),
		},
	}
	for _, object := range bundle.Objects() {
		switch object.Type() {
		case "ipv4-addr", "ipv6-addr":
			var address stixIPAddress
			if err := json.Unmarshal(object.raw, &address); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(address.BelongsToRefs, wantASNRefs[address.Value]) {
				t.Fatalf("belongs_to_refs for %s=%v want=%v", address.Value, address.BelongsToRefs, wantASNRefs[address.Value])
			}
		case "autonomous-system":
			var asn stixAutonomousSystem
			if err := json.Unmarshal(object.raw, &asn); err != nil {
				t.Fatal(err)
			}
			extension := stixTestASNExtension(t, asn.Extensions)
			if asn.Number == 64500 && (!slices.Contains(extension.Names, "Primary Name") || len(extension.AssertionIDs) != 2) {
				t.Fatalf("ASN conflict context was not preserved: %+v", asn)
			}
		case "observed-data":
			var observed stixObservedData
			if err := json.Unmarshal(object.raw, &observed); err != nil {
				t.Fatal(err)
			}
			evidence := stixTestCandidateEvidence(t, observed.Extensions)
			if evidence.SourceEnrichmentDigest != enrichment.Digest() || evidence.EnrichmentStatus == SourceEnrichmentNotEvaluated || len(observed.ExternalReferences) < 2 {
				t.Fatalf("enrichment provenance=%+v", observed)
			}
		}
	}
}

func TestBuildSTIXBundleRequiresExplicitValidIndicatorPromotion(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	candidate := candidates.Candidates()[0]
	validFrom := candidates.ResultMetadata().GeneratedAt.Add(time.Minute)
	validUntil := validFrom.Add(24 * time.Hour)
	options := STIXExportOptions{
		Producer:           STIXProducer{Name: "Example SOC", IdentityClass: STIXIdentitySystem},
		IncludeReviewNotes: true,
		Promotions: []STIXIndicatorPromotion{{
			CandidateID: candidate.ID, ValidFrom: validFrom, ValidUntil: &validUntil,
		}},
	}
	bundle, err := BuildSTIXBundle(candidates, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	counts := stixObjectCounts(bundle)
	if counts["indicator"] != 1 || counts["relationship"] != 1 || counts["observed-data"] != 1 || counts["note"] != 1 {
		t.Fatalf("object counts=%v", counts)
	}
	for _, object := range bundle.Objects() {
		switch object.Type() {
		case "indicator":
			var indicator stixIndicator
			if err := json.Unmarshal(object.raw, &indicator); err != nil {
				t.Fatal(err)
			}
			evidence := stixTestCandidateEvidence(t, indicator.Extensions)
			if indicator.Pattern != "[ipv4-addr:value = '198.51.100.20']" || !indicator.ValidFrom.Equal(validFrom) || indicator.ValidUntil == nil || !indicator.ValidUntil.Equal(validUntil) ||
				evidence.CandidateID != candidate.ID || !evidence.ReviewEligible || evidence.Excluded {
				t.Fatalf("indicator=%+v", indicator)
			}
		case "relationship":
			var relationship stixRelationship
			if err := json.Unmarshal(object.raw, &relationship); err != nil || relationship.RelationshipType != "based-on" {
				t.Fatalf("relationship=%+v error=%v", relationship, err)
			}
		case "note":
			var note stixNote
			if err := json.Unmarshal(object.raw, &note); err != nil || len(note.ObjectRefs) != 2 {
				t.Fatalf("note=%+v error=%v", note, err)
			}
		}
	}
	if candidates.Candidates()[0].PromotionEligible {
		t.Fatal("STIX export mutated upstream promotion eligibility")
	}

	defaultBundle, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{Producer: STIXProducer{Name: "Example SOC"}})
	if err != nil {
		t.Fatal(err)
	}
	if stixObjectCounts(defaultBundle)["indicator"] != 0 {
		t.Fatal("default export emitted an indicator")
	}

	lowVolume := threatTestScore(t, correlationTestConfig(AuthenticationPolicyConfig{}), correlationHealthyDNSValues(), []*AggregateReport{
		correlationTestReport("low", "receiver.example", 100, 200, threatTestRecord("192.0.2.10", "1", "example.test", "none")),
	}, ThreatCandidateOptions{})
	if lowVolume.Candidates()[0].ReviewEligible {
		t.Fatal("low-volume fixture unexpectedly review eligible")
	}
	invalidPromotion := STIXExportOptions{Producer: STIXProducer{Name: "Example SOC"}, Promotions: []STIXIndicatorPromotion{{
		CandidateID: lowVolume.Candidates()[0].ID, ValidFrom: validFrom,
	}}}
	if _, err := BuildSTIXBundle(lowVolume, nil, invalidPromotion); !errors.Is(err, ErrInvalidSTIXExportOptions) {
		t.Fatalf("non-review-eligible promotion error=%v", err)
	}
}

func TestBuildSTIXBundleRejectsInvalidOptionsCountsAndEnrichment(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	validFrom := candidates.ResultMetadata().GeneratedAt
	tests := []struct {
		name    string
		options STIXExportOptions
	}{
		{name: "missing producer"},
		{name: "invalid identity class", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC", IdentityClass: "robot"}}},
		{name: "invalid TLP", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC"}, TLP: "clear"}},
		{name: "early generated time", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC"}, GeneratedAt: candidates.ResultMetadata().GeneratedAt.Add(-time.Second)}},
		{name: "producer created after generation", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC", CreatedAt: candidates.ResultMetadata().GeneratedAt.Add(time.Second)}}},
		{name: "unknown promotion", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC"}, Promotions: []STIXIndicatorPromotion{{CandidateID: "unknown", ValidFrom: validFrom}}}},
		{name: "duplicate promotion", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC"}, Promotions: []STIXIndicatorPromotion{{CandidateID: candidates.Candidates()[0].ID, ValidFrom: validFrom}, {CandidateID: candidates.Candidates()[0].ID, ValidFrom: validFrom}}}},
		{name: "missing valid_from", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC"}, Promotions: []STIXIndicatorPromotion{{CandidateID: candidates.Candidates()[0].ID}}}},
		{name: "reversed validity", options: STIXExportOptions{Producer: STIXProducer{Name: "SOC"}, Promotions: []STIXIndicatorPromotion{{CandidateID: candidates.Candidates()[0].ID, ValidFrom: validFrom, ValidUntil: timePointer(validFrom.Add(-time.Second))}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildSTIXBundle(candidates, nil, test.options); !errors.Is(err, ErrInvalidSTIXExportOptions) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	overflow := candidates
	overflow.candidates = cloneThreatCandidates(candidates.candidates)
	overflow.candidates[0].DualFailureMessages = STIXMaximumNumberObserved + 1
	_, err := BuildSTIXBundle(overflow, nil, STIXExportOptions{Producer: STIXProducer{Name: "SOC"}})
	var countErr *STIXObservationCountError
	if !errors.Is(err, ErrSTIXObservationCountOutOfRange) || !errors.As(err, &countErr) || countErr.CandidateID != overflow.candidates[0].ID || countErr.NumberObserved != STIXMaximumNumberObserved+1 {
		t.Fatalf("count error=%v typed=%+v", err, countErr)
	}
	if !strings.Contains(countErr.Error(), string(countErr.CandidateID)) {
		t.Fatalf("count error omitted candidate ID: %v", countErr)
	}

	generatedAt := time.Unix(200_000, 0).UTC()
	enrichment, enrichErr := EnrichThreatCandidates(context.Background(), candidates, nil, SourceEnrichmentOptions{})
	if enrichErr != nil {
		t.Fatal(enrichErr)
	}
	enrichment.threatCandidateDigest = StableAnalysisID("mismatch", "candidate")
	enrichment.metadata.GeneratedAt = generatedAt
	if _, err := BuildSTIXBundle(candidates, &enrichment, STIXExportOptions{Producer: STIXProducer{Name: "SOC"}}); !errors.Is(err, ErrInvalidSTIXExportOptions) || !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("mismatched enrichment error=%v", err)
	}
}

func TestBuildSTIXBundleProducerIdentityCanRemainStableAcrossExports(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	createdAt := candidates.ResultMetadata().GeneratedAt.Add(-time.Hour)
	first, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{
		GeneratedAt: candidates.ResultMetadata().GeneratedAt,
		Producer:    STIXProducer{Name: "Example SOC", CreatedAt: createdAt},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{
		GeneratedAt: candidates.ResultMetadata().GeneratedAt.Add(time.Minute),
		Producer:    STIXProducer{Name: "Example SOC", CreatedAt: createdAt},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstIdentity := stixProducerIdentityID(t, first)
	secondIdentity := stixProducerIdentityID(t, second)
	if firstIdentity != secondIdentity || first.ID() == second.ID() {
		t.Fatalf("producer identities=(%s,%s) bundle IDs=(%s,%s)", firstIdentity, secondIdentity, first.ID(), second.ID())
	}
}

func TestSTIXExternalReferencesRequireHTTPSForClickableProvenance(t *testing.T) {
	candidateID := AnalysisID("threat_candidate:fixture")
	metadata := IPMetadata{Assertions: []IPMetadataAssertion{
		{Provenance: IPMetadataProvenance{Provider: "safe-provider", Source: "https://provider.example/evidence", ReferenceID: "safe"}},
		{Provenance: IPMetadataProvenance{Provider: "unsafe-provider", Source: "javascript:alert(1)", ReferenceID: "unsafe"}},
	}}
	references := stixCandidateExternalReferences(candidateID, metadata)
	if len(references) != 3 {
		t.Fatalf("references=%+v", references)
	}
	for _, reference := range references {
		if reference.SourceName == "safe-provider" && reference.URL != "https://provider.example/evidence" {
			t.Fatalf("safe reference=%+v", reference)
		}
		if reference.SourceName == "unsafe-provider" && (reference.URL != "" || reference.ExternalID != "unsafe") {
			t.Fatalf("unsafe reference became clickable: %+v", reference)
		}
	}
}

func TestBuildSTIXBundlePreservesCrossDomainEvidenceAsData(t *testing.T) {
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	config.Entities[0].Domains = append(config.Entities[0].Domains, DomainConfig{
		Name: "sister.test", Owner: "mail-team", Records: MonitoredRecordsConfig{SPF: []string{"sister.test"}, DMARC: []string{"_dmarc.sister.test"}},
	})
	values := correlationHealthyDNSValues()
	values["sister.test"] = "v=spf1 -all"
	values["_dmarc.sister.test"] = "v=DMARC1; p=reject; rua=mailto:reports@sister.test"
	candidates := threatTestScore(t, config, values, []*AggregateReport{
		correlationTestReport("r1", "receiver-a.example", 100, 200, threatTestRecord("198.51.100.20", "15", "example.test", "none")),
		correlationTestReport("r2", "receiver-b.example", 300, 400, threatTestRecord("198.51.100.20", "15", "sister.test", "none")),
	}, ThreatCandidateOptions{GeneratedAt: time.Unix(1_000, 0)})
	bundle, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{Producer: STIXProducer{Name: "Example SOC"}, IncludeReviewNotes: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle.Objects() {
		if object.Type() == "observed-data" {
			var observed stixObservedData
			if err := json.Unmarshal(object.raw, &observed); err != nil {
				t.Fatal(err)
			}
			evidence := stixTestCandidateEvidence(t, observed.Extensions)
			if !slices.Equal(evidence.AffectedDomains, []string{"example.test", "sister.test"}) {
				t.Fatalf("affected domains=%v", evidence.AffectedDomains)
			}
		}
		if object.Type() == "note" {
			var note stixNote
			if err := json.Unmarshal(object.raw, &note); err != nil || strings.Contains(note.Content, "example.test") || strings.Contains(note.Content, "sister.test") {
				t.Fatalf("untrusted domain entered note: %+v error=%v", note, err)
			}
		}
	}
}

func TestSTIXStandardDeterministicSCOIdentifiers(t *testing.T) {
	ipID := stixSCOID("ipv4-addr", struct {
		Value string `json:"value"`
	}{"198.51.100.3"})
	if ipID != "ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4" {
		t.Fatalf("IPv4 SCO ID=%s", ipID)
	}
	asnID := stixSCOID("autonomous-system", struct {
		Number uint32 `json:"number"`
	}{15139})
	if asnID != "autonomous-system--3aa27478-50b5-5ab8-9da9-cdc12b657fff" {
		t.Fatalf("ASN SCO ID=%s", asnID)
	}
	if err := validateSTIXIdentifier(stixObjectID("observed-data", "fixture"), "observed-data", true); err != nil {
		t.Fatal(err)
	}
}

func TestSTIXEvidenceExtensionSchemaValidatesEmittedExtensions(t *testing.T) {
	schemaData := STIXEvidenceExtensionSchema()
	var document map[string]any
	if err := json.Unmarshal(schemaData, &document); err != nil {
		t.Fatal(err)
	}
	if document["$id"] != STIXEvidenceExtensionSchemaID {
		t.Fatalf("schema ID=%v", document["$id"])
	}
	schemaData[0] = 'x'
	if fresh := STIXEvidenceExtensionSchema(); len(fresh) == 0 || fresh[0] != '{' {
		t.Fatal("schema accessor returned mutable state")
	}

	compiledDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(STIXEvidenceExtensionSchema()))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(STIXEvidenceExtensionSchemaID, compiledDocument); err != nil {
		t.Fatal(err)
	}
	validator, err := compiler.Compile(STIXEvidenceExtensionSchemaID)
	if err != nil {
		t.Fatal(err)
	}

	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	validFrom := candidates.ResultMetadata().GeneratedAt
	bundle, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{
		Producer: STIXProducer{Name: "Example SOC"}, IncludeReviewNotes: true,
		Promotions: []STIXIndicatorPromotion{{CandidateID: candidates.Candidates()[0].ID, ValidFrom: validFrom}},
	})
	if err != nil {
		t.Fatal(err)
	}
	extensionID := stixEvidenceExtensionDefinition(stixLibraryIdentity().ID).ID
	validated := 0
	for _, object := range bundle.Objects() {
		var value struct {
			Extensions map[string]json.RawMessage `json:"extensions"`
		}
		if err := json.Unmarshal(object.raw, &value); err != nil {
			t.Fatal(err)
		}
		_, ok := value.Extensions[extensionID]
		if !ok {
			continue
		}
		objectDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(object.raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := validator.Validate(objectDocument); err != nil {
			t.Fatalf("%s extension: %v", object.Type(), err)
		}
		validated++
	}
	if validated != 4 {
		t.Fatalf("validated extensions=%d want=4", validated)
	}
}

func TestValidateAndWriteSTIXBundleFailures(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	bundle, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{Producer: STIXProducer{Name: "Example SOC"}})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := WriteSTIXBundle(&buffer, bundle); err != nil || !bytes.HasSuffix(buffer.Bytes(), []byte("\n")) {
		t.Fatalf("write error=%v bytes=%q", err, buffer.Bytes())
	}
	if err := WriteSTIXBundle(nil, bundle); !errors.Is(err, ErrInvalidSTIXBundle) {
		t.Fatalf("nil writer error=%v", err)
	}
	if err := WriteSTIXBundle(stixErrorWriter{}, bundle); !errors.Is(err, errSTIXWriter) {
		t.Fatalf("writer error=%v", err)
	}
	if err := WriteSTIXBundle(stixShortWriter{}, bundle); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer error=%v", err)
	}

	tampered := bundle
	tampered.objects = bundle.Objects()
	for index := range tampered.objects {
		if tampered.objects[index].Type() == "observed-data" {
			tampered.objects[index].raw = bytes.Replace(tampered.objects[index].raw, []byte(`"number_observed":140`), []byte(`"number_observed":0`), 1)
			break
		}
	}
	if err := ValidateSTIXBundle(tampered); !errors.Is(err, ErrInvalidSTIXBundle) {
		t.Fatalf("tampered bundle error=%v", err)
	}
	if _, err := json.Marshal(STIXBundle{}); !errors.Is(err, ErrInvalidSTIXBundle) {
		t.Fatalf("zero bundle marshal error=%v", err)
	}
	if _, err := json.Marshal(STIXObject{}); !errors.Is(err, ErrInvalidSTIXBundle) {
		t.Fatalf("zero object marshal error=%v", err)
	}

	badTimestamp := bundle
	badTimestamp.objects = bundle.Objects()
	for index := range badTimestamp.objects {
		if badTimestamp.objects[index].Type() == "observed-data" {
			badTimestamp.objects[index].raw = bytes.Replace(badTimestamp.objects[index].raw, []byte(".000Z"), []byte(".000+00:00"), 1)
			break
		}
	}
	if err := ValidateSTIXBundle(badTimestamp); !errors.Is(err, ErrInvalidSTIXBundle) {
		t.Fatalf("non-Z timestamp error=%v", err)
	}

	missingCreator := bundle
	missingCreator.objects = bundle.Objects()
	for index := range missingCreator.objects {
		if missingCreator.objects[index].Type() != "observed-data" {
			continue
		}
		var value map[string]any
		if err := json.Unmarshal(missingCreator.objects[index].raw, &value); err != nil {
			t.Fatal(err)
		}
		delete(value, "created_by_ref")
		missingCreator.objects[index].raw, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if err := ValidateSTIXBundle(missingCreator); !errors.Is(err, ErrInvalidSTIXBundle) {
		t.Fatalf("missing created_by_ref error=%v", err)
	}
}

func TestSTIXGoldenBundle(t *testing.T) {
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	bundle, err := BuildSTIXBundle(candidates, nil, STIXExportOptions{Producer: STIXProducer{Name: "Example SOC"}, TLP: STIXTLPGreen})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	want, err := os.ReadFile("testdata/golden/stix_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("STIX golden fixture changed\nactual:\n%s", actual)
	}
}

func TestSTIXFullInteroperabilityGoldenBundle(t *testing.T) {
	generatedAt := time.Unix(200_000, 0).UTC()
	candidates := sourceEnrichmentTestCandidates(t, "198.51.100.20", "2001:db8::20")
	expiresAt := generatedAt.Add(time.Hour)
	enrichment, err := EnrichThreatCandidates(context.Background(), candidates, &sourceFixtureEnricher{metadata: map[string]IPMetadata{
		"198.51.100.20": sourceTestMetadata(64500, "Example ASN", "198.51.100.0/24", "Example Org", "US", "offline-fixture", generatedAt.Add(-time.Minute), &expiresAt),
		"2001:db8::20":  sourceTestMetadata(64500, "Example ASN", "2001:db8::/32", "Example Org", "US", "offline-fixture", generatedAt.Add(-time.Minute), &expiresAt),
	}}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return generatedAt })})
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidates.Candidates()[0]
	bundle, err := BuildSTIXBundle(candidates, &enrichment, STIXExportOptions{
		Producer: STIXProducer{Name: "Example SOC"}, TLP: STIXTLPAmber, IncludeReviewNotes: true,
		Promotions: []STIXIndicatorPromotion{{CandidateID: candidate.ID, ValidFrom: generatedAt, ValidUntil: timePointer(generatedAt.Add(time.Hour))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	want, err := os.ReadFile("testdata/golden/stix_bundle_full.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("full STIX interoperability fixture changed\nactual:\n%s", actual)
	}
}

func BenchmarkBuildSTIXBundle(b *testing.B) {
	candidates := sourceEnrichmentTestCandidates(b, "198.51.100.20", "2001:db8::20")
	options := STIXExportOptions{Producer: STIXProducer{Name: "Benchmark SOC"}, TLP: STIXTLPAmber, IncludeReviewNotes: true}
	b.ResetTimer()
	for range b.N {
		if _, err := BuildSTIXBundle(candidates, nil, options); err != nil {
			b.Fatal(err)
		}
	}
}

func stixObjectCounts(bundle STIXBundle) map[string]int {
	result := map[string]int{}
	for _, object := range bundle.Objects() {
		result[object.Type()]++
	}
	return result
}

func stixProducerIdentityID(t testing.TB, bundle STIXBundle) string {
	t.Helper()
	libraryID := stixLibraryIdentity().ID
	for _, object := range bundle.Objects() {
		if object.Type() == "identity" && object.ID() != libraryID {
			return object.ID()
		}
	}
	t.Fatal("producer identity not found")
	return ""
}

func stixTestCandidateEvidence(t testing.TB, values map[string]stixDMARCEvidenceExtension) stixDMARCEvidence {
	t.Helper()
	extensionID := stixEvidenceExtensionDefinition(stixLibraryIdentity().ID).ID
	value, ok := values[extensionID]
	if !ok || len(values) != 1 || value.ExtensionType != "property-extension" || value.ContextType != "candidate_evidence" {
		t.Fatalf("candidate extension=%+v", values)
	}
	return value.Evidence
}

func stixTestASNExtension(t testing.TB, values map[string]stixDMARCASNExtension) stixDMARCASNExtension {
	t.Helper()
	extensionID := stixEvidenceExtensionDefinition(stixLibraryIdentity().ID).ID
	value, ok := values[extensionID]
	if !ok || len(values) != 1 || value.ExtensionType != "property-extension" || value.ContextType != "asn_context" {
		t.Fatalf("ASN extension=%+v", values)
	}
	return value
}

func mapsEqual(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

var errSTIXWriter = errors.New("STIX writer failure")

type stixErrorWriter struct{}

func (stixErrorWriter) Write([]byte) (int, error) { return 0, errSTIXWriter }

type stixShortWriter struct{}

func (stixShortWriter) Write(value []byte) (int, error) { return len(value) - 1, nil }
