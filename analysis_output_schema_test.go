package dmarcgo

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type analysisSchemaRecord struct {
	name  string
	value any
}

type analysisSchemaMode struct {
	mode     AnalysisMode
	document any
	records  []analysisSchemaRecord
}

func TestAnalysisOutputSchemasMatchGoContracts(t *testing.T) {
	for _, spec := range analysisSchemaModes() {
		generated, err := buildAnalysisOutputSchema(spec)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("DMARCGO_UPDATE_ANALYSIS_SCHEMAS") == "1" {
			path := "schemas/analysis/" + string(spec.mode) + "/v" + AnalysisOutputSchemaVersion + ".json"
			if err := os.WriteFile(path, generated, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		embedded, err := AnalysisOutputSchema(spec.mode, AnalysisOutputSchemaVersion)
		if err != nil {
			t.Fatal(err)
		}
		var generatedValue, embeddedValue any
		if err := json.Unmarshal(generated, &generatedValue); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(embedded, &embeddedValue); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(generatedValue, embeddedValue) {
			t.Fatalf("schema for %s does not match its Go contracts; regenerate with DMARCGO_UPDATE_ANALYSIS_SCHEMAS=1 go test -run TestAnalysisOutputSchemasMatchGoContracts .", spec.mode)
		}
	}
}

func analysisSchemaModes() []analysisSchemaMode {
	return []analysisSchemaMode{
		{AnalysisModeDNSHealth, dnsHealthOutputDocument{}, []analysisSchemaRecord{
			{"metadata", dnsHealthOutputMetadata{}}, {"record", DNSRecordHealth{}}, {"domain", DNSDomainHealth{}},
			{"entity", DNSEntityHealth{}}, {"finding", DNSHealthFinding{}}, {"provider_context", DNSHealthProviderContext{}},
		}},
		{AnalysisModeReportEvidence, reportEvidenceOutputDocument{}, []analysisSchemaRecord{
			{"metadata", reportEvidenceOutputMetadata{}}, {"report", ReportEvidenceReport{}},
			{"observation", ReportEvidenceObservation{}}, {"diagnostic", ReportEvidenceDiagnostic{}},
		}},
		{AnalysisModeDNSReportCorrelation, correlationOutputDocument{}, []analysisSchemaRecord{
			{"metadata", correlationOutputMetadata{}}, {"inventory", DNSReportCorrelationInventory{}},
			{"stream", DNSReportCorrelationStream{}}, {"finding", DNSReportCorrelationFinding{}},
		}},
		{AnalysisModeThreatCandidates, threatCandidateOutputDocument{}, []analysisSchemaRecord{
			{"metadata", threatCandidateOutputMetadata{}}, {"candidate", ThreatCandidate{}},
		}},
		{AnalysisModeSourceEnrichment, sourceEnrichmentOutputDocument{}, []analysisSchemaRecord{
			{"metadata", sourceEnrichmentOutputMetadata{}}, {"candidate", EnrichedThreatCandidate{}},
			{"asn", ASNEnrichment{}}, {"diagnostic", SourceEnrichmentDiagnostic{}},
		}},
		{AnalysisModeJurisdictionContext, jurisdictionContextOutputDocument{}, []analysisSchemaRecord{
			{"metadata", jurisdictionContextOutputMetadata{}}, {"candidate", JurisdictionContextCandidate{}},
			{"finding", JurisdictionContextFinding{}},
		}},
	}
}

type analysisSchemaGenerator struct {
	definitions map[string]any
	building    map[reflect.Type]bool
}

func buildAnalysisOutputSchema(spec analysisSchemaMode) ([]byte, error) {
	generator := &analysisSchemaGenerator{definitions: map[string]any{}, building: map[reflect.Type]bool{}}
	documentType := reflect.TypeOf(spec.document)
	root := generator.objectSchema(documentType, true)
	properties := root["properties"].(map[string]any)
	baseID, _ := AnalysisOutputSchemaID(spec.mode, AnalysisOutputSchemaVersion)
	properties["schema"] = map[string]any{"const": baseID}
	properties["schema_version"] = map[string]any{"const": AnalysisOutputSchemaVersion}
	properties["mode"] = map[string]any{"const": string(spec.mode)}
	properties["profile"] = map[string]any{"const": AnalysisOutputProfileNative}
	properties["result_digest"] = map[string]any{"type": "string", "minLength": 1}
	properties["metadata"] = map[string]any{"allOf": []any{
		generator.schemaForType(reflect.TypeOf(ResultMetadata{})),
		map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"const": string(spec.mode)}}},
	}}

	jsonlID, _ := AnalysisOutputSchemaIDForFormat(spec.mode, AnalysisOutputJSONL, AnalysisOutputSchemaVersion)
	jsonlProperties := map[string]any{
		"schema":         map[string]any{"const": jsonlID},
		"schema_version": map[string]any{"const": AnalysisOutputSchemaVersion},
		"mode":           map[string]any{"const": string(spec.mode)},
		"generated_at":   map[string]any{"type": "string", "format": "date-time"},
		"result_digest":  map[string]any{"type": "string", "minLength": 1},
		"redaction":      map[string]any{"enum": []string{string(OutputRedactionPublic), string(OutputRedactionOperational), string(OutputRedactionRestricted)}},
		"record_type":    map[string]any{"type": "string"},
		"record_id":      map[string]any{"type": "string", "minLength": 1},
		"data":           map[string]any{"type": "object"},
	}
	variants := make([]any, 0, len(spec.records))
	for _, record := range spec.records {
		variants = append(variants, map[string]any{"properties": map[string]any{
			"record_type": map[string]any{"const": record.name},
			"data":        generator.schemaForType(reflect.TypeOf(record.value)),
		}})
	}
	jsonl := map[string]any{
		"type": "object", "additionalProperties": false,
		"required":   []string{"schema", "schema_version", "mode", "generated_at", "result_digest", "redaction", "record_type", "record_id", "data"},
		"properties": jsonlProperties, "oneOf": variants,
	}

	descriptor, _ := AnalysisOutputDescriptorForMode(spec.mode)
	csvID, _ := AnalysisOutputSchemaIDForFormat(spec.mode, AnalysisOutputCSV, AnalysisOutputSchemaVersion)
	csvProperties := make(map[string]any, len(descriptor.CSVColumns))
	for _, column := range descriptor.CSVColumns {
		csvProperties[column] = map[string]any{"type": "string"}
	}
	csvProperties["schema"] = map[string]any{"const": csvID}
	csvProperties["schema_version"] = map[string]any{"const": AnalysisOutputSchemaVersion}
	csvProperties["mode"] = map[string]any{"const": string(spec.mode)}
	csvProperties["redaction"] = map[string]any{"enum": []string{string(OutputRedactionPublic), string(OutputRedactionOperational), string(OutputRedactionRestricted)}}
	csv := map[string]any{
		"type": "object", "additionalProperties": false, "required": descriptor.CSVColumns, "properties": csvProperties,
	}

	generator.definitions["jsonl_record"] = jsonl
	generator.definitions["csv_record"] = csv
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$id"] = baseID
	root["title"] = "dmarcgo native " + strings.ReplaceAll(string(spec.mode), "_", " ") + " output v" + AnalysisOutputSchemaVersion
	root["$defs"] = generator.definitions
	encoded, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func (generator *analysisSchemaGenerator) schemaForType(value reflect.Type) any {
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch value.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.String:
		if value.Name() == "OutputRedaction" {
			return map[string]any{"enum": []string{string(OutputRedactionPublic), string(OutputRedactionOperational), string(OutputRedactionRestricted)}}
		}
		return map[string]any{"type": "string"}
	case reflect.Slice:
		return map[string]any{"type": []string{"array", "null"}, "items": generator.schemaForType(value.Elem())}
	case reflect.Array:
		return map[string]any{"type": "array", "minItems": value.Len(), "maxItems": value.Len(), "items": generator.schemaForType(value.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": generator.schemaForType(value.Elem())}
	case reflect.Struct:
		name := value.Name()
		if name == "" {
			return generator.objectSchema(value, false)
		}
		if _, exists := generator.definitions[name]; !exists {
			generator.definitions[name] = map[string]any{}
			if !generator.building[value] {
				generator.building[value] = true
				generator.definitions[name] = generator.objectSchema(value, false)
				delete(generator.building, value)
			}
		}
		return map[string]any{"$ref": "#/$defs/" + name}
	default:
		return map[string]any{}
	}
}

func (generator *analysisSchemaGenerator) objectSchema(value reflect.Type, root bool) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for index := range value.NumField() {
		field := value.Field(index)
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		name := parts[0]
		if field.Anonymous && name == "" {
			embedded := generator.objectSchema(field.Type, root)
			for key, schema := range embedded["properties"].(map[string]any) {
				properties[key] = schema
			}
			required = append(required, embedded["required"].([]string)...)
			continue
		}
		if field.PkgPath != "" || name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		omitEmpty := false
		for _, option := range parts[1:] {
			omitEmpty = omitEmpty || option == "omitempty"
		}
		fieldSchema := generator.schemaForType(field.Type)
		if root && field.Type.Kind() == reflect.Slice {
			fieldSchema = map[string]any{"type": "array", "items": generator.schemaForType(field.Type.Elem())}
		}
		properties[name] = fieldSchema
		if !omitEmpty && !analysisSchemaPrivacyOptional(value, name) {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}

func analysisSchemaPrivacyOptional(parent reflect.Type, field string) bool {
	if analysisRestrictedRawField(field) {
		return true
	}
	switch parent.Name() {
	case "IPMetadataProvenance":
		return field == "provider" || field == "source" || field == "reference_id"
	case "IPMetadataAssertion":
		return field == "asn_name" || field == "organization"
	case "ASNEnrichment":
		return field == "names" || field == "organizations" || field == "providers"
	default:
		return false
	}
}
