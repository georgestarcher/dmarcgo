package dmarcgo

import (
	"bytes"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
)

// AnalysisOutputSchemaVersion is the current native analysis-output contract.
// It is independent of the in-memory analysis contract and common envelope.
const AnalysisOutputSchemaVersion = "1"

// AnalysisOutputProfileNative identifies complete mode-native representation.
// Automation and agent profiles remain part of the common output envelope.
const AnalysisOutputProfileNative = "native"

//go:embed schemas/analysis/*/v1.json
var analysisOutputSchemaFS embed.FS

// AnalysisOutputFormat selects one native, mode-specific representation.
type AnalysisOutputFormat string

const (
	AnalysisOutputJSON  AnalysisOutputFormat = "json"
	AnalysisOutputJSONL AnalysisOutputFormat = "jsonl"
	AnalysisOutputCSV   AnalysisOutputFormat = "csv"
)

// ErrUnsupportedAnalysisOutput identifies an unsupported mode, format, or
// schema-version combination.
var ErrUnsupportedAnalysisOutput = errors.New("unsupported analysis output")

// AnalysisOutputOptions changes representation only. A zero value selects the
// current schema and operational redaction. Result timestamps are always
// preserved; encoding never consults a clock.
type AnalysisOutputOptions struct {
	SchemaVersion string
	Redaction     OutputRedaction
}

// AnalysisOutputDescriptor describes one independently versioned native mode.
// JSON and JSONL preserve the complete result. CSV emits every record type and
// retains each complete record as JSON in data_json in addition to useful
// flattened columns.
type AnalysisOutputDescriptor struct {
	Mode             AnalysisMode
	SchemaVersion    string
	SchemaIDs        map[AnalysisOutputFormat]string
	Formats          []AnalysisOutputFormat
	JSONLRecordTypes []string
	CSVColumns       []string
}

type analysisOutputRecord struct {
	Schema        string          `json:"schema"`
	SchemaVersion string          `json:"schema_version"`
	Mode          AnalysisMode    `json:"mode"`
	GeneratedAt   time.Time       `json:"generated_at"`
	ResultDigest  AnalysisID      `json:"result_digest"`
	Redaction     OutputRedaction `json:"redaction"`
	RecordType    string          `json:"record_type"`
	RecordID      string          `json:"record_id"`
	Data          any             `json:"data"`
}

type analysisOutputSpec struct {
	mode       AnalysisMode
	metadata   ResultMetadata
	digest     AnalysisID
	document   any
	csvColumns []analysisCSVColumn
	walk       func(func(string, string, any) error) error
}

type analysisCSVColumn struct {
	header string
	path   []string
}

const analysisPublicSafeValue = "analysis_output_public_safe"

var analysisModeRecordTypes = map[AnalysisMode][]string{
	AnalysisModeDNSHealth:            {"metadata", "record", "domain", "entity", "finding", "provider_context"},
	AnalysisModeReportEvidence:       {"metadata", "report", "observation", "diagnostic"},
	AnalysisModeDNSReportCorrelation: {"metadata", "inventory", "stream", "finding"},
	AnalysisModeThreatCandidates:     {"metadata", "candidate"},
	AnalysisModeSourceEnrichment:     {"metadata", "candidate", "asn", "diagnostic"},
	AnalysisModeJurisdictionContext:  {"metadata", "candidate", "finding"},
}

var analysisModeCSVColumns = map[AnalysisMode][]analysisCSVColumn{
	AnalysisModeDNSHealth: {
		{header: "entity_id", path: []string{"entity_id"}}, {header: "domain", path: []string{"domain"}},
		{header: "name", path: []string{"name"}}, {header: "dns_record_type", path: []string{"type"}},
		{header: "status", path: []string{"status"}}, {header: "severity", path: []string{"severity"}},
		{header: "score", path: []string{"score", "value"}}, {header: "grade", path: []string{"score", "grade"}},
	},
	AnalysisModeReportEvidence: {
		{header: "reporter", path: []string{"reporter", "value"}}, {header: "target_domain", path: []string{"target_domain", "value"}},
		{header: "source_ip", path: []string{"source_ip", "value"}}, {header: "author_domain", path: []string{"author_domain", "value"}},
		{header: "disposition", path: []string{"disposition"}}, {header: "messages", path: []string{"count", "value"}},
		{header: "combined_outcome", path: []string{"policy_outcome", "combined"}},
	},
	AnalysisModeDNSReportCorrelation: {
		{header: "entity_id", path: []string{"entity_id"}}, {header: "domain", path: []string{"domain"}},
		{header: "target_domain", path: []string{"target_domain"}}, {header: "author_domain", path: []string{"author_domain"}},
		{header: "source_ip", path: []string{"source_ip"}}, {header: "messages", path: []string{"messages"}},
		{header: "classification", path: []string{"classification"}}, {header: "severity", path: []string{"severity"}},
	},
	AnalysisModeThreatCandidates: {
		{header: "source_ip", path: []string{"source_ip"}}, {header: "ip_type", path: []string{"ip_type"}},
		{header: "score", path: []string{"score"}}, {header: "confidence", path: []string{"confidence"}},
		{header: "severity", path: []string{"severity"}}, {header: "messages", path: []string{"messages"}},
		{header: "review_eligible", path: []string{"review_eligible"}}, {header: "recommended_usage", path: []string{"recommended_usage"}},
	},
	AnalysisModeSourceEnrichment: {
		{header: "source_ip", path: []string{"candidate", "source_ip"}}, {header: "status", path: []string{"status"}},
		{header: "score", path: []string{"candidate", "score"}}, {header: "asn", path: []string{"asn"}},
		{header: "country_code", path: []string{"metadata", "assertions", "0", "country_code"}},
		{header: "organization", path: []string{"metadata", "assertions", "0", "organization"}},
	},
	AnalysisModeJurisdictionContext: {
		{header: "source_ip", path: []string{"source_ip"}}, {header: "status", path: []string{"status"}},
		{header: "tier", path: []string{"tier"}}, {header: "country_codes", path: []string{"country_codes"}},
		{header: "categories", path: []string{"categories"}}, {header: "review_priority_adjustment", path: []string{"review_priority_adjustment"}},
		{header: "severity", path: []string{"severity"}},
	},
}

// SupportedAnalysisOutputModes returns native-output modes in dependency order.
func SupportedAnalysisOutputModes() []AnalysisMode {
	return []AnalysisMode{
		AnalysisModeDNSHealth,
		AnalysisModeReportEvidence,
		AnalysisModeDNSReportCorrelation,
		AnalysisModeThreatCandidates,
		AnalysisModeSourceEnrichment,
		AnalysisModeJurisdictionContext,
	}
}

// AnalysisOutputDescriptorForMode returns stable schema and row discovery.
func AnalysisOutputDescriptorForMode(mode AnalysisMode) (AnalysisOutputDescriptor, error) {
	recordTypes, ok := analysisModeRecordTypes[mode]
	if !ok {
		return AnalysisOutputDescriptor{}, fmt.Errorf("%w: mode %q", ErrUnsupportedAnalysisOutput, mode)
	}
	columns := []string{"schema", "schema_version", "mode", "generated_at", "result_digest", "redaction", "record_type", "record_id"}
	for _, column := range analysisModeCSVColumns[mode] {
		columns = append(columns, column.header)
	}
	columns = append(columns, "data_json")
	schemaIDs := make(map[AnalysisOutputFormat]string, 3)
	for _, format := range []AnalysisOutputFormat{AnalysisOutputJSON, AnalysisOutputJSONL, AnalysisOutputCSV} {
		schemaIDs[format], _ = AnalysisOutputSchemaIDForFormat(mode, format, AnalysisOutputSchemaVersion)
	}
	return AnalysisOutputDescriptor{
		Mode: mode, SchemaVersion: AnalysisOutputSchemaVersion,
		SchemaIDs:        schemaIDs,
		Formats:          []AnalysisOutputFormat{AnalysisOutputJSON, AnalysisOutputJSONL, AnalysisOutputCSV},
		JSONLRecordTypes: append([]string(nil), recordTypes...), CSVColumns: columns,
	}, nil
}

// AnalysisOutputSchemaID returns the stable schema identifier for a mode.
func AnalysisOutputSchemaID(mode AnalysisMode, version string) (string, error) {
	if version == "" {
		version = AnalysisOutputSchemaVersion
	}
	if version != AnalysisOutputSchemaVersion {
		return "", fmt.Errorf("%w: schema version %q", ErrUnsupportedAnalysisOutput, version)
	}
	if _, ok := analysisModeRecordTypes[mode]; !ok {
		return "", fmt.Errorf("%w: mode %q", ErrUnsupportedAnalysisOutput, mode)
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/analysis/%s/v%s.json", mode, version), nil
}

// AnalysisOutputSchemaIDForFormat returns the document schema for JSON and the
// corresponding record-dictionary fragment for JSONL or CSV.
func AnalysisOutputSchemaIDForFormat(mode AnalysisMode, format AnalysisOutputFormat, version string) (string, error) {
	base, err := AnalysisOutputSchemaID(mode, version)
	if err != nil {
		return "", err
	}
	switch format {
	case AnalysisOutputJSON:
		return base, nil
	case AnalysisOutputJSONL:
		return base + "#/$defs/jsonl_record", nil
	case AnalysisOutputCSV:
		return base + "#/$defs/csv_record", nil
	default:
		return "", fmt.Errorf("%w: format %q", ErrUnsupportedAnalysisOutput, format)
	}
}

// AnalysisOutputSchema returns a copy of the embedded JSON Schema for a native
// mode. Each mode has an independent top-level field dictionary.
func AnalysisOutputSchema(mode AnalysisMode, version string) ([]byte, error) {
	if _, err := AnalysisOutputSchemaID(mode, version); err != nil {
		return nil, err
	}
	if version == "" {
		version = AnalysisOutputSchemaVersion
	}
	data, err := analysisOutputSchemaFS.ReadFile(fmt.Sprintf("schemas/analysis/%s/v%s.json", mode, version))
	if err != nil {
		return nil, fmt.Errorf("%w: schema for mode %q: %v", ErrUnsupportedAnalysisOutput, mode, err)
	}
	return append([]byte(nil), data...), nil
}

// WriteDNSHealthOutput encodes an already computed DNS-health result.
func WriteDNSHealthOutput(writer io.Writer, result DNSHealthResult, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	return writeAnalysisOutput(writer, dnsHealthOutputSpec(result), format, options)
}

// WriteReportEvidenceOutput encodes an already computed report-evidence result.
func WriteReportEvidenceOutput(writer io.Writer, result ReportEvidenceResult, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	return writeAnalysisOutput(writer, reportEvidenceOutputSpec(result), format, options)
}

// WriteDNSReportCorrelationOutput encodes an already computed correlation result.
func WriteDNSReportCorrelationOutput(writer io.Writer, result DNSReportCorrelationResult, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	return writeAnalysisOutput(writer, correlationOutputSpec(result), format, options)
}

// WriteThreatCandidatesOutput encodes already computed threat candidates.
func WriteThreatCandidatesOutput(writer io.Writer, result ThreatCandidateResult, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	return writeAnalysisOutput(writer, threatCandidateOutputSpec(result), format, options)
}

// WriteSourceEnrichmentOutput encodes an already computed enrichment result.
func WriteSourceEnrichmentOutput(writer io.Writer, result SourceEnrichmentResult, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	return writeAnalysisOutput(writer, sourceEnrichmentOutputSpec(result), format, options)
}

// WriteJurisdictionContextOutput encodes an already computed jurisdiction result.
func WriteJurisdictionContextOutput(writer io.Writer, result JurisdictionContextResult, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	return writeAnalysisOutput(writer, jurisdictionContextOutputSpec(result), format, options)
}

func writeAnalysisOutput(writer io.Writer, spec analysisOutputSpec, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
	if writer == nil {
		return fmt.Errorf("%w: nil writer", ErrUnsupportedAnalysisOutput)
	}
	options, err := normalizeAnalysisOutputOptions(options)
	if err != nil {
		return err
	}
	if err := validateAnalysisOutputSpec(spec); err != nil {
		return err
	}
	schema, _ := AnalysisOutputSchemaIDForFormat(spec.mode, format, options.SchemaVersion)
	switch format {
	case AnalysisOutputJSON:
		value, changed, err := transformAnalysisOutputValue(spec.document, options.Redaction)
		if err != nil {
			return err
		}
		setAnalysisDocumentRedaction(value, options.Redaction, changed)
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(value); err != nil {
			return fmt.Errorf("%w: %w", ErrOutputSerialization, err)
		}
		return nil
	case AnalysisOutputJSONL:
		return spec.walk(func(recordType, id string, data any) error {
			line := analysisOutputRecord{Schema: schema, SchemaVersion: options.SchemaVersion, Mode: spec.mode, GeneratedAt: spec.metadata.GeneratedAt, ResultDigest: spec.digest, Redaction: options.Redaction, RecordType: recordType, RecordID: id, Data: data}
			value, _, transformErr := transformAnalysisOutputValue(line, options.Redaction)
			if transformErr != nil {
				return transformErr
			}
			encoder := json.NewEncoder(writer)
			encoder.SetEscapeHTML(true)
			if encodeErr := encoder.Encode(value); encodeErr != nil {
				return fmt.Errorf("%w: %w", ErrOutputSerialization, encodeErr)
			}
			return nil
		})
	case AnalysisOutputCSV:
		return writeAnalysisOutputCSV(writer, spec, schema, options)
	default:
		return fmt.Errorf("%w: format %q", ErrUnsupportedAnalysisOutput, format)
	}
}

func normalizeAnalysisOutputOptions(options AnalysisOutputOptions) (AnalysisOutputOptions, error) {
	if options.SchemaVersion == "" {
		options.SchemaVersion = AnalysisOutputSchemaVersion
	}
	if options.Redaction == "" {
		options.Redaction = OutputRedactionOperational
	}
	if options.SchemaVersion != AnalysisOutputSchemaVersion {
		return options, fmt.Errorf("%w: schema version %q", ErrUnsupportedAnalysisOutput, options.SchemaVersion)
	}
	if options.Redaction != OutputRedactionPublic && options.Redaction != OutputRedactionOperational && options.Redaction != OutputRedactionRestricted {
		return options, fmt.Errorf("%w: redaction %q", ErrUnsupportedAnalysisOutput, options.Redaction)
	}
	return options, nil
}

func validateAnalysisOutputSpec(spec analysisOutputSpec) error {
	generatedAtUnavailable := spec.metadata.GeneratedAt.IsZero() && spec.mode != AnalysisModeReportEvidence
	if spec.metadata.ContractVersion != AnalysisContractVersion || spec.metadata.Mode != spec.mode || generatedAtUnavailable || spec.digest == "" || spec.walk == nil {
		return fmt.Errorf("%w: %w for mode %q", ErrUnsupportedAnalysisOutput, ErrInvalidAnalysisResult, spec.mode)
	}
	switch spec.metadata.Evaluation.State {
	case EvaluationStateEvaluated:
		if spec.metadata.Evaluation.Reason != "" {
			return fmt.Errorf("%w: evaluated result has a reason", ErrInvalidAnalysisResult)
		}
	case EvaluationStateNotEvaluated, EvaluationStateUnknown, EvaluationStateNotApplicable:
		if spec.metadata.Evaluation.Reason == "" {
			return fmt.Errorf("%w: result state %q requires a reason", ErrInvalidAnalysisResult, spec.metadata.Evaluation.State)
		}
	default:
		return fmt.Errorf("%w: result state %q", ErrInvalidAnalysisResult, spec.metadata.Evaluation.State)
	}
	return nil
}

func writeAnalysisOutputCSV(writer io.Writer, spec analysisOutputSpec, schema string, options AnalysisOutputOptions) error {
	descriptor, _ := AnalysisOutputDescriptorForMode(spec.mode)
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write(descriptor.CSVColumns); err != nil {
		return err
	}
	err := spec.walk(func(recordType, id string, data any) error {
		line := analysisOutputRecord{Schema: schema, SchemaVersion: options.SchemaVersion, Mode: spec.mode, GeneratedAt: spec.metadata.GeneratedAt, ResultDigest: spec.digest, Redaction: options.Redaction, RecordType: recordType, RecordID: id, Data: data}
		value, _, transformErr := transformAnalysisOutputValue(line, options.Redaction)
		if transformErr != nil {
			return transformErr
		}
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: internal CSV record type %T", ErrOutputSerialization, value)
		}
		dataObject, ok := object["data"].(map[string]any)
		if !ok {
			return fmt.Errorf("%w: internal CSV data type %T", ErrOutputSerialization, object["data"])
		}
		row := []string{
			csvSafe(stringValue(object["schema"])), csvSafe(stringValue(object["schema_version"])), csvSafe(stringValue(object["mode"])),
			csvSafe(stringValue(object["generated_at"])), csvSafe(stringValue(object["result_digest"])), csvSafe(stringValue(object["redaction"])),
			csvSafe(stringValue(object["record_type"])), csvSafe(stringValue(object["record_id"])),
		}
		for _, column := range spec.csvColumns {
			row = append(row, csvSafe(valueAtPath(dataObject, column.path)))
		}
		encoded, marshalErr := json.Marshal(object["data"])
		if marshalErr != nil {
			return fmt.Errorf("%w: %v", ErrOutputSerialization, marshalErr)
		}
		row = append(row, csvSafe(string(encoded)))
		return csvWriter.Write(row)
	})
	csvWriter.Flush()
	if flushErr := csvWriter.Error(); err != nil || flushErr != nil {
		return errors.Join(err, flushErr)
	}
	return nil
}

func transformAnalysisOutputValue(value any, profile OutputRedaction) (any, bool, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrOutputSerialization, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrOutputSerialization, err)
	}
	if profile == OutputRedactionRestricted {
		return decoded, false, nil
	}
	changed := false
	redacted := redactAnalysisNode(decoded, "", profile, &changed)
	return redacted, changed, nil
}

func redactAnalysisNode(value any, inheritedKind string, profile OutputRedaction, changed *bool) any {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(typed))
		for _, key := range keys {
			if analysisRestrictedRawField(key) {
				*changed = true
				continue
			}
			kind := analysisRedactionKind(key, inheritedKind)
			if key == "name" {
				if _, hasType := typed["type"]; hasType {
					kind = "target_domain"
				}
			}
			if profile == OutputRedactionPublic && kind == "" {
				switch child := typed[key].(type) {
				case string:
					if analysisPublicStringSafe(key, child, typed) {
						kind = analysisPublicSafeValue
					} else {
						kind = "untrusted_output"
					}
				case []any:
					if analysisStringSlice(child) {
						if analysisPublicStringListSafe(key) {
							kind = analysisPublicSafeValue
						} else {
							kind = "untrusted_output"
						}
					}
				}
			}
			if profile == OutputRedactionOperational && analysisOperationalFreeText(key, typed) {
				*changed = true
				continue
			}
			out[key] = redactAnalysisNode(typed[key], kind, profile, changed)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = redactAnalysisNode(typed[i], inheritedKind, profile, changed)
		}
		return out
	case string:
		if profile == OutputRedactionPublic && inheritedKind != "" && inheritedKind != analysisPublicSafeValue && typed != "" {
			*changed = true
			return redactionToken(inheritedKind, typed)
		}
		return typed
	default:
		return value
	}
}

func analysisRestrictedRawField(key string) bool {
	switch key {
	case "raw", "raw_value", "raw_dns_values", "txt_values", "fragments", "joined":
		return true
	default:
		return false
	}
}

func analysisPublicStringSafe(key, value string, object map[string]any) bool {
	if key == "value" {
		_, timestamp := object["available"]
		return timestamp
	}
	if key == "reason" {
		_, exclusion := object["created_at"]
		return !exclusion
	}
	switch key {
	case "schema", "schema_version", "mode", "profile", "redaction", "record_type", "contract_version",
		"generated_at", "observed_at", "dns_observed_at", "provider_reviewed_at", "lookup_at", "created_at", "effective_at", "as_of", "expires_at",
		"version", "evidence_schema_version", "scoring_version", "catalog_version", "overlay_version",
		"state", "code", "severity", "confidence", "confidence_level", "sensitivity", "status", "type", "kind", "grade",
		"classification", "relationship_type", "inventory_state", "candidate_basis", "temporal_relationship", "freshness",
		"tier", "recommended_usage", "provider_status", "include_status", "match_rule", "evidence_confidence",
		"policy_freshness", "ip_type", "unknown_policy", "combined", "dkim", "spf",
		"summary", "recommendation", "standard", "message", "explanation":
		return true
	case "name":
		_, versionedProfile := object["version"]
		return versionedProfile
	case "result":
		switch value {
		case "", "none", "pass", "fail", "neutral", "softfail", "temperror", "permerror", "policy", "nxdomain":
			return true
		default:
			return false
		}
	case "disposition":
		return value == "" || value == "none" || value == "quarantine" || value == "reject"
	case "scope":
		return value == "" || value == "mfrom" || value == "helo" || value == "domain" || value == "entity" || value == "portfolio" || value == "source" || value == "cidr" || value == "sender"
	case "country_code":
		return len(value) == 0 || len(value) == 2
	default:
		return false
	}
}

func analysisPublicStringListSafe(key string) bool {
	switch key {
	case "categories", "reasons", "country_codes", "policy_override_types", "conflict_fields":
		return true
	default:
		return false
	}
}

func analysisStringSlice(values []any) bool {
	for _, value := range values {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	return true
}

func analysisRedactionKind(key, inherited string) string {
	if key == "value" && inherited != "" {
		return inherited
	}
	if key == "record_id" || key == "result_digest" || key == "digest" || key == "id" || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "_ids") || strings.HasSuffix(key, "_digest") || strings.HasSuffix(key, "_digests") {
		return "analysis_reference"
	}
	if key == "source_ip" || key == "source_ips" || strings.HasSuffix(key, "_source_ips") {
		return "source_ip"
	}
	if key == "reporter" || key == "reporters" || key == "reporting_org" {
		return "reporting_org"
	}
	if key == "report_id" {
		return "analysis_reference"
	}
	if key == "dkim_selector" || key == "dkim_selectors" || key == "expected_selectors" || key == "monitored_selectors" {
		return "dkim_selector"
	}
	if key == "domain" || key == "domains" || key == "target_domain" || key == "author_domain" || key == "policy_domain" || key == "portfolio_domain" || strings.HasSuffix(key, "_domain") || strings.HasSuffix(key, "_domains") || strings.HasSuffix(key, "_names") {
		return "target_domain"
	}
	if key == "organization_id" || key == "organization" || key == "organizations" || key == "entity_id" || key == "entity_ids" || key == "owner" || key == "parent" {
		return "organization"
	}
	if key == "provider" || key == "providers" || key == "provider_name" || key == "source" || key == "reference_id" || key == "asn_name" || key == "names" || key == "network_prefix" || key == "network_prefixes" {
		return "enrichment_metadata"
	}
	if key == "matched_include" || key == "catalog_include" || key == "spf_record_name" {
		return "target_domain"
	}
	return ""
}

func analysisOperationalFreeText(key string, object map[string]any) bool {
	if _, provenance := object["lookup_at"]; provenance {
		return key == "provider" || key == "source" || key == "reference_id"
	}
	if _, assertion := object["provenance"]; assertion {
		return key == "asn_name" || key == "organization"
	}
	if _, aggregate := object["assertion_ids"]; aggregate {
		return key == "names" || key == "organizations" || key == "providers"
	}
	return false
}

func setAnalysisDocumentRedaction(value any, profile OutputRedaction, changed bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	object["redaction"] = map[string]any{"profile": string(profile), "operational_fields_changed": changed}
}

func csvSafe(value string) string {
	if value == "" {
		return ""
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case json.Number:
		return typed.String()
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case []any, map[string]any:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	default:
		return fmt.Sprint(typed)
	}
}

func valueAtPath(value any, path []string) string {
	current := value
	for _, part := range path {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case []any:
			var index int
			if _, err := fmt.Sscanf(part, "%d", &index); err != nil || index < 0 || index >= len(typed) {
				return ""
			}
			current = typed[index]
		default:
			return ""
		}
	}
	return stringValue(current)
}

func recordID(value any, fallback string) string {
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer {
		reflected = reflected.Elem()
	}
	if reflected.IsValid() && reflected.Kind() == reflect.Struct {
		for _, name := range []string{"ID", "CandidateID"} {
			field := reflected.FieldByName(name)
			if field.IsValid() && field.Kind() == reflect.String && field.String() != "" {
				return field.String()
			}
		}
		candidate := reflected.FieldByName("Candidate")
		if candidate.IsValid() && candidate.Kind() == reflect.Struct {
			id := candidate.FieldByName("ID")
			if id.IsValid() && id.Kind() == reflect.String && id.String() != "" {
				return id.String()
			}
		}
	}
	return fallback
}

func walkSlice[T any](recordType string, values []T, visit func(string, string, any) error) error {
	for index := range values {
		fallback := string(StableAnalysisID("analysis_output_record", recordType, canonicalSortKey(values[index])))
		if err := visit(recordType, recordID(values[index], fallback), values[index]); err != nil {
			return err
		}
	}
	return nil
}
