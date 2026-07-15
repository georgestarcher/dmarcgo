package dmarcgo

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type outputDataSchemaCase struct {
	mode     OutputMode
	variants []outputDataSchemaVariant
}

type outputDataSchemaVariant struct {
	value        any
	view         CampaignOutputView
	evidenceKind string
}

func TestOutputDataSchemasMatchGoContracts(t *testing.T) {
	for _, test := range outputDataSchemaCases() {
		generated, err := buildOutputDataSchema(test)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("DMARCGO_UPDATE_OUTPUT_DATA_SCHEMAS") == "1" {
			path := "schemas/output-data/" + string(test.mode) + "/v" + OutputDataSchemaVersion + ".json"
			if err := os.WriteFile(path, generated, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		embedded, err := OutputDataSchema(test.mode, OutputDataSchemaVersion)
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
			t.Fatalf("data schema for %s does not match its Go contracts; regenerate with DMARCGO_UPDATE_OUTPUT_DATA_SCHEMAS=1 go test -run TestOutputDataSchemasMatchGoContracts .", test.mode)
		}
	}
}

func outputDataSchemaCases() []outputDataSchemaCase {
	return []outputDataSchemaCase{
		{mode: OutputModeCampaignValidation, variants: []outputDataSchemaVariant{
			{value: campaignConfigurationPrivilegedData{}, view: CampaignOutputPrivileged},
			{value: campaignConfigurationDisclosureData{}, view: CampaignOutputDisclosureSafe},
		}},
		{mode: OutputModeCampaignClassification, variants: []outputDataSchemaVariant{
			{value: campaignClassificationPrivilegedData{}, view: CampaignOutputPrivileged},
			{value: campaignClassificationDisclosureData{}, view: CampaignOutputDisclosureSafe},
			{value: campaignReportPrivilegedData{}, view: CampaignOutputPrivileged, evidenceKind: "aggregate_report"},
			{value: campaignReportDisclosureData{}, view: CampaignOutputDisclosureSafe, evidenceKind: "aggregate_report"},
		}},
	}
}

func buildOutputDataSchema(test outputDataSchemaCase) ([]byte, error) {
	generator := &analysisSchemaGenerator{definitions: map[string]any{}, building: map[reflect.Type]bool{}}
	variants := make([]any, 0, len(test.variants))
	for _, variant := range test.variants {
		ref := generator.schemaForType(reflect.TypeOf(variant.value))
		properties := map[string]any{"view": map[string]any{"const": string(variant.view)}}
		if variant.evidenceKind != "" {
			properties["evidence_kind"] = map[string]any{"const": variant.evidenceKind}
		}
		variants = append(variants, map[string]any{"allOf": []any{ref, map[string]any{"properties": properties}}})
	}
	id, _ := OutputDataSchemaID(test.mode, OutputDataSchemaVersion)
	root := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     id,
		"title":   "dmarcgo " + string(test.mode) + " common-envelope data v" + OutputDataSchemaVersion,
		"oneOf":   variants,
		"$defs":   generator.definitions,
	}
	encoded, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
