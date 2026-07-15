package dmarcgo

import (
	"embed"
	"fmt"
)

// OutputDataSchemaVersion is the current common-envelope mode-data contract.
// It is independent of the Go module and common envelope versions.
const OutputDataSchemaVersion = "1"

// OutputEmptyDataSchemaID identifies the deliberately omitted mode payload
// used by summary-detail and failed envelopes.
const OutputEmptyDataSchemaID = OutputSchemaID + "#/$defs/emptyData"

const (
	campaignConfigurationOutputDataSchemaID  = "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/output-data/campaign_configuration_validation/v1.json"
	campaignClassificationOutputDataSchemaID = "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/output-data/campaign_classification/v1.json"
)

//go:embed schemas/output-data/*/v1.json
var outputDataSchemaFS embed.FS

// OutputDataSchemaID returns the schema identifier placed in data_schema for a
// mode. Baseline and native-analysis modes use strict fragments of their
// existing schemas; campaign modes use dedicated multi-view data schemas.
func OutputDataSchemaID(mode OutputMode, version string) (string, error) {
	if version == "" {
		version = OutputDataSchemaVersion
	}
	if version != OutputDataSchemaVersion {
		return "", fmt.Errorf("%w: data schema version %q", ErrUnsupportedOutputSchema, version)
	}
	switch mode {
	case OutputModeReportValidation:
		return OutputSchemaID + "#/$defs/validationFindingList", nil
	case OutputModeReportSummary:
		return OutputSchemaID + "#/$defs/reportSummary", nil
	case OutputModeAggregateSummary:
		return OutputSchemaID + "#/$defs/aggregateSummary", nil
	case OutputModeReportRows:
		return OutputSchemaID + "#/$defs/featureRowList", nil
	case OutputModeSourceReview:
		return OutputSchemaID + "#/$defs/sourceReview", nil
	case OutputModeCampaignValidation:
		return campaignConfigurationOutputDataSchemaID, nil
	case OutputModeCampaignClassification:
		return campaignClassificationOutputDataSchemaID, nil
	default:
		if _, err := AnalysisOutputDescriptorForMode(mode); err == nil {
			schema, _ := AnalysisOutputSchemaID(mode, AnalysisOutputSchemaVersion)
			return schema + "#/$defs/envelope_data", nil
		}
		return "", fmt.Errorf("%w: unsupported output mode %q", ErrUnsupportedOutputSchema, mode)
	}
}

// OutputDataSchema returns the complete schema document containing the
// fragment identified by OutputDataSchemaID. The returned bytes are a copy.
func OutputDataSchema(mode OutputMode, version string) ([]byte, error) {
	if _, err := OutputDataSchemaID(mode, version); err != nil {
		return nil, err
	}
	switch mode {
	case OutputModeReportValidation, OutputModeReportSummary, OutputModeAggregateSummary, OutputModeReportRows, OutputModeSourceReview:
		return OutputSchema(), nil
	case OutputModeCampaignValidation, OutputModeCampaignClassification:
		data, err := outputDataSchemaFS.ReadFile("schemas/output-data/" + string(mode) + "/v1.json")
		if err != nil {
			return nil, fmt.Errorf("%w: data schema for mode %q: %v", ErrUnsupportedOutputSchema, mode, err)
		}
		return append([]byte(nil), data...), nil
	default:
		return AnalysisOutputSchema(mode, AnalysisOutputSchemaVersion)
	}
}

func outputDataSchemaForMode(mode OutputMode) string {
	schema, err := OutputDataSchemaID(mode, OutputDataSchemaVersion)
	if err != nil {
		return OutputEmptyDataSchemaID
	}
	return schema
}
