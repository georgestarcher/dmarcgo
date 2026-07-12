package dmarcgo

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// AnalysisContractVersion identifies the shared in-memory result conventions.
// It is independent of both the Go module version and serialized output schemas.
const AnalysisContractVersion = "1"

// ErrInvalidAnalysisResult identifies an incomplete or inconsistent completed
// result supplied to a downstream stage.
var ErrInvalidAnalysisResult = errors.New("invalid analysis result")

// AnalysisMode identifies one independently executable analysis or export mode.
type AnalysisMode string

const (
	AnalysisModeReportValidation        AnalysisMode = "report_validation"
	AnalysisModeReportSummary           AnalysisMode = "report_summary"
	AnalysisModeAggregateSummary        AnalysisMode = "aggregate_summary"
	AnalysisModeReportRows              AnalysisMode = "report_rows"
	AnalysisModeSourceReview            AnalysisMode = "source_review"
	AnalysisModeConfigurationValidation AnalysisMode = "configuration_validation"
	AnalysisModeConfigurationHealth     AnalysisMode = "configuration_health"
	AnalysisModeDNSSnapshot             AnalysisMode = "dns_snapshot"
	AnalysisModeDNSAuthentication       AnalysisMode = "dns_authentication_records"
	AnalysisModeDNSHealth               AnalysisMode = "dns_health"
	AnalysisModeReportEvidence          AnalysisMode = "report_evidence"
	AnalysisModeSenderVariance          AnalysisMode = "sender_variance"
	AnalysisModeDNSReportCorrelation    AnalysisMode = "dns_report_correlation"
	AnalysisModeThreatCandidates        AnalysisMode = "threat_candidates"
	AnalysisModeSourceEnrichment        AnalysisMode = "source_enrichment"
	AnalysisModeCampaignValidation      AnalysisMode = "campaign_configuration_validation"
	AnalysisModeCampaignClassification  AnalysisMode = "campaign_classification"
)

// EvaluationState records whether a requested analysis was performed.
type EvaluationState string

const (
	EvaluationStateEvaluated     EvaluationState = "evaluated"
	EvaluationStateNotEvaluated  EvaluationState = "not_evaluated"
	EvaluationStateUnknown       EvaluationState = "unknown"
	EvaluationStateNotApplicable EvaluationState = "not_applicable"
)

// Evaluation records an analysis state and, when needed, why it was not
// evaluated. Reason is library-generated text, not untrusted input.
type Evaluation struct {
	State  EvaluationState `json:"state"`
	Reason string          `json:"reason,omitempty"`
}

// FindingSeverity is the operational importance of a finding.
type FindingSeverity string

const (
	FindingSeverityInfo     FindingSeverity = "info"
	FindingSeverityLow      FindingSeverity = "low"
	FindingSeverityMedium   FindingSeverity = "medium"
	FindingSeverityHigh     FindingSeverity = "high"
	FindingSeverityCritical FindingSeverity = "critical"
)

// FindingConfidence describes how strongly supplied evidence supports a finding.
type FindingConfidence string

const (
	FindingConfidenceLow    FindingConfidence = "low"
	FindingConfidenceMedium FindingConfidence = "medium"
	FindingConfidenceHigh   FindingConfidence = "high"
)

// Sensitivity classifies the minimum disclosure boundary for a value.
type Sensitivity string

const (
	SensitivityPublic      Sensitivity = "public"
	SensitivityOperational Sensitivity = "operational"
	SensitivityRestricted  Sensitivity = "restricted"
)

// FindingCode is a stable machine-readable finding family. Explanatory prose
// may change without changing the code.
type FindingCode string

// FindingID identifies one finding within a completed result.
type FindingID string

// EvidenceID identifies one evidence item within a completed result.
type EvidenceID string

// ActionCode is a stable machine-readable recommended-action family.
type ActionCode string

// ActionID identifies one recommended action within a completed result.
type ActionID string

// ProvenanceID identifies the snapshot or artifact from which evidence came.
type ProvenanceID string

// DiagnosticCode is a stable machine-readable warning or error family.
type DiagnosticCode string

// AnalysisID is a deterministic identifier derived from canonical inputs.
type AnalysisID string

// ResultMetadata is embedded by mode-specific completed result values. Analysis
// and collection stages create it; output encoders copy it without changing it.
type ResultMetadata struct {
	ContractVersion string       `json:"contract_version"`
	Mode            AnalysisMode `json:"mode"`
	GeneratedAt     time.Time    `json:"generated_at"`
	Evaluation      Evaluation   `json:"evaluation"`
}

// Result is implemented by completed mode-specific values. Implementations
// must return metadata without performing analysis, I/O, or network access.
type Result interface {
	ResultMetadata() ResultMetadata
}

// Clock supplies stage timestamps. Networked collection stages should accept a
// caller-provided Clock when reproducible timestamps matter; pure analysis
// stages should preserve timestamps already present on their inputs.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

// Now returns the function's current time.
func (f ClockFunc) Now() time.Time { return f() }

// StableAnalysisID returns a SHA-256 identifier with explicit namespace and
// length framing. Callers must canonicalize domain-specific values before use.
// Length framing prevents different part boundaries from producing the same
// byte sequence.
func StableAnalysisID(namespace string, parts ...string) AnalysisID {
	hash := sha256.New()
	writeIDPart(hash, namespace)
	for _, part := range parts {
		writeIDPart(hash, part)
	}
	return AnalysisID(namespace + ":" + hex.EncodeToString(hash.Sum(nil)))
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeIDPart(writer byteWriter, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}
