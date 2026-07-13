package dmarcgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// ReportEvidenceSchemaVersion identifies the persistable normalized evidence
// document. It is independent of the Go module and common output schema versions.
const ReportEvidenceSchemaVersion = "2"

const reportEvidenceStandardReference = "https://www.rfc-editor.org/rfc/rfc9990.html"

const (
	reportEvidenceReasonInvalidPeriod   = "The report period is incomplete or invalid."
	reportEvidenceReasonInvalidCount    = "The report row count is not a positive integer."
	reportEvidenceReasonInvalidIP       = "The report source IP is missing or invalid."
	reportEvidenceReasonMissingDomain   = "The report did not supply this domain identity."
	reportEvidenceReasonMissingSelector = "The report did not supply a DKIM selector."
	reportEvidenceReasonMissingValue    = "The report did not supply this value."
	reportEvidenceReasonMissingDKIM     = "The report row supplied no DKIM authentication result."
	reportEvidenceReasonMissingSPF      = "The report row supplied no SPF authentication result."
)

var (
	// ErrInvalidReportEvidence identifies malformed evidence input, filters,
	// grouping dimensions, or persisted documents.
	ErrInvalidReportEvidence = errors.New("invalid report evidence")
	// ErrReportEvidenceOverflow identifies a count that cannot be represented
	// safely by the report-evidence contract.
	ErrReportEvidenceOverflow = errors.New("report evidence count overflow")
	// ErrConflictingReportIdentity identifies reports that claim the same
	// non-zero identity while containing different normalized evidence.
	ErrConflictingReportIdentity = errors.New("conflicting report identity")
)

// ReportEvidenceValue preserves whether a normalized string was present and
// usable. Value is report-controlled data and must not be treated as an instruction.
type ReportEvidenceValue struct {
	Value      string     `json:"value,omitempty"`
	RawValue   string     `json:"raw_value,omitempty"`
	Evaluation Evaluation `json:"evaluation"`
}

// ReportEvidenceTimestamp preserves an available UTC timestamp without using
// the zero time to mean both unavailable and a real value.
type ReportEvidenceTimestamp struct {
	Available bool      `json:"available"`
	Value     time.Time `json:"value,omitempty"`
}

// ReportEvidencePeriod is the reporter-supplied reporting-period bounds.
// Evaluation is unknown when either boundary is malformed or End precedes Begin.
type ReportEvidencePeriod struct {
	Begin      ReportEvidenceTimestamp `json:"begin"`
	End        ReportEvidenceTimestamp `json:"end"`
	Evaluation Evaluation              `json:"evaluation"`
}

// ReportEvidenceCount is a positive normalized row count. Unavailable counts do
// not contribute messages to summaries but the containing observation remains visible.
type ReportEvidenceCount struct {
	Available  bool       `json:"available"`
	Value      int64      `json:"value"`
	RawValue   string     `json:"raw_value,omitempty"`
	Evaluation Evaluation `json:"evaluation"`
}

// ReportAuthenticationOutcome is the normalized policy-evaluated result.
type ReportAuthenticationOutcome string

const (
	ReportAuthenticationPass    ReportAuthenticationOutcome = "pass"
	ReportAuthenticationFail    ReportAuthenticationOutcome = "fail"
	ReportAuthenticationUnknown ReportAuthenticationOutcome = "unknown"
)

// ReportEvidencePolicyOutcome preserves the DMARC-aligned DKIM and SPF results
// and their derived combined outcome. Combined is pass when either mechanism
// passes, fail only when both fail, and unknown otherwise.
type ReportEvidencePolicyOutcome struct {
	DKIM     ReportAuthenticationOutcome `json:"dkim"`
	SPF      ReportAuthenticationOutcome `json:"spf"`
	Combined ReportAuthenticationOutcome `json:"combined"`
}

// ReportEvidenceDKIM is one normalized DKIM auth_results entry. An absent
// selector remains an explicit unknown value rather than becoming a failure.
type ReportEvidenceDKIM struct {
	Domain   ReportEvidenceValue `json:"domain"`
	Selector ReportEvidenceValue `json:"selector"`
	Result   string              `json:"result,omitempty"`
}

// ReportEvidenceSPF is the optional normalized SPF auth_results entry.
type ReportEvidenceSPF struct {
	Evaluation Evaluation          `json:"evaluation"`
	Domain     ReportEvidenceValue `json:"domain"`
	Scope      ReportEvidenceValue `json:"scope"`
	Result     string              `json:"result,omitempty"`
}

// ReportEvidenceReport records normalized report-level provenance without
// retaining the source AggregateReport or its raw extension text.
type ReportEvidenceReport struct {
	ID             EvidenceID           `json:"id"`
	ContentDigest  AnalysisID           `json:"content_digest"`
	Identity       ReportIdentity       `json:"identity"`
	Reporter       ReportEvidenceValue  `json:"reporter"`
	TargetDomain   ReportEvidenceValue  `json:"target_domain"`
	Period         ReportEvidencePeriod `json:"period"`
	ObservationIDs []EvidenceID         `json:"observation_ids"`
	Records        int64                `json:"records"`
	CountedRecords int64                `json:"counted_records"`
	InvalidRecords int64                `json:"invalid_records"`
	Messages       int64                `json:"messages"`
	Sensitivity    Sensitivity          `json:"sensitivity"`
}

// ReportEvidenceObservation is one normalized aggregate-report row. DKIM may
// contain multiple signing results because RFC 9990 permits repeated entries.
type ReportEvidenceObservation struct {
	ID                  EvidenceID                  `json:"id"`
	ReportEvidenceID    EvidenceID                  `json:"report_evidence_id"`
	RecordIndex         int                         `json:"record_index"`
	Reporter            ReportEvidenceValue         `json:"reporter"`
	TargetDomain        ReportEvidenceValue         `json:"target_domain"`
	Period              ReportEvidencePeriod        `json:"period"`
	SourceIP            ReportEvidenceValue         `json:"source_ip"`
	AuthorDomain        ReportEvidenceValue         `json:"author_domain"`
	SPF                 ReportEvidenceSPF           `json:"spf"`
	DKIMEvaluation      Evaluation                  `json:"dkim_evaluation"`
	DKIM                []ReportEvidenceDKIM        `json:"dkim"`
	PolicyOutcome       ReportEvidencePolicyOutcome `json:"policy_outcome"`
	PolicyOverrideTypes []string                    `json:"policy_override_types"`
	Disposition         string                      `json:"disposition,omitempty"`
	Count               ReportEvidenceCount         `json:"count"`
	Sensitivity         Sensitivity                 `json:"sensitivity"`
}

// ReportEvidenceDiagnostic is library-generated validation information. It
// never copies report text into Message.
type ReportEvidenceDiagnostic struct {
	Code                 DiagnosticCode  `json:"code"`
	Severity             FindingSeverity `json:"severity"`
	ReportEvidenceID     EvidenceID      `json:"report_evidence_id,omitempty"`
	ObservationID        EvidenceID      `json:"observation_id,omitempty"`
	DuplicateOccurrences int             `json:"duplicate_occurrences,omitempty"`
	Message              string          `json:"message"`
	Standard             string          `json:"standard"`
}

// ReportEvidenceOutcomeCount counts messages for one DKIM/SPF combination.
type ReportEvidenceOutcomeCount struct {
	DKIM     ReportAuthenticationOutcome `json:"dkim"`
	SPF      ReportAuthenticationOutcome `json:"spf"`
	Messages int64                       `json:"messages"`
}

// ReportEvidenceDispositionCount counts messages for one normalized disposition.
type ReportEvidenceDispositionCount struct {
	Disposition string `json:"disposition"`
	Messages    int64  `json:"messages"`
}

// ReportEvidenceOutcomeTotals preserves pass, fail, and unknown message counts.
type ReportEvidenceOutcomeTotals struct {
	Pass    int64 `json:"pass"`
	Fail    int64 `json:"fail"`
	Unknown int64 `json:"unknown"`
}

// ReportEvidenceGroupKey is populated only for requested grouping dimensions.
type ReportEvidenceGroupKey struct {
	SourceIP     string                      `json:"source_ip,omitempty"`
	TargetDomain string                      `json:"target_domain,omitempty"`
	AuthorDomain string                      `json:"author_domain,omitempty"`
	SPFDomain    string                      `json:"spf_domain,omitempty"`
	DKIMDomain   string                      `json:"dkim_domain,omitempty"`
	DKIMSelector string                      `json:"dkim_selector,omitempty"`
	Reporter     string                      `json:"reporter,omitempty"`
	Disposition  string                      `json:"disposition,omitempty"`
	Combined     ReportAuthenticationOutcome `json:"combined_outcome,omitempty"`
	DKIMOutcome  ReportAuthenticationOutcome `json:"dkim_outcome,omitempty"`
	SPFOutcome   ReportAuthenticationOutcome `json:"spf_outcome,omitempty"`
}

// ReportEvidenceAggregate summarizes a filtered group. FirstSeen and LastSeen
// are report-period bounds, not exact message timestamps.
type ReportEvidenceAggregate struct {
	Key               ReportEvidenceGroupKey           `json:"key"`
	Records           int64                            `json:"records"`
	CountedRecords    int64                            `json:"counted_records"`
	InvalidRecords    int64                            `json:"invalid_records"`
	Messages          int64                            `json:"messages"`
	Reports           int                              `json:"reports"`
	ReporterDiversity int                              `json:"reporter_diversity"`
	FirstSeen         ReportEvidenceTimestamp          `json:"first_seen"`
	LastSeen          ReportEvidenceTimestamp          `json:"last_seen"`
	Combined          ReportEvidenceOutcomeTotals      `json:"combined"`
	DKIM              ReportEvidenceOutcomeTotals      `json:"dkim"`
	SPF               ReportEvidenceOutcomeTotals      `json:"spf"`
	Combinations      []ReportEvidenceOutcomeCount     `json:"combinations"`
	Dispositions      []ReportEvidenceDispositionCount `json:"dispositions"`
}

// ReportEvidenceDimension selects a deterministic aggregation key field.
type ReportEvidenceDimension string

const (
	ReportEvidenceBySourceIP        ReportEvidenceDimension = "source_ip"
	ReportEvidenceByTargetDomain    ReportEvidenceDimension = "target_domain"
	ReportEvidenceByAuthorDomain    ReportEvidenceDimension = "author_domain"
	ReportEvidenceBySPFDomain       ReportEvidenceDimension = "spf_domain"
	ReportEvidenceByDKIMDomain      ReportEvidenceDimension = "dkim_domain"
	ReportEvidenceByDKIMSelector    ReportEvidenceDimension = "dkim_selector"
	ReportEvidenceByReporter        ReportEvidenceDimension = "reporter"
	ReportEvidenceByDisposition     ReportEvidenceDimension = "disposition"
	ReportEvidenceByCombinedOutcome ReportEvidenceDimension = "combined_outcome"
	ReportEvidenceByDKIMOutcome     ReportEvidenceDimension = "dkim_outcome"
	ReportEvidenceBySPFOutcome      ReportEvidenceDimension = "spf_outcome"
)

// ReportEvidenceFilter selects observations. PeriodStart and PeriodEnd define
// a half-open caller window and match reports whose complete reported bounds overlap it.
type ReportEvidenceFilter struct {
	ReportEvidenceIDs []EvidenceID
	SourceIPs         []string
	TargetDomains     []string
	AuthorDomains     []string
	SPFDomains        []string
	DKIMDomains       []string
	DKIMSelectors     []string
	Reporters         []string
	Dispositions      []string
	CombinedOutcomes  []ReportAuthenticationOutcome
	DKIMOutcomes      []ReportAuthenticationOutcome
	SPFOutcomes       []ReportAuthenticationOutcome
	PeriodStart       time.Time
	PeriodEnd         time.Time
}

// ReportEvidenceOptions controls pure normalization. GeneratedAt is explicit;
// when zero it deterministically defaults to the latest valid report-period end.
type ReportEvidenceOptions struct {
	GeneratedAt time.Time
}

// ReportEvidenceResult is an immutable, reusable report-only evidence value.
// Accessors, filtering, aggregation, and JSON persistence perform no parsing,
// filesystem, DNS, enrichment, or other network access.
type ReportEvidenceResult struct {
	metadata     ResultMetadata
	digest       AnalysisID
	reports      []ReportEvidenceReport
	observations []ReportEvidenceObservation
	summary      ReportEvidenceAggregate
	diagnostics  []ReportEvidenceDiagnostic
}

func (result ReportEvidenceResult) ResultMetadata() ResultMetadata { return result.metadata }
func (result ReportEvidenceResult) Digest() AnalysisID             { return result.digest }
func (result ReportEvidenceResult) Reports() []ReportEvidenceReport {
	return cloneReportEvidenceReports(result.reports)
}
func (result ReportEvidenceResult) Observations() []ReportEvidenceObservation {
	return cloneReportEvidenceObservations(result.observations)
}
func (result ReportEvidenceResult) Summary() ReportEvidenceAggregate {
	return cloneReportEvidenceAggregate(result.summary)
}
func (result ReportEvidenceResult) Diagnostics() []ReportEvidenceDiagnostic {
	return append([]ReportEvidenceDiagnostic{}, result.diagnostics...)
}

type preparedReportEvidence struct {
	identity      ReportIdentity
	identityKey   string
	reporter      ReportEvidenceValue
	targetDomain  ReportEvidenceValue
	period        ReportEvidencePeriod
	observations  []ReportEvidenceObservation
	contentDigest AnalysisID
}

// AnalyzeReportEvidence normalizes supplied parsed reports exactly once. Nil
// reports are skipped. Identical reports with the same non-zero ReportIdentity
// are counted once; conflicting content for the same identity is rejected.
func AnalyzeReportEvidence(reports []*AggregateReport, options ReportEvidenceOptions) (ReportEvidenceResult, error) {
	prepared := make([]preparedReportEvidence, 0, len(reports))
	for _, report := range reports {
		if report == nil {
			continue
		}
		value, err := prepareReportEvidence(*report)
		if err != nil {
			return ReportEvidenceResult{}, err
		}
		prepared = append(prepared, value)
	}
	sort.Slice(prepared, func(i, j int) bool {
		if prepared[i].identityKey != prepared[j].identityKey {
			return prepared[i].identityKey < prepared[j].identityKey
		}
		return prepared[i].contentDigest < prepared[j].contentDigest
	})

	selected := make([]preparedReportEvidence, 0, len(prepared))
	duplicateCounts := map[string]int{}
	seen := map[string]AnalysisID{}
	for _, candidate := range prepared {
		if candidate.identity.IsZero() {
			selected = append(selected, candidate)
			continue
		}
		if digest, ok := seen[candidate.identityKey]; ok {
			if digest != candidate.contentDigest {
				return ReportEvidenceResult{}, errors.Join(ErrConflictingReportIdentity, fmt.Errorf("report identity has multiple normalized contents"))
			}
			duplicateCounts[candidate.identityKey]++
			continue
		}
		seen[candidate.identityKey] = candidate.contentDigest
		selected = append(selected, candidate)
	}

	reportValues := make([]ReportEvidenceReport, 0, len(selected))
	observations := make([]ReportEvidenceObservation, 0)
	diagnostics := make([]ReportEvidenceDiagnostic, 0)
	zeroOccurrences := map[AnalysisID]int{}
	generatedAt := options.GeneratedAt.UTC()
	generatedAtFromPeriod := false
	for _, candidate := range selected {
		ordinal := 0
		if candidate.identity.IsZero() {
			ordinal = zeroOccurrences[candidate.contentDigest]
			zeroOccurrences[candidate.contentDigest]++
		}
		reportID := reportEvidenceReportID(candidate, ordinal)
		reportValue := ReportEvidenceReport{
			ID: reportID, ContentDigest: candidate.contentDigest, Identity: candidate.identity,
			Reporter: candidate.reporter, TargetDomain: candidate.targetDomain, Period: candidate.period,
			ObservationIDs: []EvidenceID{}, Records: int64(len(candidate.observations)), Sensitivity: SensitivityRestricted,
		}
		observationOccurrences := map[string]int{}
		if options.GeneratedAt.IsZero() && candidate.period.Evaluation.State == EvaluationStateEvaluated && candidate.period.End.Available &&
			(!generatedAtFromPeriod || candidate.period.End.Value.After(generatedAt)) {
			generatedAt = candidate.period.End.Value
			generatedAtFromPeriod = true
		}
		for index, value := range candidate.observations {
			value.ReportEvidenceID = reportID
			value.RecordIndex = index
			payload, _ := json.Marshal(reportEvidenceObservationCanonical(value))
			canonicalObservation := string(payload)
			occurrence := observationOccurrences[canonicalObservation]
			observationOccurrences[canonicalObservation]++
			value.ID = EvidenceID(StableAnalysisID("report_evidence_observation", string(reportID), canonicalObservation, strconv.Itoa(occurrence)))
			reportValue.ObservationIDs = append(reportValue.ObservationIDs, value.ID)
			if value.Count.Available {
				reportValue.CountedRecords++
				var err error
				reportValue.Messages, err = checkedEvidenceAdd(reportValue.Messages, value.Count.Value)
				if err != nil {
					return ReportEvidenceResult{}, err
				}
			} else {
				reportValue.InvalidRecords++
				diagnostics = append(diagnostics, reportEvidenceObservationDiagnostic(value, "report.evidence.invalid_count"))
			}
			if value.SourceIP.Evaluation.State != EvaluationStateEvaluated {
				diagnostics = append(diagnostics, reportEvidenceObservationDiagnostic(value, "report.evidence.invalid_source_ip"))
			}
			if value.AuthorDomain.Evaluation.State != EvaluationStateEvaluated {
				diagnostics = append(diagnostics, reportEvidenceObservationDiagnostic(value, "report.evidence.missing_author_domain"))
			}
			observations = append(observations, value)
		}
		if candidate.period.Evaluation.State != EvaluationStateEvaluated {
			diagnostics = append(diagnostics, reportEvidenceReportDiagnostic(reportID, "report.evidence.invalid_period", 0))
		}
		if duplicates := duplicateCounts[candidate.identityKey]; duplicates > 0 {
			diagnostics = append(diagnostics, reportEvidenceReportDiagnostic(reportID, "report.evidence.duplicate_report_ignored", duplicates))
		}
		reportValues = append(reportValues, reportValue)
	}

	sortReportEvidenceReports(reportValues)
	sortReportEvidenceObservations(observations)
	sortReportEvidenceDiagnostics(diagnostics)
	summary, err := aggregateReportEvidenceObservations(observations, nil)
	if err != nil {
		return ReportEvidenceResult{}, err
	}
	summary = finalizeReportEvidenceCorpusSummary(summary, reportValues)
	return newReportEvidenceResult(generatedAt, reportValues, observations, summary, diagnostics)
}

func prepareReportEvidence(report AggregateReport) (preparedReportEvidence, error) {
	identity := normalizedReportIdentity(report)
	reporter := normalizedEvidenceText(report.ReportMetadata.OrgName, true)
	targetDomain := normalizedEvidenceDomain(report.PolicyPublished.Domain)
	period := normalizedEvidencePeriod(report.ReportMetadata.DateRange)
	observations := make([]ReportEvidenceObservation, 0, len(report.Record))
	for _, record := range report.Record {
		observations = append(observations, normalizedReportEvidenceObservation(record, reporter, targetDomain, period))
	}
	sortReportEvidenceObservations(observations)
	canonicalObservations := make([]reportEvidenceObservationContent, len(observations))
	for index, observation := range observations {
		canonicalObservations[index] = reportEvidenceObservationCanonical(observation)
	}
	canonical, err := json.Marshal(struct {
		Identity     ReportIdentity                     `json:"identity"`
		Reporter     ReportEvidenceValue                `json:"reporter"`
		TargetDomain ReportEvidenceValue                `json:"target_domain"`
		Period       ReportEvidencePeriod               `json:"period"`
		Observations []reportEvidenceObservationContent `json:"observations"`
	}{identity, reporter, targetDomain, period, canonicalObservations})
	if err != nil {
		return preparedReportEvidence{}, errors.Join(ErrInvalidReportEvidence, err)
	}
	return preparedReportEvidence{
		identity: identity, identityKey: canonicalReportEvidenceIdentity(identity), reporter: reporter, targetDomain: targetDomain,
		period: period, observations: observations, contentDigest: StableAnalysisID("report_evidence_content", string(canonical)),
	}, nil
}

type reportEvidenceObservationContent struct {
	Reporter            ReportEvidenceValue         `json:"reporter"`
	TargetDomain        ReportEvidenceValue         `json:"target_domain"`
	Period              ReportEvidencePeriod        `json:"period"`
	SourceIP            ReportEvidenceValue         `json:"source_ip"`
	AuthorDomain        ReportEvidenceValue         `json:"author_domain"`
	SPF                 ReportEvidenceSPF           `json:"spf"`
	DKIMEvaluation      Evaluation                  `json:"dkim_evaluation"`
	DKIM                []ReportEvidenceDKIM        `json:"dkim"`
	PolicyOutcome       ReportEvidencePolicyOutcome `json:"policy_outcome"`
	PolicyOverrideTypes []string                    `json:"policy_override_types"`
	Disposition         string                      `json:"disposition,omitempty"`
	Count               ReportEvidenceCount         `json:"count"`
	Sensitivity         Sensitivity                 `json:"sensitivity"`
}

func reportEvidenceObservationCanonical(value ReportEvidenceObservation) reportEvidenceObservationContent {
	return reportEvidenceObservationContent{
		Reporter: value.Reporter, TargetDomain: value.TargetDomain, Period: value.Period,
		SourceIP: value.SourceIP, AuthorDomain: value.AuthorDomain, SPF: value.SPF,
		DKIMEvaluation: value.DKIMEvaluation, DKIM: cloneReportEvidenceDKIM(value.DKIM),
		PolicyOutcome: value.PolicyOutcome, PolicyOverrideTypes: append([]string{}, value.PolicyOverrideTypes...),
		Disposition: value.Disposition, Count: value.Count,
		Sensitivity: value.Sensitivity,
	}
}

func normalizedReportEvidenceObservation(record Record, reporter, targetDomain ReportEvidenceValue, period ReportEvidencePeriod) ReportEvidenceObservation {
	dkim := make([]ReportEvidenceDKIM, 0, len(record.AuthResults.DKIM))
	for _, result := range record.AuthResults.DKIM {
		dkim = append(dkim, ReportEvidenceDKIM{
			Domain: normalizedEvidenceDomain(result.Domain), Selector: normalizedEvidenceSelector(result.Selector),
			Result: normalizeEvidenceToken(result.Result),
		})
	}
	sort.Slice(dkim, func(i, j int) bool {
		if order := compareReportEvidenceValue(dkim[i].Domain, dkim[j].Domain); order != 0 {
			return order < 0
		}
		if order := compareReportEvidenceValue(dkim[i].Selector, dkim[j].Selector); order != 0 {
			return order < 0
		}
		return dkim[i].Result < dkim[j].Result
	})
	dkimEvaluation := Evaluation{State: EvaluationStateEvaluated}
	if len(dkim) == 0 {
		dkimEvaluation = Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonMissingDKIM}
	}
	spf := ReportEvidenceSPF{
		Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonMissingSPF},
		Domain:     normalizedEvidenceDomain(""), Scope: normalizedEvidenceText("", true),
	}
	if record.AuthResults.SPF != nil {
		spf = ReportEvidenceSPF{
			Evaluation: Evaluation{State: EvaluationStateEvaluated},
			Domain:     normalizedEvidenceDomain(record.AuthResults.SPF.Domain),
			Scope:      normalizedEvidenceText(record.AuthResults.SPF.Scope, true),
			Result:     normalizeEvidenceToken(record.AuthResults.SPF.Result),
		}
	}
	dkimOutcome := normalizedPolicyOutcome(record.Row.PolicyEvaluated.DKIM)
	spfOutcome := normalizedPolicyOutcome(record.Row.PolicyEvaluated.SPF)
	combined := ReportAuthenticationUnknown
	if dkimOutcome == ReportAuthenticationPass || spfOutcome == ReportAuthenticationPass {
		combined = ReportAuthenticationPass
	} else if dkimOutcome == ReportAuthenticationFail && spfOutcome == ReportAuthenticationFail {
		combined = ReportAuthenticationFail
	}
	return ReportEvidenceObservation{
		Reporter: reporter, TargetDomain: targetDomain, Period: period,
		SourceIP: normalizedEvidenceIP(record.Row.SourceIP), AuthorDomain: normalizedEvidenceDomain(record.Identifiers.HeaderFrom),
		SPF: spf, DKIMEvaluation: dkimEvaluation, DKIM: dkim,
		PolicyOutcome:       ReportEvidencePolicyOutcome{DKIM: dkimOutcome, SPF: spfOutcome, Combined: combined},
		PolicyOverrideTypes: normalizedPolicyOverrideTypes(record.Row.PolicyEvaluated.Reasons),
		Disposition:         normalizeEvidenceToken(record.Row.PolicyEvaluated.Disposition), Count: normalizedEvidenceCount(record.Row.Count),
		Sensitivity: SensitivityRestricted,
	}
}

func normalizedPolicyOverrideTypes(reasons []PolicyOverrideReason) []string {
	values := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if value := normalizeEvidenceToken(reason.Type); validPolicyOverrideType(value) {
			values = append(values, value)
		}
	}
	return compactSortedStrings(values)
}

func compareReportEvidenceValue(left, right ReportEvidenceValue) int {
	if order := strings.Compare(left.Value, right.Value); order != 0 {
		return order
	}
	if order := strings.Compare(left.RawValue, right.RawValue); order != 0 {
		return order
	}
	if order := strings.Compare(string(left.Evaluation.State), string(right.Evaluation.State)); order != 0 {
		return order
	}
	return strings.Compare(left.Evaluation.Reason, right.Evaluation.Reason)
}

func normalizedReportIdentity(report AggregateReport) ReportIdentity {
	return ReportIdentity{
		ReportID:     strings.TrimSpace(normalizeEvidenceUTF8(report.ReportMetadata.ReportID)),
		ReportingOrg: normalizeEvidenceToken(report.ReportMetadata.OrgName),
		PolicyDomain: normalizeEvidenceDomainValue(report.PolicyPublished.Domain),
		Begin:        strings.TrimSpace(normalizeEvidenceUTF8(report.ReportMetadata.DateRange.Begin)),
		End:          strings.TrimSpace(normalizeEvidenceUTF8(report.ReportMetadata.DateRange.End)),
	}
}

func normalizedEvidencePeriod(value DateRange) ReportEvidencePeriod {
	begin, beginErr := epochStringToTime(value.Begin)
	end, endErr := epochStringToTime(value.End)
	period := ReportEvidencePeriod{Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonInvalidPeriod}}
	if beginErr == nil {
		begin = begin.UTC()
		_, beginErr = begin.MarshalJSON()
		if beginErr == nil {
			period.Begin = ReportEvidenceTimestamp{Available: true, Value: begin}
		}
	}
	if endErr == nil {
		end = end.UTC()
		_, endErr = end.MarshalJSON()
		if endErr == nil {
			period.End = ReportEvidenceTimestamp{Available: true, Value: end}
		}
	}
	if beginErr == nil && endErr == nil && !end.Before(begin) {
		period.Evaluation = Evaluation{State: EvaluationStateEvaluated}
	}
	return period
}

func normalizedEvidenceCount(raw string) ReportEvidenceCount {
	raw = strings.TrimSpace(normalizeEvidenceUTF8(raw))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return ReportEvidenceCount{RawValue: raw, Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonInvalidCount}}
	}
	return ReportEvidenceCount{Available: true, Value: value, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
}

func normalizedEvidenceIP(raw string) ReportEvidenceValue {
	raw = strings.TrimSpace(normalizeEvidenceUTF8(raw))
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		return ReportEvidenceValue{RawValue: raw, Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonInvalidIP}}
	}
	return ReportEvidenceValue{Value: addr.Unmap().String(), Evaluation: Evaluation{State: EvaluationStateEvaluated}}
}

func normalizedEvidenceDomain(raw string) ReportEvidenceValue {
	raw = strings.TrimSpace(normalizeEvidenceUTF8(raw))
	value := normalizeEvidenceDomainValue(raw)
	if value == "" {
		return ReportEvidenceValue{RawValue: raw, Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonMissingDomain}}
	}
	return ReportEvidenceValue{Value: value, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
}

func normalizedEvidenceSelector(raw string) ReportEvidenceValue {
	value := normalizeEvidenceToken(raw)
	if value == "" {
		return ReportEvidenceValue{Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonMissingSelector}}
	}
	return ReportEvidenceValue{Value: value, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
}

func normalizedEvidenceText(raw string, fold bool) ReportEvidenceValue {
	value := strings.TrimSpace(normalizeEvidenceUTF8(raw))
	if fold {
		value = strings.ToLower(value)
	}
	if value == "" {
		return ReportEvidenceValue{Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: reportEvidenceReasonMissingValue}}
	}
	return ReportEvidenceValue{Value: value, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
}

func normalizeEvidenceDomainValue(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(normalizeEvidenceUTF8(value)), ".")
	if value == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.IsValid() {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || len(ascii) > 253 {
		return ""
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || !dnsLabelPattern.MatchString(label) {
			return ""
		}
	}
	return ascii
}

func normalizeEvidenceToken(value string) string {
	return strings.ToLower(strings.TrimSpace(normalizeEvidenceUTF8(value)))
}

func normalizeEvidenceUTF8(value string) string {
	return strings.ToValidUTF8(value, "\uFFFD")
}

func normalizedPolicyOutcome(value string) ReportAuthenticationOutcome {
	switch normalizeEvidenceToken(value) {
	case "pass":
		return ReportAuthenticationPass
	case "fail":
		return ReportAuthenticationFail
	default:
		return ReportAuthenticationUnknown
	}
}

func reportEvidenceReportID(value preparedReportEvidence, ordinal int) EvidenceID {
	if !value.identity.IsZero() {
		return EvidenceID(StableAnalysisID("report_evidence_report",
			value.identity.ReportID, value.identity.ReportingOrg, value.identity.PolicyDomain, value.identity.Begin, value.identity.End,
			string(value.contentDigest)))
	}
	return EvidenceID(StableAnalysisID("report_evidence_report", string(value.contentDigest), strconv.Itoa(ordinal)))
}

func canonicalReportEvidenceIdentity(value ReportIdentity) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}

func reportEvidenceObservationDiagnostic(value ReportEvidenceObservation, code DiagnosticCode) ReportEvidenceDiagnostic {
	diagnostic := ReportEvidenceDiagnostic{
		Code: code, Severity: FindingSeverityMedium, ReportEvidenceID: value.ReportEvidenceID,
		ObservationID: value.ID, Standard: reportEvidenceStandardReference,
	}
	switch code {
	case "report.evidence.invalid_count":
		diagnostic.Message = "The report row count is not a positive integer and was excluded from message totals."
	case "report.evidence.invalid_source_ip":
		diagnostic.Message = "The report row source IP is missing or invalid and remains unknown."
	case "report.evidence.missing_author_domain":
		diagnostic.Message = "The report row author domain is missing and remains unknown."
	}
	return diagnostic
}

func reportEvidenceReportDiagnostic(reportID EvidenceID, code DiagnosticCode, occurrences int) ReportEvidenceDiagnostic {
	diagnostic := ReportEvidenceDiagnostic{
		Code: code, Severity: FindingSeverityMedium, ReportEvidenceID: reportID,
		DuplicateOccurrences: occurrences, Standard: reportEvidenceStandardReference,
	}
	switch code {
	case "report.evidence.invalid_period":
		diagnostic.Message = "The report period is incomplete or invalid and cannot support time-window filtering."
	case "report.evidence.duplicate_report_ignored":
		diagnostic.Severity = FindingSeverityInfo
		diagnostic.Message = "An identical report identity and content was counted once."
	}
	return diagnostic
}

func checkedEvidenceAdd(left, right int64) (int64, error) {
	if right < 0 || left > math.MaxInt64-right {
		return 0, ErrReportEvidenceOverflow
	}
	return left + right, nil
}

func sortReportEvidenceReports(values []ReportEvidenceReport) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}

func sortReportEvidenceObservations(values []ReportEvidenceObservation) {
	type keyedObservation struct {
		value ReportEvidenceObservation
		key   string
	}
	keyed := make([]keyedObservation, len(values))
	for index, value := range values {
		payload, _ := json.Marshal(reportEvidenceObservationCanonical(value))
		keyed[index] = keyedObservation{value: value, key: string(payload) + "\x00" + string(value.ReportEvidenceID) + "\x00" + string(value.ID)}
	}
	sort.SliceStable(keyed, func(i, j int) bool { return keyed[i].key < keyed[j].key })
	for index := range keyed {
		values[index] = keyed[index].value
	}
}

func sortReportEvidenceDiagnostics(values []ReportEvidenceDiagnostic) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].ReportEvidenceID != values[j].ReportEvidenceID {
			return values[i].ReportEvidenceID < values[j].ReportEvidenceID
		}
		if values[i].ObservationID != values[j].ObservationID {
			return values[i].ObservationID < values[j].ObservationID
		}
		return values[i].Code < values[j].Code
	})
}

type compiledReportEvidenceFilter struct {
	reportIDs        map[EvidenceID]struct{}
	sourceIPs        map[string]struct{}
	targetDomains    map[string]struct{}
	authorDomains    map[string]struct{}
	spfDomains       map[string]struct{}
	dkimDomains      map[string]struct{}
	dkimSelectors    map[string]struct{}
	reporters        map[string]struct{}
	dispositions     map[string]struct{}
	combinedOutcomes map[ReportAuthenticationOutcome]struct{}
	dkimOutcomes     map[ReportAuthenticationOutcome]struct{}
	spfOutcomes      map[ReportAuthenticationOutcome]struct{}
	periodStart      time.Time
	periodEnd        time.Time
}

// Filter returns observations matching filter in deterministic order.
func (result ReportEvidenceResult) Filter(filter ReportEvidenceFilter) ([]ReportEvidenceObservation, error) {
	compiled, err := compileReportEvidenceFilter(filter)
	if err != nil {
		return nil, err
	}
	values := make([]ReportEvidenceObservation, 0, len(result.observations))
	for _, observation := range result.observations {
		if reportEvidenceFilterMatches(observation, compiled) {
			values = append(values, cloneReportEvidenceObservation(observation))
		}
	}
	return values, nil
}

// Aggregate filters and groups completed observations without rerunning report
// normalization. With no dimensions it returns one corpus-wide aggregate.
func (result ReportEvidenceResult) Aggregate(filter ReportEvidenceFilter, dimensions ...ReportEvidenceDimension) ([]ReportEvidenceAggregate, error) {
	if len(dimensions) == 0 && reportEvidenceFilterIsZero(filter) {
		return []ReportEvidenceAggregate{result.Summary()}, nil
	}
	observations, err := result.Filter(filter)
	if err != nil {
		return nil, err
	}
	return aggregateReportEvidenceGroups(observations, dimensions)
}

func reportEvidenceFilterIsZero(value ReportEvidenceFilter) bool {
	return len(value.ReportEvidenceIDs) == 0 && len(value.SourceIPs) == 0 && len(value.TargetDomains) == 0 &&
		len(value.AuthorDomains) == 0 && len(value.SPFDomains) == 0 && len(value.DKIMDomains) == 0 &&
		len(value.DKIMSelectors) == 0 && len(value.Reporters) == 0 && len(value.Dispositions) == 0 &&
		len(value.CombinedOutcomes) == 0 && len(value.DKIMOutcomes) == 0 && len(value.SPFOutcomes) == 0 &&
		value.PeriodStart.IsZero() && value.PeriodEnd.IsZero()
}

func compileReportEvidenceFilter(filter ReportEvidenceFilter) (compiledReportEvidenceFilter, error) {
	compiled := compiledReportEvidenceFilter{periodStart: filter.PeriodStart.UTC(), periodEnd: filter.PeriodEnd.UTC()}
	if !compiled.periodStart.IsZero() && !compiled.periodEnd.IsZero() && !compiled.periodEnd.After(compiled.periodStart) {
		return compiledReportEvidenceFilter{}, errors.Join(ErrInvalidReportEvidence, errors.New("period end must be after period start"))
	}
	if len(filter.ReportEvidenceIDs) > 0 {
		compiled.reportIDs = map[EvidenceID]struct{}{}
		for _, value := range filter.ReportEvidenceIDs {
			if value == "" {
				return compiledReportEvidenceFilter{}, errors.Join(ErrInvalidReportEvidence, errors.New("empty report evidence ID filter"))
			}
			compiled.reportIDs[value] = struct{}{}
		}
	}
	var err error
	if compiled.sourceIPs, err = normalizeEvidenceFilterValues(filter.SourceIPs, normalizeFilterIP); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.targetDomains, err = normalizeEvidenceFilterValues(filter.TargetDomains, normalizeFilterDomain); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.authorDomains, err = normalizeEvidenceFilterValues(filter.AuthorDomains, normalizeFilterDomain); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.spfDomains, err = normalizeEvidenceFilterValues(filter.SPFDomains, normalizeFilterDomain); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.dkimDomains, err = normalizeEvidenceFilterValues(filter.DKIMDomains, normalizeFilterDomain); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.dkimSelectors, err = normalizeEvidenceFilterValues(filter.DKIMSelectors, normalizeFilterToken); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.reporters, err = normalizeEvidenceFilterValues(filter.Reporters, normalizeFilterToken); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if compiled.dispositions, err = normalizeEvidenceFilterValues(filter.Dispositions, normalizeFilterToken); err != nil {
		return compiledReportEvidenceFilter{}, err
	}
	if len(filter.CombinedOutcomes) > 0 {
		if compiled.combinedOutcomes, err = normalizeEvidenceOutcomeFilter(filter.CombinedOutcomes); err != nil {
			return compiledReportEvidenceFilter{}, err
		}
	}
	if len(filter.DKIMOutcomes) > 0 {
		if compiled.dkimOutcomes, err = normalizeEvidenceOutcomeFilter(filter.DKIMOutcomes); err != nil {
			return compiledReportEvidenceFilter{}, err
		}
	}
	if len(filter.SPFOutcomes) > 0 {
		if compiled.spfOutcomes, err = normalizeEvidenceOutcomeFilter(filter.SPFOutcomes); err != nil {
			return compiledReportEvidenceFilter{}, err
		}
	}
	return compiled, nil
}

func normalizeEvidenceOutcomeFilter(values []ReportAuthenticationOutcome) (map[ReportAuthenticationOutcome]struct{}, error) {
	result := map[ReportAuthenticationOutcome]struct{}{}
	for _, value := range values {
		if !validReportAuthenticationOutcome(value) {
			return nil, errors.Join(ErrInvalidReportEvidence, errors.New("unsupported authentication outcome filter"))
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func normalizeEvidenceFilterValues(values []string, normalize func(string) (string, error)) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, nil
	}
	result := map[string]struct{}{}
	for _, value := range values {
		normalized, err := normalize(value)
		if err != nil || normalized == "" {
			return nil, errors.Join(ErrInvalidReportEvidence, err)
		}
		result[normalized] = struct{}{}
	}
	return result, nil
}

func normalizeFilterIP(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return "", errors.New("invalid source IP filter")
	}
	return addr.Unmap().String(), nil
}

func normalizeFilterDomain(value string) (string, error) {
	value = normalizeEvidenceDomainValue(value)
	if value == "" {
		return "", errors.New("empty domain filter")
	}
	return value, nil
}

func normalizeFilterToken(value string) (string, error) {
	value = normalizeEvidenceToken(value)
	if value == "" {
		return "", errors.New("empty text filter")
	}
	return value, nil
}

func reportEvidenceFilterMatches(value ReportEvidenceObservation, filter compiledReportEvidenceFilter) bool {
	if !evidenceIDIncluded(filter.reportIDs, value.ReportEvidenceID) ||
		!evidenceStringIncluded(filter.sourceIPs, value.SourceIP.Value) ||
		!evidenceStringIncluded(filter.targetDomains, value.TargetDomain.Value) ||
		!evidenceStringIncluded(filter.authorDomains, value.AuthorDomain.Value) ||
		!evidenceStringIncluded(filter.spfDomains, value.SPF.Domain.Value) ||
		!evidenceStringIncluded(filter.reporters, value.Reporter.Value) ||
		!evidenceStringIncluded(filter.dispositions, value.Disposition) ||
		!evidenceOutcomeIncluded(filter.combinedOutcomes, value.PolicyOutcome.Combined) ||
		!evidenceOutcomeIncluded(filter.dkimOutcomes, value.PolicyOutcome.DKIM) ||
		!evidenceOutcomeIncluded(filter.spfOutcomes, value.PolicyOutcome.SPF) {
		return false
	}
	if filter.dkimDomains != nil {
		matched := false
		for _, dkim := range value.DKIM {
			if evidenceStringIncluded(filter.dkimDomains, dkim.Domain.Value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if filter.dkimSelectors != nil {
		matched := false
		for _, dkim := range value.DKIM {
			if evidenceStringIncluded(filter.dkimSelectors, dkim.Selector.Value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if !filter.periodStart.IsZero() || !filter.periodEnd.IsZero() {
		if value.Period.Evaluation.State != EvaluationStateEvaluated {
			return false
		}
		if !filter.periodStart.IsZero() && value.Period.End.Value.Before(filter.periodStart) {
			return false
		}
		if !filter.periodEnd.IsZero() && !value.Period.Begin.Value.Before(filter.periodEnd) {
			return false
		}
	}
	return true
}

func evidenceStringIncluded(values map[string]struct{}, value string) bool {
	if values == nil {
		return true
	}
	_, ok := values[value]
	return ok
}

func evidenceIDIncluded(values map[EvidenceID]struct{}, value EvidenceID) bool {
	if values == nil {
		return true
	}
	_, ok := values[value]
	return ok
}

func evidenceOutcomeIncluded(values map[ReportAuthenticationOutcome]struct{}, value ReportAuthenticationOutcome) bool {
	if values == nil {
		return true
	}
	_, ok := values[value]
	return ok
}

func validReportAuthenticationOutcome(value ReportAuthenticationOutcome) bool {
	return value == ReportAuthenticationPass || value == ReportAuthenticationFail || value == ReportAuthenticationUnknown
}

type reportEvidenceAggregateState struct {
	value        ReportEvidenceAggregate
	reports      map[EvidenceID]struct{}
	reporters    map[string]struct{}
	combinations map[string]int64
	dispositions map[string]int64
}

func aggregateReportEvidenceObservations(observations []ReportEvidenceObservation, dimensions []ReportEvidenceDimension) (ReportEvidenceAggregate, error) {
	groups, err := aggregateReportEvidenceGroups(observations, dimensions)
	if err != nil {
		return ReportEvidenceAggregate{}, err
	}
	if len(groups) == 0 {
		return ReportEvidenceAggregate{Combinations: []ReportEvidenceOutcomeCount{}, Dispositions: []ReportEvidenceDispositionCount{}}, nil
	}
	return groups[0], nil
}

func aggregateReportEvidenceGroups(observations []ReportEvidenceObservation, dimensions []ReportEvidenceDimension) ([]ReportEvidenceAggregate, error) {
	dimensionSet, err := validateReportEvidenceDimensions(dimensions)
	if err != nil {
		return nil, err
	}
	states := map[string]*reportEvidenceAggregateState{}
	if len(observations) == 0 && len(dimensions) == 0 {
		states[""] = newReportEvidenceAggregateState(ReportEvidenceGroupKey{})
	}
	for _, observation := range observations {
		for _, key := range reportEvidenceGroupKeys(observation, dimensionSet) {
			encoded, _ := json.Marshal(key)
			mapKey := string(encoded)
			state := states[mapKey]
			if state == nil {
				state = newReportEvidenceAggregateState(key)
				states[mapKey] = state
			}
			if err := state.add(observation); err != nil {
				return nil, err
			}
		}
	}
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ReportEvidenceAggregate, 0, len(keys))
	for _, key := range keys {
		result = append(result, states[key].finish())
	}
	return result, nil
}

func validateReportEvidenceDimensions(values []ReportEvidenceDimension) (map[ReportEvidenceDimension]struct{}, error) {
	result := map[ReportEvidenceDimension]struct{}{}
	for _, value := range values {
		switch value {
		case ReportEvidenceBySourceIP, ReportEvidenceByTargetDomain, ReportEvidenceByAuthorDomain, ReportEvidenceBySPFDomain,
			ReportEvidenceByDKIMDomain, ReportEvidenceByDKIMSelector, ReportEvidenceByReporter, ReportEvidenceByDisposition,
			ReportEvidenceByCombinedOutcome, ReportEvidenceByDKIMOutcome, ReportEvidenceBySPFOutcome:
		default:
			return nil, errors.Join(ErrInvalidReportEvidence, errors.New("unsupported report evidence dimension"))
		}
		if _, duplicate := result[value]; duplicate {
			return nil, errors.Join(ErrInvalidReportEvidence, errors.New("duplicate report evidence dimension"))
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func reportEvidenceGroupKeys(value ReportEvidenceObservation, dimensions map[ReportEvidenceDimension]struct{}) []ReportEvidenceGroupKey {
	base := ReportEvidenceGroupKey{}
	if _, ok := dimensions[ReportEvidenceBySourceIP]; ok {
		base.SourceIP = value.SourceIP.Value
	}
	if _, ok := dimensions[ReportEvidenceByTargetDomain]; ok {
		base.TargetDomain = value.TargetDomain.Value
	}
	if _, ok := dimensions[ReportEvidenceByAuthorDomain]; ok {
		base.AuthorDomain = value.AuthorDomain.Value
	}
	if _, ok := dimensions[ReportEvidenceBySPFDomain]; ok {
		base.SPFDomain = value.SPF.Domain.Value
	}
	if _, ok := dimensions[ReportEvidenceByReporter]; ok {
		base.Reporter = value.Reporter.Value
	}
	if _, ok := dimensions[ReportEvidenceByDisposition]; ok {
		base.Disposition = aggregateDisposition(value.Disposition)
	}
	if _, ok := dimensions[ReportEvidenceByCombinedOutcome]; ok {
		base.Combined = value.PolicyOutcome.Combined
	}
	if _, ok := dimensions[ReportEvidenceByDKIMOutcome]; ok {
		base.DKIMOutcome = value.PolicyOutcome.DKIM
	}
	if _, ok := dimensions[ReportEvidenceBySPFOutcome]; ok {
		base.SPFOutcome = value.PolicyOutcome.SPF
	}
	_, byDomain := dimensions[ReportEvidenceByDKIMDomain]
	_, bySelector := dimensions[ReportEvidenceByDKIMSelector]
	if !byDomain && !bySelector {
		return []ReportEvidenceGroupKey{base}
	}
	result := make([]ReportEvidenceGroupKey, 0, len(value.DKIM))
	seen := map[string]struct{}{}
	for _, dkim := range value.DKIM {
		key := base
		if byDomain {
			key.DKIMDomain = dkim.Domain.Value
		}
		if bySelector {
			key.DKIMSelector = dkim.Selector.Value
		}
		encoded, _ := json.Marshal(key)
		if _, duplicate := seen[string(encoded)]; duplicate {
			continue
		}
		seen[string(encoded)] = struct{}{}
		result = append(result, key)
	}
	if len(result) == 0 {
		result = append(result, base)
	}
	return result
}

func newReportEvidenceAggregateState(key ReportEvidenceGroupKey) *reportEvidenceAggregateState {
	return &reportEvidenceAggregateState{
		value:   ReportEvidenceAggregate{Key: key, Combinations: []ReportEvidenceOutcomeCount{}, Dispositions: []ReportEvidenceDispositionCount{}},
		reports: map[EvidenceID]struct{}{}, reporters: map[string]struct{}{}, combinations: map[string]int64{}, dispositions: map[string]int64{},
	}
}

func (state *reportEvidenceAggregateState) add(value ReportEvidenceObservation) error {
	var err error
	state.value.Records, err = checkedEvidenceAdd(state.value.Records, 1)
	if err != nil {
		return err
	}
	state.reports[value.ReportEvidenceID] = struct{}{}
	if value.Reporter.Value != "" {
		state.reporters[value.Reporter.Value] = struct{}{}
	}
	if value.Period.Evaluation.State == EvaluationStateEvaluated {
		if !state.value.FirstSeen.Available || value.Period.Begin.Value.Before(state.value.FirstSeen.Value) {
			state.value.FirstSeen = value.Period.Begin
		}
		if !state.value.LastSeen.Available || value.Period.End.Value.After(state.value.LastSeen.Value) {
			state.value.LastSeen = value.Period.End
		}
	}
	if !value.Count.Available {
		state.value.InvalidRecords, err = checkedEvidenceAdd(state.value.InvalidRecords, 1)
		return err
	}
	state.value.CountedRecords, err = checkedEvidenceAdd(state.value.CountedRecords, 1)
	if err != nil {
		return err
	}
	state.value.Messages, err = checkedEvidenceAdd(state.value.Messages, value.Count.Value)
	if err != nil {
		return err
	}
	if err = addReportEvidenceOutcome(&state.value.Combined, value.PolicyOutcome.Combined, value.Count.Value); err != nil {
		return err
	}
	if err = addReportEvidenceOutcome(&state.value.DKIM, value.PolicyOutcome.DKIM, value.Count.Value); err != nil {
		return err
	}
	if err = addReportEvidenceOutcome(&state.value.SPF, value.PolicyOutcome.SPF, value.Count.Value); err != nil {
		return err
	}
	combination := string(value.PolicyOutcome.DKIM) + "\x00" + string(value.PolicyOutcome.SPF)
	state.combinations[combination], err = checkedEvidenceAdd(state.combinations[combination], value.Count.Value)
	if err != nil {
		return err
	}
	disposition := aggregateDisposition(value.Disposition)
	state.dispositions[disposition], err = checkedEvidenceAdd(state.dispositions[disposition], value.Count.Value)
	return err
}

func addReportEvidenceOutcome(target *ReportEvidenceOutcomeTotals, outcome ReportAuthenticationOutcome, count int64) error {
	var err error
	switch outcome {
	case ReportAuthenticationPass:
		target.Pass, err = checkedEvidenceAdd(target.Pass, count)
	case ReportAuthenticationFail:
		target.Fail, err = checkedEvidenceAdd(target.Fail, count)
	default:
		target.Unknown, err = checkedEvidenceAdd(target.Unknown, count)
	}
	return err
}

func aggregateDisposition(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func (state *reportEvidenceAggregateState) finish() ReportEvidenceAggregate {
	state.value.Reports = len(state.reports)
	state.value.ReporterDiversity = len(state.reporters)
	combinationKeys := make([]string, 0, len(state.combinations))
	for key := range state.combinations {
		combinationKeys = append(combinationKeys, key)
	}
	sort.Strings(combinationKeys)
	for _, key := range combinationKeys {
		dkim, spf, _ := strings.Cut(key, "\x00")
		state.value.Combinations = append(state.value.Combinations, ReportEvidenceOutcomeCount{
			DKIM: ReportAuthenticationOutcome(dkim), SPF: ReportAuthenticationOutcome(spf), Messages: state.combinations[key],
		})
	}
	dispositionKeys := make([]string, 0, len(state.dispositions))
	for key := range state.dispositions {
		dispositionKeys = append(dispositionKeys, key)
	}
	sort.Strings(dispositionKeys)
	for _, key := range dispositionKeys {
		state.value.Dispositions = append(state.value.Dispositions, ReportEvidenceDispositionCount{Disposition: key, Messages: state.dispositions[key]})
	}
	return state.value
}

func finalizeReportEvidenceCorpusSummary(value ReportEvidenceAggregate, reports []ReportEvidenceReport) ReportEvidenceAggregate {
	value.Reports = len(reports)
	reporters := map[string]struct{}{}
	for _, report := range reports {
		if report.Reporter.Value != "" {
			reporters[report.Reporter.Value] = struct{}{}
		}
		if report.Period.Evaluation.State != EvaluationStateEvaluated {
			continue
		}
		if !value.FirstSeen.Available || report.Period.Begin.Value.Before(value.FirstSeen.Value) {
			value.FirstSeen = report.Period.Begin
		}
		if !value.LastSeen.Available || report.Period.End.Value.After(value.LastSeen.Value) {
			value.LastSeen = report.Period.End
		}
	}
	value.ReporterDiversity = len(reporters)
	return value
}

type reportEvidenceDocument struct {
	SchemaVersion string                      `json:"schema_version"`
	Metadata      ResultMetadata              `json:"metadata"`
	Digest        AnalysisID                  `json:"digest"`
	Reports       []ReportEvidenceReport      `json:"reports"`
	Observations  []ReportEvidenceObservation `json:"observations"`
	Summary       ReportEvidenceAggregate     `json:"summary"`
	Diagnostics   []ReportEvidenceDiagnostic  `json:"diagnostics"`
}

func newReportEvidenceResult(generatedAt time.Time, reports []ReportEvidenceReport, observations []ReportEvidenceObservation, summary ReportEvidenceAggregate, diagnostics []ReportEvidenceDiagnostic) (ReportEvidenceResult, error) {
	metadata := ResultMetadata{
		ContractVersion: AnalysisContractVersion, Mode: AnalysisModeReportEvidence, GeneratedAt: generatedAt.UTC(),
		Evaluation: Evaluation{State: EvaluationStateEvaluated},
	}
	reports = cloneReportEvidenceReports(reports)
	observations = cloneReportEvidenceObservations(observations)
	summary = cloneReportEvidenceAggregate(summary)
	diagnostics = append([]ReportEvidenceDiagnostic{}, diagnostics...)
	sortReportEvidenceReports(reports)
	sortReportEvidenceObservations(observations)
	sortReportEvidenceDiagnostics(diagnostics)
	canonical, err := json.Marshal(struct {
		SchemaVersion string                      `json:"schema_version"`
		Metadata      ResultMetadata              `json:"metadata"`
		Reports       []ReportEvidenceReport      `json:"reports"`
		Observations  []ReportEvidenceObservation `json:"observations"`
		Summary       ReportEvidenceAggregate     `json:"summary"`
		Diagnostics   []ReportEvidenceDiagnostic  `json:"diagnostics"`
	}{ReportEvidenceSchemaVersion, metadata, reports, observations, summary, diagnostics})
	if err != nil {
		return ReportEvidenceResult{}, errors.Join(ErrInvalidReportEvidence, err)
	}
	return ReportEvidenceResult{
		metadata: metadata, digest: StableAnalysisID("report_evidence", string(canonical)), reports: reports,
		observations: observations, summary: summary, diagnostics: diagnostics,
	}, nil
}

// MarshalJSON serializes the immutable intermediate evidence document. This is
// a persistence format; the mode-specific automation encoders remain separate.
func (result ReportEvidenceResult) MarshalJSON() ([]byte, error) {
	if result.digest == "" || result.metadata.ContractVersion != AnalysisContractVersion || result.metadata.Mode != AnalysisModeReportEvidence ||
		!validEvaluation(result.metadata.Evaluation, EvaluationStateEvaluated, "") {
		return nil, ErrInvalidAnalysisResult
	}
	return json.Marshal(reportEvidenceDocument{
		SchemaVersion: ReportEvidenceSchemaVersion, Metadata: result.metadata, Digest: result.digest,
		Reports: result.Reports(), Observations: result.Observations(), Summary: result.Summary(), Diagnostics: result.Diagnostics(),
	})
}

// LoadReportEvidenceJSON strictly loads a persisted report-evidence document.
// It validates references, counts, summary contents, metadata, and digest and
// performs no report parsing or external I/O.
func LoadReportEvidenceJSON(data []byte) (ReportEvidenceResult, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document reportEvidenceDocument
	if err := decoder.Decode(&document); err != nil {
		return ReportEvidenceResult{}, errors.Join(ErrInvalidReportEvidence, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return ReportEvidenceResult{}, errors.Join(ErrInvalidReportEvidence, err)
	}
	if document.SchemaVersion != ReportEvidenceSchemaVersion || document.Metadata.ContractVersion != AnalysisContractVersion ||
		document.Metadata.Mode != AnalysisModeReportEvidence || !validEvaluation(document.Metadata.Evaluation, EvaluationStateEvaluated, "") || document.Digest == "" {
		return ReportEvidenceResult{}, ErrInvalidReportEvidence
	}
	reports := cloneReportEvidenceReports(document.Reports)
	observations := cloneReportEvidenceObservations(document.Observations)
	diagnostics := append([]ReportEvidenceDiagnostic{}, document.Diagnostics...)
	sortReportEvidenceReports(reports)
	sortReportEvidenceObservations(observations)
	sortReportEvidenceDiagnostics(diagnostics)
	if err := validateReportEvidenceReferences(reports, observations, diagnostics); err != nil {
		return ReportEvidenceResult{}, err
	}
	summary, err := aggregateReportEvidenceObservations(observations, nil)
	if err != nil {
		return ReportEvidenceResult{}, err
	}
	summary = finalizeReportEvidenceCorpusSummary(summary, reports)
	wantSummary, _ := json.Marshal(summary)
	gotSummary, _ := json.Marshal(document.Summary)
	if !bytes.Equal(wantSummary, gotSummary) {
		return ReportEvidenceResult{}, errors.Join(ErrInvalidReportEvidence, errors.New("persisted summary does not match observations"))
	}
	result, err := newReportEvidenceResult(document.Metadata.GeneratedAt, reports, observations, summary, diagnostics)
	if err != nil {
		return ReportEvidenceResult{}, err
	}
	if result.Digest() != document.Digest {
		return ReportEvidenceResult{}, errors.Join(ErrInvalidReportEvidence, errors.New("persisted digest does not match contents"))
	}
	return result, nil
}

func validateReportEvidenceReferences(reports []ReportEvidenceReport, observations []ReportEvidenceObservation, diagnostics []ReportEvidenceDiagnostic) error {
	reportByID := map[EvidenceID]ReportEvidenceReport{}
	observationByID := map[EvidenceID]ReportEvidenceObservation{}
	observationsByReport := map[EvidenceID][]ReportEvidenceObservation{}
	for _, report := range reports {
		if report.ID == "" || report.ContentDigest == "" {
			return ErrInvalidReportEvidence
		}
		if _, duplicate := reportByID[report.ID]; duplicate {
			return errors.Join(ErrInvalidReportEvidence, errors.New("duplicate report evidence ID"))
		}
		reportByID[report.ID] = report
	}
	if err := validateReportEvidenceGeneratedValues(reports, observations); err != nil {
		return err
	}
	for _, observation := range observations {
		if observation.ID == "" || observation.ReportEvidenceID == "" {
			return ErrInvalidReportEvidence
		}
		if _, duplicate := observationByID[observation.ID]; duplicate {
			return errors.Join(ErrInvalidReportEvidence, errors.New("duplicate observation evidence ID"))
		}
		if _, ok := reportByID[observation.ReportEvidenceID]; !ok {
			return errors.Join(ErrInvalidReportEvidence, errors.New("observation references an unknown report"))
		}
		observationByID[observation.ID] = observation
		observationsByReport[observation.ReportEvidenceID] = append(observationsByReport[observation.ReportEvidenceID], observation)
	}
	for _, report := range reports {
		values := observationsByReport[report.ID]
		if int64(len(values)) != report.Records || len(report.ObservationIDs) != len(values) {
			return errors.Join(ErrInvalidReportEvidence, errors.New("report record count does not match observations"))
		}
		ids := append([]EvidenceID(nil), report.ObservationIDs...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		actualIDs := make([]EvidenceID, 0, len(values))
		var counted, invalid, messages int64
		for _, value := range values {
			actualIDs = append(actualIDs, value.ID)
			if value.Count.Available {
				counted++
				var err error
				messages, err = checkedEvidenceAdd(messages, value.Count.Value)
				if err != nil {
					return err
				}
			} else {
				invalid++
			}
		}
		sort.Slice(actualIDs, func(i, j int) bool { return actualIDs[i] < actualIDs[j] })
		if !equalEvidenceIDs(ids, actualIDs) || counted != report.CountedRecords || invalid != report.InvalidRecords || messages != report.Messages {
			return errors.Join(ErrInvalidReportEvidence, errors.New("report counters or references do not match observations"))
		}
	}
	expectedDiagnostics := make([]ReportEvidenceDiagnostic, 0)
	for _, report := range reports {
		if report.Period.Evaluation.State != EvaluationStateEvaluated {
			expectedDiagnostics = append(expectedDiagnostics, reportEvidenceReportDiagnostic(report.ID, "report.evidence.invalid_period", 0))
		}
	}
	for _, observation := range observations {
		if !observation.Count.Available {
			expectedDiagnostics = append(expectedDiagnostics, reportEvidenceObservationDiagnostic(observation, "report.evidence.invalid_count"))
		}
		if observation.SourceIP.Evaluation.State != EvaluationStateEvaluated {
			expectedDiagnostics = append(expectedDiagnostics, reportEvidenceObservationDiagnostic(observation, "report.evidence.invalid_source_ip"))
		}
		if observation.AuthorDomain.Evaluation.State != EvaluationStateEvaluated {
			expectedDiagnostics = append(expectedDiagnostics, reportEvidenceObservationDiagnostic(observation, "report.evidence.missing_author_domain"))
		}
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.ReportEvidenceID != "" {
			if _, ok := reportByID[diagnostic.ReportEvidenceID]; !ok {
				return errors.Join(ErrInvalidReportEvidence, errors.New("diagnostic references an unknown report"))
			}
		}
		if diagnostic.ObservationID != "" {
			if _, ok := observationByID[diagnostic.ObservationID]; !ok {
				return errors.Join(ErrInvalidReportEvidence, errors.New("diagnostic references an unknown observation"))
			}
		}
		if diagnostic.Code == "report.evidence.duplicate_report_ignored" {
			if diagnostic.DuplicateOccurrences <= 0 || diagnostic.ObservationID != "" {
				return errors.Join(ErrInvalidReportEvidence, errors.New("invalid duplicate-report diagnostic"))
			}
			expected := reportEvidenceReportDiagnostic(diagnostic.ReportEvidenceID, diagnostic.Code, diagnostic.DuplicateOccurrences)
			if diagnostic != expected {
				return errors.Join(ErrInvalidReportEvidence, errors.New("persisted diagnostic contains untrusted generated text"))
			}
			expectedDiagnostics = append(expectedDiagnostics, expected)
		}
	}
	sortReportEvidenceDiagnostics(expectedDiagnostics)
	wantDiagnostics, _ := json.Marshal(expectedDiagnostics)
	gotDiagnostics, _ := json.Marshal(diagnostics)
	if !bytes.Equal(wantDiagnostics, gotDiagnostics) {
		return errors.Join(ErrInvalidReportEvidence, errors.New("persisted diagnostics do not match evidence"))
	}
	return nil
}

func validateReportEvidenceGeneratedValues(reports []ReportEvidenceReport, observations []ReportEvidenceObservation) error {
	observationsByReport := map[EvidenceID][]ReportEvidenceObservation{}
	for _, observation := range observations {
		observationsByReport[observation.ReportEvidenceID] = append(observationsByReport[observation.ReportEvidenceID], observation)
		if observation.Sensitivity != SensitivityRestricted || !validNormalizedEvidenceIP(observation.SourceIP) ||
			!validNormalizedEvidenceValue(observation.AuthorDomain, reportEvidenceReasonMissingDomain, normalizeEvidenceDomainValue) ||
			!validNormalizedEvidenceValue(observation.Reporter, reportEvidenceReasonMissingValue, normalizeEvidenceToken) ||
			!validNormalizedEvidenceValue(observation.TargetDomain, reportEvidenceReasonMissingDomain, normalizeEvidenceDomainValue) ||
			!validReportEvidencePeriod(observation.Period) || !validReportEvidenceCount(observation.Count) ||
			normalizeEvidenceToken(observation.Disposition) != observation.Disposition || !validReportEvidencePolicyOutcome(observation.PolicyOutcome) ||
			!validPolicyOverrideTypes(observation.PolicyOverrideTypes) {
			return errors.Join(ErrInvalidReportEvidence, errors.New("persisted observation contains invalid normalized values"))
		}
		if len(observation.DKIM) == 0 {
			if !validEvaluation(observation.DKIMEvaluation, EvaluationStateUnknown, reportEvidenceReasonMissingDKIM) {
				return ErrInvalidReportEvidence
			}
		} else if !validEvaluation(observation.DKIMEvaluation, EvaluationStateEvaluated, "") {
			return ErrInvalidReportEvidence
		}
		for _, dkim := range observation.DKIM {
			if !validNormalizedEvidenceValue(dkim.Domain, reportEvidenceReasonMissingDomain, normalizeEvidenceDomainValue) ||
				!validNormalizedEvidenceValue(dkim.Selector, reportEvidenceReasonMissingSelector, normalizeEvidenceToken) ||
				normalizeEvidenceToken(dkim.Result) != dkim.Result {
				return ErrInvalidReportEvidence
			}
		}
		if observation.SPF.Evaluation.State == EvaluationStateUnknown {
			if !validEvaluation(observation.SPF.Evaluation, EvaluationStateUnknown, reportEvidenceReasonMissingSPF) || observation.SPF.Result != "" ||
				observation.SPF.Domain.Value != "" || observation.SPF.Scope.Value != "" ||
				!validNormalizedEvidenceValue(observation.SPF.Domain, reportEvidenceReasonMissingDomain, normalizeEvidenceDomainValue) ||
				!validNormalizedEvidenceValue(observation.SPF.Scope, reportEvidenceReasonMissingValue, normalizeEvidenceToken) {
				return ErrInvalidReportEvidence
			}
		} else if !validEvaluation(observation.SPF.Evaluation, EvaluationStateEvaluated, "") ||
			!validNormalizedEvidenceValue(observation.SPF.Domain, reportEvidenceReasonMissingDomain, normalizeEvidenceDomainValue) ||
			!validNormalizedEvidenceValue(observation.SPF.Scope, reportEvidenceReasonMissingValue, normalizeEvidenceToken) ||
			normalizeEvidenceToken(observation.SPF.Result) != observation.SPF.Result {
			return ErrInvalidReportEvidence
		}
	}

	zeroIDsByDigest := map[AnalysisID][]EvidenceID{}
	identityDigests := map[string]AnalysisID{}
	for _, report := range reports {
		if report.Sensitivity != SensitivityRestricted || !validNormalizedEvidenceValue(report.Reporter, reportEvidenceReasonMissingValue, normalizeEvidenceToken) ||
			!validNormalizedEvidenceValue(report.TargetDomain, reportEvidenceReasonMissingDomain, normalizeEvidenceDomainValue) || !validReportEvidencePeriod(report.Period) ||
			report.Identity.ReportID != strings.TrimSpace(report.Identity.ReportID) || report.Identity.ReportingOrg != normalizeEvidenceToken(report.Identity.ReportingOrg) ||
			report.Identity.PolicyDomain != normalizeEvidenceDomainValue(report.Identity.PolicyDomain) || report.Identity.Begin != strings.TrimSpace(report.Identity.Begin) ||
			report.Identity.End != strings.TrimSpace(report.Identity.End) || report.Reporter.Value != report.Identity.ReportingOrg || report.TargetDomain.Value != report.Identity.PolicyDomain ||
			report.Period != normalizedEvidencePeriod(DateRange{Begin: report.Identity.Begin, End: report.Identity.End}) {
			return errors.Join(ErrInvalidReportEvidence, errors.New("persisted report contains invalid normalized values"))
		}
		values := observationsByReport[report.ID]
		indices := make([]int, 0, len(values))
		canonicalObservations := make([]reportEvidenceObservationContent, 0, len(values))
		for _, observation := range values {
			if observation.Reporter != report.Reporter || observation.TargetDomain != report.TargetDomain || observation.Period != report.Period {
				return errors.Join(ErrInvalidReportEvidence, errors.New("observation provenance differs from its report"))
			}
			indices = append(indices, observation.RecordIndex)
			canonicalObservations = append(canonicalObservations, reportEvidenceObservationCanonical(observation))
		}
		sort.Ints(indices)
		for index, value := range indices {
			if value != index {
				return errors.Join(ErrInvalidReportEvidence, errors.New("observation record indices are not canonical"))
			}
		}
		sort.Slice(values, func(i, j int) bool { return values[i].RecordIndex < values[j].RecordIndex })
		occurrences := map[string]int{}
		for _, observation := range values {
			payload, _ := json.Marshal(reportEvidenceObservationCanonical(observation))
			canonicalObservation := string(payload)
			occurrence := occurrences[canonicalObservation]
			occurrences[canonicalObservation]++
			expectedID := EvidenceID(StableAnalysisID("report_evidence_observation", string(report.ID), canonicalObservation, strconv.Itoa(occurrence)))
			if observation.ID != expectedID {
				return errors.Join(ErrInvalidReportEvidence, errors.New("observation evidence ID does not match normalized contents"))
			}
		}
		sort.Slice(canonicalObservations, func(i, j int) bool {
			left, _ := json.Marshal(canonicalObservations[i])
			right, _ := json.Marshal(canonicalObservations[j])
			return bytes.Compare(left, right) < 0
		})
		canonical, _ := json.Marshal(struct {
			Identity     ReportIdentity                     `json:"identity"`
			Reporter     ReportEvidenceValue                `json:"reporter"`
			TargetDomain ReportEvidenceValue                `json:"target_domain"`
			Period       ReportEvidencePeriod               `json:"period"`
			Observations []reportEvidenceObservationContent `json:"observations"`
		}{report.Identity, report.Reporter, report.TargetDomain, report.Period, canonicalObservations})
		contentDigest := StableAnalysisID("report_evidence_content", string(canonical))
		if report.ContentDigest != contentDigest {
			return errors.Join(ErrInvalidReportEvidence, errors.New("report content digest does not match observations"))
		}
		prepared := preparedReportEvidence{identity: report.Identity, contentDigest: contentDigest}
		if report.Identity.IsZero() {
			zeroIDsByDigest[contentDigest] = append(zeroIDsByDigest[contentDigest], report.ID)
		} else {
			identityKey := canonicalReportEvidenceIdentity(report.Identity)
			if previous, exists := identityDigests[identityKey]; exists && previous != contentDigest {
				return errors.Join(ErrInvalidReportEvidence, ErrConflictingReportIdentity)
			}
			identityDigests[identityKey] = contentDigest
			if report.ID != reportEvidenceReportID(prepared, 0) {
				return errors.Join(ErrInvalidReportEvidence, errors.New("report evidence ID does not match identity"))
			}
		}
	}
	for digest, actual := range zeroIDsByDigest {
		sort.Slice(actual, func(i, j int) bool { return actual[i] < actual[j] })
		expected := make([]EvidenceID, len(actual))
		for index := range expected {
			expected[index] = reportEvidenceReportID(preparedReportEvidence{contentDigest: digest}, index)
		}
		sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })
		if !equalEvidenceIDs(actual, expected) {
			return errors.Join(ErrInvalidReportEvidence, errors.New("zero-identity report evidence IDs are not canonical"))
		}
	}
	return nil
}

func validPolicyOverrideTypes(values []string) bool {
	if values == nil {
		return false
	}
	for index, value := range values {
		if !validPolicyOverrideType(value) || normalizeEvidenceToken(value) != value || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validPolicyOverrideType(value string) bool {
	switch value {
	case "local_policy", "mailing_list", "other", "policy_test_mode", "trusted_forwarder":
		return true
	default:
		return false
	}
}

func validEvaluation(value Evaluation, state EvaluationState, reason string) bool {
	return value.State == state && value.Reason == reason
}

func validNormalizedEvidenceValue(value ReportEvidenceValue, missingReason string, normalize func(string) string) bool {
	if value.Value == "" {
		return value.RawValue == strings.TrimSpace(value.RawValue) && (value.RawValue == "" || normalize(value.RawValue) == "") &&
			validEvaluation(value.Evaluation, EvaluationStateUnknown, missingReason)
	}
	return value.RawValue == "" && normalize(value.Value) == value.Value && validEvaluation(value.Evaluation, EvaluationStateEvaluated, "")
}

func validNormalizedEvidenceIP(value ReportEvidenceValue) bool {
	if value.Value == "" {
		raw := strings.TrimSpace(value.RawValue)
		addr, err := netip.ParseAddr(raw)
		return raw == value.RawValue && (raw == "" || err != nil || addr.Zone() != "") &&
			validEvaluation(value.Evaluation, EvaluationStateUnknown, reportEvidenceReasonInvalidIP)
	}
	addr, err := netip.ParseAddr(value.Value)
	return value.RawValue == "" && err == nil && addr.Zone() == "" && addr.Unmap().String() == value.Value &&
		validEvaluation(value.Evaluation, EvaluationStateEvaluated, "")
}

func validReportEvidencePeriod(value ReportEvidencePeriod) bool {
	valid := value.Begin.Available && value.End.Available && value.Begin.Value.Location() == time.UTC && value.End.Value.Location() == time.UTC &&
		!value.End.Value.Before(value.Begin.Value)
	if valid {
		return validEvaluation(value.Evaluation, EvaluationStateEvaluated, "")
	}
	if value.Begin.Available && value.Begin.Value.Location() != time.UTC || value.End.Available && value.End.Value.Location() != time.UTC {
		return false
	}
	if !value.Begin.Available && !value.Begin.Value.IsZero() || !value.End.Available && !value.End.Value.IsZero() {
		return false
	}
	return validEvaluation(value.Evaluation, EvaluationStateUnknown, reportEvidenceReasonInvalidPeriod)
}

func validReportEvidenceCount(value ReportEvidenceCount) bool {
	if value.Available {
		return value.Value > 0 && value.RawValue == "" && validEvaluation(value.Evaluation, EvaluationStateEvaluated, "")
	}
	return value.Value == 0 && value.RawValue == strings.TrimSpace(value.RawValue) &&
		validEvaluation(value.Evaluation, EvaluationStateUnknown, reportEvidenceReasonInvalidCount)
}

func validReportEvidencePolicyOutcome(value ReportEvidencePolicyOutcome) bool {
	if !validReportAuthenticationOutcome(value.DKIM) || !validReportAuthenticationOutcome(value.SPF) || !validReportAuthenticationOutcome(value.Combined) {
		return false
	}
	want := ReportAuthenticationUnknown
	if value.DKIM == ReportAuthenticationPass || value.SPF == ReportAuthenticationPass {
		want = ReportAuthenticationPass
	} else if value.DKIM == ReportAuthenticationFail && value.SPF == ReportAuthenticationFail {
		want = ReportAuthenticationFail
	}
	return value.Combined == want
}

func equalEvidenceIDs(left, right []EvidenceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneReportEvidenceReports(values []ReportEvidenceReport) []ReportEvidenceReport {
	result := make([]ReportEvidenceReport, len(values))
	for index, value := range values {
		result[index] = value
		result[index].ObservationIDs = append([]EvidenceID{}, value.ObservationIDs...)
	}
	return result
}

func cloneReportEvidenceObservations(values []ReportEvidenceObservation) []ReportEvidenceObservation {
	result := make([]ReportEvidenceObservation, len(values))
	for index, value := range values {
		result[index] = cloneReportEvidenceObservation(value)
	}
	return result
}

func cloneReportEvidenceObservation(value ReportEvidenceObservation) ReportEvidenceObservation {
	value.DKIM = cloneReportEvidenceDKIM(value.DKIM)
	value.PolicyOverrideTypes = append([]string{}, value.PolicyOverrideTypes...)
	return value
}

func cloneReportEvidenceDKIM(values []ReportEvidenceDKIM) []ReportEvidenceDKIM {
	return append([]ReportEvidenceDKIM{}, values...)
}

func cloneReportEvidenceAggregate(value ReportEvidenceAggregate) ReportEvidenceAggregate {
	value.Combinations = append([]ReportEvidenceOutcomeCount{}, value.Combinations...)
	value.Dispositions = append([]ReportEvidenceDispositionCount{}, value.Dispositions...)
	return value
}
