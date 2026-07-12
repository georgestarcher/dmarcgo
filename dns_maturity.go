package dmarcgo

import (
	"sort"
	"strings"
)

// DNSHealthMaturityVersion identifies the current maturity-classification
// contract independently from the numeric health-scoring algorithm.
const DNSHealthMaturityVersion = "1"

// DNSHealthMaturityLevel classifies how completely a domain operates email
// authentication. Health scores and maturity levels answer different questions.
type DNSHealthMaturityLevel int

const (
	DNSHealthMaturityUnmanaged DNSHealthMaturityLevel = iota
	DNSHealthMaturityBasic
	DNSHealthMaturityMonitored
	DNSHealthMaturityEnforced
	DNSHealthMaturityManaged
	DNSHealthMaturityAdaptive
)

// DNSHealthMaturitySignal is one library-defined criterion used to explain a
// maturity classification. Explanations never contain record-controlled text.
type DNSHealthMaturitySignal struct {
	Code        string     `json:"code"`
	Satisfied   bool       `json:"satisfied"`
	Evaluation  Evaluation `json:"evaluation"`
	Explanation string     `json:"explanation"`
}

// DNSHealthCoverage describes how much of the configured record inventory had
// conclusive DNS evidence. Missing records are evaluated evidence, not unknown.
type DNSHealthCoverage struct {
	PlannedRecords   int `json:"planned_records"`
	EvaluatedRecords int `json:"evaluated_records"`
	UnknownRecords   int `json:"unknown_records"`
	Percent          int `json:"percent"`
}

// DNSHealthMaturityDistribution preserves the complete domain distribution in
// entity and portfolio rollups so a low-maturity domain cannot be averaged away.
type DNSHealthMaturityDistribution struct {
	Unmanaged int `json:"unmanaged"`
	Basic     int `json:"basic"`
	Monitored int `json:"monitored"`
	Enforced  int `json:"enforced"`
	Managed   int `json:"managed"`
	Adaptive  int `json:"adaptive"`
	Unknown   int `json:"unknown"`
}

// DNSHealthMaturity is an evidence-backed classification and its guardrails.
// DNS-only evidence can establish at most Enforced. Managed and Adaptive also
// require operational evidence that this evaluator intentionally does not infer.
type DNSHealthMaturity struct {
	Version                string                        `json:"version"`
	Available              bool                          `json:"available"`
	Level                  DNSHealthMaturityLevel        `json:"level,omitempty"`
	Name                   string                        `json:"name"`
	Evaluation             Evaluation                    `json:"evaluation"`
	MaximumObservableLevel DNSHealthMaturityLevel        `json:"maximum_observable_level"`
	Coverage               DNSHealthCoverage             `json:"coverage"`
	Signals                []DNSHealthMaturitySignal     `json:"signals"`
	Distribution           DNSHealthMaturityDistribution `json:"distribution"`
}

// DNSHealthMaturityName returns the stable display name for one maturity level.
func DNSHealthMaturityName(level DNSHealthMaturityLevel) (string, bool) {
	switch level {
	case DNSHealthMaturityUnmanaged:
		return "unmanaged", true
	case DNSHealthMaturityBasic:
		return "basic", true
	case DNSHealthMaturityMonitored:
		return "monitored", true
	case DNSHealthMaturityEnforced:
		return "enforced", true
	case DNSHealthMaturityManaged:
		return "managed", true
	case DNSHealthMaturityAdaptive:
		return "adaptive", true
	default:
		return "", false
	}
}

func (evaluator *dnsHealthEvaluator) evaluateDomainMaturity(entity Entity, domain MonitoredDomain, records []DNSRecordHealth) DNSHealthMaturity {
	coverage := DNSHealthCoverage{PlannedRecords: len(records)}
	applicableDMARC, hasApplicableDMARC := evaluator.domainDMARCRecordName(domain)
	var published, usableSPF, usableDKIM, strongDKIM, dmarcPresent, dmarcEnforced, dmarcScopeEnforced, reportingConfigured bool
	var spfPlanned, spfUnknown, dkimPlanned, dkimUnknown, dmarcPlanned, dmarcUnknown int
	spfEvaluationComplete := true
	allCurrent := len(records) > 0
	for _, health := range records {
		set, ok := evaluator.sets[dnsHealthRecordKey(health.Name, health.Type)]
		conclusive := maturityEvidenceConclusive(set, ok)
		if conclusive {
			coverage.EvaluatedRecords++
		} else {
			coverage.UnknownRecords++
		}
		switch health.Type {
		case DNSRecordSPF:
			spfPlanned++
			if !conclusive {
				spfUnknown++
			}
		case DNSRecordDKIM:
			dkimPlanned++
			if !conclusive {
				dkimUnknown++
			}
		case DNSRecordDMARC:
			if hasApplicableDMARC && health.Name == applicableDMARC {
				dmarcPlanned++
				if !conclusive {
					dmarcUnknown++
				}
			}
		}
		if !ok || len(set.Records) != 1 {
			allCurrent = false
			continue
		}
		if set.Status != AuthenticationRecordValid {
			allCurrent = false
		}
		parsed := set.Records[0]
		switch health.Type {
		case DNSRecordSPF:
			if parsed.SPF != nil && maturityUsableSPF(*parsed.SPF, set.Status) {
				usableSPF = true
				published = true
				if len(parsed.SPF.Relationships) > 0 && !parsed.SPF.Lookup.ExpandedAvailable {
					spfEvaluationComplete = false
				}
			}
		case DNSRecordDKIM:
			if parsed.DKIM != nil && maturityUsableDKIM(*parsed.DKIM, set.Status) {
				usableDKIM = true
				published = true
				if maturityStrongDKIM(*parsed.DKIM) {
					strongDKIM = true
				}
			}
		case DNSRecordDMARC:
			if !hasApplicableDMARC || health.Name != applicableDMARC {
				continue
			}
			if parsed.DMARC != nil {
				effectivePolicy := dmarcPolicyForConfiguredDomain(domain.Name, health.Name, *parsed.DMARC)
				if !maturityUsableDMARC(effectivePolicy, set.Status) {
					continue
				}
				dmarcPresent = true
				published = true
				reportingConfigured = reportingConfigured || len(parsed.DMARC.AggregateReports) > 0
				dmarcEnforced = dmarcEnforced || dmarcPolicyIsEnforced(effectivePolicy)
				dmarcScopeEnforced = dmarcScopeEnforced || maturityDMARCScopeEnforced(domain.Name, health.Name, *parsed.DMARC)
			}
		}
	}
	if coverage.PlannedRecords > 0 {
		coverage.Percent = (coverage.EvaluatedRecords*100 + coverage.PlannedRecords/2) / coverage.PlannedRecords
	}
	ownerAssigned := domain.Owner != "" || entity.Owner != "" || evaluator.organization.Owner != ""
	senderInventory := len(domain.ExpectedSenders) > 0
	completeEvidence := coverage.PlannedRecords > 0 && coverage.UnknownRecords == 0
	recordsPublishedState := maturitySignalState(coverage.PlannedRecords, coverage.UnknownRecords, published)
	spfAvailableState := maturitySignalState(spfPlanned, spfUnknown, usableSPF)
	dkimAvailableState := maturitySignalState(dkimPlanned, dkimUnknown, usableDKIM)
	dkimStrongState := maturitySignalState(dkimPlanned, dkimUnknown, strongDKIM)
	dmarcPresentState := maturitySignalState(dmarcPlanned, dmarcUnknown, dmarcPresent)
	dmarcEnforcedState := maturitySignalState(dmarcPlanned, dmarcUnknown, dmarcEnforced)
	dmarcScopeState := maturitySignalState(dmarcPlanned, dmarcUnknown, dmarcScopeEnforced)
	reportingState := maturitySignalState(dmarcPlanned, dmarcUnknown, reportingConfigured)
	managedDNSReady := usableSPF && spfEvaluationComplete && strongDKIM && dmarcEnforced && dmarcScopeEnforced && reportingConfigured && ownerAssigned && senderInventory && completeEvidence && allCurrent

	level := DNSHealthMaturityUnmanaged
	available := coverage.EvaluatedRecords > 0
	if published {
		level = DNSHealthMaturityBasic
	}
	if usableSPF && usableDKIM && dmarcPresent && reportingConfigured {
		level = DNSHealthMaturityMonitored
	}
	if usableSPF && usableDKIM && dmarcEnforced {
		level = DNSHealthMaturityEnforced
	}
	name, _ := DNSHealthMaturityName(level)
	evaluation := Evaluation{State: EvaluationStateEvaluated}
	if !available {
		name = "unknown"
		evaluation = Evaluation{State: EvaluationStateUnknown, Reason: "No conclusive configured-record evidence is available for maturity classification."}
	}
	maturity := DNSHealthMaturity{
		Version: DNSHealthMaturityVersion, Available: available, Level: level, Name: name, Evaluation: evaluation,
		MaximumObservableLevel: DNSHealthMaturityEnforced, Coverage: coverage,
		Signals: []DNSHealthMaturitySignal{
			maturitySignal("dns.maturity.records_published", published, recordsPublishedState, "At least one usable authentication record is published."),
			maturitySignal("dns.maturity.spf_available", usableSPF, spfAvailableState, "A usable SPF policy is present in the configured evidence."),
			maturitySignal("dns.maturity.spf_evaluation_complete", usableSPF && spfEvaluationComplete, maturitySPFEvaluationState(usableSPF, spfEvaluationComplete, spfAvailableState), "Complete SPF dependency evidence stays within evaluation limits without unresolved relationships."),
			maturitySignal("dns.maturity.dkim_available", usableDKIM, dkimAvailableState, "A usable DKIM selector is present in the configured evidence."),
			maturitySignal("dns.maturity.dkim_strong", strongDKIM, dkimStrongState, "A production DKIM selector uses Ed25519 or an RSA key of at least 2048 bits."),
			maturitySignal("dns.maturity.dmarc_published", dmarcPresent, dmarcPresentState, "An applicable DMARC policy is published."),
			maturitySignal("dns.maturity.dmarc_enforced", dmarcEnforced, dmarcEnforcedState, "The effective DMARC policy is quarantine or reject."),
			maturitySignal("dns.maturity.dmarc_scope_enforced", dmarcScopeEnforced, dmarcScopeState, "The applicable DMARC policy protects the policy domain, subdomains, and nonexistent subdomains through explicit or inherited enforcement."),
			maturitySignal("dns.maturity.aggregate_reporting_configured", reportingConfigured, reportingState, "At least one valid DMARC aggregate-report destination is configured."),
			maturitySignal("dns.maturity.owner_assigned", ownerAssigned, EvaluationStateEvaluated, "The portfolio assigns accountable ownership for this domain."),
			maturitySignal("dns.maturity.sender_inventory_declared", senderInventory, EvaluationStateEvaluated, "The portfolio declares at least one expected sender for this domain."),
			maturitySignal("dns.maturity.evidence_complete", completeEvidence, EvaluationStateEvaluated, "Every configured record has conclusive DNS evidence."),
			maturitySignal("dns.maturity.managed_dns_ready", managedDNSReady, EvaluationStateEvaluated, "DNS posture, ownership, and inventory meet the prerequisites for separately verified managed operations."),
			maturitySignal("dns.maturity.report_handling_verified", false, EvaluationStateUnknown, "DNS configuration cannot prove that aggregate reports are received, retained, and reviewed."),
			maturitySignal("dns.maturity.adaptive_operations_verified", false, EvaluationStateUnknown, "DNS configuration cannot prove automated drift detection, tested rotation, or reviewed correlation."),
		},
	}
	sort.Slice(maturity.Signals, func(i, j int) bool { return maturity.Signals[i].Code < maturity.Signals[j].Code })
	addDNSHealthMaturityCount(&maturity.Distribution, maturity)
	return maturity
}

func maturitySPFEvaluationState(usable, complete bool, availableState EvaluationState) EvaluationState {
	if !usable {
		return availableState
	}
	if usable && !complete {
		return EvaluationStateUnknown
	}
	return EvaluationStateEvaluated
}

func maturitySignalState(planned, unknown int, satisfied bool) EvaluationState {
	if satisfied || planned == 0 || unknown == 0 {
		return EvaluationStateEvaluated
	}
	return EvaluationStateUnknown
}

func maturityEvidenceConclusive(set AuthenticationRecordSet, available bool) bool {
	if !available {
		return false
	}
	switch set.Status {
	case AuthenticationRecordValid, AuthenticationRecordMissing, AuthenticationRecordMalformed,
		AuthenticationRecordInvalid, AuthenticationRecordUnsupported, AuthenticationRecordWeak,
		AuthenticationRecordConflicting:
		return true
	default:
		return false
	}
}

func maturitySignal(code string, satisfied bool, state EvaluationState, explanation string) DNSHealthMaturitySignal {
	return DNSHealthMaturitySignal{Code: code, Satisfied: satisfied, Evaluation: Evaluation{State: state}, Explanation: explanation}
}

func maturityUsableSPF(record SPFRecord, status AuthenticationRecordStatus) bool {
	if status != AuthenticationRecordValid && status != AuthenticationRecordWeak {
		return false
	}
	for _, term := range record.Terms {
		if term.Mechanism == "all" && term.Qualifier == SPFQualifierPass {
			return false
		}
	}
	return true
}

func maturityUsableDKIM(record DKIMKeyRecord, status AuthenticationRecordStatus) bool {
	return (status == AuthenticationRecordValid || status == AuthenticationRecordWeak) && !record.Revoked && record.PublicKey != ""
}

func maturityUsableDMARC(policy DMARCPolicy, status AuthenticationRecordStatus) bool {
	return (status == AuthenticationRecordValid || status == AuthenticationRecordWeak) && policy != ""
}

func maturityStrongDKIM(record DKIMKeyRecord) bool {
	if record.Revoked || containsString(record.Flags, "y") {
		return false
	}
	return record.KeyType == "ed25519" || (record.KeyType == "rsa" && record.KeyBits >= 2048)
}

func maturityDMARCScopeEnforced(domain, recordName string, record DMARCPolicyRecord) bool {
	return dmarcPolicyIsEnforced(dmarcPolicyForConfiguredDomain(domain, recordName, record)) &&
		dmarcPolicyIsEnforced(effectiveDMARCPolicyForScope(record, dmarcPolicyScopeSubdomain)) &&
		dmarcPolicyIsEnforced(effectiveDMARCPolicyForScope(record, dmarcPolicyScopeNonexistent))
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func rollupDNSHealthMaturity(children []DNSHealthMaturity) DNSHealthMaturity {
	result := DNSHealthMaturity{
		Version: DNSHealthMaturityVersion, Name: "unknown", Evaluation: Evaluation{State: EvaluationStateUnknown, Reason: "No conclusive child maturity is available."},
		MaximumObservableLevel: DNSHealthMaturityEnforced, Signals: []DNSHealthMaturitySignal{},
	}
	minimum := DNSHealthMaturityAdaptive
	for _, child := range children {
		result.Coverage.PlannedRecords += child.Coverage.PlannedRecords
		result.Coverage.EvaluatedRecords += child.Coverage.EvaluatedRecords
		result.Coverage.UnknownRecords += child.Coverage.UnknownRecords
		mergeDNSHealthMaturityDistribution(&result.Distribution, child.Distribution)
		if child.Available && child.Level < minimum {
			minimum = child.Level
		}
	}
	if result.Coverage.PlannedRecords > 0 {
		result.Coverage.Percent = (result.Coverage.EvaluatedRecords*100 + result.Coverage.PlannedRecords/2) / result.Coverage.PlannedRecords
	}
	if minimum != DNSHealthMaturityAdaptive || result.Distribution.Adaptive > 0 {
		result.Available = true
		result.Level = minimum
		result.Name, _ = DNSHealthMaturityName(minimum)
		result.Evaluation = Evaluation{State: EvaluationStateEvaluated}
	}
	return result
}

func addDNSHealthMaturityCount(distribution *DNSHealthMaturityDistribution, maturity DNSHealthMaturity) {
	if !maturity.Available {
		distribution.Unknown++
		return
	}
	switch maturity.Level {
	case DNSHealthMaturityUnmanaged:
		distribution.Unmanaged++
	case DNSHealthMaturityBasic:
		distribution.Basic++
	case DNSHealthMaturityMonitored:
		distribution.Monitored++
	case DNSHealthMaturityEnforced:
		distribution.Enforced++
	case DNSHealthMaturityManaged:
		distribution.Managed++
	case DNSHealthMaturityAdaptive:
		distribution.Adaptive++
	}
}

func mergeDNSHealthMaturityDistribution(target *DNSHealthMaturityDistribution, source DNSHealthMaturityDistribution) {
	target.Unmanaged += source.Unmanaged
	target.Basic += source.Basic
	target.Monitored += source.Monitored
	target.Enforced += source.Enforced
	target.Managed += source.Managed
	target.Adaptive += source.Adaptive
	target.Unknown += source.Unknown
}

func cloneDNSHealthMaturity(value DNSHealthMaturity) DNSHealthMaturity {
	value.Signals = append([]DNSHealthMaturitySignal(nil), value.Signals...)
	return value
}
