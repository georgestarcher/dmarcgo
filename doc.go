// Package dmarcgo parses DMARC aggregate report artifacts.
//
// The package targets DMARC aggregate reports, historically described by RFC
// 7489 and currently specified by RFC 9990. It accepts legacy reports with no
// namespace, the historical dmarc.org aggregate-report namespace, and the RFC
// 9990 namespace.
//
// Supported inputs are gzip XML, gzip-compressed tar, zip, tar, zlib, and raw
// XML payloads containing DMARC aggregate report data. Use LoadFile(),
// FileReport.LoadFile(), LoadBytes(), or LoadReader() to deserialize report
// artifacts. Use ParseBytes() or ParseReader() when the input is already raw
// XML. Use LoadReaderContext() when caller cancellation should be honored while reading.
// Use AggregateReport.Rows() for flattened records, AggregateReport.Summary()
// for aggregate counts, AggregateReport.Validate() or
// AggregateReport.ValidateStrict() for data-quality findings, SummarizeReports()
// for multi-report counts, and AggregateReport.UnauthenticatedSources() for
// unauthenticated source-IP summaries. Use ParseReportFilename() for common
// bang-separated attachment names and ExcludeUnauthenticatedSources() for
// caller-owned exact-IP or CIDR suppression lists. Use ReportKey(),
// DeduplicateReports(), AnonymizeReport(), and top-N helpers for practical
// report-consumer workflows. BuildReportSummaryOutput(),
// BuildAggregateSummaryOutput(), BuildValidationOutput(),
// BuildReportRowsOutput(), BuildSourceReviewOutput(), and BuildFailureOutput()
// create versioned, deterministic envelopes for automation and AI consumers.
// Output profiles change representation only; they never trigger parsing,
// analysis, or network access. Use OutputSchemaForVersion() and
// SupportedOutputModes() for contract discovery.
//
// AnalysisMode, ResultMetadata, EvaluationState, and Result define the shared
// conventions used by independently callable analysis stages. Networked stages
// accept explicit dependencies and Clock values; pure analysis and output
// stages consume already completed values without hidden I/O.
//
// AnalyzeReportEvidence converts parsed aggregate reports into immutable,
// deterministic report-only evidence with stable provenance, explicit unknown
// values, checked counts, filtering, aggregation, and strict JSON persistence.
// It never loads files, resolves DNS, enriches source addresses, interprets
// expected-sender inventory, or consults the current time.
//
// CorrelateReportEvidence performs the later pure comparison of a normalized
// Portfolio, completed DNSHealthResult, and completed ReportEvidenceResult. It
// resolves declared selectors and unambiguous SPF identities, preserves DNS and
// report times separately, and emits deterministic onboarding, configuration,
// variance, unknown-source, and insufficient-evidence findings. Provider
// context never becomes authorization, and correlation performs no collection,
// parsing, enrichment, storage, or clock access.
//
// ScoreThreatCandidates performs the following pure source-review stage over a
// normalized Portfolio, completed ReportEvidenceResult, and completed
// DNSReportCorrelationResult. Versioned profiles preserve supporting evidence,
// deductions, confidence caps, scoped exclusions, and exact recomputation.
// Results are review-only, never assert malicious ownership or safe-to-block
// status, and perform no collection, parsing, enrichment, storage, or clock access.
//
// EnrichThreatCandidates is the separate optional source-enrichment stage.
// It calls only an explicit caller-supplied IPEnricher for review-eligible,
// non-excluded candidates, with bounded concurrency, cancellation, partial
// failure, deterministic ASN views, and immutable enriched copies. Passing nil
// is a no-op. The library ships no provider or credentials, performs no PTR
// lookup, and never contacts an observed source IP. Enrichment never enables
// promotion or automatic action.
//
// EvaluateJurisdictionContext is the following pure, offline context stage. It
// compares completed coarse country assertions with an explicit immutable
// JurisdictionRiskPolicy, preserves conflicts and provenance, and emits only
// review context. The optional separate priority adjustment is disabled by
// default and never changes threat score, confidence, severity, exclusions,
// eligibility, promotion, or recommended usage. Country context is not actor
// attribution, malicious intent, nationality, or legal advice. Policy text
// remains untrusted structured data and never enters generated instructions.
//
// PortfolioConfig and LoadPortfolioYAML define organization-owned domains,
// explicit monitored record names, expected senders, reusable policies,
// ownership, inheritance, and scoped exclusions. Portfolio loading is strict,
// deterministic, and side-effect free; it never resolves DNS or reads process
// environment variables implicitly.
//
// CollectDNSSnapshot performs the explicit networked stage for configured TXT
// owner names. Callers supply a context-aware TXTResolver and may choose the
// limited NetTXTResolver adapter or DNSMessageResolver for TTL, RCODE, CNAME,
// authority, and negative-cache SOA evidence. A DNSSnapshot is immutable and
// reusable; consuming it never performs another lookup.
//
// ParseAuthenticationRecords performs the following pure stage over a supplied
// DNSSnapshot. ParseSPFRecord, ParseDKIMKeyRecord, and ParseDMARCPolicyRecord
// expose the same side-effect-free parsers for individual values.
// DMARCPolicyDiscoveryNames computes RFC 9989 tree-walk names without resolving
// them. Record-controlled notes, reporting URIs, and extension values remain
// untrusted evidence and never become library-generated instructions.
//
// EvaluateDNSHealth performs the next pure stage over a normalized Portfolio,
// completed DNSAuthenticationResult, and explicit ProviderCatalog. It produces
// deterministic record, domain, entity, and portfolio findings and versioned
// explainable scores. Recognized static SPF dependencies add inventory context
// but never change findings, scores, or sender authorization.
// Independent mechanism grades, evidence coverage, and categorical maturity
// remain separate. DNS-only evidence can establish enforcement but cannot prove
// managed report handling or adaptive operations.
// Unavailable DNS evidence remains unknown by default; evaluation never
// refreshes DNS, reparses TXT values, loads reports, or consults the current time.
//
// DefaultProviderCatalog loads reviewed, versioned provider metadata without
// network access. LoadProviderCatalogYAML accepts strict caller-owned metadata,
// and OverlayProviderCatalog adds or explicitly replaces entries without global
// mutation. MatchSPFRelationship recognizes only static parsed dependencies.
// Provider matches are context only: they never authorize senders, validate
// live DNS, grant health points, or trust provider IP space.
//
// DMARC failure reports, also called ruf or forensic reports, are described by
// RFC 9991 and use a different ARF/MARF message format. They are intentionally
// out of scope for this package.
package dmarcgo
