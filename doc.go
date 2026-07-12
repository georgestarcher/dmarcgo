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
// DMARC failure reports, also called ruf or forensic reports, are described by
// RFC 9991 and use a different ARF/MARF message format. They are intentionally
// out of scope for this package.
package dmarcgo
