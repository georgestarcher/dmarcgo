// Package dmarcgo parses DMARC aggregate report artifacts.
//
// The package targets DMARC aggregate reports, historically described by RFC
// 7489 and currently specified by RFC 9990. It accepts legacy reports with no
// namespace, the historical dmarc.org aggregate-report namespace, and the RFC
// 9990 namespace.
//
// Supported inputs are gzip, zip, and zlib encoded payloads containing XML DMARC
// aggregate report data. Use LoadFile(), FileReport.LoadFile(),
// LoadBytes(), or LoadReader() to deserialize report artifacts.
// Use ParseBytes() or ParseReader() when the input is already raw XML. Use LoadReaderContext() when caller cancellation should be honored while reading.
// Use AggregateReport.Rows() for flattened records, AggregateReport.Summary()
// for aggregate counts, AggregateReport.Validate() or AggregateReport.ValidateStrict() for data-quality findings,
// SummarizeReports() for multi-report counts, and AggregateReport.UnauthenticatedSources()
// for unauthenticated source-IP summaries.
//
// DMARC failure reports, also called ruf or forensic reports, are described by
// RFC 9991 and use a different ARF/MARF message format. They are intentionally
// out of scope for this package.
package dmarcgo
