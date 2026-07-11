// Package dmarcgo parses DMARC aggregate report artifacts.
//
// The package targets DMARC aggregate reports, historically described by RFC
// 7489 and currently specified by RFC 9990. It accepts legacy reports with no
// namespace, the historical dmarc.org aggregate-report namespace, and the RFC
// 9990 namespace.
//
// Supported inputs are gzip, zip, and zlib encoded payloads containing XML DMARC
// aggregate report data. Use Report.LoadReportFile(), LoadReportFile(),
// LoadReportBytes(), or LoadReportReader() to deserialize report artifacts.
// Use ParseBytes() or ParseReader() when the input is already raw XML. Use LoadReportReaderContext() when caller cancellation should be honored while reading.
// Use DmarcReport.Features() for flattened records, DmarcReport.Summary()
// for aggregate counts, DmarcReport.Validate() or DmarcReport.ValidateStrictRFC9990() for data-quality findings,
// SummarizeReports() for multi-report counts, and DmarcReport.SuspiciousSources()
// for unauthenticated source-IP summaries.
//
// DMARC failure reports, also called ruf or forensic reports, are described by
// RFC 9991 and use a different ARF/MARF message format. They are intentionally
// out of scope for this package.
package dmarcgo
