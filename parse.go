package dmarcgo

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/georgestarcher/dmarcgo/v2/utilities"
)

// ErrMalformedXML is wrapped when a payload is readable but cannot be parsed as
// DMARC aggregate XML.
var ErrMalformedXML = errors.New("malformed DMARC XML")

// ErrUnsupportedReportFormat is wrapped when bytes cannot be decoded as gzip,
// gzip-compressed tar, zip, tar, zlib, or raw XML.
var ErrUnsupportedReportFormat = errors.New("unsupported DMARC report format")

// ReportLoadError wraps a load failure with optional path and format context.
type ReportLoadError struct {
	Path   string
	Format string
	Err    error
}

// Error returns a human-readable load failure.
func (e *ReportLoadError) Error() string {
	if e == nil {
		return ""
	}
	context := "DMARC report load failed"
	if e.Path != "" {
		context += " for " + e.Path
	}
	if e.Format != "" {
		context += " as " + e.Format
	}
	if e.Err != nil {
		return context + ": " + e.Err.Error()
	}
	return context
}

// Unwrap returns the underlying load error.
func (e *ReportLoadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// LoadOption configures file and archive loading helpers.
type LoadOption func(*loadConfig)

type loadConfig struct {
	maxDecompressedBytes int64
}

// WithMaxDecompressedBytes sets the maximum decompressed payload size. A value
// of zero uses utilities.DefaultMaxDecompressedBytes. A negative value disables
// the limit.
func WithMaxDecompressedBytes(maxBytes int64) LoadOption {
	return func(config *loadConfig) {
		config.maxDecompressedBytes = maxBytes
	}
}

func applyLoadOptions(options []LoadOption) loadConfig {
	var config loadConfig
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}
	return config
}

// LoadFile loads a DMARC aggregate report artifact from path.
func LoadFile(path string, options ...LoadOption) (*AggregateReport, error) {
	fileReport, err := LoadReportFile(path, options...)
	if err != nil {
		return nil, err
	}
	return &fileReport.Content, nil
}

// LoadReportFile loads a DMARC aggregate report archive from path and returns
// file-loading metadata. Prefer LoadFile for new code.
func LoadReportFile(path string, options ...LoadOption) (*FileReport, error) {
	config := applyLoadOptions(options)
	report := &FileReport{MaxDecompressedBytes: config.maxDecompressedBytes}
	if err := report.LoadFile(path); err != nil {
		var loadErr *ReportLoadError
		if errors.As(err, &loadErr) {
			return nil, err
		}
		return nil, &ReportLoadError{Path: path, Err: err}
	}
	return report, nil
}

// ParseBytes parses raw XML DMARC aggregate report bytes.
func ParseBytes(payload []byte) (*AggregateReport, error) {
	var report AggregateReport
	if err := decodeDMARCXML(payload, &report); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedXML, err)
	}
	return &report, nil
}

// ParseReader parses raw XML DMARC aggregate report data from reader.
func ParseReader(reader io.Reader, options ...LoadOption) (*AggregateReport, error) {
	config := applyLoadOptions(options)
	payload, err := readAllLimited(reader, config.maxDecompressedBytes)
	if err != nil {
		return nil, err
	}
	return ParseBytes(payload)
}

// LoadBytes loads a DMARC aggregate report from gzip, zip, tar, zlib, or raw XML
// bytes. Archive formats are attempted before raw XML.
func LoadBytes(payload []byte, options ...LoadOption) (*AggregateReport, error) {
	config := applyLoadOptions(options)
	readers := []func([]byte, int64) ([]byte, error){
		readGzipBytes,
		readZipBytes,
		readTarBytes,
		readZlibBytes,
		readGzipTarBytes,
	}

	var unsupportedErr error
	var decodedParseError error
	for _, reader := range readers {
		decoded, err := reader(payload, config.maxDecompressedBytes)
		if err != nil {
			if unsupportedErr == nil {
				unsupportedErr = err
			}
			continue
		}
		report, err := ParseBytes(decoded)
		if err != nil {
			if decodedParseError == nil {
				decodedParseError = err
			}
			continue
		}
		return report, nil
	}

	if report, err := ParseBytes(payload); err == nil {
		return report, nil
	} else {
		if decodedParseError != nil {
			return nil, decodedParseError
		}
		if unsupportedErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnsupportedReportFormat, unsupportedErr)
		}
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedReportFormat, err)
	}
}

// LoadReportBytes is a deprecated alias for LoadBytes.
func LoadReportBytes(payload []byte, options ...LoadOption) (*AggregateReport, error) {
	return LoadBytes(payload, options...)
}

// LoadReader loads a DMARC aggregate report from gzip, zip, tar, zlib, or raw
// XML data read from reader.
func LoadReader(reader io.Reader, options ...LoadOption) (*AggregateReport, error) {
	return LoadReaderContext(context.Background(), reader, options...)
}

// LoadReportReader is a deprecated alias for LoadReader.
func LoadReportReader(reader io.Reader, options ...LoadOption) (*AggregateReport, error) {
	return LoadReader(reader, options...)
}

// LoadReaderContext loads a DMARC aggregate report from reader and checks
// ctx while reading. It is useful for request-scoped server work.
func LoadReaderContext(ctx context.Context, reader io.Reader, options ...LoadOption) (*AggregateReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config := applyLoadOptions(options)
	payload, err := readAllLimited(contextReader{ctx: ctx, reader: reader}, config.maxDecompressedBytes)
	if err != nil {
		return nil, err
	}
	return LoadBytes(payload, options...)
}

// LoadReportReaderContext is a deprecated alias for LoadReaderContext.
func LoadReportReaderContext(ctx context.Context, reader io.Reader, options ...LoadOption) (*AggregateReport, error) {
	return LoadReaderContext(ctx, reader, options...)
}

// ReportFileResult is the per-file result returned by LoadReportsFromDir.
type ReportFileResult struct {
	Path   string
	Report *AggregateReport
	Err    error
}

// LoadReportsFromDir loads all regular files in dir, returning one result per
// file. Per-file parse errors are captured in ReportFileResult.Err instead of
// aborting the whole batch.
func LoadReportsFromDir(dir string, options ...LoadOption) ([]ReportFileResult, error) {
	files, err := utilities.GetFiles(dir)
	if err != nil {
		return nil, err
	}

	results := make([]ReportFileResult, 0, len(files))
	for _, name := range files {
		path := filepath.Join(dir, name)
		report, err := LoadFile(path, options...)
		results = append(results, ReportFileResult{Path: path, Report: report, Err: err})
	}
	return results, nil
}

// WriteFeaturesJSONL writes flattened feature rows as JSON Lines.
func WriteFeaturesJSONL(writer io.Writer, features []FeatureRow) error {
	for _, feature := range features {
		if err := writeJSONLine(writer, feature); err != nil {
			return err
		}
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}

func readAllLimited(reader io.Reader, maxBytes int64) ([]byte, error) {
	limit := maxBytes
	if limit == 0 {
		limit = utilities.DefaultMaxDecompressedBytes
	}
	if limit < 0 {
		return io.ReadAll(reader)
	}

	limited := io.LimitReader(reader, limit+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("%w: limit is %d bytes", utilities.ErrPayloadTooLarge, limit)
	}
	return payload, nil
}

func readGzipBytes(payload []byte, maxBytes int64) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer closeAfterRead(reader)
	return readAllLimited(reader, maxBytes)
}

func readGzipTarBytes(payload []byte, maxBytes int64) ([]byte, error) {
	decoded, err := readGzipBytes(payload, maxBytes)
	if err != nil {
		return nil, err
	}
	return readTarBytes(decoded, maxBytes)
}

func readZlibBytes(payload []byte, maxBytes int64) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer closeAfterRead(reader)
	return readAllLimited(reader, maxBytes)
}

func readZipBytes(payload []byte, maxBytes int64) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, err
	}

	var firstRegularFile []byte
	var firstErr error
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		decoded, err := readZipEntryBytes(file, maxBytes)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if strings.HasSuffix(strings.ToLower(file.Name), ".xml") {
			return decoded, nil
		}
		if firstRegularFile == nil {
			firstRegularFile = decoded
		}
	}
	if firstRegularFile != nil {
		return firstRegularFile, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("zip archive contains no regular files")
}

func readZipEntryBytes(file *zip.File, maxBytes int64) ([]byte, error) {
	limit := maxBytes
	if limit == 0 {
		limit = utilities.DefaultMaxDecompressedBytes
	}
	if limit >= 0 && file.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%w: zip entry %q is %d bytes, limit is %d", utilities.ErrPayloadTooLarge, file.Name, file.UncompressedSize64, limit)
	}

	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer closeAfterRead(reader)
	return readAllLimited(reader, maxBytes)
}

// closeAfterRead explicitly acknowledges cleanup-only close errors. Complete
// reads surface archive integrity and I/O failures before this resource cleanup.
func closeAfterRead(closer io.Closer) {
	_ = closer.Close()
}

func readTarBytes(payload []byte, maxBytes int64) ([]byte, error) {
	return readTarReader(tar.NewReader(bytes.NewReader(payload)), maxBytes)
}

func readTarReader(reader *tar.Reader, maxBytes int64) ([]byte, error) {
	var firstRegularFile []byte
	var firstErr error
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size < 0 {
			continue
		}
		limit := maxBytes
		if limit == 0 {
			limit = utilities.DefaultMaxDecompressedBytes
		}
		if limit >= 0 && header.Size > limit {
			err := fmt.Errorf("%w: tar entry %q is %d bytes, limit is %d", utilities.ErrPayloadTooLarge, header.Name, header.Size, limit)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		decoded, err := readAllLimited(reader, maxBytes)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if strings.HasSuffix(strings.ToLower(header.Name), ".xml") {
			return decoded, nil
		}
		if firstRegularFile == nil {
			firstRegularFile = decoded
		}
	}
	if firstRegularFile != nil {
		return firstRegularFile, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("tar archive contains no regular files")
}

func writeJSONLine(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	_, err = writer.Write([]byte("\n"))
	return err
}
