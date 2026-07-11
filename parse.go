package dmarcgo

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/georgestarcher/dmarcgo/utilities"
)

// ErrMalformedXML is wrapped when a payload is readable but cannot be parsed as
// DMARC aggregate XML.
var ErrMalformedXML = errors.New("malformed DMARC XML")

// ErrUnsupportedReportFormat is returned when bytes cannot be decoded as gzip,
// zip, zlib, or raw XML.
var ErrUnsupportedReportFormat = errors.New("unsupported DMARC report format")

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

// LoadReportFile loads a DMARC aggregate report archive from path.
func LoadReportFile(path string, options ...LoadOption) (*Report, error) {
	config := applyLoadOptions(options)
	report := &Report{MaxDecompressedBytes: config.maxDecompressedBytes}
	if err := report.LoadReportFileFromPath(path); err != nil {
		return nil, err
	}
	return report, nil
}

// ParseBytes parses raw XML DMARC aggregate report bytes.
func ParseBytes(payload []byte) (*DmarcReport, error) {
	var report DmarcReport
	if err := decodeDMARCXML(payload, &report); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedXML, err)
	}
	return &report, nil
}

// ParseReader parses raw XML DMARC aggregate report data from reader.
func ParseReader(reader io.Reader, options ...LoadOption) (*DmarcReport, error) {
	config := applyLoadOptions(options)
	payload, err := readAllLimited(reader, config.maxDecompressedBytes)
	if err != nil {
		return nil, err
	}
	return ParseBytes(payload)
}

// LoadReportBytes loads a DMARC aggregate report from gzip, zip, zlib, or raw XML
// bytes. Archive formats are attempted before raw XML.
func LoadReportBytes(payload []byte, options ...LoadOption) (*DmarcReport, error) {
	config := applyLoadOptions(options)
	readers := []func([]byte, int64) ([]byte, error){
		readGzipBytes,
		readZipBytes,
		readZlibBytes,
	}

	var parseError error
	for _, reader := range readers {
		decoded, err := reader(payload, config.maxDecompressedBytes)
		if err != nil {
			continue
		}
		report, err := ParseBytes(decoded)
		if err != nil {
			parseError = err
			continue
		}
		return report, nil
	}

	if report, err := ParseBytes(payload); err == nil {
		return report, nil
	} else {
		parseError = err
	}

	if parseError != nil {
		return nil, parseError
	}
	return nil, ErrUnsupportedReportFormat
}

// LoadReportReader loads a DMARC aggregate report from gzip, zip, zlib, or raw
// XML data read from reader.
func LoadReportReader(reader io.Reader, options ...LoadOption) (*DmarcReport, error) {
	config := applyLoadOptions(options)
	payload, err := readAllLimited(reader, config.maxDecompressedBytes)
	if err != nil {
		return nil, err
	}
	return LoadReportBytes(payload, options...)
}

// ReportFileResult is the per-file result returned by LoadReportsFromDir.
type ReportFileResult struct {
	Path   string
	Report *Report
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
		report, err := LoadReportFile(path, options...)
		results = append(results, ReportFileResult{Path: path, Report: report, Err: err})
	}
	return results, nil
}

// WriteFeaturesJSONL writes flattened feature rows as JSON Lines.
func WriteFeaturesJSONL(writer io.Writer, features []DmarcReportFeatures) error {
	for _, feature := range features {
		if err := writeJSONLine(writer, feature); err != nil {
			return err
		}
	}
	return nil
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
	defer reader.Close()
	return readAllLimited(reader, maxBytes)
}

func readZlibBytes(payload []byte, maxBytes int64) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
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
	defer reader.Close()
	return readAllLimited(reader, maxBytes)
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
