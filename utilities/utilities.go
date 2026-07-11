package utilities

import (
	"archive/zip"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// DefaultMaxDecompressedBytes limits decompressed report payloads to reduce the
// risk of archive bombs. Set Report.MaxDecompressedBytes or call the WithLimit
// helpers to choose a different value.
const DefaultMaxDecompressedBytes int64 = 50 << 20

// ErrPayloadTooLarge is returned when decompressed report data exceeds a limit.
var ErrPayloadTooLarge = errors.New("decompressed report payload exceeds limit")

// GetFiles returns sorted regular file names from directory.
func GetFiles(directory string) ([]string, error) {
	var files []string

	e, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, entity := range e {
		if entity.IsDir() {
			continue
		}
		files = append(files, entity.Name())
	}
	sort.Strings(files)
	return files, nil
}

// ReadGZ returns gzip encoded file contents using DefaultMaxDecompressedBytes.
func ReadGZ(filepath string) ([]byte, error) {
	return ReadGZWithLimit(filepath, DefaultMaxDecompressedBytes)
}

// ReadGZWithLimit returns gzip encoded file contents up to maxBytes.
func ReadGZWithLimit(filepath string, maxBytes int64) ([]byte, error) {
	fi, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer fi.Close()

	fgz, err := gzip.NewReader(fi)
	if err != nil {
		return nil, err
	}
	defer fgz.Close()
	return readAllLimited(fgz, maxBytes)
}

// ReadZZ returns zlib encoded file contents using DefaultMaxDecompressedBytes.
func ReadZZ(filepath string) ([]byte, error) {
	return ReadZZWithLimit(filepath, DefaultMaxDecompressedBytes)
}

// ReadZZWithLimit returns zlib encoded file contents up to maxBytes.
func ReadZZWithLimit(filepath string, maxBytes int64) ([]byte, error) {
	fi, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer fi.Close()

	fgz, err := zlib.NewReader(fi)
	if err != nil {
		return nil, err
	}
	defer fgz.Close()
	return readAllLimited(fgz, maxBytes)
}

// ReadZip returns the first readable file from the archive using
// DefaultMaxDecompressedBytes, preferring entries whose names end with .xml.
func ReadZip(filepath string) ([]byte, error) {
	return ReadZipWithLimit(filepath, DefaultMaxDecompressedBytes)
}

// ReadZipWithLimit returns the first readable file from the archive, preferring
// entries whose names end with .xml. Directory entries are skipped. If the
// archive has no regular files, an error is returned.
func ReadZipWithLimit(filepath string, maxBytes int64) ([]byte, error) {
	var firstRegularFile []byte
	var firstErr error

	zipReader, err := zip.OpenReader(filepath)
	if err != nil {
		return nil, err
	}
	defer zipReader.Close()

	for _, zipFile := range zipReader.File {
		zipFileInfo := zipFile.FileInfo()
		if zipFileInfo.IsDir() {
			continue
		}

		unzippedFileBytes, err := readZipFile(zipFile, maxBytes)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		if strings.HasSuffix(strings.ToLower(zipFile.Name), ".xml") {
			return unzippedFileBytes, nil
		}

		if firstRegularFile == nil {
			firstRegularFile = unzippedFileBytes
		}
	}

	if firstRegularFile != nil {
		return firstRegularFile, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("zip file %q contains no regular files", filepath)
}

func readZipFile(zf *zip.File, maxBytes int64) ([]byte, error) {
	limit := normalizedLimit(maxBytes)
	if limit > 0 && zf.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%w: zip entry %q is %d bytes, limit is %d", ErrPayloadTooLarge, zf.Name, zf.UncompressedSize64, limit)
	}

	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readAllLimited(f, maxBytes)
}

func readAllLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	limit := normalizedLimit(maxBytes)
	if limit <= 0 {
		return io.ReadAll(r)
	}

	limited := io.LimitReader(r, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: limit is %d bytes", ErrPayloadTooLarge, limit)
	}
	return data, nil
}

func normalizedLimit(maxBytes int64) int64 {
	if maxBytes == 0 {
		return DefaultMaxDecompressedBytes
	}
	return maxBytes
}
