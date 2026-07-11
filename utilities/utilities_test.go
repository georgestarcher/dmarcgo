package utilities

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Test get count of files in directory
func TestGetFiles(t *testing.T) {

	target_directory := "../testdata/fixtures/"
	report_files, err := GetFiles(target_directory)

	if err != nil {
		t.Error(err)
	}
	want := 4
	got := report_files

	if len(got) != want {
		t.Errorf("got %v, wanted %v", len(got), want)
	}
}

// Test get files sorted output
func TestGetFilesSorted(t *testing.T) {
	targetDirectory := t.TempDir()
	if _, err := os.Create(filepath.Join(targetDirectory, "b.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Create(filepath.Join(targetDirectory, "a.txt")); err != nil {
		t.Fatal(err)
	}

	files, err := GetFiles(targetDirectory)
	if err != nil {
		t.Fatal(err)
	}

	if got := files[0]; got != "a.txt" {
		t.Fatalf("got %q first file, wanted %q", got, "a.txt")
	}
	if got := files[1]; got != "b.txt" {
		t.Fatalf("got %q second file, wanted %q", got, "b.txt")
	}
}

// Test read gzip file
func TestReadGZ(t *testing.T) {

	target_file := "../testdata/fixtures/amazonses.com!georgestarcher.com!1518134400!1518220800.xml.gz"
	contents, err := ReadGZ(target_file)
	if err != nil {
		t.Error(err)
	}

	want := "69beecf8fa55a01f30a1896bd72b9436fc875b0b12074f53eb223e8df2581e53"
	h := sha256.New()
	h.Write([]byte(contents))
	got := hex.EncodeToString(h.Sum(nil))

	if got != want {
		t.Errorf("got %x wanted %v\n", got, want)
	}
}

// Test read zip file
func TestReadZip(t *testing.T) {
	target_file := "../testdata/fixtures/aol.com!georgestarcher.com!1342497600!1342584000.zip"
	contents, err := ReadZip(target_file)
	if err != nil {
		t.Error(err)
	}
	want := "2d15ff286e5006e581daa4ef471e665910eeb9d6e2c2469a95ce23e2439be8e3"
	h := sha256.New()
	h.Write([]byte(contents))
	got := hex.EncodeToString(h.Sum(nil))

	if got != want {
		t.Errorf("got %+v wanted %+v\n", got, want)
	}
}

// Test read zlib file
func TestReadZZ(t *testing.T) {

	target_file := "../testdata/fixtures/aol.com!georgestarcher.com!1342497600!1342584000.zlib"
	contents, err := ReadZZ(target_file)
	if err != nil {
		t.Error(err)
	}
	want := "2d15ff286e5006e581daa4ef471e665910eeb9d6e2c2469a95ce23e2439be8e3"
	h := sha256.New()
	h.Write([]byte(contents))
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("got %x wanted %v\n", got, want)
	}
}

// Test zip reading prefers XML content when multiple files are present
func TestReadZipPrefersXMLFile(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "mixed.zip")

	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)

	readme, err := zw.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readme.Write([]byte("plain text payload")); err != nil {
		t.Fatal(err)
	}

	xmlFile, err := zw.Create("report.xml")
	if err != nil {
		t.Fatal(err)
	}
	xmlPayload := []byte("<feedback><report_metadata></report_metadata></feedback>")
	if _, err := xmlFile.Write(xmlPayload); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ReadZip(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, xmlPayload) {
		t.Fatalf("ReadZip() returned %q, wanted %q", string(got), string(xmlPayload))
	}
}

// Test zip reading returns an error for archive without regular files
func TestReadZipNoRegularFiles(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "empty.zip")

	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	_, err = zw.Create("empty/")
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadZip(archivePath); err == nil {
		t.Fatal("expected error for zip with no regular files")
	}
}

// Test zip reading ignores directories and still returns a regular XML payload
func TestReadZipIgnoresDirectoryEntries(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "dir.zip")

	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(out)

	if _, err := zipWriter.Create("nested/"); err != nil {
		t.Fatal(err)
	}
	nestedPayload, err := zipWriter.Create("nested/report.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nestedPayload.Write([]byte("<feedback>nested-payload</feedback>")); err != nil {
		t.Fatal(err)
	}
	payloadFile, err := zipWriter.Create("payload.xml")
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte("<feedback>nested-payload</feedback>")
	if _, err := payloadFile.Write(expected); err != nil {
		t.Fatal(err)
	}

	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ReadZip(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(expected) {
		t.Fatalf("got %q, wanted %q", string(got), string(expected))
	}
}

func TestReadGZWithLimitRejectsLargePayload(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "large.xml.gz")

	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(out)
	if _, err := gw.Write([]byte("1234567890")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadGZWithLimit(archivePath, 5); err == nil {
		t.Fatal("expected size limit error")
	} else if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("got %v, wanted ErrPayloadTooLarge", err)
	}
}

func TestReadZipWithLimitRejectsLargeEntry(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "large.zip")

	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	entry, err := zw.Create("report.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("1234567890")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadZipWithLimit(archivePath, 5); err == nil {
		t.Fatal("expected size limit error")
	} else if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("got %v, wanted ErrPayloadTooLarge", err)
	}
}
