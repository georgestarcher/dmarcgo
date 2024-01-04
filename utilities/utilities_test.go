package utilities

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Test get count of files in directory
func TestGetFiles(t *testing.T) {

	target_directory := "../test_files/"
	report_files, err := GetFiles(target_directory)

	if err != nil {
		t.Error(err)
	}
	want := 3
	got := report_files

	if len(got) != want {
		t.Errorf("got %v, wanted %v", len(got), want)
	}
}

// Test read gzip file
func TestReadGZ(t *testing.T) {

	target_file := "../test_files/amazonses.com!georgestarcher.com!1518134400!1518220800.xml.gz"
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
	target_file := "../test_files/aol.com!georgestarcher.com!1342497600!1342584000.zip"
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

	target_file := "../test_files/aol.com!georgestarcher.com!1342497600!1342584000.zlib"
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
