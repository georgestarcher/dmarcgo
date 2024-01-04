package utilities

import (
	"archive/zip"
	"compress/gzip"
	"compress/zlib"
	"io"
	"log"
	"os"
)

// Get File Names from Directory
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
	return files, nil
}

// Get gzip encoded File Contents File
func ReadGZ(filepath string) ([]byte, error) {

	fi, err := os.Open(filepath)
	if err !=
		nil {
		log.Fatal(err)
	}

	fgz, err := gzip.NewReader(fi)
	if err != nil {
		return nil, err
	}
	defer fgz.Close()
	s, err := io.ReadAll(fgz)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Get zlib encoded File Contents
func ReadZZ(filepath string) ([]byte, error) {

	fi, err := os.Open(filepath)
	if err !=
		nil {
		log.Fatal(err)
	}

	fgz, err := zlib.NewReader(fi)
	if err != nil {
		return nil, err
	}
	defer fgz.Close()
	s, err := io.ReadAll(fgz)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Get Zip File Contents
func ReadZip(filepath string) ([]byte, error) {

	var unzippedFileBytes []byte
	var err error

	zipReader, err := zip.OpenReader(filepath)
	if err != nil {
		return nil, err
	}

	defer zipReader.Close()

	// Read all the files from zip archive
	for _, zipFile := range zipReader.File {
		unzippedFileBytes, err = readZipFile(zipFile)
	}
	return unzippedFileBytes, err
}

// Read Zip File Bytes
func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
