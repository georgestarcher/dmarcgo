# dmarcgo [![Build Status](https://github.com/georgestarcher/dmarcgo/workflows/dmarcgo%20CI/badge.svg)](https://github.com/georgestarcher/dmarcgo/actions)[![Report Card](https://goreportcard.com/badge/github.com/georgestarcher/dmarcgo)](https://goreportcard.com/report/github.com/georgestarcher/dmarcgo)

A Go (golang) module for handling Email [DMARC](https://dmarc.org) summary reports.

Written by George Starcher

MIT license, check license.txt for more information

All text above must be included in any redistribution

## Installation

```shell
go get github.com/georgestarcher/dmarcgo
```

## Usage

1. Make a Report object
2. Set the path to the report file
3. Call the LoadReportFile() method. This method will try to load the file as a gzip, zip then zlib compressed file automatically. 

In your Go app you can do something like the below. You can use the json.Marshal of the Features() method to send the unspooled summary report file to a system such as Splunk etc for processing.

```go
package main

import (
	"dmarc"
	"encoding/json"
	"fmt"
	"log"
	"utilities"
)

func main() {

	report_directory := "../../reports/dmarc/"
	report_files, err := utilities.GetFiles(report_directory)
	if err != nil {
		log.Fatal(err)
	}

	dmarcReport := new(dmarc.Report)
	for _, file := range report_files {
		dmarcReport.FilePath = fmt.Sprintf("%+v%+v", report_directory, file)
		fmt.Printf("Called on: %+v\n", dmarcReport.FilePath)
		err = dmarcReport.LoadReportFile()
		if err != nil {
			log.Fatal(err)
		}
		for _, report := range dmarcReport.Content.Features() {
			feature_json, err := json.Marshal(report)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(feature_json))
		}
	}
}
```


