package main

import (
	"os"

	"github.com/puerco/protobom/pkg/reader"
	"github.com/puerco/protobom/pkg/writer"
	"github.com/sirupsen/logrus"
)

func main() {
	if len(os.Args) != 2 {
		logrus.Fatal("usage: %s sbom.json")
	}

	parser := reader.New()

	doc, err := parser.ParseFile(os.Args[1])
	if err != nil {
		logrus.Fatalf("parsing file: %v", err)
	}

	logrus.Infof("%+v", doc)

	renderer := writer.New()
	if err := renderer.WriteStream(doc, os.Stdout); err != nil {
		logrus.Fatalf("writing sbom to stdout: %v", err)
	}

}
