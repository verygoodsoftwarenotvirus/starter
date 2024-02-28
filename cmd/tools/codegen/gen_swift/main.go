package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/cmd/tools/codegen"

	"github.com/hashicorp/go-multierror"
)

const (
	destinationDirectory = "artifacts/swift"

	timeType            = "time.Time"
	mapStringToBoolType = "map[string]bool"
	stringType          = "string"
	boolType            = "bool"
)

type CodeLine struct {
	FieldType    string
	FieldName    string
	DefaultValue string
	IsReadonly   bool
	IsPointer    bool
	IsSlice      bool
	CustomType   bool
}

func main() {
	if destinationDirectory == "artifacts/swift" {
		if err := os.RemoveAll(destinationDirectory); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(destinationDirectory, os.ModePerm); err != nil {
			panic(err)
		}
	}

	var errors *multierror.Error

	if err := os.WriteFile(fmt.Sprintf("%s/%s", destinationDirectory, "_unions.swift"), []byte(buildUnionsFile()), 0o600); err != nil {
		errors = multierror.Append(errors, err)
	}

	for _, filename := range sortedMapKeys(codegen.TypeDefinitionFilesToGenerate) {
		typesToGenerateFor := codegen.TypeDefinitionFilesToGenerate[filename]
		output := ""
		filesToImportsMapForFile := map[string]map[string]struct{}{}

		for _, typ := range typesToGenerateFor {
			typClass, _, err := swiftStruct(typ)
			if err != nil {
				panic(err)
			}

			output += typClass + "\n"
		}

		fileOutput := copyString(generatedDisclaimer) + "\n" + "import Foundation\n"
		for _, file := range sortedMapKeys(filesToImportsMapForFile) {
			imports := filesToImportsMapForFile[file]
			if file == filename {
				continue
			}

			fileOutput += fmt.Sprintf("import { %s } from './%s';\n", strings.Join(sortedMapKeys(imports), ", "), strings.TrimSuffix(file, ".ts"))
		}

		finalOutput := fileOutput + "\n" + output

		if err := os.WriteFile(fmt.Sprintf("%s/%s", destinationDirectory, filename), []byte(strings.TrimSpace(finalOutput)+"\n"), 0o600); err != nil {
			errors = multierror.Append(errors, err)
		}
	}

	if err := errors.ErrorOrNil(); err != nil {
		panic(err)
	}
}
