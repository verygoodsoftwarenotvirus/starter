package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"

	"github.com/verygoodsoftwarenotvirus/starter/cmd/tools/codegen"

	"github.com/invopop/jsonschema"
)

func getTypeName(x any) string {
	if t := reflect.TypeOf(x); t.Kind() == reflect.Ptr {
		return t.Elem().Name()
	} else {
		return t.Name()
	}
}

func writeSchemaToFile(schema *jsonschema.Schema, outputFilepath string) error {
	encodedSchema, err := json.MarshalIndent(schema, "", "\t")
	if err != nil {
		return err
	}

	if writeErr := os.WriteFile(outputFilepath, encodedSchema, os.ModePerm); writeErr != nil {
		return writeErr
	}

	return nil
}

func main() {
	if err := os.MkdirAll("artifacts", os.ModeDir); err != nil {
		log.Println("artifacts directory already exists")
	}

	for _, typesToGenerateFor := range codegen.TypeDefinitionFilesToGenerate {
		for _, typ := range typesToGenerateFor {
			schema := jsonschema.Reflect(typ)

			if err := writeSchemaToFile(schema, fmt.Sprintf("artifacts/%s.jsonschema", getTypeName(typ))); err != nil {
				panic(err)
			}
		}
	}
}
