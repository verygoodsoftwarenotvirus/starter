package main

import (
	"fmt"
)

type unionDefinition struct {
	Name,
	ConstName,
	Comment string
	Values []string
}

var (
	unions = []*unionDefinition{}
)

func buildUnionDeclaration(def *unionDefinition) string {
	if def == nil {
		return ""
	}

	output := ""

	output += fmt.Sprintf("/**\n * %s\n */\n", def.Comment)
	output += fmt.Sprintf("export const ALL_%s: string[] = [\n", def.ConstName)
	for _, value := range def.Values {
		output += fmt.Sprintf("  %q,\n", value)
	}
	output += "];\n"

	output += fmt.Sprintf("type %sTypeTuple = typeof ALL_%s;\n", def.Name, def.ConstName)
	output += fmt.Sprintf("export type %s = %sTypeTuple[number];\n\n", def.Name, def.Name)

	return output
}

func buildUnionsFile() string {
	output := copyString(generatedDisclaimer)

	for _, def := range unions {
		output += buildUnionDeclaration(def)
	}

	return output
}
