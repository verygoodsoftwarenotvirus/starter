package main

import (
	"fmt"
	"strings"
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
	output += fmt.Sprintf("enum %s: String{\n", def.Name)
	for _, value := range def.Values {
		output += fmt.Sprintf("case %s = %q\n", strings.ReplaceAll(value, " ", "_"), value)
	}
	output += "}\n"

	return output
}

func buildUnionsFile() string {
	output := copyString(generatedDisclaimer)

	for _, def := range unions {
		output += buildUnionDeclaration(def)
	}

	return output
}
