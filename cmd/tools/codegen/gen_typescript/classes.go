package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"text/template"

	"github.com/verygoodsoftwarenotvirus/starter/cmd/tools/codegen"
)

const (
	fieldTemplate = `	{{.FieldName}}{{if .IsPointer}}?{{end}}: {{if not .IsPointer}}NonNullable<{{end}}{{if .IsSlice}}Array<{{end}}{{.FieldType}}{{if .IsSlice}}>{{end -}}{{if not .IsPointer}}>{{end -}}{{ if ne .DefaultValue "" }} = {{ .DefaultValue }}{{ end -}};` + "\n"
)

func typescriptClass[T any](x T) (out string, imports []string, err error) {
	typ := reflect.TypeOf(x)
	fieldsForType := reflect.VisibleFields(typ)

	output := fmt.Sprintf("export class %s implements I%s {\n", typ.Name(), typ.Name())
	importedTypes := []string{}

	parsedLines := []CodeLine{}
	for i := range fieldsForType {
		field := fieldsForType[i]
		if field.Name == "_" {
			continue
		}

		fieldName := strings.TrimSuffix(field.Tag.Get("json"), ",omitempty")
		if fieldName == "-" {
			continue
		}

		fieldType := strings.Replace(strings.TrimPrefix(strings.Replace(field.Type.String(), "[]", "", 1), "*"), "types.", "", 1)
		isPointer := field.Type.Kind() == reflect.Ptr
		isSlice := field.Type.Kind() == reflect.Slice
		defaultValue := ""
		customType := isCustomType(fieldType)

		if fieldType == "UserLoginInput" {
			continue
		}

		if isSlice {
			defaultValue = "[]"
		}

		if isCustomType(fieldType) {
			importedTypes = append(importedTypes, fieldType)
		}

		switch fieldType {
		case stringType:
			if !isSlice {
				defaultValue = `''`
				if isPointer {
					defaultValue = ""
				}
			}
		case mapStringToBoolType:
			fieldType = "Record<string, boolean>"
			defaultValue = "{}"
		case timeType:
			fieldType = stringType
			if !isPointer {
				defaultValue = "'1970-01-01T00:00:00Z'"
			}
		case boolType:
			fieldType = "boolean"
			if !isSlice {
				defaultValue = "false"
			}
		}

		if numberMatcherRegex.MatchString(field.Type.String()) {
			fieldType = "number"
			if !isPointer && !isSlice {
				defaultValue = "0"
			}
		}

		if customType && !isSlice && !isPointer {
			defaultValue = fmt.Sprintf("new %s()", fieldType)
		}

		if t, ok := codegen.CustomTypeMap[fmt.Sprintf("%s.%s", typ.Name(), fieldName)]; ok {
			fieldType = t
			importedTypes = append(importedTypes, t)
			defaultValue = codegen.DefaultEnumValues[t]
		}

		line := CodeLine{
			FieldType:    fieldType,
			FieldName:    fieldName,
			IsPointer:    isPointer,
			IsSlice:      isSlice,
			DefaultValue: defaultValue,
			CustomType:   customType,
		}

		tmpl := template.Must(template.New("").Parse(fieldTemplate))

		var b bytes.Buffer
		if tmplExecErr := tmpl.Execute(&b, line); tmplExecErr != nil {
			return "", nil, tmplExecErr
		}

		thisLine := b.String()
		output += thisLine
		parsedLines = append(parsedLines, line)
	}

	output += fmt.Sprintf(`
	constructor(input: Partial<%s> = {}) {
`, typ.Name())

	for i := range parsedLines {
		line := parsedLines[i]

		dv := ""
		if line.DefaultValue != "" {
			dv = fmt.Sprintf(" ?? %s", line.DefaultValue)
		}

		output += fmt.Sprintf("    this.%s = input.%s%s;\n", line.FieldName, line.FieldName, dv)
	}

	output += "	}\n}\n"

	return output, importedTypes, nil
}
