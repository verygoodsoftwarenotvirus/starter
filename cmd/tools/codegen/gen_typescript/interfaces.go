package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"text/template"

	"github.com/verygoodsoftwarenotvirus/starter/cmd/tools/codegen"
)

func typescriptInterface[T any](x T) (out string, imports []string, err error) {
	typ := reflect.TypeOf(x)
	typeName := typ.Name()
	fieldsForType := reflect.VisibleFields(typ)

	output := fmt.Sprintf("export interface I%s {\n", typeName)

	importedTypes := []string{}
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

		if fieldType == "UserLoginInput" {
			continue
		}

		if isCustomType(fieldType) {
			importedTypes = append(importedTypes, fieldType)
		}

		switch fieldType {
		case timeType:
			fieldType = stringType
		case mapStringToBoolType:
			fieldType = "Record<string, boolean>"
		case boolType:
			fieldType = "boolean"
		}

		if numberMatcherRegex.MatchString(field.Type.String()) {
			fieldType = "number"
		}

		if t, ok := codegen.CustomTypeMap[fmt.Sprintf("%s.%s", typ.Name(), fieldName)]; ok {
			fieldType = t
			importedTypes = append(importedTypes, t)
		}

		line := CodeLine{
			FieldType: fieldType,
			FieldName: fieldName,
			IsPointer: isPointer,
			IsSlice:   isSlice,
		}

		tmpl := template.Must(template.New("").Parse(`	{{.FieldName}}{{if .IsPointer}}?{{end}}: {{if not .IsPointer}}NonNullable<{{end}}{{if .IsSlice}}Array<{{end}}{{.FieldType}}{{if .IsSlice}}>{{end -}}{{if not .IsPointer}}>{{end -}};` + "\n"))

		var b bytes.Buffer
		if tmplExecErr := tmpl.Execute(&b, line); tmplExecErr != nil {
			return "", nil, tmplExecErr
		}

		output += b.String()
	}

	output += "}\n"

	return output, importedTypes, nil
}
