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
	fieldTemplate = `	let {{.FieldName}}: {{if .IsSlice}}[{{end}}{{.FieldType}}{{if .IsPointer}}?{{end}}{{if .IsSlice}}]{{end -}}{{ if ne .DefaultValue "" }} = {{ .DefaultValue }}{{ end -}};`
)

func swiftStruct[T any](x T) (out string, imports []string, err error) {
	typ := reflect.TypeOf(x)
	fieldsForType := reflect.VisibleFields(typ)

	output := fmt.Sprintf("struct %s {\n", typ.Name())
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

		fieldType := strings.Replace(strings.Replace(strings.Replace(field.Type.String(), "[]", "", 1), "*", "", 1), "types.", "", 1)
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
			fieldType = "String"
			if !isSlice {
				defaultValue = `""`
				if isPointer {
					defaultValue = ""
				}
			}
		case mapStringToBoolType:
			fieldType = "[String: Bool]"
			defaultValue = "[String: Bool]()"
		case timeType:
			fieldType = "Date"
			if !isPointer {
				defaultValue = `Date(timeIntervalSince1970: 0)`
			}
		case boolType:
			fieldType = "Bool"
			if !isSlice {
				defaultValue = "false"
			}
		}

		ts := fieldType
		if numberMatcherRegex.MatchString(ts) {
			switch ts {
			case "int", "int8", "int16", "int32", "int64":
				fieldType = "Int"
			case "uint", "uint8", "uint16", "uint32", "uint64":
				fieldType = "UInt"
			case "float32", "float64":
				fieldType = "Double"
			}
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

		output += b.String() + "\n"
	}

	output += "}\n"

	return output, importedTypes, nil
}
