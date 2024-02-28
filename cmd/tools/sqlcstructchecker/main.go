package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/go-multierror"
)

func noTestFiles(f os.FileInfo) bool {
	return !f.IsDir() && !strings.HasSuffix(f.Name(), "_test.go")
}

func fetchTypesForPackage(pkg string, nameFilter func(string) bool) map[string]*ast.StructType {
	fileset := token.NewFileSet()
	astPkg, err := parser.ParseDir(fileset, pkg, noTestFiles, parser.AllErrors)
	if err != nil {
		log.Fatalf("failed to parse package: %p", err)
	}

	if len(astPkg) != 1 {
		return nil
	}

	foundTypes := map[string]*ast.StructType{}
	for _, p := range astPkg {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch t := n.(type) {
				case *ast.TypeSpec:
					if structType, ok := t.Type.(*ast.StructType); ok && nameFilter(t.Name.Name) {
						foundTypes[t.Name.Name] = structType
					}
				}
				return true
			})
		}
	}

	return foundTypes
}

func getFieldsForStruct(structType *ast.StructType) map[string]string {
	structFields := make(map[string]string)

	for _, field := range structType.Fields.List {
		fieldType := ""
		switch t := field.Type.(type) {
		case *ast.Ident:
			fieldType = t.Name
		case *ast.SelectorExpr:
			fieldType = fmt.Sprintf("%s.%s", t.X, t.Sel.Name)
		}

		for _, name := range field.Names {
			if name.Name != "_" {
				structFields[name.Name] = fieldType
			}
		}
	}

	return structFields
}

func main() {
	paramTypes := fetchTypesForPackage("internal/database/postgres/generated", func(s string) bool {
		return strings.HasSuffix(s, "Params")
	})

	fileset := token.NewFileSet()
	astPkg, err := parser.ParseDir(fileset, "internal/database/postgres", noTestFiles, parser.AllErrors)
	if err != nil {
		log.Fatalf("failed to parse package: %p", err)
	}

	var errors *multierror.Error

	for _, p := range astPkg {
		for fileName, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch t := n.(type) {
				case *ast.File:
					for _, decl := range t.Decls {
						switch dt := decl.(type) {
						case *ast.FuncDecl:
							for _, stmt := range dt.Body.List {
								switch st := stmt.(type) {
								case *ast.AssignStmt:
									for _, expr := range st.Rhs {
										switch et := expr.(type) {
										case *ast.CallExpr:
											switch ft := et.Fun.(type) {
											case *ast.SelectorExpr:
												if ftIdent, ok := ft.X.(*ast.SelectorExpr); ok {
													if ftIdent.Sel.Name == "generatedQuerier" {
														if len(et.Args) == 3 {
															thirdParam := et.Args[2]

															if ue, isUE := thirdParam.(*ast.UnaryExpr); isUE {
																if se, isSE := ue.X.(*ast.CompositeLit); isSE {
																	if tt, isType := se.Type.(*ast.SelectorExpr); isType {
																		lookup := tt.Sel.Name
																		if fieldDef, present := paramTypes[lookup]; present {
																			fieldsUsed := map[string]string{}
																			for _, el := range se.Elts {
																				if kv, isKV := el.(*ast.KeyValueExpr); isKV {
																					if ident, isIdent := kv.Key.(*ast.Ident); isIdent {
																						fieldsUsed[ident.Name] = ""
																					}
																				}
																			}

																			structsForField := getFieldsForStruct(fieldDef)
																			for fieldName := range structsForField {
																				if _, used := fieldsUsed[fieldName]; !used {
																					errors = multierror.Append(errors, fmt.Errorf("field %s not used in %s in %s", fieldName, lookup, strings.TrimPrefix(fileName, "internal/database/postgres/")))
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
				return true
			})
		}
	}

	if errors.ErrorOrNil() != nil {
		log.Fatal(errors)
	}
}
