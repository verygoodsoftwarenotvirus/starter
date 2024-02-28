package main

import "fmt"

type QueryType string

const (
	ExecType     QueryType = ":exec"
	ExecRowsType QueryType = ":execrows"
	ManyType     QueryType = ":many"
	OneType      QueryType = ":one"
)

type QueryAnnotation struct {
	Name string
	Type QueryType
}

type Query struct {
	Content    string
	Annotation QueryAnnotation
}

func (q *Query) Render() string {
	return fmt.Sprintf("-- name: %s %s\n\n%s", q.Annotation.Name, q.Annotation.Type, q.Content)
}
