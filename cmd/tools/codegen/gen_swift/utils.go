package main

import (
	"sort"
	"strings"
)

func copyString(s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	return sb.String()
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
