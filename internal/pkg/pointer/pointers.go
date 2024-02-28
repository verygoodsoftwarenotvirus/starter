package pointer

// To returns a pointer to a value.
func To[T any](x T) *T {
	return &x
}
