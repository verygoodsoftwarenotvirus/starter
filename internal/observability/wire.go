package observability

import "github.com/google/wire"

var (
	ProvidersObservability = wire.NewSet(
		wire.FieldsOf(
			new(*Config),
			"Logging",
			"Tracing",
		),
	)
)
