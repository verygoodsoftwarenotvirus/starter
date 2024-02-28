package tracing

import "github.com/google/wire"

var (
	ProvidersTracing = wire.NewSet(
		BuildTracedHTTPClient,
	)
)
