package postgres

import (
	"github.com/google/wire"
)

var (
	// ProvidersPostgres are what we offer to dependency injection.
	ProvidersPostgres = wire.NewSet(
		ProvideDatabaseClient,
	)
)
