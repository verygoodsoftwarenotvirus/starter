package config

import (
	"github.com/google/wire"
)

var (
	// DatabaseConfigProviders represents this package's offering to the dependency manager.
	DatabaseConfigProviders = wire.NewSet(
		ProvideSessionManager,
	)
)
