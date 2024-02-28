package chi

import "github.com/google/wire"

var (
	// ProvidersChi are what we provide to the dependency injector.
	ProvidersChi = wire.NewSet(
		NewRouter,
		NewRouteParamManager,
	)
)
