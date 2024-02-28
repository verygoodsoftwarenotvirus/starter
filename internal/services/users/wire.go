package users

import (
	"github.com/google/wire"
)

// Providers are what we provide for dependency injectors.
var Providers = wire.NewSet(
	ProvideUsersService,
)
