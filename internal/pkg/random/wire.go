package random

import "github.com/google/wire"

// ProvidersRandom are what we offer to dependency injection.
var ProvidersRandom = wire.NewSet(
	NewGenerator,
)
