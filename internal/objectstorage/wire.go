package objectstorage

import "github.com/google/wire"

var (
	// Providers are what we provide to the dependency injection framework.
	Providers = wire.NewSet(
		NewUploadManager,
	)
)
