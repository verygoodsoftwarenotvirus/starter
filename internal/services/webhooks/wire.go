package webhooks

import (
	"github.com/google/wire"
)

var (
	// Providers are our collection of what we provide to other services.
	Providers = wire.NewSet(
		ProvideWebhooksService,
	)
)
