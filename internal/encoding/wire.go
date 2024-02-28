package encoding

import (
	"github.com/google/wire"
)

var (
	// EncDecProviders provides ResponseEncoders for dependency injection.
	EncDecProviders = wire.NewSet(
		ProvideServerEncoderDecoder,
		ProvideContentType,
	)
)

// ProvideContentType provides a ContentType from a Config.
func ProvideContentType(cfg Config) ContentType {
	return contentTypeFromString(cfg.ContentType)
}
