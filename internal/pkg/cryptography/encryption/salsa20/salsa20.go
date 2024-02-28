package salsa20

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/cryptography/encryption"
)

// salsa20Impl is the standard EncryptorDecryptor implementation.
type salsa20Impl struct {
	tracer tracing.Tracer
	logger logging.Logger
	key    [32]byte
}

func NewEncryptorDecryptor(tracerProvider tracing.TracerProvider, logger logging.Logger, key []byte) (encryption.EncryptorDecryptor, error) {
	if len(key) != 32 {
		return nil, encryption.ErrIncorrectKeyLength
	}

	return &salsa20Impl{
		logger: logging.EnsureLogger(logger).WithName("encryptor"),
		tracer: tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("encryptor")),
	}, nil
}
