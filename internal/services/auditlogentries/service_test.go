package auditlogentries

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	mockrouting "github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func buildTestService() *service {
	return &service{
		logger:                   logging.NewNoopLogger(),
		auditLogEntryDataManager: &mocktypes.AuditLogEntryDataManagerMock{},
		auditLogEntryIDFetcher:   func(req *http.Request) string { return "" },
		encoderDecoder:           encoding.ProvideServerEncoderDecoder(nil, nil, encoding.ContentTypeJSON),
		tracer:                   tracing.NewTracerForTest("test"),
		cfg:                      &Config{},
	}
}

func TestProvideAuditLogEntriesService(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			AuditLogEntryIDURIParamKey,
		).Return(func(*http.Request) string { return "" })
		cfg := &Config{}

		s, err := ProvideService(
			ctx,
			logger,
			cfg,
			&mocktypes.AuditLogEntryDataManagerMock{},
			mockencoding.NewMockEncoderDecoder(),
			rpm,
			tracing.NewNoopTracerProvider(),
		)

		assert.NotNil(t, s)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, rpm)
	})
}
