package algolia

import (
	"context"
	"fmt"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	algolia "github.com/algolia/algoliasearch-client-go/v3/algolia/search"
)

var (
	_ search.Index[types.UserSearchSubset] = (*indexManager[types.UserSearchSubset])(nil)
)

type (
	indexManager[T search.Searchable] struct {
		logger   logging.Logger
		tracer   tracing.Tracer
		client   *algolia.Index
		DataType *T
		timeout  time.Duration
	}
)

func ProvideIndexManager[T search.Searchable](
	_ context.Context,
	logger logging.Logger,
	tracerProvider tracing.TracerProvider,
	cfg *Config,
	indexName string,
) (search.Index[T], error) {
	im := &indexManager[T]{
		tracer:  tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(fmt.Sprintf("search_%s", indexName))),
		logger:  logging.EnsureLogger(logger).WithName(indexName),
		client:  algolia.NewClient(cfg.AppID, cfg.APIKey).InitIndex(indexName),
		timeout: cfg.Timeout,
	}

	return im, nil
}
