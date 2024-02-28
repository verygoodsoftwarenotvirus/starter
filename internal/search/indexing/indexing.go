package indexing

import (
	"context"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/config"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

var (
	ErrNilIndexRequest = errors.New("nil index request")

	// AllIndexTypes is a list of all index types.
	AllIndexTypes = []string{
		search.IndexTypeUsers,
	}
)

func HandleIndexRequest(ctx context.Context, l logging.Logger, tracerProvider tracing.TracerProvider, searchConfig *config.Config, dataManager database.DataManager, indexReq *IndexRequest) error {
	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("search-indexer"))
	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	if indexReq == nil {
		return observability.PrepareAndLogError(ErrNilIndexRequest, l, span, "handling index requests")
	}

	logger := l.WithValue("index_type_requested", indexReq.IndexType)

	var (
		im                search.IndexManager
		toBeIndexed       any
		err               error
		markAsIndexedFunc func() error
	)

	switch indexReq.IndexType {
	case search.IndexTypeUsers:
		im, err = config.ProvideIndex[types.UserSearchSubset](ctx, logger, tracerProvider, searchConfig, indexReq.IndexType)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "initializing index manager")
		}

		var user *types.User
		user, err = dataManager.GetUser(ctx, indexReq.RowID)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "getting user")
		}

		toBeIndexed = converters.ConvertUserToUserSearchSubset(user)
		markAsIndexedFunc = func() error { return dataManager.MarkUserAsIndexed(ctx, indexReq.RowID) }
	default:
		logger.Info("invalid index type specified, exiting")
		return nil
	}

	if indexReq.Delete {
		if err = im.Delete(ctx, indexReq.RowID); err != nil {
			return observability.PrepareAndLogError(err, logger, span, "deleting data")
		}

		return nil
	} else {
		if err = im.Index(ctx, indexReq.RowID, toBeIndexed); err != nil {
			return observability.PrepareAndLogError(err, logger, span, "indexing data")
		}

		if err = markAsIndexedFunc(); err != nil {
			return observability.PrepareAndLogError(err, logger, span, "marking data as indexed")
		}
	}

	return nil
}

type IndexRequest struct {
	RowID     string `json:"rowID"`
	IndexType string `json:"type"`
	Delete    bool   `json:"delete"`
}
