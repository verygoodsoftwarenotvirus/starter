package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	msgconfig "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/indexing"

	_ "github.com/KimMachineGun/automemlimit"
	"github.com/hashicorp/go-multierror"
	"go.opentelemetry.io/otel"
	_ "go.uber.org/automaxprocs"
)

func doTheThing() error {
	ctx := context.Background()

	logger := (&loggingcfg.Config{Level: logging.DebugLevel, Provider: loggingcfg.ProviderSlog}).ProvideLogger()

	if strings.TrimSpace(strings.ToLower(os.Getenv("CEASE_OPERATION"))) == "true" {
		logger.Info("CEASE_OPERATION is set to true, exiting")
	}

	cfg, err := config.GetSearchDataIndexSchedulerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		log.Fatal(fmt.Errorf("error getting config: %w", err))
	}

	logger = logger.WithValue("commit", cfg.Commit())

	tracerProvider, err := cfg.Observability.Tracing.ProvideTracerProvider(ctx, logger)
	if err != nil {
		logger.Error(err, "initializing tracer")
	}
	otel.SetTracerProvider(tracerProvider)
	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("search_indexer_cloud_function"))

	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	// manual db timeout until I find out what's wrong
	dbConnectionContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	dataManager, err := postgres.ProvideDatabaseClient(dbConnectionContext, logger, tracerProvider, &cfg.Database)
	if err != nil {
		cancel()
		return observability.PrepareError(err, span, "establishing database connection")
	}

	if err = dataManager.DB().PingContext(ctx); err != nil {
		cancel()
		return observability.PrepareError(err, span, "pinging database")
	}
	defer dataManager.Close()

	cancel()

	publisherProvider, err := msgconfig.ProvidePublisherProvider(ctx, logger, tracerProvider, &cfg.Events)
	if err != nil {
		return observability.PrepareError(err, span, "configuring queue manager")
	}
	defer publisherProvider.Close()

	searchDataIndexPublisher, err := publisherProvider.ProvidePublisher(os.Getenv("SEARCH_INDEXING_TOPIC_NAME"))
	if err != nil {
		return observability.PrepareError(err, span, "configuring search indexing publisher")
	}
	defer searchDataIndexPublisher.Stop()

	// figure out what records to join
	//nolint:gosec // not important to use crypto/rand here
	chosenIndex := indexing.AllIndexTypes[rand.Intn(len(indexing.AllIndexTypes))]

	logger = logger.WithValue("chosen_index_type", chosenIndex)
	logger.Info("index type chosen")

	var actionFunc func(context.Context) ([]string, error)
	switch chosenIndex {
	case search.IndexTypeUsers:
		actionFunc = dataManager.GetUserIDsThatNeedSearchIndexing
	default:
		logger.Info("unhandled index type chosen, exiting")
		return nil
	}

	var ids []string
	ids, err = actionFunc(ctx)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			observability.AcknowledgeError(err, logger, span, "getting %s IDs that need search indexing", chosenIndex)
			return err
		}
		return nil
	}

	if len(ids) > 0 {
		logger.WithValue("count", len(ids)).Info("publishing search index requests")
	}

	var errs *multierror.Error
	for _, id := range ids {
		indexReq := &indexing.IndexRequest{
			RowID:     id,
			IndexType: chosenIndex,
		}
		if err = searchDataIndexPublisher.Publish(ctx, indexReq); err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	return errs.ErrorOrNil()
}

func main() {
	if err := doTheThing(); err != nil {
		log.Fatal(err)
	}
}
