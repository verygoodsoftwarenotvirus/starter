package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/algolia"
	searchcfg "github.com/verygoodsoftwarenotvirus/starter/internal/search/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/indexing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

func main() {
	indicesPtr := flag.String("indices", "", "indices to initialize")
	wipePtr := flag.Bool("wipe", false, "whether to wipe the indices or not")

	flag.Parse()

	indices := strings.Split(*indicesPtr, ",")
	if len(indices) == 0 {
		log.Fatal("indices are required")
	}

	ctx := context.Background()

	logger := (&loggingcfg.Config{Level: logging.DebugLevel, Provider: loggingcfg.ProviderSlog}).ProvideLogger()

	tracerProvider := tracing.NewNoopTracerProvider()

	cfg := &searchcfg.Config{
		Provider: searchcfg.AlgoliaProvider,
		Algolia: &algolia.Config{
			AppID:  os.Getenv("ALGOLIA_APP_ID"),
			APIKey: os.Getenv("ALGOLIA_API_KEY"),
		},
	}

	dbConfig := &dbconfig.Config{
		ConnectionDetails: os.Getenv("DATABASE_URL"),
	}

	dataManager, err := postgres.ProvideDatabaseClient(ctx, logger, tracerProvider, dbConfig)
	if dataManager != nil {
		defer dataManager.Close()
	}

	if err != nil {
		log.Println(fmt.Errorf("initializing database client: %w", err))
		return
	}

	var (
		im               search.IndexManager
		indexRequestChan = make(chan *indexing.IndexRequest)
		wipeOnce         sync.Once
		waitGroup        sync.WaitGroup
	)

	go func() {
		for x := range indexRequestChan {
			wipeOnce.Do(func() {
				if *wipePtr {
					log.Println("wiping index")
					if err = im.Wipe(ctx); err != nil {
						log.Println(fmt.Errorf("wiping index: %w", err))
						return
					}
					log.Println("wiped index")
				}
			})

			if err = indexing.HandleIndexRequest(ctx, logger, tracerProvider, cfg, dataManager, x); err != nil {
				observability.AcknowledgeError(err, logger, nil, "indexing row")
			}

			waitGroup.Done()
		}
	}()

	for i, index := range indices {
		if i > 0 {
			waitGroup.Wait()
		}

		filter := types.DefaultQueryFilter()
		filter.Limit = pointer.To(uint8(50))
		thresholdMet := false

		switch index {
		case search.IndexTypeUsers:
			im, err = searchcfg.ProvideIndex[types.UserSearchSubset](ctx, logger, tracerProvider, cfg, index)
			if err != nil {
				observability.AcknowledgeError(err, logger, nil, "initializing index manager")
				return
			}

			for !thresholdMet {
				var data *types.QueryFilteredResult[types.User]
				data, err = dataManager.GetUsers(ctx, filter)
				if err != nil {
					log.Println(fmt.Errorf("getting user data: %w", err))
					return
				}

				for _, x := range data.Data {
					indexRequestChan <- &indexing.IndexRequest{
						RowID:     x.ID,
						IndexType: search.IndexTypeUsers,
					}
					waitGroup.Add(1)
				}

				thresholdMet = len(data.Data) == 0
				*filter.Page++
			}
		}
	}
}
