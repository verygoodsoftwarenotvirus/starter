package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/cryptography/encryption"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/cryptography/encryption/salsa20"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"

	"github.com/alexedwards/scs/postgresstore"
	"github.com/alexedwards/scs/v2"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	tracingName = "db_client"

	// https://www.postgresql.org/docs/current/errcodes-appendix.html
	postgresDuplicateEntryErrorCode = "23505"
)

var _ database.DataManager = (*Querier)(nil)

// Querier is the primary database querying client. All tracing/logging/query execution happens here. Query building generally happens elsewhere.
type Querier struct {
	tracer                  tracing.Tracer
	logger                  logging.Logger
	secretGenerator         random.Generator
	oauth2ClientTokenEncDec encryption.EncryptorDecryptor
	generatedQuerier        generated.Querier
	timeFunc                func() time.Time
	config                  *dbconfig.Config
	db                      *sql.DB
	migrateOnce             sync.Once
}

// ProvideDatabaseClient provides a new DataManager client.
func ProvideDatabaseClient(ctx context.Context, logger logging.Logger, tracerProvider tracing.TracerProvider, cfg *dbconfig.Config) (database.DataManager, error) {
	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(tracingName))

	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	db, err := sql.Open("pgx", cfg.ConnectionDetails)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres database: %w", err)
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(7)
	db.SetConnMaxLifetime(1800 * time.Second)

	encDec, err := salsa20.NewEncryptorDecryptor(tracerProvider, logger, []byte(cfg.OAuth2TokenEncryptionKey))
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "creating encryptor/decryptor with secret length %d", len(cfg.OAuth2TokenEncryptionKey))
	}

	c := &Querier{
		db:                      db,
		config:                  cfg,
		tracer:                  tracer,
		timeFunc:                defaultTimeFunc,
		generatedQuerier:        generated.New(),
		secretGenerator:         random.NewGenerator(logger, tracerProvider),
		logger:                  logging.EnsureLogger(logger).WithName("querier"),
		oauth2ClientTokenEncDec: encDec,
	}

	if cfg.RunMigrations {
		c.logger.Debug("migrating querier")

		if err = c.Migrate(ctx, cfg.PingWaitPeriod, cfg.MaxPingAttempts); err != nil {
			return nil, observability.PrepareAndLogError(err, logger, span, "migrating database")
		}

		c.logger.Debug("querier migrated!")
	}

	return c, nil
}

// DB provides the database object.
func (q *Querier) DB() *sql.DB {
	q.logger.Info("closing database connection")
	return q.db
}

// Close closes the database connection.
func (q *Querier) Close() {
	if err := q.db.Close(); err != nil {
		q.logger.Error(err, "closing database connection")
	}
}

// ProvideSessionStore provides the scs Store for Postgres.
func (q *Querier) ProvideSessionStore() scs.Store {
	return postgresstore.New(q.db)
}

// IsReady is a simple wrapper around the core querier IsReady call.
func (q *Querier) IsReady(ctx context.Context, waitPeriod time.Duration, maxAttempts uint64) (ready bool) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	attemptCount := 0

	logger := q.logger.WithValue("connection_url", q.config.ConnectionDetails)

	for !ready {
		err := q.db.PingContext(ctx)
		if err != nil {
			logger.WithValue("attempt_count", attemptCount).Debug("ping failed, waiting for db")
			time.Sleep(waitPeriod)

			attemptCount++
			if attemptCount >= int(maxAttempts) {
				break
			}
		} else {
			ready = true
			return ready
		}
	}

	return false
}

func defaultTimeFunc() time.Time {
	return time.Now()
}

func (q *Querier) currentTime() time.Time {
	if q == nil || q.timeFunc == nil {
		return defaultTimeFunc()
	}

	return q.timeFunc()
}

func (q *Querier) checkRowsForErrorAndClose(ctx context.Context, rows database.ResultIterator) error {
	_, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if err := rows.Err(); err != nil {
		q.logger.Error(err, "row error")
		return observability.PrepareAndLogError(err, q.logger, span, "row error")
	}

	if err := rows.Close(); err != nil {
		q.logger.Error(err, "closing database rows")
		return observability.PrepareAndLogError(err, q.logger, span, "closing database rows")
	}

	return nil
}

func (q *Querier) rollbackTransaction(ctx context.Context, tx database.SQLQueryExecutorAndTransactionManager) {
	_, span := q.tracer.StartSpan(ctx)
	defer span.End()

	q.logger.Debug("rolling back transaction")

	if err := tx.Rollback(); err != nil {
		observability.AcknowledgeError(err, q.logger, span, "rolling back transaction")
	}

	q.logger.Debug("transaction rolled back")
}
