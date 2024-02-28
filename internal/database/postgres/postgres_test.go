package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/cryptography/encryption/aes"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	try "gopkg.in/matryer/try.v1"
)

const (
	exampleQuantity = 3
)

var (
	runningContainerTests = true // strings.ToLower(os.Getenv("RUN_CONTAINER_TESTS")) == "true"
)

var _ sqlmock.Argument = (*idMatcher)(nil)

type idMatcher struct{}

func (s *idMatcher) Match(v driver.Value) bool {
	x, ok := v.(string)
	if !ok {
		return false
	}

	if err := identifiers.Validate(x); err != nil {
		return false
	}

	return true
}

type sqlmockExpecterWrapper struct {
	sqlmock.Sqlmock
}

func (e *sqlmockExpecterWrapper) AssertExpectations(t mock.TestingT) bool {
	return assert.NoError(t, e.Sqlmock.ExpectationsWereMet(), "not all database expectations were met")
}

func buildTestClient(t *testing.T) (*Querier, *sqlmockExpecterWrapper) {
	t.Helper()

	fakeDB, sqlMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)

	encDec, err := aes.NewEncryptorDecryptor(tracing.NewNoopTracerProvider(), logging.NewNoopLogger(), []byte("blahblahblahblahblahblahblahblah"))
	require.NoError(t, err)

	c := &Querier{
		db: fakeDB,
		config: &config.Config{
			ConnectionDetails: t.Name(),
			LogQueries:        false,
		},
		logger:                  logging.NewNoopLogger(),
		generatedQuerier:        generated.New(),
		timeFunc:                defaultTimeFunc,
		tracer:                  tracing.NewTracerForTest("test"),
		oauth2ClientTokenEncDec: encDec,
	}

	return c, &sqlmockExpecterWrapper{Sqlmock: sqlMock}
}

func hashStringToNumber(s string) uint64 {
	// Create a new FNV-1a 64-bit hash object
	h := fnv.New64a()

	// Write the bytes of the string into the hash object
	_, err := h.Write([]byte(s))
	if err != nil {
		// Handle error if necessary
		panic(err)
	}

	// Return the resulting hash value as a number (uint64)
	return h.Sum64()
}

func reverseString(input string) string {
	runes := []rune(input)
	length := len(runes)

	for i, j := 0, length-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

func splitReverseConcat(input string) string {
	length := len(input)
	halfLength := length / 2

	firstHalf := input[:halfLength]
	secondHalf := input[halfLength:]

	reversedFirstHalf := reverseString(firstHalf)
	reversedSecondHalf := reverseString(secondHalf)

	return reversedSecondHalf + reversedFirstHalf
}

const (
	defaultImage = "postgres:15"
)

func buildDatabaseClientForTest(t *testing.T, ctx context.Context) (*Querier, *postgres.PostgresContainer) {
	t.Helper()

	dbUsername := fmt.Sprintf("%d", hashStringToNumber(t.Name()))
	testcontainers.Logger = log.New(io.Discard, "", log.LstdFlags)

	var container *postgres.PostgresContainer
	err := try.Do(func(attempt int) (bool, error) {
		var containerErr error
		container, containerErr = postgres.RunContainer(
			ctx,
			testcontainers.WithImage(defaultImage),
			postgres.WithDatabase(splitReverseConcat(dbUsername)),
			postgres.WithUsername(dbUsername),
			postgres.WithPassword(reverseString(dbUsername)),
			testcontainers.WithWaitStrategyAndDeadline(2*time.Minute, wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		)

		return attempt < 5, containerErr
	})
	require.NoError(t, err)
	require.NotNil(t, container)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	dbc, err := ProvideDatabaseClient(ctx, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), &config.Config{ConnectionDetails: connStr, RunMigrations: true, OAuth2TokenEncryptionKey: "blahblahblahblahblahblahblahblah"})
	require.NoError(t, err)
	require.NotNil(t, dbc)

	return dbc.(*Querier), container
}

// end helper funcs

func TestQuerier_IsReady(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		db.ExpectPing().WillDelayFor(0)

		assert.True(t, c.IsReady(ctx, time.Second, 1))
	})

	T.Run("with error pinging database", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		db.ExpectPing().WillReturnError(errors.New("blah"))

		assert.False(t, c.IsReady(ctx, time.Second, 1))
	})

	T.Run("exhausting all available queries", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		c, db := buildTestClient(t)

		c.IsReady(ctx, time.Second, 1)

		db.ExpectPing().WillReturnError(errors.New("blah"))

		assert.False(t, c.IsReady(ctx, time.Second, 1))
	})
}

func TestProvideDatabaseClient(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		exampleConfig := &config.Config{
			Debug:                    true,
			OAuth2TokenEncryptionKey: "blahblahblahblahblahblahblahblah",
			RunMigrations:            false,
			MaxPingAttempts:          1,
		}

		actual, err := ProvideDatabaseClient(ctx, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), exampleConfig)
		assert.NotNil(t, actual)
		assert.NoError(t, err)
	})
}

func TestDefaultTimeFunc(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		assert.NotZero(t, defaultTimeFunc())
	})
}

func TestQuerier_currentTime(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		c, _ := buildTestClient(t)

		assert.NotEmpty(t, c.currentTime())
	})

	T.Run("handles nil", func(t *testing.T) {
		t.Parallel()

		var c *Querier

		assert.NotEmpty(t, c.currentTime())
	})
}

func TestQuerier_rollbackTransaction(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		db.ExpectBegin()
		db.ExpectRollback().WillReturnError(errors.New("blah"))

		tx, err := c.db.BeginTx(ctx, nil)
		require.NoError(t, err)

		c.rollbackTransaction(ctx, tx)
	})
}

func TestQuerier_handleRows(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		mockRows := &database.MockResultIterator{}
		mockRows.On("Err").Return(nil)
		mockRows.On("Close").Return(nil)

		c, _ := buildTestClient(t)

		err := c.checkRowsForErrorAndClose(ctx, mockRows)
		assert.NoError(t, err)
	})

	T.Run("with row error", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		expected := errors.New("blah")

		mockRows := &database.MockResultIterator{}
		mockRows.On("Err").Return(expected)

		c, _ := buildTestClient(t)

		err := c.checkRowsForErrorAndClose(ctx, mockRows)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, expected))
	})

	T.Run("with close error", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		expected := errors.New("blah")

		mockRows := &database.MockResultIterator{}
		mockRows.On("Err").Return(nil)
		mockRows.On("Close").Return(expected)

		c, _ := buildTestClient(t)

		err := c.checkRowsForErrorAndClose(ctx, mockRows)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, expected))
	})
}
