package database

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/alexedwards/scs/v2"
)

var (
	// ErrDatabaseNotReady indicates the given database is not ready.
	ErrDatabaseNotReady = errors.New("database is not ready yet")

	// ErrUserAlreadyExists indicates that a user with that username has already been created.
	ErrUserAlreadyExists = errors.New("user already exists")
)

type (
	// Scanner represents any database response (i.e. sql.Row[s]).
	Scanner interface {
		Scan(dest ...any) error
	}

	// ResultIterator represents any iterable database response (i.e. sql.Rows).
	ResultIterator interface {
		Next() bool
		Err() error
		Scanner
		io.Closer
	}

	// SQLQueryExecutor is a subset interface for sql.{DB|Tx} objects.
	SQLQueryExecutor interface {
		ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
		PrepareContext(context.Context, string) (*sql.Stmt, error)
		QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
		QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	}

	// SQLTransactionManager is a subset interface for sql.{DB|Tx} objects.
	SQLTransactionManager interface {
		Rollback() error
	}

	// SQLQueryExecutorAndTransactionManager is a subset interface for sql.{DB|Tx} objects.
	SQLQueryExecutorAndTransactionManager interface {
		SQLQueryExecutor
		SQLTransactionManager
	}

	// DataManager describes anything that stores data for our services.
	DataManager interface {
		DB() *sql.DB
		Close()
		Migrate(ctx context.Context, waitPeriod time.Duration, maxAttempts uint64) error
		IsReady(ctx context.Context, waitPeriod time.Duration, maxAttempts uint64) (ready bool)
		ProvideSessionStore() scs.Store

		types.AdminUserDataManager
		types.AccountDataManager
		types.AccountInvitationDataManager
		types.AccountUserMembershipDataManager
		types.UserDataManager
		types.PasswordResetTokenDataManager
		types.WebhookDataManager
		types.ServiceSettingDataManager
		types.ServiceSettingConfigurationDataManager
		types.OAuth2ClientDataManager
		types.OAuth2ClientTokenDataManager
		types.UserNotificationDataManager
		types.AuditLogEntryDataManager
	}
)
