package postgres

import (
	"context"
	"embed"
	"fmt"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"

	"github.com/GuiaBolso/darwin"
)

func fetchMigration(name string) string {
	file, err := rawMigrations.ReadFile(fmt.Sprintf("migrations/%s.sql", name))
	if err != nil {
		panic(err)
	}

	return string(file)
}

// BuildMigrationFunc returns a sync.Once compatible function closure that will migrate a postgres database.
func (q *Querier) migrationFunc() {
	driver := darwin.NewGenericDriver(q.db, darwin.PostgresDialect{})
	if err := darwin.New(driver, migrations, nil).Migrate(); err != nil {
		panic(fmt.Errorf("running migration: %w", err))
	}
}

// Migrate is a simple wrapper around the core querier Migrate call.
func (q *Querier) Migrate(ctx context.Context, waitPeriod time.Duration, maxAttempts uint64) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	q.logger.Info("migrating db")

	if !q.IsReady(ctx, waitPeriod, maxAttempts) {
		return database.ErrDatabaseNotReady
	}

	q.migrateOnce.Do(q.migrationFunc)

	return nil
}

var (
	//go:embed migrations/*.sql
	rawMigrations embed.FS

	migrations = []darwin.Migration{
		{
			Version:     1,
			Description: "basic infrastructural tables",
			Script:      fetchMigration("00001_baseline"),
		},
	}
)
