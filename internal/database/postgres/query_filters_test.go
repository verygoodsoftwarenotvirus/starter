package postgres

import (
	"fmt"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/Masterminds/squirrel"
	"github.com/stretchr/testify/assert"
)

func TestQueryFilter_ApplyFilterToQueryBuilder(T *testing.T) {
	T.Parallel()

	exampleTableName := "stuff"
	baseQueryBuilder := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar).
		Select("things").
		From(exampleTableName).
		Where(squirrel.Eq{fmt.Sprintf("%s.condition", exampleTableName): true})

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		qf := &types.QueryFilter{
			Page:          pointer.To(uint16(100)),
			Limit:         pointer.To(uint8(50)),
			CreatedAfter:  pointer.To(time.Now().Truncate(time.Second)),
			CreatedBefore: pointer.To(time.Now().Truncate(time.Second)),
			UpdatedAfter:  pointer.To(time.Now().Truncate(time.Second)),
			UpdatedBefore: pointer.To(time.Now().Truncate(time.Second)),
			SortBy:        types.SortDescending,
		}

		sb := squirrel.StatementBuilder.Select("*").From("testing")
		sb = applyFilterToQueryBuilder(qf, exampleTableName, sb)
		expected := "SELECT * FROM testing WHERE stuff.created_at > ? AND stuff.created_at < ? AND stuff.last_updated_at > ? AND stuff.last_updated_at < ? LIMIT 50 OFFSET 4950"
		actual, _, err := sb.ToSql()

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		sb := squirrel.StatementBuilder.Select("*").From("testing")
		sb = applyFilterToQueryBuilder(nil, exampleTableName, sb)
		expected := "SELECT * FROM testing"
		actual, _, err := sb.ToSql()

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})

	T.Run("basic usage", func(t *testing.T) {
		t.Parallel()

		qf := &types.QueryFilter{
			Limit: pointer.To(uint8(15)),
			Page:  pointer.To(uint16(2)),
		}

		expected := "SELECT things FROM stuff WHERE stuff.condition = $1 LIMIT 15 OFFSET 15"
		x := applyFilterToQueryBuilder(qf, exampleTableName, baseQueryBuilder)
		actual, args, err := x.ToSql()

		assert.Equal(t, expected, actual, "expected and actual queries don't match")
		assert.Nil(t, err)
		assert.NotEmpty(t, args)
	})

	T.Run("whole kit and kaboodle", func(t *testing.T) {
		t.Parallel()

		qf := &types.QueryFilter{
			Limit:         pointer.To(uint8(20)),
			Page:          pointer.To(uint16(6)),
			CreatedAfter:  pointer.To(time.Now().Truncate(time.Second)),
			CreatedBefore: pointer.To(time.Now().Truncate(time.Second)),
			UpdatedAfter:  pointer.To(time.Now().Truncate(time.Second)),
			UpdatedBefore: pointer.To(time.Now().Truncate(time.Second)),
		}

		expected := "SELECT things FROM stuff WHERE stuff.condition = $1 AND stuff.created_at > $2 AND stuff.created_at < $3 AND stuff.last_updated_at > $4 AND stuff.last_updated_at < $5 LIMIT 20 OFFSET 100"
		x := applyFilterToQueryBuilder(qf, exampleTableName, baseQueryBuilder)
		actual, args, err := x.ToSql()

		assert.Equal(t, expected, actual, "expected and actual queries don't match")
		assert.Nil(t, err)
		assert.NotEmpty(t, args)
	})

	T.Run("with zero limit", func(t *testing.T) {
		t.Parallel()

		qf := &types.QueryFilter{
			Limit: pointer.To(uint8(0)),
			Page:  pointer.To(uint16(1)),
		}
		expected := "SELECT things FROM stuff WHERE stuff.condition = $1 LIMIT 250"
		x := applyFilterToQueryBuilder(qf, exampleTableName, baseQueryBuilder)
		actual, args, err := x.ToSql()

		assert.Equal(t, expected, actual, "expected and actual queries don't match")
		assert.Nil(t, err)
		assert.NotEmpty(t, args)
	})
}

func TestQueryFilter_ApplyFilterToSubCountQueryBuilder(T *testing.T) {
	T.Parallel()

	exampleTableName := "stuff"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		qf := &types.QueryFilter{
			Page:          pointer.To(uint16(100)),
			Limit:         pointer.To(uint8(50)),
			CreatedAfter:  pointer.To(time.Now().Truncate(time.Second)),
			CreatedBefore: pointer.To(time.Now().Truncate(time.Second)),
			UpdatedAfter:  pointer.To(time.Now().Truncate(time.Second)),
			UpdatedBefore: pointer.To(time.Now().Truncate(time.Second)),
			SortBy:        types.SortDescending,
		}

		sb := squirrel.StatementBuilder.Select("*").From("testing")
		sb = applyFilterToSubCountQueryBuilder(qf, exampleTableName, sb)
		expected := "SELECT * FROM testing WHERE stuff.created_at > ? AND stuff.created_at < ? AND stuff.last_updated_at > ? AND stuff.last_updated_at < ?"
		actual, _, err := sb.ToSql()

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})

	T.Run("with nil filter", func(t *testing.T) {
		t.Parallel()

		sb := squirrel.StatementBuilder.Select("*").From("testing")
		sb = applyFilterToSubCountQueryBuilder(nil, exampleTableName, sb)
		expected := "SELECT * FROM testing"
		actual, _, err := sb.ToSql()

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
}
