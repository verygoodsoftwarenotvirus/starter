package postgres

import (
	"fmt"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/Masterminds/squirrel"
)

// applyFilterToQueryBuilder applies the query filter to a query builder.
func applyFilterToQueryBuilder(qf *types.QueryFilter, tableName string, queryBuilder squirrel.SelectBuilder) squirrel.SelectBuilder {
	if qf == nil {
		return queryBuilder
	}

	qf.SetPage(qf.Page)

	if qp := qf.QueryOffset(); qp > 0 {
		queryBuilder = queryBuilder.Offset(uint64(qp))
	}

	if qf.Limit != nil && *qf.Limit != 0 {
		queryBuilder = queryBuilder.Limit(uint64(*qf.Limit))
	} else {
		queryBuilder = queryBuilder.Limit(types.MaxLimit)
	}

	if qf.CreatedAfter != nil {
		queryBuilder = queryBuilder.Where(squirrel.Gt{fmt.Sprintf("%s.%s", tableName, "created_at"): qf.CreatedAfter})
	}

	if qf.CreatedBefore != nil {
		queryBuilder = queryBuilder.Where(squirrel.Lt{fmt.Sprintf("%s.%s", tableName, "created_at"): qf.CreatedBefore})
	}

	if qf.UpdatedAfter != nil {
		queryBuilder = queryBuilder.Where(squirrel.Gt{fmt.Sprintf("%s.%s", tableName, "last_updated_at"): qf.UpdatedAfter})
	}

	if qf.UpdatedBefore != nil {
		queryBuilder = queryBuilder.Where(squirrel.Lt{fmt.Sprintf("%s.%s", tableName, "last_updated_at"): qf.UpdatedBefore})
	}

	return queryBuilder
}

// applyFilterToSubCountQueryBuilder applies the query filter to a query builder.
func applyFilterToSubCountQueryBuilder(qf *types.QueryFilter, tableName string, queryBuilder squirrel.SelectBuilder) squirrel.SelectBuilder {
	if qf == nil {
		return queryBuilder
	}

	if qf.CreatedAfter != nil {
		queryBuilder = queryBuilder.Where(squirrel.Gt{fmt.Sprintf("%s.%s", tableName, "created_at"): qf.CreatedAfter})
	}

	if qf.CreatedBefore != nil {
		queryBuilder = queryBuilder.Where(squirrel.Lt{fmt.Sprintf("%s.%s", tableName, "created_at"): qf.CreatedBefore})
	}

	if qf.UpdatedAfter != nil {
		queryBuilder = queryBuilder.Where(squirrel.Gt{fmt.Sprintf("%s.%s", tableName, "last_updated_at"): qf.UpdatedAfter})
	}

	if qf.UpdatedBefore != nil {
		queryBuilder = queryBuilder.Where(squirrel.Lt{fmt.Sprintf("%s.%s", tableName, "last_updated_at"): qf.UpdatedBefore})
	}

	return queryBuilder
}
